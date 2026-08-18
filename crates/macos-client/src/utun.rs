use std::{
    ffi::CStr,
    io,
    mem::{size_of, zeroed},
    net::Ipv4Addr,
    os::fd::RawFd,
    process::Command,
};

const PF_SYSTEM: libc::c_int = 32;
const AF_SYSTEM: libc::c_uchar = 32;
const AF_SYS_CONTROL: libc::c_ushort = 2;
const SYSPROTO_CONTROL: libc::c_int = 2;
const UTUN_OPT_IFNAME: libc::c_int = 2;
const MAX_KCTL_NAME: usize = 96;
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control\0";

#[repr(C)]
struct ControlInfo {
    id: u32,
    name: [libc::c_char; MAX_KCTL_NAME],
}

#[repr(C)]
struct SockAddrControl {
    length: libc::c_uchar,
    family: libc::c_uchar,
    system_address: libc::c_ushort,
    id: u32,
    unit: u32,
    reserved: [u32; 5],
}

pub(crate) struct Utun {
    descriptor: RawFd,
    name: String,
}

impl Utun {
    pub(crate) fn create() -> Result<Self, io::Error> {
        let descriptor = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        match connect_control(descriptor) {
            Ok(name) => Ok(Self { descriptor, name }),
            Err(error) => {
                unsafe { libc::close(descriptor) };
                Err(error)
            }
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn set_nonblocking(&self) -> Result<(), io::Error> {
        let flags = unsafe { libc::fcntl(self.descriptor, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(self.descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(crate) fn configure(
        &self,
        address: Ipv4Addr,
        prefix_len: u8,
        mtu: u16,
    ) -> Result<(), io::Error> {
        if prefix_len > 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid tunnel prefix length",
            ));
        }
        let mask = Ipv4Addr::from(if prefix_len == 0 {
            0
        } else {
            u32::MAX << (32 - prefix_len)
        });
        run(
            "/sbin/ifconfig",
            &[
                &self.name,
                "inet",
                &address.to_string(),
                &address.to_string(),
                "netmask",
                &mask.to_string(),
                "mtu",
                &mtu.to_string(),
                "up",
            ],
        )
    }

    pub(crate) fn read_packet(&self, packet: &mut [u8]) -> Result<Option<usize>, io::Error> {
        let mut family = [0_u8; 4];
        let mut vectors = [
            libc::iovec {
                iov_base: family.as_mut_ptr().cast(),
                iov_len: family.len(),
            },
            libc::iovec {
                iov_base: packet.as_mut_ptr().cast(),
                iov_len: packet.len(),
            },
        ];
        let length = unsafe { libc::readv(self.descriptor, vectors.as_mut_ptr(), 2) };
        if length < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(length).map_err(io::Error::other)?;
        if length < family.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun packet is missing its address-family header",
            ));
        }
        match u32::from_be_bytes(family) {
            value if value == libc::AF_INET as u32 => Ok(Some(length - family.len())),
            value if value == libc::AF_INET6 as u32 => Ok(None),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "utun received an unknown address family",
            )),
        }
    }

    pub(crate) fn write_packet(&self, packet: &[u8]) -> Result<(), io::Error> {
        let family = (libc::AF_INET as u32).to_be_bytes();
        let mut vectors = [
            libc::iovec {
                iov_base: family.as_ptr().cast_mut().cast(),
                iov_len: family.len(),
            },
            libc::iovec {
                iov_base: packet.as_ptr().cast_mut().cast(),
                iov_len: packet.len(),
            },
        ];
        let written = unsafe { libc::writev(self.descriptor, vectors.as_mut_ptr(), 2) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        let expected = family.len() + packet.len();
        if usize::try_from(written).map_err(io::Error::other)? != expected {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short write to utun",
            ));
        }
        Ok(())
    }
}

impl Drop for Utun {
    fn drop(&mut self) {
        unsafe { libc::close(self.descriptor) };
    }
}

fn connect_control(descriptor: RawFd) -> Result<String, io::Error> {
    let mut info: ControlInfo = unsafe { zeroed() };
    for (destination, source) in info.name.iter_mut().zip(UTUN_CONTROL_NAME) {
        *destination = libc::c_char::try_from(*source).map_err(io::Error::other)?;
    }
    if unsafe { libc::ioctl(descriptor, CTLIOCGINFO, &mut info) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let address = SockAddrControl {
        length: u8::try_from(size_of::<SockAddrControl>()).map_err(io::Error::other)?,
        family: AF_SYSTEM,
        system_address: AF_SYS_CONTROL,
        id: info.id,
        unit: 0,
        reserved: [0; 5],
    };
    let result = unsafe {
        libc::connect(
            descriptor,
            (&raw const address).cast::<libc::sockaddr>(),
            u32::try_from(size_of::<SockAddrControl>()).map_err(io::Error::other)?,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut name = [0_i8; 64];
    let mut length = u32::try_from(name.len()).map_err(io::Error::other)?;
    if unsafe {
        libc::getsockopt(
            descriptor,
            SYSPROTO_CONTROL,
            UTUN_OPT_IFNAME,
            name.as_mut_ptr().cast(),
            &raw mut length,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    unsafe { CStr::from_ptr(name.as_ptr()) }
        .to_str()
        .map(str::to_owned)
        .map_err(io::Error::other)
}

fn run(program: &str, arguments: &[&str]) -> Result<(), io::Error> {
    let output = Command::new(program).args(arguments).output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{} {} failed: {}",
        program,
        arguments.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
