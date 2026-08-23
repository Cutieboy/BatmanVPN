#![doc = "Minimal in-place editing of the IP packets `WinDivert` hands over."]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Offsets into an IPv4 header, in bytes.
mod v4 {
    pub(super) const PROTOCOL: usize = 9;
    pub(super) const SOURCE: usize = 12;
    pub(super) const DESTINATION: usize = 16;
    pub(super) const FRAGMENT: usize = 6;
    pub(super) const MIN_HEADER: usize = 20;
}

/// Offsets into an IPv6 header, in bytes.
mod v6 {
    pub(super) const NEXT_HEADER: usize = 6;
    pub(super) const SOURCE: usize = 8;
    pub(super) const DESTINATION: usize = 24;
    pub(super) const HEADER: usize = 40;
}

pub(crate) const PROTOCOL_TCP: u8 = 6;
pub(crate) const PROTOCOL_UDP: u8 = 17;

/// The low 13 bits of the IPv4 fragment field hold the offset; the upper 3
/// are flags.
const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;

/// A borrowed IP packet that can have its addresses rewritten.
///
/// Rewriting invalidates the IP, TCP and UDP checksums. Nothing here
/// recomputes them: the caller hands the packet to
/// [`Handle::calc_checksums`](super::Handle::calc_checksums), which fixes every
/// checksum the packet actually carries in one pass.
pub(crate) struct Packet<'a> {
    bytes: &'a mut [u8],
    header_length: usize,
    version: Version,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Version {
    V4,
    V6,
}

impl<'a> Packet<'a> {
    /// Parses the IP header of `bytes`.
    ///
    /// Returns `None` for anything this module refuses to edit blindly:
    /// truncated headers, a declared header length that runs past the buffer,
    /// or an IPv6 packet carrying extension headers. Guessing at any of those
    /// would mean writing an address over the wrong bytes.
    pub(crate) fn parse(bytes: &'a mut [u8]) -> Option<Self> {
        let version = match bytes.first()? >> 4 {
            4 => Version::V4,
            6 => Version::V6,
            _ => return None,
        };
        let header_length = match version {
            Version::V4 => {
                // The low nibble counts 32-bit words, and options may extend
                // the header past the 20-byte minimum.
                let length = usize::from(bytes[0] & 0x0f) * 4;
                if length < v4::MIN_HEADER {
                    return None;
                }
                length
            }
            Version::V6 => {
                // Extension headers would displace the transport header, and
                // the port offsets below assume it starts immediately.
                if !matches!(bytes.get(v6::NEXT_HEADER)?, &PROTOCOL_TCP | &PROTOCOL_UDP) {
                    return None;
                }
                v6::HEADER
            }
        };
        (bytes.len() >= header_length).then_some(Self {
            bytes,
            header_length,
            version,
        })
    }

    pub(crate) fn protocol(&self) -> u8 {
        match self.version {
            Version::V4 => self.bytes[v4::PROTOCOL],
            Version::V6 => self.bytes[v6::NEXT_HEADER],
        }
    }

    pub(crate) fn source(&self) -> IpAddr {
        self.address(self.source_offset())
    }

    pub(crate) fn destination(&self) -> IpAddr {
        self.address(self.destination_offset())
    }

    /// Replaces the source address.
    ///
    /// Returns `false` when `address` belongs to the other family, which would
    /// otherwise write four bytes into a sixteen-byte field or vice versa.
    pub(crate) fn set_source(&mut self, address: IpAddr) -> bool {
        let offset = self.source_offset();
        self.set_address(offset, address)
    }

    /// Replaces the destination address.
    ///
    /// Returns `false` on an address family mismatch.
    pub(crate) fn set_destination(&mut self, address: IpAddr) -> bool {
        let offset = self.destination_offset();
        self.set_address(offset, address)
    }

    /// Reads the transport source and destination ports.
    ///
    /// Returns `None` unless the packet carries a complete TCP or UDP header.
    /// A trailing IPv4 fragment has no transport header at all, so it reports
    /// `None` rather than reading payload bytes as ports.
    pub(crate) fn ports(&self) -> Option<(u16, u16)> {
        if !matches!(self.protocol(), PROTOCOL_TCP | PROTOCOL_UDP) || !self.is_first_fragment() {
            return None;
        }
        let transport = self.bytes.get(self.header_length..)?;
        let source = u16::from_be_bytes([*transport.first()?, *transport.get(1)?]);
        let destination = u16::from_be_bytes([*transport.get(2)?, *transport.get(3)?]);
        Some((source, destination))
    }

    /// Reports whether this packet carries the transport header.
    ///
    /// Only the first fragment of a fragmented IPv4 datagram does. The later
    /// ones still need their addresses rewritten, so they are not rejected
    /// outright: they simply have no ports to read.
    fn is_first_fragment(&self) -> bool {
        match self.version {
            Version::V4 => {
                let field =
                    u16::from_be_bytes([self.bytes[v4::FRAGMENT], self.bytes[v4::FRAGMENT + 1]]);
                let fragment_offset = field & FRAGMENT_OFFSET_MASK;
                fragment_offset == 0
            }
            Version::V6 => true,
        }
    }

    const fn source_offset(&self) -> usize {
        match self.version {
            Version::V4 => v4::SOURCE,
            Version::V6 => v6::SOURCE,
        }
    }

    const fn destination_offset(&self) -> usize {
        match self.version {
            Version::V4 => v4::DESTINATION,
            Version::V6 => v6::DESTINATION,
        }
    }

    fn address(&self, offset: usize) -> IpAddr {
        match self.version {
            Version::V4 => {
                let mut octets = [0_u8; 4];
                octets.copy_from_slice(&self.bytes[offset..offset + 4]);
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            Version::V6 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&self.bytes[offset..offset + 16]);
                IpAddr::V6(Ipv6Addr::from(octets))
            }
        }
    }

    fn set_address(&mut self, offset: usize, address: IpAddr) -> bool {
        match (self.version, address) {
            (Version::V4, IpAddr::V4(address)) => {
                self.bytes[offset..offset + 4].copy_from_slice(&address.octets());
                true
            }
            (Version::V6, IpAddr::V6(address)) => {
                self.bytes[offset..offset + 16].copy_from_slice(&address.octets());
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Packet, PROTOCOL_TCP, PROTOCOL_UDP};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    /// A 20-byte IPv4 header followed by eight bytes of UDP.
    fn ipv4_udp() -> Vec<u8> {
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45; // version 4, 5 words of header
        packet[9] = PROTOCOL_UDP;
        packet[12..16].copy_from_slice(&Ipv4Addr::new(10, 77, 0, 22).octets());
        packet[16..20].copy_from_slice(&Ipv4Addr::new(1, 1, 1, 1).octets());
        packet[20..22].copy_from_slice(&54_518_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
        packet
    }

    fn ipv6_tcp() -> Vec<u8> {
        let mut packet = vec![0_u8; 60];
        packet[0] = 0x60;
        packet[6] = PROTOCOL_TCP;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[40..42].copy_from_slice(&443_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&51_000_u16.to_be_bytes());
        packet
    }

    #[test]
    fn reads_an_ipv4_udp_packet() {
        let mut bytes = ipv4_udp();
        let packet = Packet::parse(&mut bytes).expect("parses");
        assert_eq!(packet.protocol(), PROTOCOL_UDP);
        assert_eq!(packet.source(), IpAddr::V4(Ipv4Addr::new(10, 77, 0, 22)));
        assert_eq!(packet.destination(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(packet.ports(), Some((54_518, 53)));
    }

    #[test]
    fn rewrites_the_source_leaving_everything_else_alone() {
        let mut bytes = ipv4_udp();
        let original = bytes.clone();
        let mut packet = Packet::parse(&mut bytes).expect("parses");
        assert!(packet.set_source(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 189))));
        assert_eq!(packet.source(), IpAddr::V4(Ipv4Addr::new(192, 168, 0, 189)));
        assert_eq!(packet.destination(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(packet.ports(), Some((54_518, 53)));
        // Only the four source bytes may differ.
        assert_eq!(bytes[..12], original[..12]);
        assert_eq!(bytes[16..], original[16..]);
    }

    #[test]
    fn refuses_to_write_an_address_of_the_wrong_family() {
        let mut bytes = ipv4_udp();
        let mut packet = Packet::parse(&mut bytes).expect("parses");
        assert!(!packet.set_source(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // The refusal must leave the packet untouched, not half-written.
        assert_eq!(packet.source(), IpAddr::V4(Ipv4Addr::new(10, 77, 0, 22)));
    }

    #[test]
    fn handles_ipv4_options_when_locating_the_ports() {
        let mut bytes = ipv4_udp();
        // Grow the header to six words and shift the transport header along.
        bytes.splice(20..20, [0_u8; 4]);
        bytes[0] = 0x46;
        let packet = Packet::parse(&mut bytes).expect("parses");
        assert_eq!(packet.ports(), Some((54_518, 53)));
    }

    #[test]
    fn reports_no_ports_for_a_trailing_fragment() {
        let mut bytes = ipv4_udp();
        // A non-zero fragment offset means these bytes are payload, not ports.
        bytes[6..8].copy_from_slice(&185_u16.to_be_bytes());
        let packet = Packet::parse(&mut bytes).expect("parses");
        assert_eq!(packet.ports(), None);
        // The addresses are still rewritable, which is what keeps a fragmented
        // datagram intact end to end.
        assert_eq!(packet.source(), IpAddr::V4(Ipv4Addr::new(10, 77, 0, 22)));
    }

    #[test]
    fn reads_an_ipv6_packet() {
        let mut bytes = ipv6_tcp();
        let mut packet = Packet::parse(&mut bytes).expect("parses");
        assert_eq!(packet.protocol(), PROTOCOL_TCP);
        assert_eq!(packet.ports(), Some((443, 51_000)));
        let replacement = "fe80::725c:fc9c:dce3:314b".parse().expect("address");
        assert!(packet.set_destination(IpAddr::V6(replacement)));
        assert_eq!(packet.destination(), IpAddr::V6(replacement));
    }

    #[test]
    fn rejects_packets_it_cannot_edit_safely() {
        // Not IP at all.
        assert!(Packet::parse(&mut [0x00_u8; 40]).is_none());
        // Header length below the IPv4 minimum.
        let mut short_header = ipv4_udp();
        short_header[0] = 0x44;
        assert!(Packet::parse(&mut short_header).is_none());
        // Declared header longer than the buffer.
        let mut truncated = ipv4_udp();
        truncated[0] = 0x4f;
        truncated.truncate(24);
        assert!(Packet::parse(&mut truncated).is_none());
        // IPv6 with a hop-by-hop extension header displacing the ports.
        let mut extended = ipv6_tcp();
        extended[6] = 0;
        assert!(Packet::parse(&mut extended).is_none());
        // Empty input.
        assert!(Packet::parse(&mut []).is_none());
    }
}
