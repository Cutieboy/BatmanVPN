mod connect;
mod dns;
mod protocol;

use std::{io, net::Ipv4Addr};

use tokio::{io::copy_bidirectional, net::TcpStream};

use self::{
    connect::connect_marked,
    dns::resolve_ipv4,
    protocol::{read_request, write_failure, write_success, Target},
};

pub(crate) async fn serve_client(
    mut client: TcpStream,
    dns_server: Ipv4Addr,
    mark: u32,
) -> io::Result<()> {
    let target = match read_request(&mut client).await {
        Ok(target) => target,
        Err(error) => {
            let _ = write_failure(&mut client, error.reply_code).await;
            return Err(error.source);
        }
    };
    let (address, port) = match target {
        Target::Ipv4(address, port) => (address, port),
        Target::Domain(name, port) => match resolve_ipv4(&name, dns_server, mark).await {
            Ok(address) => (address, port),
            Err(error) => {
                let _ = write_failure(&mut client, 0x04).await;
                return Err(error);
            }
        },
    };
    let mut remote = match connect_marked(address, port, mark).await {
        Ok(remote) => remote,
        Err(error) => {
            let _ = write_failure(&mut client, reply_code(&error)).await;
            return Err(error);
        }
    };
    write_success(&mut client, remote.local_addr()?).await?;
    copy_bidirectional(&mut client, &mut remote).await?;
    Ok(())
}

fn reply_code(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => 0x05,
        io::ErrorKind::TimedOut => 0x06,
        io::ErrorKind::NetworkUnreachable => 0x03,
        io::ErrorKind::HostUnreachable => 0x04,
        _ => 0x01,
    }
}
