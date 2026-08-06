use std::{
    sync::{atomic::AtomicBool, mpsc, Arc, Mutex},
    thread,
};

use mousevpn_config::ValidatedClientConfig;
use mousevpn_linux_platform::{
    ensure_no_competing_full_tunnel, DnsGuard, FirewallGuard, LinuxTun, LinuxTunConfig, RouteGuard,
    DEFAULT_TX_QUEUE_LEN,
};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    flag,
};

use crate::{
    handshake::connect,
    outgoing,
    packet_loop::{PacketLoop, POLL_INTERVAL},
    ClientError,
};

/// Connects to the server, creates TUN and runs until a fatal packet-loop error.
///
/// # Errors
///
/// Returns an error when handshake, TUN creation, UDP or packet processing fails.
pub fn run(config: &ValidatedClientConfig) -> Result<(), ClientError> {
    ensure_no_competing_full_tunnel()?;
    let (incoming, plane, parameters) = connect(config)?;
    incoming.set_read_timeout(Some(POLL_INTERVAL))?;
    let mut outgoing = incoming.try_clone()?;
    let tun = Arc::new(LinuxTun::create(&LinuxTunConfig {
        name: config.tun_name.clone(),
        address: parameters.client_address,
        prefix_len: parameters.prefix_len,
        mtu: parameters.mtu,
        tx_queue_len: DEFAULT_TX_QUEUE_LEN,
    })?);
    let server_ip = match config.server.ip() {
        std::net::IpAddr::V4(address) => address,
        std::net::IpAddr::V6(_) => {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "IPv6 server endpoints are not supported by the MVP route manager",
            )));
        }
    };
    let tun_name = tun.name()?;
    let _firewall = FirewallGuard::install(server_ip, config.server.port(), &tun_name)?;
    let _routes = RouteGuard::install(server_ip, &tun_name)?;
    let _dns = DnsGuard::install(&tun_name, parameters.dns)?;
    let plane = Arc::new(Mutex::new(plane));
    let stopping = Arc::new(AtomicBool::new(false));
    let reconnecting = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stopping))?;
    flag::register(SIGTERM, Arc::clone(&stopping))?;

    let outgoing_tun = Arc::clone(&tun);
    let outgoing_plane = Arc::clone(&plane);
    let outgoing_stopping = Arc::clone(&stopping);
    let outgoing_reconnecting = Arc::clone(&reconnecting);
    let (worker_sender, worker_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = outgoing::run(
            &outgoing_tun,
            &outgoing_plane,
            &mut outgoing,
            &outgoing_stopping,
            &outgoing_reconnecting,
        );
        let _ = worker_sender.send(result);
    });
    eprintln!("MouseVPN connected; press Ctrl+C to disconnect safely");

    PacketLoop {
        config,
        transport: incoming,
        parameters,
        tun,
        plane,
        stopping,
        reconnecting,
        worker: worker_receiver,
    }
    .run()
}
