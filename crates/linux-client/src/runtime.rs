use std::{
    net::SocketAddrV4,
    sync::{atomic::AtomicBool, mpsc, Arc, Mutex},
    thread,
};

use mousevpn_config::ValidatedClientConfig;
use mousevpn_linux_platform::{
    ensure_no_competing_full_tunnel, DnsGuard, FirewallGuard, LinuxTun, LinuxTunConfig,
    ProxyRouteGuard, RouteGuard, DEFAULT_TX_QUEUE_LEN, PROXY_MARK,
};
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    flag,
};

use crate::{
    handshake::connect,
    outgoing,
    packet_loop::{PacketLoop, POLL_INTERVAL},
    proxy::ProxyServerGuard,
    ClientError,
};

#[derive(Clone, Copy)]
enum Mode {
    FullTunnel,
    Proxy(SocketAddrV4),
}

enum NetworkGuard {
    Full {
        _firewall: FirewallGuard,
        routes: RouteGuard,
        _dns: DnsGuard,
    },
    Proxy {
        _routes: ProxyRouteGuard,
        _server: ProxyServerGuard,
    },
}

/// Connects to the server, creates TUN and runs until a fatal packet-loop error.
///
/// # Errors
///
/// Returns an error when handshake, TUN creation, UDP or packet processing fails.
pub fn run(config: &ValidatedClientConfig) -> Result<(), ClientError> {
    run_mode(config, Mode::FullTunnel, Arc::new(AtomicBool::new(false)))
}

/// Connects like [`run`], while allowing an embedding application to request
/// graceful shutdown through the supplied flag.
///
/// # Errors
///
/// Returns an error when handshake, TUN creation, UDP or packet processing fails.
pub fn run_with_stop(
    config: &ValidatedClientConfig,
    stopping: Arc<AtomicBool>,
) -> Result<(), ClientError> {
    run_mode(config, Mode::FullTunnel, stopping)
}

/// Runs a loopback SOCKS5 proxy whose outbound sockets alone use `MouseVPN`.
///
/// # Errors
///
/// Returns an error when the tunnel, policy routing, listener or packet processing fails.
pub fn run_proxy(config: &ValidatedClientConfig, listen: SocketAddrV4) -> Result<(), ClientError> {
    if !listen.ip().is_loopback() || listen.port() == 0 {
        return Err(ClientError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "proxy listener must use 127.0.0.0/8 and a nonzero port",
        )));
    }
    run_mode(
        config,
        Mode::Proxy(listen),
        Arc::new(AtomicBool::new(false)),
    )
}

fn run_mode(
    config: &ValidatedClientConfig,
    mode: Mode,
    stopping: Arc<AtomicBool>,
) -> Result<(), ClientError> {
    ensure_no_competing_full_tunnel()
        .map_err(|error| context("checking existing VPN routes", &error))?;
    let (incoming, plane, parameters) = connect(config)?;
    incoming.set_read_timeout(Some(POLL_INTERVAL))?;
    let mut outgoing = incoming.try_clone()?;
    let tun = Arc::new(
        LinuxTun::create(&LinuxTunConfig {
            name: config.tun_name.clone(),
            address: parameters.client_address,
            prefix_len: parameters.prefix_len,
            mtu: parameters.mtu,
            tx_queue_len: DEFAULT_TX_QUEUE_LEN,
        })
        .map_err(|error| context("creating the MouseVPN tunnel", &error))?,
    );
    let tun_name = tun.name()?;
    // The two directions share no mutable state; only reconnect swaps the
    // sender, so the send path is uncontended and the receive path is lock-free.
    let (sender, receiver) = plane.split();
    let sender = Arc::new(Mutex::new(sender));
    let reconnecting = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&stopping))?;
    flag::register(SIGTERM, Arc::clone(&stopping))?;
    let mut network = match mode {
        Mode::FullTunnel => {
            let server_ip = match config.server.ip() {
                std::net::IpAddr::V4(address) => address,
                std::net::IpAddr::V6(_) => {
                    return Err(ClientError::Io(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "IPv6 server endpoints are not supported by the MVP route manager",
                    )));
                }
            };
            NetworkGuard::Full {
                _firewall: FirewallGuard::install(server_ip, config.server.port(), &tun_name)
                    .map_err(|error| context("installing the MouseVPN firewall", &error))?,
                routes: RouteGuard::install(server_ip, &tun_name)
                    .map_err(|error| context("installing VPN routes", &error))?,
                _dns: DnsGuard::install(&tun_name, parameters.dns)
                    .map_err(|error| context("configuring VPN DNS", &error))?,
            }
        }
        Mode::Proxy(listen) => NetworkGuard::Proxy {
            _routes: ProxyRouteGuard::install(&tun_name)?,
            _server: ProxyServerGuard::start(
                listen,
                parameters.dns,
                PROXY_MARK,
                Arc::clone(&stopping),
            )?,
        },
    };

    let outgoing_tun = Arc::clone(&tun);
    let outgoing_sender = Arc::clone(&sender);
    let outgoing_stopping = Arc::clone(&stopping);
    let outgoing_reconnecting = Arc::clone(&reconnecting);
    let (worker_sender, worker_receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = outgoing::run(
            &outgoing_tun,
            &outgoing_sender,
            &mut outgoing,
            &outgoing_stopping,
            &outgoing_reconnecting,
        );
        let _ = worker_sender.send(result);
    });
    match mode {
        Mode::FullTunnel => {
            eprintln!("MOUSEVPN_STATE=connected");
            eprintln!("MouseVPN connected; press Ctrl+C to disconnect safely");
        }
        Mode::Proxy(listen) => {
            eprintln!("MouseVPN SOCKS5 proxy listening on {listen}; press Ctrl+C to stop");
        }
    }

    let routes = match &mut network {
        NetworkGuard::Full { routes, .. } => Some(routes),
        NetworkGuard::Proxy { .. } => None,
    };
    PacketLoop {
        config,
        transport: incoming,
        parameters,
        tun,
        receiver,
        sender,
        stopping,
        reconnecting,
        worker: worker_receiver,
        routes,
    }
    .run()
}

fn context(operation: &str, error: &std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{operation}: {error}"))
}
