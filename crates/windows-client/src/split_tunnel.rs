#![doc = "Runs a per-application tunnel that needs no adapter and no routes."]

use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

use mousevpn_client_wire::{ClientWire, MAX_WIRE_DATAGRAM_LEN};
use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::{DataPlaneError, Decoded};
use mousevpn_protocol::Datagram;
use mousevpn_transport::DatagramTransport;

use crate::{
    handshake::connect,
    netcfg, network, packet_loop,
    platform::ensure_supported_runtime,
    windivert::{
        divert::{prepare_inbound, Diverter, Translation},
        flow::FlowWatcher,
        Address, Library,
    },
    AppRoutingPolicy, ClientError,
};

const DATAGRAM_BUFFER_LEN: usize = 65_535;

/// Tunnels only the applications the policy selects, leaving the rest of the
/// machine on its physical link.
///
/// Nothing here touches the routing table, creates an adapter, or installs
/// firewall filters. Traffic reaches the tunnel because `WinDivert` lifts it out
/// of the stack, not because a route sent it somewhere. That is what keeps
/// excluded applications working exactly as they did before `MouseVPN` started:
/// their packets are handed straight back, unmodified.
///
/// The tunnel address exists only on the wire. Every packet is translated in
/// both directions, so applications continue to see the physical address they
/// bound to.
///
/// # Errors
///
/// Returns [`ClientError`] when elevation, the handshake, `WinDivert`, or packet
/// processing fails.
///
/// # Panics
///
/// Panics if the outbound worker thread cannot be created.
pub fn run_split_tunnel(
    config: &ValidatedClientConfig,
    stopping: &Arc<AtomicBool>,
    app_routing: &AppRoutingPolicy,
) -> Result<(), ClientError> {
    ensure_supported_runtime()?;
    let _runtime_lock = network::RuntimeLock::acquire()?;

    let wire = ClientWire::from_config(config)?;
    let (incoming, plane, parameters) = connect(config, &wire)?;
    incoming.set_read_timeout(Some(packet_loop::UDP_POLL))?;
    let outgoing = incoming.try_clone()?;

    // Both addresses are fixed for the life of the session, which is what
    // makes the translation stateless.
    let physical = network::physical_addresses()?.ipv4;
    let translation = Translation::new(
        IpAddr::V4(physical),
        IpAddr::V4(parameters.client_address),
        parameters.mtu,
    );
    // Inbound injection has to name the interface the packet should look like
    // it arrived on, so translated replies reach the application's socket.
    let route = netcfg::default_ipv4_route(None)?;

    let library = Library::load()?;
    // The watcher must be running before the diverter captures anything:
    // packets of a flow it has not classified yet pass through untranslated.
    let watcher = FlowWatcher::start(&library, app_routing)?;
    let diverter = Arc::new(Diverter::open(
        &library,
        watcher.table(),
        translation,
        config.server,
    )?);

    let (sender, receiver) = plane.split();
    let sender = Arc::new(Mutex::new(sender));

    eprintln!("MOUSEVPN_STATE=connected");
    eprintln!("MOUSEVPN_MODE=split_tunnel");

    let outbound = thread::Builder::new()
        .name("mousevpn-split-outbound".to_owned())
        .spawn({
            let diverter = Arc::clone(&diverter);
            let sender = Arc::clone(&sender);
            let stopping = Arc::clone(stopping);
            let wire = wire.clone();
            let mut transport = outgoing;
            move || {
                let mut encrypted = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
                let mut datagram = Vec::with_capacity(MAX_WIRE_DATAGRAM_LEN);
                let mut oversized = 0_u64;
                diverter.run(&stopping, |packet| {
                    let encoded = sender
                        .lock()
                        .map_err(|_| poisoned())
                        .and_then(|mut sender| {
                            sender.encode_ip_into(packet, &mut encrypted).map_err(|error| {
                                match error {
                                    // An application may emit a packet larger
                                    // than the tunnel can carry. Dropping one
                                    // packet is recoverable; stopping is not.
                                    DataPlaneError::PacketExceedsMtu { .. }
                                    | DataPlaneError::Ip(_) => Skip,
                                    error => Fatal(error.into()),
                                }
                            })
                        });
                    match encoded {
                        Ok(()) => {}
                        Err(Skip) => {
                            // Clamping the segment size keeps TCP within the
                            // tunnel, so anything still arriving oversized is
                            // a datagram protocol probing upwards. Counting it
                            // is what turns a silent black hole into evidence.
                            oversized = oversized.saturating_add(1);
                            if oversized.is_power_of_two() {
                                eprintln!(
                                    "MOUSEVPN_SPLIT_WARNING=dropped {oversized} packet(s) larger \
                                     than the tunnel MTU"
                                );
                            }
                            return;
                        }
                        Err(Fatal(error)) => {
                            eprintln!("MOUSEVPN_SPLIT_WARNING={error}");
                            return;
                        }
                    }
                    if let Err(error) = wire
                        .encode(&encrypted, &mut datagram)
                        .map_err(ClientError::from)
                        .and_then(|()| transport.send(&datagram).map_err(ClientError::from))
                    {
                        eprintln!("MOUSEVPN_SPLIT_WARNING={error}");
                    }
                })
            }
        })
        .map_err(|error| {
            ClientError::Platform(format!("failed to start the split tunnel sender: {error}"))
        })?;

    let result = receive_loop(
        ReceiveContext {
            transport: incoming,
            wire: &wire,
            translation,
            interface_index: route.interface_index,
            diverter: &diverter,
        },
        receiver,
        stopping,
    );

    // The outbound worker parks inside WinDivert, so it only notices the stop
    // flag once the handle is shut down.
    stopping.store(true, Ordering::Release);
    diverter.stop();
    match outbound.join() {
        Ok(worker) => worker?,
        Err(_) => eprintln!("MOUSEVPN_SPLIT_WARNING=the split tunnel sender panicked"),
    }
    result
}

struct ReceiveContext<'a> {
    transport: mousevpn_transport::UdpTransport,
    wire: &'a ClientWire,
    translation: Translation,
    interface_index: u32,
    diverter: &'a Diverter,
}

/// Translates packets arriving from the server and injects them locally.
fn receive_loop(
    mut context: ReceiveContext<'_>,
    mut receiver: mousevpn_data_plane::TunnelReceiver,
    stopping: &AtomicBool,
) -> Result<(), ClientError> {
    let mut encrypted = vec![0_u8; MAX_WIRE_DATAGRAM_LEN];
    let mut payload = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
    let mut plaintext = Vec::with_capacity(DATAGRAM_BUFFER_LEN);
    // Every injected packet claims the same arrival interface, which is the
    // one the application would have used without the tunnel.
    let address = Address::for_inbound(context.interface_index, 0);

    while !stopping.load(Ordering::Acquire) {
        let length = match context.transport.receive(&mut encrypted) {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let decoded = context
            .wire
            .decode(&encrypted[..length], &mut payload)
            .ok()
            .filter(|decoded| *decoded)
            .and_then(|_| Datagram::decode(&payload).ok())
            .map(|datagram| receiver.decode_into(datagram, &mut plaintext));
        let Some(Ok(Decoded::Ip(packet))) = decoded else {
            continue;
        };
        let mut packet = packet.to_vec();
        // A packet addressed to anything but the tunnel address is not ours to
        // deliver, and injecting it could hand an application traffic it never
        // asked for.
        if !prepare_inbound(&mut packet, context.translation) {
            continue;
        }
        context.diverter.inject_inbound(&mut packet, address);
    }
    Ok(())
}

/// Distinguishes a packet worth dropping from a failure worth reporting.
enum SendFailure {
    Skip,
    Fatal(ClientError),
}
use SendFailure::{Fatal, Skip};

fn poisoned() -> SendFailure {
    Fatal(ClientError::Platform(
        "the split tunnel sender lock was poisoned".to_owned(),
    ))
}
