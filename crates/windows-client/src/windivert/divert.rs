#![doc = "Moves selected applications' packets between the stack and the tunnel."]

use std::{
    fmt::Write as _,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, RwLock,
    },
};

use super::{
    flow::{Disposition, FlowKey, FlowTable},
    packet::{Packet, PROTOCOL_TCP, PROTOCOL_UDP},
    Address, Handle, Library, LAYER_NETWORK, MTU_MAX,
};
use crate::ClientError;

/// What to do with a captured outbound packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    /// The packet belongs to a routed application: it has been rewritten to
    /// carry the tunnel's source address and must go to the data plane.
    Tunnel,
    /// The packet belongs to an application that stays on the physical link.
    /// It has not been touched and must be reinjected exactly as captured.
    PassThrough,
    /// The packet belongs to a routed application but cannot be tunnelled.
    /// It must be discarded rather than handed back, because reinjecting it
    /// would send traffic the user asked to protect out in the clear.
    Discard,
}

/// How the split tunnel translates between the two ends of a session.
///
/// Applications only ever see `physical`, because every packet is translated
/// before it reaches them. `tunnel` exists solely on the wire to the server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Translation {
    pub(crate) physical: IpAddr,
    pub(crate) tunnel: IpAddr,
    /// The largest TCP segment the tunnel can carry, clamped into the
    /// handshake of every routed connection.
    pub(crate) max_segment_size: u16,
}

impl Translation {
    /// Derives the segment limit from the tunnel's MTU.
    ///
    /// A full-tunnel session hands this MTU to the Wintun adapter and the stack
    /// sizes everything accordingly. There is no adapter here, so the limit has
    /// to be imposed on the connections themselves.
    pub(crate) fn new(physical: IpAddr, tunnel: IpAddr, tunnel_mtu: u16) -> Self {
        // IPv4 and TCP headers, twenty bytes each, come off the top.
        const HEADERS: u16 = 40;
        Self {
            physical,
            tunnel,
            max_segment_size: tunnel_mtu.saturating_sub(HEADERS),
        }
    }
}

/// Builds the capture filter.
///
/// Two exclusions are load-bearing. Our own tunnel datagrams must never be
/// captured, or every packet we send would come straight back to us and the
/// client would wedge itself. Loopback is excluded because local traffic has no
/// business crossing a VPN and capturing it only costs latency.
/// Compiles the built-in filter plus any extras, reporting each verdict.
///
/// Exposed for the `filter_check` example: a filter the driver rejects is
/// otherwise only visible as `ERROR_INVALID_PARAMETER` at connection time.
///
/// # Errors
///
/// Returns [`ClientError::Platform`] when `WinDivert.dll` cannot be loaded.
pub fn check_capture_filters(extra: &[String]) -> Result<String, ClientError> {
    let library = Library::load()?;
    let server: SocketAddr = "203.0.113.10:51820".parse().unwrap_or_else(|_| {
        unreachable!("the sample endpoint is a literal");
    });
    let mut report = String::new();
    let built_in = filter(server);
    for candidate in std::iter::once(&built_in).chain(extra) {
        let verdict = match library.check_filter(candidate, LAYER_NETWORK) {
            Ok(()) => "OK  ".to_owned(),
            Err(error) => format!("FAIL {error}\n     "),
        };
        let _ = writeln!(report, "{verdict}{candidate}");
    }
    Ok(report)
}

/// The exclusion is written as a disjunction rather than the more obvious
/// `not (udp and dst == server and port == p)`. `WinDivert` applies negation to
/// a single test, not to a parenthesised group, and rejects the latter with a
/// parse error that surfaces only as `ERROR_INVALID_PARAMETER` when the handle
/// is opened. De Morgan's law gives the same meaning in a form it accepts.
fn filter(server: SocketAddr) -> String {
    let family = if server.is_ipv4() { "ip" } else { "ipv6" };
    format!(
        "outbound and !loopback and {family} and \
         (tcp or (udp and ({family}.DstAddr != {} or udp.DstPort != {})))",
        server.ip(),
        server.port()
    )
}

/// Rewrites a captured outbound packet when it belongs in the tunnel.
///
/// Returns [`Outcome::PassThrough`] for anything not positively identified as
/// routed: unparseable packets, protocols without ports, and flows the watcher
/// has not classified. Defaulting to "leave it alone" means an unknown packet
/// keeps working over the physical link instead of vanishing into a tunnel
/// that may not expect it.
pub(crate) fn prepare_outbound(
    bytes: &mut [u8],
    table: &FlowTable,
    translation: Translation,
) -> Outcome {
    let Some(mut packet) = Packet::parse(bytes) else {
        return Outcome::PassThrough;
    };
    if !matches!(packet.protocol(), PROTOCOL_TCP | PROTOCOL_UDP) {
        return Outcome::PassThrough;
    }
    let Some((source_port, destination_port)) = packet.ports() else {
        return Outcome::PassThrough;
    };
    let key = FlowKey {
        protocol: packet.protocol(),
        local: packet.source(),
        local_port: source_port,
        remote: packet.destination(),
        remote_port: destination_port,
    };
    if table.lookup(&key) != Some(Disposition::Tunnel) {
        return Outcome::PassThrough;
    }
    // The application bound to the physical address, but the server only
    // recognises the tunnel one. Anything else would come back to the wrong
    // place, if it came back at all.
    //
    // This fails when the flow is IPv6, because the session only assigns an
    // IPv4 address. Handing such a packet back would put traffic the policy
    // routes through the tunnel onto the physical link instead, so it is
    // dropped: the application sees the address family fail and falls back.
    if !packet.set_source(translation.tunnel) {
        return Outcome::Discard;
    }
    packet.clamp_mss(translation.max_segment_size);
    Outcome::Tunnel
}

/// Restores the physical destination on a packet arriving from the tunnel.
///
/// Returns `false` when the packet is not addressed to the tunnel address, so
/// traffic meant for something else is never redirected at an application.
pub(crate) fn prepare_inbound(bytes: &mut [u8], translation: Translation) -> bool {
    let Some(mut packet) = Packet::parse(bytes) else {
        return false;
    };
    if packet.destination() != translation.tunnel {
        return false;
    }
    if !packet.set_destination(translation.physical) {
        return false;
    }
    // Clamping only the outbound handshake limits what the peer sends us, not
    // what we send it: our segment size comes from the option in its reply.
    // Leaving that alone lets the stack build packets too large for the tunnel,
    // so downloads work while anything we upload disappears.
    packet.clamp_mss(translation.max_segment_size);
    true
}

/// Captures outbound packets and feeds the routed ones to the tunnel.
///
/// The translation is shared rather than copied because a reconnect can change
/// it: the server may assign a different tunnel address or MTU, and moving
/// between networks changes the physical address too.
pub(crate) struct Diverter {
    handle: Arc<Handle>,
    table: Arc<FlowTable>,
    translation: Arc<RwLock<Translation>>,
}

impl Diverter {
    /// Opens the network-layer handle used for capture and injection.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the handle cannot be opened,
    /// which includes a filter the driver rejects.
    pub(crate) fn open(
        library: &Arc<Library>,
        table: Arc<FlowTable>,
        translation: Arc<RwLock<Translation>>,
        server: SocketAddr,
    ) -> Result<Self, ClientError> {
        // Priority 0 keeps MouseVPN below tools that deliberately sit high,
        // and nothing here depends on winning against another filter.
        let handle = Arc::new(library.open(&filter(server), LAYER_NETWORK, 0, 0)?);
        Ok(Self {
            handle,
            table,
            translation,
        })
    }

    /// Runs the capture loop until [`Diverter::stop`] is called.
    ///
    /// `sink` receives every packet bound for the tunnel, already rewritten.
    /// Packets that stay on the physical link are reinjected before `sink` is
    /// consulted, so a slow data plane cannot stall unrelated traffic.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the capture fails. A shutdown is
    /// not a failure and returns `Ok(())`.
    pub(crate) fn run(
        &self,
        stopping: &AtomicBool,
        mut sink: impl FnMut(&[u8]),
    ) -> Result<(), ClientError> {
        let mut buffer = vec![0_u8; MTU_MAX];
        let mut address = Address::zeroed();
        let mut discarded = 0_u64;
        while !stopping.load(Ordering::Acquire) {
            let Some(length) = self.handle.recv(&mut buffer, &mut address)? else {
                return Ok(());
            };
            // Read once per packet: a reconnect may have replaced the
            // addresses since the last one arrived.
            let Ok(translation) = self.translation.read().map(|guard| *guard) else {
                return Err(ClientError::Platform(
                    "the split tunnel translation lock was poisoned".to_owned(),
                ));
            };
            let packet = &mut buffer[..length];
            match prepare_outbound(packet, &self.table, translation) {
                Outcome::PassThrough => {
                    // Captured but unmodified, so the checksums the stack
                    // computed are still correct and reinjection is a
                    // straight handback.
                    self.reinject(packet, &address);
                }
                Outcome::Discard => {
                    discarded = discarded.saturating_add(1);
                    if discarded.is_power_of_two() {
                        eprintln!(
                            "MOUSEVPN_DIVERT_WARNING=discarded {discarded} packet(s) of routed \
                             applications that this session cannot carry, usually IPv6"
                        );
                    }
                }
                Outcome::Tunnel => {
                    // The source address changed, which invalidates the IP and
                    // transport checksums the stack had already filled in.
                    if let Err(error) = self.handle.calc_checksums(packet, &mut address) {
                        eprintln!("MOUSEVPN_DIVERT_WARNING={error}");
                        continue;
                    }
                    sink(packet);
                }
            }
        }
        Ok(())
    }

    /// Hands a packet back to the stack, reporting drops without stopping.
    ///
    /// A failed reinjection loses one packet. Both TCP and QUIC recover from
    /// that, whereas returning an error here would take down the tunnel.
    fn reinject(&self, packet: &[u8], address: &Address) {
        if let Err(error) = self.handle.send(packet, address) {
            eprintln!("MOUSEVPN_DIVERT_WARNING={error}");
        }
    }

    /// Delivers a translated packet from the tunnel to the local stack.
    ///
    /// The destination address changed on the way in, so the checksums the
    /// server computed no longer hold and are recomputed before injection.
    /// Failures are reported and dropped for the same reason as
    /// [`Diverter::reinject`]: one lost packet is recoverable, a torn-down
    /// tunnel is not.
    pub(crate) fn inject_inbound(&self, packet: &mut [u8], address: Address) {
        let mut address = address;
        if let Err(error) = self.handle.calc_checksums(packet, &mut address) {
            eprintln!("MOUSEVPN_DIVERT_WARNING={error}");
            return;
        }
        if let Err(error) = self.handle.send(packet, &address) {
            eprintln!("MOUSEVPN_DIVERT_WARNING={error}");
        }
    }

    /// Unblocks the capture loop.
    pub(crate) fn stop(&self) {
        self.handle.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::{filter, prepare_inbound, prepare_outbound, Outcome, Translation};
    use crate::windivert::{
        flow::{Disposition, FlowKey, FlowTable},
        packet::PROTOCOL_UDP,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    const PHYSICAL: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 189));
    const TUNNEL: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 77, 0, 22));
    const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

    fn addresses() -> Translation {
        Translation::new(PHYSICAL, TUNNEL, 1280)
    }

    fn udp_packet(source: IpAddr, destination: IpAddr) -> Vec<u8> {
        let (IpAddr::V4(source), IpAddr::V4(destination)) = (source, destination) else {
            unreachable!("tests use IPv4")
        };
        let mut packet = vec![0_u8; 28];
        packet[0] = 0x45;
        packet[9] = PROTOCOL_UDP;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&54_518_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
        packet
    }

    fn table_with(disposition: Disposition) -> FlowTable {
        let table = FlowTable::default();
        table.insert_for_test(
            FlowKey {
                protocol: PROTOCOL_UDP,
                local: PHYSICAL,
                local_port: 54_518,
                remote: REMOTE,
                remote_port: 53,
            },
            disposition,
        );
        table
    }

    #[test]
    fn rewrites_a_routed_packet_onto_the_tunnel_address() {
        let mut packet = udp_packet(PHYSICAL, REMOTE);
        let table = table_with(Disposition::Tunnel);
        assert_eq!(
            prepare_outbound(&mut packet, &table, addresses()),
            Outcome::Tunnel
        );
        assert_eq!(&packet[12..16], &[10, 77, 0, 22]);
        // The destination and ports must survive untouched.
        assert_eq!(&packet[16..20], &[1, 1, 1, 1]);
        assert_eq!(&packet[20..24], &[0xd4, 0xf6, 0x00, 0x35]);
    }

    #[test]
    fn leaves_an_excluded_packet_byte_for_byte_alone() {
        let mut packet = udp_packet(PHYSICAL, REMOTE);
        let original = packet.clone();
        let table = table_with(Disposition::Direct);
        assert_eq!(
            prepare_outbound(&mut packet, &table, addresses()),
            Outcome::PassThrough
        );
        assert_eq!(packet, original);
    }

    #[test]
    fn passes_through_a_flow_the_watcher_has_not_classified() {
        // Racing the flow layer must not swallow traffic: an unknown packet
        // keeps working on the physical link.
        let mut packet = udp_packet(PHYSICAL, REMOTE);
        let original = packet.clone();
        assert_eq!(
            prepare_outbound(&mut packet, &FlowTable::default(), addresses()),
            Outcome::PassThrough
        );
        assert_eq!(packet, original);
    }

    #[test]
    fn restores_the_physical_address_on_the_way_back() {
        let mut packet = udp_packet(REMOTE, TUNNEL);
        assert!(prepare_inbound(&mut packet, addresses()));
        assert_eq!(&packet[16..20], &[192, 168, 0, 189]);
    }

    /// A SYN-ACK arriving from the tunnel, offering a segment size sized for a
    /// physical link.
    fn inbound_syn_ack(mss: u16) -> Vec<u8> {
        let (IpAddr::V4(remote), IpAddr::V4(tunnel)) = (REMOTE, TUNNEL) else {
            unreachable!("tests use IPv4")
        };
        let mut packet = vec![0_u8; 20 + 24];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&remote.octets());
        packet[16..20].copy_from_slice(&tunnel.octets());
        packet[20..22].copy_from_slice(&443_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&51_000_u16.to_be_bytes());
        // Six words of header, SYN and ACK set.
        packet[32] = 6 << 4;
        packet[33] = 0x12;
        packet[40] = 2;
        packet[41] = 4;
        packet[42..44].copy_from_slice(&mss.to_be_bytes());
        packet
    }

    #[test]
    fn clamps_the_segment_size_the_peer_offers_us() {
        // Without this the peer's own limit governs what we send, and every
        // upload larger than the tunnel's MTU vanishes while downloads work.
        let mut packet = inbound_syn_ack(1460);
        assert!(prepare_inbound(&mut packet, addresses()));
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), 1240);
        assert_eq!(&packet[16..20], &[192, 168, 0, 189]);
    }

    #[test]
    fn refuses_inbound_packets_addressed_elsewhere() {
        let mut packet = udp_packet(REMOTE, PHYSICAL);
        let original = packet.clone();
        assert!(!prepare_inbound(&mut packet, addresses()));
        assert_eq!(packet, original);
    }

    #[test]
    fn excludes_our_own_tunnel_datagrams_from_capture() {
        let server: SocketAddr = "203.0.113.10:51820".parse().expect("address");
        let filter = filter(server);
        // Without this exclusion every datagram we send would be recaptured.
        assert!(filter.contains("203.0.113.10"));
        assert!(filter.contains("51820"));
        assert!(filter.contains("outbound"));
        assert!(filter.contains("!loopback"));
    }

    #[test]
    fn derives_the_segment_limit_from_the_tunnel_mtu() {
        // 1280 less twenty bytes of IPv4 header and twenty of TCP.
        assert_eq!(addresses().max_segment_size, 1240);
        // A nonsensically small MTU must not wrap around into a huge limit.
        assert_eq!(Translation::new(PHYSICAL, TUNNEL, 8).max_segment_size, 0);
    }

    #[test]
    fn discards_a_routed_flow_it_cannot_translate() {
        // An IPv6 flow of a routed application has no tunnel address to take.
        // Handing it back would put protected traffic on the physical link.
        let mut packet = vec![0_u8; 60];
        packet[0] = 0x60;
        packet[6] = PROTOCOL_UDP;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[40..42].copy_from_slice(&54_518_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&53_u16.to_be_bytes());

        let table = FlowTable::default();
        table.insert_for_test(
            FlowKey {
                protocol: PROTOCOL_UDP,
                local: IpAddr::V6(Ipv6Addr::LOCALHOST),
                local_port: 54_518,
                remote: IpAddr::V6(Ipv6Addr::LOCALHOST),
                remote_port: 53,
            },
            Disposition::Tunnel,
        );
        assert_eq!(
            prepare_outbound(&mut packet, &table, addresses()),
            Outcome::Discard
        );
    }

    #[test]
    fn never_negates_a_parenthesised_group() {
        // WinDivert negates a single test, not a group, and reports the
        // difference only as ERROR_INVALID_PARAMETER from WinDivertOpen. Both
        // spellings of negation are checked so neither creeps back in.
        for server in ["203.0.113.10:51820", "[2001:db8::1]:51820"] {
            let filter = filter(server.parse().expect("address"));
            assert!(!filter.contains("not ("), "{filter}");
            assert!(!filter.contains("!("), "{filter}");
        }
    }

    #[test]
    fn keeps_the_tunnel_exclusion_scoped_to_udp() {
        // Hoisting the address test out of the udp branch would exclude TCP to
        // the server as well, and silently stop tunnelling it.
        let server: SocketAddr = "203.0.113.10:51820".parse().expect("address");
        let filter = filter(server);
        let udp_branch = filter.split("tcp or ").nth(1).expect("udp branch");
        assert!(udp_branch.contains("203.0.113.10"));
    }
}
