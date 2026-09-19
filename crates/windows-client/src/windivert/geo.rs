#![doc = "Geo-direct routing data and DNS correlation for the Windows split tunnel."]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use super::{
    flow::FlowTable,
    Address, Handle, Library, LAYER_NETWORK, FLAG_RECV_ONLY, FLAG_SNIFF,
};
use crate::ClientError;

const DIRECT_IPS: &str = include_str!("../../resources/roscomvpn/direct.txt");
const CATEGORY_RU: &str = include_str!("../../resources/roscomvpn/category-ru");
const WHITELIST: &str = include_str!("../../resources/roscomvpn/whitelist");

const DNS_FILTER: &str = "inbound and !loopback and udp and udp.SrcPort == 53";
const DNS_BUFFER: usize = 4096;
const DNS_TTL_FALLBACK: u32 = 60;

#[derive(Clone, Copy)]
struct TrieNode {
    child: [Option<usize>; 2],
    terminal: bool,
}

#[derive(Clone)]
struct Ipv4Trie {
    nodes: Vec<TrieNode>,
}

impl Ipv4Trie {
    fn new() -> Self {
        Self {
            nodes: vec![TrieNode {
                child: [None, None],
                terminal: false,
            }],
        }
    }

    fn insert(&mut self, address: u32, prefix: u8) {
        let mut node = 0;
        for bit in 0..prefix {
            let branch = usize::from(((address >> (31 - bit)) & 1) != 0);
            node = match self.nodes[node].child[branch] {
                Some(child) => child,
                None => {
                    let child = self.nodes.len();
                    self.nodes.push(TrieNode {
                        child: [None, None],
                        terminal: false,
                    });
                    self.nodes[node].child[branch] = Some(child);
                    child
                }
            };
        }
        self.nodes[node].terminal = true;
    }

    fn contains(&self, address: u32) -> bool {
        let mut node = 0;
        if self.nodes[node].terminal {
            return true;
        }
        for bit in 0..32 {
            let branch = usize::from(((address >> (31 - bit)) & 1) != 0);
            let Some(child) = self.nodes[node].child[branch] else {
                return false;
            };
            node = child;
            if self.nodes[node].terminal {
                return true;
            }
        }
        false
    }
}

impl Default for Ipv4Trie {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_cidr(line: &str) -> Option<(u32, u8)> {
    let (address, prefix) = line.split_once('/')?;
    let address = address.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    (prefix <= 32).then_some((u32::from(address), prefix))
}

#[derive(Clone)]
pub(crate) struct GeoRouter {
    cidrs: Arc<Ipv4Trie>,
    domains: Arc<Vec<String>>,
}

impl GeoRouter {
    pub(crate) fn embedded() -> Result<Self, ClientError> {
        let mut cidrs = Ipv4Trie::new();
        for (address, prefix) in DIRECT_IPS.lines().filter_map(|line| parse_cidr(line.trim())) {
            cidrs.insert(address, prefix);
        }

        let mut domains = CATEGORY_RU
            .lines()
            .chain(WHITELIST.lines())
            .filter_map(parse_domain)
            .collect::<Vec<_>>();
        domains.sort_unstable();
        domains.dedup();

        if domains.is_empty() {
            return Err(ClientError::Platform(
                "embedded RoscomVPN geo-direct data is empty".to_owned(),
            ));
        }

        Ok(Self {
            cidrs: Arc::new(cidrs),
            domains: Arc::new(domains),
        })
    }

    pub(crate) fn is_direct_ip(&self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(address) => self.cidrs.contains(u32::from(address)),
            IpAddr::V6(_) => false,
        }
    }

    pub(crate) fn is_direct_domain(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.domains.iter().any(|candidate| {
            domain == candidate || domain.ends_with(&format!(".{candidate}"))
        })
    }
}

fn parse_domain(line: &str) -> Option<String> {
    let line = line.split('#').next()?.trim();
    if line.is_empty() {
        return None;
    }
    let domain = line.strip_prefix("domain:").unwrap_or(line).trim();
    if domain.is_empty() || domain.contains(char::is_whitespace) {
        return None;
    }
    Some(normalize_domain(domain))
}

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Correlates ordinary DNS responses with the direct-domain lists without
/// changing the machine's DNS configuration.
///
/// WinDivert's network layer has no process id, so DNS correlation is the safe
/// way to turn a domain decision into an IP decision before the application's
/// TCP/UDP connection is captured. The handle is sniff-only: the original DNS
/// response continues through Windows untouched.
pub(crate) struct DnsWatcher {
    handle: Arc<Handle>,
    stopping: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl DnsWatcher {
    pub(crate) fn start(
        library: &Arc<Library>,
        router: GeoRouter,
        table: Arc<FlowTable>,
    ) -> Result<Self, ClientError> {
        let handle = Arc::new(library.open(
            DNS_FILTER,
            LAYER_NETWORK,
            100,
            FLAG_SNIFF | FLAG_RECV_ONLY,
        )?);
        handle.tune_queues();

        let stopping = Arc::new(AtomicBool::new(false));
        let thread = thread::Builder::new()
            .name("mousevpn-dns-geo-watcher".to_owned())
            .spawn({
                let handle = Arc::clone(&handle);
                let stopping = Arc::clone(&stopping);
                move || run_dns_watcher(&handle, &stopping, &router, &table)
            })
            .map_err(|error| {
                ClientError::Platform(format!("failed to start DNS geo watcher: {error}"))
            })?;

        Ok(Self {
            handle,
            stopping,
            thread: Some(thread),
        })
    }
}

impl Drop for DnsWatcher {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.handle.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run_dns_watcher(
    handle: &Handle,
    stopping: &AtomicBool,
    router: &GeoRouter,
    table: &FlowTable,
) {
    let mut buffer = vec![0_u8; DNS_BUFFER];
    let mut address = Address::zeroed();

    while !stopping.load(Ordering::Acquire) {
        match handle.recv(&mut buffer, &mut address) {
            Ok(Some(length)) => observe_dns_response(&buffer[..length], router, table),
            Ok(None) => return,
            Err(error) => {
                if !stopping.load(Ordering::Acquire) {
                    eprintln!("MOUSEVPN_GEO_WARNING=DNS watcher stopped: {error}");
                }
                return;
            }
        }
    }
}

fn observe_dns_response(bytes: &[u8], router: &GeoRouter, table: &FlowTable) {
    let Some(payload) = udp_payload(bytes) else {
        return;
    };
    if payload.len() < 12 {
        return;
    }

    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 == 0 {
        return;
    }
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    let answers = u16::from_be_bytes([payload[6], payload[7]]);
    if questions == 0 || answers == 0 {
        return;
    }

    let mut offset = 12;
    let Some(domain) = read_dns_name(payload, &mut offset) else {
        return;
    };
    if !router.is_direct_domain(&domain) || payload.len().saturating_sub(offset) < 4 {
        return;
    }
    offset += 4; // QTYPE + QCLASS.

    for _ in 0..answers {
        let Some(_) = read_dns_name(payload, &mut offset) else {
            return;
        };
        if payload.len().saturating_sub(offset) < 10 {
            return;
        }
        let record_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let class = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
        let ttl = u32::from_be_bytes([
            payload[offset + 4],
            payload[offset + 5],
            payload[offset + 6],
            payload[offset + 7],
        ]);
        let data_len = usize::from(u16::from_be_bytes([
            payload[offset + 8],
            payload[offset + 9],
        ]));
        offset += 10;
        let end = offset.saturating_add(data_len);
        if end > payload.len() {
            return;
        }

        if class == 1 {
            let address = match (record_type, data_len) {
                (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ))),
                (28, 16) => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&payload[offset..end]);
                    Some(IpAddr::V6(Ipv6Addr::from(octets)))
                }
                _ => None,
            };
            if let Some(address) = address {
                let ttl = if ttl == 0 { DNS_TTL_FALLBACK } else { ttl };
                table.route_direct_ip(address, Duration::from_secs(u64::from(ttl)));
            }
        }
        offset = end;
    }
}

fn udp_payload(bytes: &[u8]) -> Option<&[u8]> {
    let version = bytes.first()? >> 4;
    let transport = match version {
        4 => {
            let header = usize::from(bytes[0] & 0x0f) * 4;
            if header < 20 || bytes.len() < header + 8 || bytes[9] != 17 {
                return None;
            }
            header
        }
        6 => {
            if bytes.len() < 48 || bytes[6] != 17 {
                return None;
            }
            40
        }
        _ => return None,
    };
    let payload = transport + 8;
    (bytes.len() >= payload).then_some(&bytes[payload..])
}

fn read_dns_name(packet: &[u8], offset: &mut usize) -> Option<String> {
    let mut cursor = *offset;
    let mut jumped = false;
    let mut labels = Vec::new();

    for _ in 0..64 {
        let length = *packet.get(cursor)?;
        if length == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Some(labels.join("."));
        }
        if length & 0xc0 == 0xc0 {
            let next = *packet.get(cursor + 1)?;
            let pointer = ((usize::from(length & 0x3f)) << 8) | usize::from(next);
            if pointer >= packet.len() {
                return None;
            }
            if !jumped {
                *offset = cursor + 2;
                jumped = true;
            }
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        let start = cursor + 1;
        let end = start + usize::from(length);
        let label = std::str::from_utf8(packet.get(start..end)?).ok()?;
        labels.push(label.to_owned());
        cursor = end;
    }
    None
}
