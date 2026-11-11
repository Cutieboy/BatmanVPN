#![doc = "Tracks which process owns each network flow, using the `WinDivert` flow layer."]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Condvar, Mutex, RwLock,
    },
    thread,
    time::{Duration, Instant},
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
        NO_ERROR,
    },
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, SetTcpEntry, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
        MIB_TCP_STATE_CLOSED, MIB_TCP_STATE_DELETE_TCB, MIB_TCP_STATE_LISTEN,
        MIB_TCP_STATE_TIME_WAIT, TCP_TABLE_OWNER_PID_ALL,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetProcessTimes, OpenProcess, QueryFullProcessImageNameW,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
};

use super::{
    divert::{is_local_network, DNS_PORT},
    geo::GeoRouter,
    packet::PROTOCOL_TCP,
    Address, Handle, Library, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED,
    EVENT_SOCKET_CONNECT, FLAG_RECV_ONLY, FLAG_SNIFF, LAYER_FLOW, LAYER_SOCKET,
};
use crate::{normalize_windows_path, AppRoutingMode, AppRoutingPolicy, ClientError};

/// Identifies one flow by the tuple the packet layer can also observe.
///
/// The endpoint id would be cheaper, but packets do not carry it: matching a
/// packet against a policy decision has to go through the 5-tuple.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FlowKey {
    pub(crate) protocol: u8,
    pub(crate) local: IpAddr,
    pub(crate) local_port: u16,
    pub(crate) remote: IpAddr,
    pub(crate) remote_port: u16,
}

/// What the policy decided for a flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Disposition {
    /// The flow belongs in the tunnel.
    Tunnel,
    /// The flow must reach the internet over the physical adapter.
    Direct,
    /// Pre-existing direct TCP flow belonging to a policy-tunnelled app:
    /// blocked/discarded so it cannot keep leaking over the ISP.
    Discard,
}

/// A routing decision and how it was reached.
///
/// The packet path can only guess — it has no process knowledge — while the
/// watcher derives its answer from a real executable. The provenance lets an
/// authoritative answer replace a guess without letting two authoritative
/// answers (from the socket and flow layers) overwrite each other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Entry {
    disposition: Disposition,
    /// `true` when the decision was made by the packet path before the
    /// watcher had classified the flow. Such a guess must not outlive the
    /// watcher's authoritative answer.
    provisional: bool,
    /// `true` when seeded at startup from `GetExtendedTcpTable`. Because
    /// `LAYER_FLOW` may not emit `FLOW_DELETED` for pre-existing sockets,
    /// a subsequent `EVENT_SOCKET_CONNECT` reusing the 5-tuple replaces it.
    preexisting: bool,
}

/// The decisions taken so far, shared with the packet path.
///
/// Reads vastly outnumber writes: every diverted packet consults the table,
/// while entries only change when a flow is created or torn down.
#[derive(Default)]
pub(crate) struct FlowTable {
    entries: RwLock<HashMap<FlowKey, Entry>>,
    /// IPs learned from direct-domain DNS answers for the lifetime of their DNS TTL.
    geo_direct_ips: RwLock<HashMap<IpAddr, Instant>>,
    has_watcher: AtomicBool,
    stopped: AtomicBool,
    notify: (Mutex<()>, Condvar),
}

impl FlowTable {
    pub(crate) fn lookup(&self, key: &FlowKey) -> Option<Disposition> {
        self.entries
            .read()
            .ok()
            .and_then(|entries| entries.get(key).map(|entry| entry.disposition))
    }

    pub(crate) fn enable_wait(&self) {
        self.has_watcher.store(true, Ordering::Release);
    }

    pub(crate) fn stop_waiting(&self) {
        self.stopped.store(true, Ordering::Release);
        self.wake_waiters();
    }

    fn wake_waiters(&self) {
        let _guard = self.notify.0.lock();
        self.notify.1.notify_all();
    }

    /// Looks up `key`, waiting briefly for the live FlowWatcher to classify
    /// a newly opened connection if `enable_wait` was called.
    pub(crate) fn lookup_or_wait(&self, key: &FlowKey, timeout: Duration) -> Option<Disposition> {
        if let Some(disposition) = self.lookup(key) {
            return Some(disposition);
        }
        if !self.has_watcher.load(Ordering::Acquire)
            || self.stopped.load(Ordering::Acquire)
            || timeout.is_zero()
        {
            return None;
        }
        let deadline = Instant::now() + timeout;
        let Ok(mut guard) = self.notify.0.lock() else {
            return self.lookup(key);
        };
        loop {
            if let Some(disposition) = self.lookup(key) {
                return Some(disposition);
            }
            if self.stopped.load(Ordering::Acquire) {
                return None;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return self.lookup(key);
            }
            let Ok((next_guard, _)) = self.notify.1.wait_timeout(guard, remaining) else {
                return self.lookup(key);
            };
            guard = next_guard;
        }
    }

    pub(crate) fn route_direct_ip(&self, address: IpAddr, ttl: std::time::Duration) {
        if let Ok(mut ips) = self.geo_direct_ips.write() {
            ips.insert(address, std::time::Instant::now() + ttl);
        }
    }

    pub(crate) fn is_geo_direct_ip(&self, address: IpAddr) -> bool {
        let now = std::time::Instant::now();
        let Ok(mut ips) = self.geo_direct_ips.write() else {
            return false;
        };
        ips.retain(|_, expires| *expires > now);
        ips.contains_key(&address)
    }

    /// Records an attributed decision from the FlowWatcher.
    ///
    /// An authoritative decision (derived from a real process) replaces any
    /// provisional guess made by the packet path, but does not overwrite
    /// another authoritative decision — the first attributed event wins,
    /// preventing a later event from a different layer from flip-flopping
    /// the routing of an already-established flow.
    pub(crate) fn insert(&self, key: FlowKey, disposition: Disposition) {
        self.insert_with_provenance(key, disposition, false, false);
    }

    fn insert_preexisting(&self, key: FlowKey, disposition: Disposition) {
        self.insert_with_provenance(key, disposition, true, false);
    }

    fn insert_socket_connect(&self, key: FlowKey, disposition: Disposition, attributed: bool) {
        if attributed {
            self.insert_with_provenance(key, disposition, false, true);
        } else if let Ok(mut entries) = self.entries.write() {
            entries
                .entry(key)
                .and_modify(|existing| {
                    if existing.preexisting {
                        existing.disposition = disposition;
                        existing.provisional = false;
                        existing.preexisting = false;
                    }
                })
                .or_insert(Entry {
                    disposition,
                    provisional: false,
                    preexisting: false,
                });
            drop(entries);
            self.wake_waiters();
        }
    }

    fn insert_with_provenance(
        &self,
        key: FlowKey,
        disposition: Disposition,
        preexisting: bool,
        replace_preexisting: bool,
    ) {
        if let Ok(mut entries) = self.entries.write() {
            entries
                .entry(key)
                .and_modify(|existing| {
                    // Override a provisional guess (or a stale preexisting
                    // entry when a brand-new socket connect reuses the tuple).
                    if existing.provisional || (replace_preexisting && existing.preexisting) {
                        existing.disposition = disposition;
                        existing.provisional = false;
                        existing.preexisting = preexisting;
                    }
                })
                .or_insert(Entry {
                    disposition,
                    provisional: false,
                    preexisting,
                });
        }
        self.wake_waiters();
    }

    /// Records a decision that could not be attributed to a process.
    ///
    /// The flow layer reports some flows twice: once for the application that
    /// owns them and once for a process we cannot open, which on this machine
    /// is the System process reporting a flow that also crosses another
    /// tunnel's adapter. Both carry the same five-tuple, so a plain insert
    /// lets whichever arrives last decide, and an unattributable event can
    /// quietly downgrade a routed application to the physical link.
    ///
    /// An answer derived from no process therefore never replaces one derived
    /// from a real executable, nor a provisional guess from the packet path.
    fn insert_unattributed(&self, key: FlowKey, disposition: Disposition) {
        if let Ok(mut entries) = self.entries.write() {
            entries.entry(key).or_insert(Entry {
                disposition,
                provisional: false,
                preexisting: false,
            });
        }
        self.wake_waiters();
    }

    /// Records a provisional decision made by the packet path for an
    /// unclassified flow.
    ///
    /// The packet path has no process knowledge, so its guess must not
    /// outlast the watcher's authoritative answer. A later attributed
    /// [`insert`] will replace this entry. An unattributed event or another
    /// provisional insert will not.
    pub(crate) fn insert_provisional(&self, key: FlowKey, disposition: Disposition) {
        if let Ok(mut entries) = self.entries.write() {
            entries.entry(key).or_insert(Entry {
                disposition,
                provisional: true,
                preexisting: false,
            });
        }
    }

    fn remove(&self, key: &FlowKey) {
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(key);
        }
    }

    /// Forgets every classification.
    ///
    /// Needed when the physical address changes: it forms part of every key
    /// here, so entries recorded against the old one can never match again and
    /// would keep the table growing for the life of the session.
    pub(crate) fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
        if let Ok(mut ips) = self.geo_direct_ips.write() {
            ips.clear();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.read().map_or(0, |entries| entries.len())
    }

    /// Seeds a decision so the diverter can be tested without a live watcher.
    #[cfg(test)]
    pub(crate) fn insert_for_test(&self, key: FlowKey, disposition: Disposition) {
        self.insert(key, disposition);
    }
}

/// Watches flow establishment and classifies each flow against the policy.
///
/// The handle is opened in sniffing mode: this layer only observes, and must
/// never delay or drop a connection. A stall here would be indistinguishable
/// from a broken network.
pub(crate) struct FlowWatcher {
    handles: Vec<Arc<Handle>>,
    table: Arc<FlowTable>,
    classifier: Arc<Classifier>,
    stopping: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl FlowWatcher {
    /// Starts watching flows for `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the `WinDivert` flow handle cannot
    /// be opened.
    /// Watches both the socket and the flow layer.
    ///
    /// The socket layer is what makes a blocked destination reachable at all.
    /// Its connect event fires before the SYN leaves, so the first packet is
    /// already classified. The flow layer only reports a flow once it is
    /// established, which never happens for a destination that is blocked
    /// without the tunnel: the SYN would go out untunnelled, draw no reply,
    /// and the flow that would have classified it never exists.
    ///
    /// The flow layer is still worth watching. It covers unconnected datagram
    /// sockets, which never raise a connect event, and its delete event is
    /// what retires an entry.
    pub(crate) fn start(
        library: &Arc<Library>,
        policy: &AppRoutingPolicy,
    ) -> Result<Self, ClientError> {
        let table = Arc::new(FlowTable::default());
        table.enable_wait();
        let stopping = Arc::new(AtomicBool::new(false));
        let classifier = Arc::new(Classifier::new(policy));
        // The two layers classify the same flows by different means, so losing
        // one degrades coverage while losing both stops classification
        // altogether. Only the second loss is worth alarming about, and
        // telling them apart needs a count.
        let watching = Arc::new(AtomicUsize::new(2));
        let mut handles = Vec::new();
        let mut threads = Vec::new();

        for (layer, name) in [
            (LAYER_SOCKET, "mousevpn-socket-watcher"),
            (LAYER_FLOW, "mousevpn-flow-watcher"),
        ] {
            // Priority is irrelevant for a sniffing handle, but a distinct
            // value keeps MouseVPN identifiable in `windivertctl` output.
            let handle = Arc::new(library.open("true", layer, 0, FLAG_SNIFF | FLAG_RECV_ONLY)?);
            // An overflowing event queue is not a lost statistic here: a
            // connect event that never arrives is a flow that never gets
            // classified, and an unclassified flow of a routed application
            // leaves on the physical link.
            handle.tune_queues();
            let thread = thread::Builder::new()
                .name(name.to_owned())
                .spawn({
                    let handle = Arc::clone(&handle);
                    let table = Arc::clone(&table);
                    let stopping = Arc::clone(&stopping);
                    let classifier = Arc::clone(&classifier);
                    let watching = Arc::clone(&watching);
                    move || run(&handle, &table, &classifier, &stopping, &watching)
                })
                .map_err(|error| {
                    ClientError::Platform(format!("failed to start {name}: {error}"))
                })?;
            handles.push(handle);
            threads.push(thread);
        }

        Ok(Self {
            handles,
            table,
            classifier,
            stopping,
            threads,
        })
    }

    pub(crate) fn table(&self) -> Arc<FlowTable> {
        Arc::clone(&self.table)
    }

    /// Enumerates TCP sockets established before capture began so excluded
    /// apps remain Direct and tunnelled apps cannot silently continue over
    /// the physical ISP link.
    pub(crate) fn preclassify_existing_tcp(
        &self,
        server: SocketAddr,
        geo: Option<&GeoRouter>,
        own_pid: u32,
    ) {
        preclassify_ipv4_tcp(&self.table, &self.classifier, server, geo, own_pid);
        preclassify_ipv6_tcp(&self.table, &self.classifier, server, geo, own_pid);
    }
}

impl Drop for FlowWatcher {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.table.stop_waiting();
        // Each watcher parks inside `recv`, so it only observes `stopping`
        // after the shutdown drains its queue and wakes it.
        for handle in &self.handles {
            handle.shutdown();
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

fn run(
    handle: &Handle,
    table: &FlowTable,
    classifier: &Classifier,
    stopping: &AtomicBool,
    watching: &AtomicUsize,
) {
    // Flow events carry no packet payload, so the receive buffer stays empty.
    let mut address = Address::zeroed();
    while !stopping.load(Ordering::Acquire) {
        match handle.recv(&mut [], &mut address) {
            Ok(Some(_)) => {}
            // An orderly shutdown.
            Ok(None) => return,
            Err(error) => {
                // Losing flow tracking degrades routing accuracy but must not
                // tear down a working tunnel. Losing the last watcher is a
                // different thing entirely: no new flow is classified after
                // it, and an unclassified flow of a routed application leaves
                // on the physical link. That is a silent leak, so it is
                // reported on the channel the application actually shows the
                // user rather than on one only a log reader would find.
                eprintln!("MOUSEVPN_FLOW_WARNING={error}");
                if watching.fetch_sub(1, Ordering::AcqRel) == 1 {
                    eprintln!(
                        "MOUSEVPN_RUNTIME_WARNING=application routing stopped tracking new \
                         connections; applications selected for the tunnel may now be \
                         connecting directly"
                    );
                }
                return;
            }
        }
        let Some(flow) = address.flow() else {
            continue;
        };
        let Some(key) = flow_key(&flow, address.ipv6()) else {
            continue;
        };
        match address.event() {
            // A connect event carries the process before the first packet is
            // sent, which is the only moment that helps a destination that is
            // unreachable without the tunnel.
            EVENT_SOCKET_CONNECT => {
                let (disposition, attributed) = classifier.classify(flow.process_id);
                table.insert_socket_connect(key, disposition, attributed);
            }
            EVENT_FLOW_ESTABLISHED => {
                let (disposition, attributed) = classifier.classify(flow.process_id);
                if attributed {
                    table.insert(key, disposition);
                } else {
                    table.insert_unattributed(key, disposition);
                }
            }
            // Remove on FLOW_DELETED rather than SOCKET_CLOSE so graceful
            // closing FIN-ACK/LAST_ACK packets keep their flow disposition.
            EVENT_FLOW_DELETED => table.remove(&key),
            _ => {}
        }
    }
}

/// Prints live flow events for `seconds`, then stops.
///
/// This is a diagnostic, not part of the connection path. It answers three
/// questions that only a real machine can: whether the vendored driver loads
/// without test signing, whether the flow layer reports process ids in time,
/// and whether the address layout this module assumes is the one `WinDivert`
/// actually uses.
///
/// Every event is printed with both the decoded tuple and the raw address
/// words, so a wrong layout assumption shows up as visible evidence rather
/// than as flows that quietly never decode.
///
/// # Errors
///
/// Returns [`ClientError::Platform`] when the library or the flow handle
/// cannot be opened.
pub fn probe(seconds: u64, policy: &AppRoutingPolicy) -> Result<(), ClientError> {
    let library = Library::load()?;
    let classifier = Classifier::new(policy);
    println!("WinDivert.dll loaded");
    let handle = Arc::new(library.open("true", LAYER_FLOW, 0, FLAG_SNIFF | FLAG_RECV_ONLY)?);
    println!("flow handle open; the WinDivert driver service is running");
    println!("watching flows for {seconds}s\n");

    thread::spawn({
        let handle = Arc::clone(&handle);
        move || {
            thread::sleep(std::time::Duration::from_secs(seconds));
            handle.shutdown();
        }
    });

    let mut address = Address::zeroed();
    let (mut established, mut deleted, mut undecoded, mut printed) = (0_u64, 0_u64, 0_u64, 0_u64);
    while handle.recv(&mut [], &mut address)?.is_some() {
        let Some(flow) = address.flow() else {
            continue;
        };
        let event = match address.event() {
            EVENT_FLOW_ESTABLISHED => {
                established += 1;
                "established"
            }
            EVENT_FLOW_DELETED => {
                deleted += 1;
                "deleted"
            }
            _ => continue,
        };
        let decoded = flow_key(&flow, address.ipv6());
        if decoded.is_none() {
            undecoded += 1;
        }
        // Deleted flows are noisy and add nothing once establishment decodes,
        // so the detailed log stays bounded and focused.
        if printed >= 40 || event == "deleted" {
            continue;
        }
        printed += 1;
        let path = Process::open(flow.process_id)
            .and_then(|process| process.image_path())
            .map_or_else(|| "<unknown>".to_owned(), |path| path.display().to_string());
        // The verdict is the whole point: a routed application whose flows read
        // DIRECT is a policy mismatch, not a tunnel fault.
        let verdict = match classifier.classify(flow.process_id) {
            (Disposition::Tunnel, true) => "TUNNEL",
            (Disposition::Direct, true) => "direct",
            // A flow the layer reports twice appears once for a process that
            // cannot be opened. Marking it keeps that from reading as a
            // policy decision about the application.
            (Disposition::Tunnel, false) => "tunnel?",
            (Disposition::Direct, false) => "direct?",
            (Disposition::Discard, _) => "DISCARD",
        };
        match decoded {
            Some(key) => println!(
                "{verdict} {event:<11} pid={:<6} proto={:<3} {}:{} -> {}:{}  {path}",
                flow.process_id,
                key.protocol,
                key.local,
                key.local_port,
                key.remote,
                key.remote_port
            ),
            None => println!(
                "{verdict} {event:<11} pid={:<6} proto={:<3} UNDECODED ipv6={} local={:08x?} remote={:08x?}  {path}",
                flow.process_id,
                flow.protocol,
                address.ipv6(),
                flow.local_addr,
                flow.remote_addr
            ),
        }
    }

    println!("\nestablished={established} deleted={deleted} undecoded={undecoded}");
    if undecoded > 0 {
        println!(
            "WARNING: {undecoded} flow(s) did not match the assumed IPv4-mapped layout; \
             compare the raw words above against decode_address()"
        );
    }
    Ok(())
}

/// The most classifications remembered at once.
///
/// Each entry is a process that opened at least one connection during the
/// session. Machines that churn through processes — a build, a shell loop —
/// would otherwise grow this for as long as the tunnel is up.
const CLASSIFICATION_CAPACITY: usize = 4_096;

/// Decides where a process's traffic belongs, caching the answer per process.
///
/// Resolving an executable path costs a kernel query and a buffer; the same
/// process reappears for every flow a busy application creates, so the answer
/// is memoised.
///
/// The entry is keyed by the process id *and* its creation time, not the id
/// alone. Windows reuses process ids freely, and an id-only cache hands the
/// verdict made for an exited program to whichever program inherits its
/// number — which is to say it silently routes an application the opposite of
/// what the user selected, and keeps doing so. The creation time is what makes
/// two processes that share an id distinguishable.
struct Classifier {
    mode: AppRoutingMode,
    apps: Vec<PathBuf>,
    /// Maps a process, identified beyond reuse, to whether it is listed.
    cache: Mutex<HashMap<(u32, u64), bool>>,
}

impl Classifier {
    fn new(policy: &AppRoutingPolicy) -> Self {
        Self {
            mode: policy.mode,
            apps: policy
                .apps
                .iter()
                .map(|path| normalize_windows_path(path))
                .collect(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Decides where a flow belongs, and reports whether a process backed the
    /// decision.
    ///
    /// The second value matters because an unattributable flow still gets a
    /// default, and that default must not overrule a decision made from a real
    /// executable for the same five-tuple.
    fn classify(&self, process_id: u32) -> (Disposition, bool) {
        let (listed, attributed) = self.is_listed(process_id);
        let disposition = match (self.mode, listed) {
            // Selected applications bypass the tunnel; everything else uses it.
            (AppRoutingMode::Exclude, true) | (AppRoutingMode::Include, false) => {
                Disposition::Direct
            }
            (AppRoutingMode::Exclude, false) | (AppRoutingMode::Include, true) => {
                Disposition::Tunnel
            }
        };
        (disposition, attributed)
    }

    fn is_listed(&self, process_id: u32) -> (bool, bool) {
        // Protected system processes cannot be opened at all. That answer is
        // not remembered, because there is no creation time to key it by and
        // an id on its own is not a stable name for a process. Retrying costs
        // one failing open.
        let Some(process) = Process::open(process_id) else {
            return (false, false);
        };
        let Some(created) = process.created() else {
            return process
                .image_path()
                .map_or((false, false), |path| (self.matches(&path), true));
        };
        let key = (process_id, created);
        if let Ok(cache) = self.cache.lock() {
            if let Some(listed) = cache.get(&key) {
                return (*listed, true);
            }
        }

        let Some(path) = process.image_path() else {
            return (false, false);
        };
        // An excluded desktop application can delegate its network work to a
        // helper process. Windhawk is a concrete example: its UI can launch a
        // VSCodium/Node extension host which owns the actual HTTPS socket.
        // Treat a descendant of an excluded application as excluded too, so
        // the user's bypass follows the application rather than one executable
        // image. The parent PID alone is not enough because Windows can reuse
        // PIDs; require each parent to have been created no later than its
        // child before accepting the ancestry.
        let listed = self.matches(&path)
            || (!self.apps.is_empty() && self.matches_excluded_ancestor(process_id, created));

        if let Ok(mut cache) = self.cache.lock() {
            // Dropping everything is cruder than evicting the coldest entry
            // and costs one re-query for the processes still running. Both are
            // off the packet path, and this cannot get the eviction order
            // wrong.
            if cache.len() >= CLASSIFICATION_CAPACITY {
                cache.clear();
            }
            cache.insert(key, listed);
        }
        (listed, true)
    }

    fn matches_excluded_ancestor(&self, process_id: u32, child_created: u64) -> bool {
        let Some(snapshot) = ProcessSnapshot::new() else {
            return false;
        };
        let mut current = process_id;
        let mut child_time = child_created;
        let mut visited = std::collections::HashSet::new();

        while let Some(parent_id) = snapshot.parent_of(current) {
            if parent_id == 0 || parent_id == current || !visited.insert(parent_id) {
                return false;
            }
            let Some(parent) = Process::open(parent_id) else {
                return false;
            };
            let Some(parent_created) = parent.created() else {
                return false;
            };
            // A reused parent PID cannot be an ancestor when the replacement
            // process started after the child.
            if parent_created > child_time {
                return false;
            }
            if parent
                .image_path()
                .is_some_and(|path| self.matches(&path))
            {
                return true;
            }
            current = parent_id;
            child_time = parent_created;
        }
        false
    }

    fn matches(&self, path: &Path) -> bool {
        self.apps
            .iter()
            .any(|candidate| paths_equal(candidate, path))
    }
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    left.as_os_str()
        .to_string_lossy()
        .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
}

/// A point-in-time map of process IDs to their parent process IDs.
///
/// Tool Help exposes the parent PID in the same snapshot as the process list.
/// Taking one snapshot per uncached classification keeps ancestry checks off the
/// packet path while avoiding a separate process enumeration for every parent.
struct ProcessSnapshot {
    parents: std::collections::HashMap<u32, u32>,
}

impl ProcessSnapshot {
    fn new() -> Option<Self> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut parents = std::collections::HashMap::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            cntUsage: 0,
            th32ProcessID: 0,
            th32DefaultHeapID: 0,
            th32ModuleID: 0,
            cntThreads: 0,
            th32ParentProcessID: 0,
            pcPriClassBase: 0,
            dwFlags: 0,
            szExeFile: [0; 260],
        };
        let first = unsafe { Process32FirstW(snapshot, &raw mut entry) };
        if first == 0 {
            unsafe { CloseHandle(snapshot) };
            return None;
        }
        loop {
            parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
            if unsafe { Process32NextW(snapshot, &raw mut entry) } == 0 {
                break;
            }
        }
        unsafe { CloseHandle(snapshot) };
        Some(Self { parents })
    }

    fn parent_of(&self, process_id: u32) -> Option<u32> {
        self.parents.get(&process_id).copied()
    }
}

/// An open process handle, closed exactly once when it goes out of scope.
struct Process(HANDLE);

impl Process {
    /// Opens `process_id` for the two queries below.
    ///
    /// Returns `None` for processes that have already exited or that the
    /// helper cannot open, which includes protected system processes.
    fn open(process_id: u32) -> Option<Self> {
        // SAFETY: a failed open returns null, which is checked before use.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        (!handle.is_null()).then_some(Self(handle))
    }

    /// Reads the moment the process started, as a 100-nanosecond file time.
    ///
    /// This is what distinguishes a process from an unrelated one that later
    /// inherits its id.
    fn created(&self) -> Option<u64> {
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut ignored = [FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        }; 3];
        // SAFETY: every out parameter points at a live `FILETIME`, and the
        // handle is valid for the lifetime of `self`.
        let ok = unsafe {
            GetProcessTimes(
                self.0,
                &raw mut creation,
                &raw mut ignored[0],
                &raw mut ignored[1],
                &raw mut ignored[2],
            )
        };
        (ok != 0).then(|| {
            u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime)
        })
    }

    /// Resolves the executable backing the process.
    fn image_path(&self) -> Option<PathBuf> {
        const ERROR_INSUFFICIENT_BUFFER: i32 = 122;
        // Windows paths reach 32767 characters, but essentially never do.
        // Starting small and growing only when Windows says so keeps the
        // common case to one small allocation instead of 64KB per process.
        let mut capacity = 512_usize;
        loop {
            let mut buffer = vec![0_u16; capacity];
            let mut length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
            // SAFETY: `length` describes `buffer` and the handle is valid for
            // the lifetime of `self`.
            let ok = unsafe {
                QueryFullProcessImageNameW(
                    self.0,
                    // `PROCESS_NAME_WIN32`: the Win32 path, matching the paths
                    // the UI stores. The native NT form would never compare
                    // equal to them.
                    0,
                    buffer.as_mut_ptr(),
                    &raw mut length,
                )
            };
            if ok != 0 {
                let path = String::from_utf16_lossy(&buffer[..length as usize]);
                return Some(normalize_windows_path(Path::new(&path)));
            }
            if std::io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER)
                || capacity >= 32_768
            {
                return None;
            }
            capacity = (capacity * 2).min(32_768);
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // SAFETY: the handle came from `OpenProcess` and is closed exactly
        // once, when the only owner is dropped.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Builds a flow key from the `WinDivert` flow data.
///
/// `WinDivert` reports flow addresses as IPv4-mapped IPv6 in its host-order
/// representation, where word 0 holds the least significant part. An IPv4 flow
/// therefore arrives as `[addr, 0xffff, 0, 0]`.
fn flow_key(flow: &super::FlowData, ipv6: bool) -> Option<FlowKey> {
    let local = decode_address(flow.local_addr, ipv6)?;
    let remote = decode_address(flow.remote_addr, ipv6)?;
    Some(FlowKey {
        protocol: flow.protocol,
        local,
        local_port: flow.local_port,
        remote,
        remote_port: flow.remote_port,
    })
}

fn decode_address(words: [u32; 4], ipv6: bool) -> Option<IpAddr> {
    if ipv6 {
        // Host order stores the words least significant first, so the IPv6
        // address reads back in reverse.
        let mut octets = [0_u8; 16];
        for (index, word) in words.iter().rev().enumerate() {
            octets[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }
    // An IPv4 flow must carry the ::ffff:0:0/96 mapping prefix. Anything else
    // means the layout assumption is wrong, and silently trusting word 0 would
    // route traffic by a garbage address.
    (words[1] == 0xffff && words[2] == 0 && words[3] == 0)
        .then(|| IpAddr::V4(Ipv4Addr::from(words[0])))
}

fn decode_tcp_port(raw: u32) -> u16 {
    u16::from_be((raw & 0xffff) as u16)
}

fn is_active_tcp_state(state: u32) -> bool {
    !matches!(
        state,
        x if x == MIB_TCP_STATE_CLOSED as u32
            || x == MIB_TCP_STATE_LISTEN as u32
            || x == MIB_TCP_STATE_TIME_WAIT as u32
    )
}

fn apply_preclassified_tcp_entry(
    table: &FlowTable,
    classifier: &Classifier,
    server: SocketAddr,
    geo: Option<&GeoRouter>,
    own_pid: u32,
    key: FlowKey,
    pid: u32,
) -> Option<Disposition> {
    if pid == own_pid || pid == 0 {
        return None;
    }
    if SocketAddr::new(key.remote, key.remote_port) == server
        || key.remote_port == DNS_PORT
        || is_local_network(key.remote)
        || geo.is_some_and(|router| router.is_direct_ip(key.remote) || table.is_geo_direct_ip(key.remote))
    {
        return None;
    }
    // FlowWatcher is already running: never clobber a flow opened after startup.
    if table.lookup(&key).is_some() {
        return None;
    }
    let (disposition, _attributed) = classifier.classify(pid);
    let effective = match disposition {
        Disposition::Direct => Disposition::Direct,
        Disposition::Tunnel | Disposition::Discard => Disposition::Discard,
    };
    table.insert_preexisting(key, effective);
    Some(effective)
}

fn read_extended_tcp_table(family: u32) -> Option<Vec<u64>> {
    let mut size = 0_u32;
    let status = unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &raw mut size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if status != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return None;
    }
    let words = (size as usize).div_ceil(std::mem::size_of::<u64>()) + 8;
    let mut buffer = vec![0_u64; words];
    let mut actual_size = u32::try_from(std::mem::size_of_val(buffer.as_slice())).ok()?;
    let status = unsafe {
        GetExtendedTcpTable(
            buffer.as_mut_ptr().cast(),
            &raw mut actual_size,
            0,
            family,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    (status == NO_ERROR).then_some(buffer)
}

fn preclassify_ipv4_tcp(
    table: &FlowTable,
    classifier: &Classifier,
    server: SocketAddr,
    geo: Option<&GeoRouter>,
    own_pid: u32,
) {
    let Some(buffer) = read_extended_tcp_table(u32::from(AF_INET)) else {
        return;
    };
    if buffer.len() < std::mem::size_of::<u32>() {
        return;
    }
    let table_ptr = buffer.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
    let count = unsafe { (*table_ptr).dwNumEntries as usize };
    let rows_offset = std::mem::offset_of!(MIB_TCPTABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_TCPROW_OWNER_PID>();
    let max_rows = std::mem::size_of_val(buffer.as_slice()).saturating_sub(rows_offset) / row_size;
    let rows = unsafe { std::slice::from_raw_parts((*table_ptr).table.as_ptr(), count.min(max_rows)) };
    let mut reset_count = 0_u64;
    for row in rows {
        if !is_active_tcp_state(row.dwState) {
            continue;
        }
        let key = FlowKey {
            protocol: PROTOCOL_TCP,
            local: IpAddr::V4(Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes())),
            local_port: decode_tcp_port(row.dwLocalPort),
            remote: IpAddr::V4(Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes())),
            remote_port: decode_tcp_port(row.dwRemotePort),
        };
        if apply_preclassified_tcp_entry(table, classifier, server, geo, own_pid, key, row.dwOwningPid)
            == Some(Disposition::Discard)
        {
            let delete_row = MIB_TCPROW_LH {
                Anonymous: MIB_TCPROW_LH_0 {
                    dwState: MIB_TCP_STATE_DELETE_TCB as u32,
                },
                dwLocalAddr: row.dwLocalAddr,
                dwLocalPort: row.dwLocalPort,
                dwRemoteAddr: row.dwRemoteAddr,
                dwRemotePort: row.dwRemotePort,
            };
            if unsafe { SetTcpEntry(&raw const delete_row) } == NO_ERROR {
                reset_count = reset_count.saturating_add(1);
            }
        }
    }
    if reset_count > 0 {
        eprintln!("MOUSEVPN_PREEXISTING_TCP_RESET=ipv4 count={reset_count}");
    }
}

fn preclassify_ipv6_tcp(
    table: &FlowTable,
    classifier: &Classifier,
    server: SocketAddr,
    geo: Option<&GeoRouter>,
    own_pid: u32,
) {
    let Some(buffer) = read_extended_tcp_table(u32::from(AF_INET6)) else {
        return;
    };
    if buffer.len() < std::mem::size_of::<u32>() {
        return;
    }
    let table_ptr = buffer.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
    let count = unsafe { (*table_ptr).dwNumEntries as usize };
    let rows_offset = std::mem::offset_of!(MIB_TCP6TABLE_OWNER_PID, table);
    let row_size = std::mem::size_of::<MIB_TCP6ROW_OWNER_PID>();
    let max_rows = std::mem::size_of_val(buffer.as_slice()).saturating_sub(rows_offset) / row_size;
    let rows = unsafe { std::slice::from_raw_parts((*table_ptr).table.as_ptr(), count.min(max_rows)) };
    let mut discard_count = 0_u64;
    for row in rows {
        if !is_active_tcp_state(row.dwState) {
            continue;
        }
        let key = FlowKey {
            protocol: PROTOCOL_TCP,
            local: IpAddr::V6(Ipv6Addr::from(row.ucLocalAddr)),
            local_port: decode_tcp_port(row.dwLocalPort),
            remote: IpAddr::V6(Ipv6Addr::from(row.ucRemoteAddr)),
            remote_port: decode_tcp_port(row.dwRemotePort),
        };
        if apply_preclassified_tcp_entry(table, classifier, server, geo, own_pid, key, row.dwOwningPid)
            == Some(Disposition::Discard)
        {
            discard_count = discard_count.saturating_add(1);
        }
    }
    if discard_count > 0 {
        eprintln!("MOUSEVPN_PREEXISTING_TCP_DISCARD=ipv6 count={discard_count}");
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_address, normalize_windows_path, paths_equal, AppRoutingMode, AppRoutingPolicy,
        Classifier, Disposition, FlowKey, FlowTable, Process,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::{Path, PathBuf},
    };

    fn key() -> FlowKey {
        FlowKey {
            protocol: 6,
            local: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            local_port: 51_000,
            remote: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            remote_port: 443,
        }
    }

    #[test]
    fn decodes_an_ipv4_mapped_flow_address() {
        // ::ffff:93.184.216.34 in WinDivert's host-order representation.
        let words = [u32::from(Ipv4Addr::new(93, 184, 216, 34)), 0xffff, 0, 0];
        assert_eq!(
            decode_address(words, false),
            Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
        );
    }

    #[test]
    fn rejects_an_ipv4_address_without_the_mapping_prefix() {
        // Guards the host-order assumption: a network-order layout would put
        // the mapping prefix in a different word and must not decode silently.
        assert_eq!(decode_address([0, 0, 0xffff, 12345], false), None);
    }

    #[test]
    fn an_unattributed_event_never_downgrades_a_classified_flow() {
        // The flow layer reports some flows twice, once for a process that
        // cannot be opened. Letting that second event win sends a routed
        // application out on the physical link.
        let table = FlowTable::default();
        table.insert(key(), Disposition::Tunnel);
        table.insert_unattributed(key(), Disposition::Direct);
        assert_eq!(table.lookup(&key()), Some(Disposition::Tunnel));
    }

    #[test]
    fn a_later_attributed_event_never_overwrites_the_first_decision() {
        let table = FlowTable::default();
        table.insert(key(), Disposition::Tunnel);
        table.insert(key(), Disposition::Direct);
        assert_eq!(table.lookup(&key()), Some(Disposition::Tunnel));
    }

    #[test]
    fn an_unattributed_event_still_seeds_an_unknown_flow() {
        let table = FlowTable::default();
        table.insert_unattributed(key(), Disposition::Tunnel);
        assert_eq!(table.lookup(&key()), Some(Disposition::Tunnel));
    }

    #[test]
    fn tracks_and_forgets_flows() {
        let table = FlowTable::default();
        assert_eq!(table.lookup(&key()), None);
        table.insert(key(), Disposition::Direct);
        assert_eq!(table.lookup(&key()), Some(Disposition::Direct));
        table.remove(&key());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn an_attributed_event_replaces_a_provisional_guess() {
        // The packet path pins an unclassified SYN to the default (Tunnel).
        // When the watcher later learns the process is excluded, its
        // authoritative Direct answer must replace the guess — otherwise an
        // excluded application would be permanently tunnelled.
        let table = FlowTable::default();
        table.insert_provisional(key(), Disposition::Tunnel);
        assert_eq!(table.lookup(&key()), Some(Disposition::Tunnel));
        table.insert(key(), Disposition::Direct);
        assert_eq!(table.lookup(&key()), Some(Disposition::Direct));
    }

    #[test]
    fn a_provisional_guess_does_not_override_an_attributed_decision() {
        // The watcher classified the flow first (e.g. the socket connect event
        // beat the SYN). A later provisional insert must not flip it.
        let table = FlowTable::default();
        table.insert(key(), Disposition::Direct);
        table.insert_provisional(key(), Disposition::Tunnel);
        assert_eq!(table.lookup(&key()), Some(Disposition::Direct));
    }

    #[test]
    fn an_unattributed_event_does_not_replace_a_provisional_guess() {
        // The System process reporting a flow must not downgrade the packet
        // path's provisional default. Only an attributed decision may.
        let table = FlowTable::default();
        table.insert_provisional(key(), Disposition::Tunnel);
        table.insert_unattributed(key(), Disposition::Direct);
        assert_eq!(table.lookup(&key()), Some(Disposition::Tunnel));
    }

    #[test]
    fn identifies_a_process_beyond_its_id() {
        // The creation time is what a cache entry is keyed by, so it has to be
        // readable and identical every time the same process is opened. If it
        // were not stable, every lookup would miss and the memoisation would
        // silently do nothing.
        let id = std::process::id();
        let created = Process::open(id)
            .and_then(|process| process.created())
            .expect("the running process has a creation time");
        assert_ne!(created, 0);
        assert_eq!(
            Process::open(id).and_then(|process| process.created()),
            Some(created)
        );
    }

    #[test]
    fn resolves_a_running_executable_without_a_64kb_buffer() {
        let path = Process::open(std::process::id())
            .and_then(|process| process.image_path())
            .expect("the running process has an image path");
        // The growth loop starts at 512 characters; an ordinary path must
        // resolve on the first attempt and come back normalised.
        assert!(path.is_absolute(), "{}", path.display());
        assert_eq!(path, normalize_windows_path(&path));
    }

    #[test]
    fn classifies_the_running_process_the_same_way_twice() {
        // The second call is the one that goes through the cache. A key that
        // did not survive the round trip would show up here as the two
        // answers disagreeing.
        let executable = std::env::current_exe().expect("current executable");
        let listed = Classifier::new(&AppRoutingPolicy {
            mode: AppRoutingMode::Include,
            apps: vec![executable],
            package_sids: Vec::new(),
        });
        let id = std::process::id();
        assert_eq!(listed.classify(id), (Disposition::Tunnel, true));
        assert_eq!(listed.classify(id), (Disposition::Tunnel, true));

        let unlisted = Classifier::new(&AppRoutingPolicy {
            mode: AppRoutingMode::Include,
            apps: vec![PathBuf::from(r"C:\nowhere\absent.exe")],
            package_sids: Vec::new(),
        });
        assert_eq!(unlisted.classify(id), (Disposition::Direct, true));
        assert_eq!(unlisted.classify(id), (Disposition::Direct, true));
    }

    #[test]
    fn forgets_the_oldest_classifications_rather_than_growing_without_bound() {
        // Long sessions on a machine that churns through processes would
        // otherwise accumulate one entry per process ever seen.
        let classifier = Classifier::new(&AppRoutingPolicy::default());
        if let Ok(mut cache) = classifier.cache.lock() {
            for index in 0..u32::try_from(super::CLASSIFICATION_CAPACITY).expect("capacity fits") {
                cache.insert((index, 1), false);
            }
        }
        let _ = classifier.classify(std::process::id());
        let size = classifier.cache.lock().map_or(0, |cache| cache.len());
        assert!(size <= super::CLASSIFICATION_CAPACITY, "{size}");
    }

    #[test]
    fn compares_executable_paths_case_insensitively() {
        assert!(paths_equal(
            Path::new(r"C:\Apps\Browser.exe"),
            Path::new(r"c:\apps\browser.EXE")
        ));
    }

    #[test]
    fn lookup_or_wait_wakes_when_watcher_inserts_decision() {
        let table = std::sync::Arc::new(FlowTable::default());
        table.enable_wait();
        let writer_table = std::sync::Arc::clone(&table);
        let flow = key();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            writer_table.insert(flow, Disposition::Direct);
        });
        assert_eq!(
            table.lookup_or_wait(&key(), std::time::Duration::from_millis(200)),
            Some(Disposition::Direct)
        );
        handle.join().expect("writer thread");
    }

    #[test]
    fn preclassification_respects_policy_server_lan_and_watcher_race() {
        let executable = std::env::current_exe().expect("exe");
        let server: SocketAddr = "203.0.113.10:443".parse().expect("server");
        let pid = std::process::id();
        let other_pid = pid.saturating_add(1);
        let make_key = |port: u16, remote: IpAddr, remote_port: u16| FlowKey {
            protocol: 6,
            local: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            local_port: port,
            remote,
            remote_port,
        };

        // Exclude mode: listed app stays Direct; unlisted or dead PID becomes Discard.
        let exclude_classifier = super::Classifier::new(&AppRoutingPolicy {
            mode: AppRoutingMode::Exclude,
            apps: vec![executable.clone()],
            package_sids: Vec::new(),
        });
        let table = FlowTable::default();
        let k_excluded = make_key(50_001, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let k_dead = make_key(50_002, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let k_lan = make_key(50_003, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let k_server = make_key(50_004, server.ip(), server.port());
        let k_own = make_key(50_005, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        let k_raced = make_key(50_006, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);
        table.insert(k_raced, Disposition::Tunnel);

        assert_eq!(super::apply_preclassified_tcp_entry(&table, &exclude_classifier, server, None, other_pid, k_excluded, pid), Some(Disposition::Direct));
        assert_eq!(super::apply_preclassified_tcp_entry(&table, &exclude_classifier, server, None, other_pid, k_dead, 999_999_999), Some(Disposition::Discard));
        assert_eq!(super::apply_preclassified_tcp_entry(&table, &exclude_classifier, server, None, other_pid, k_lan, pid), None);
        assert_eq!(super::apply_preclassified_tcp_entry(&table, &exclude_classifier, server, None, other_pid, k_server, pid), None);
        assert_eq!(super::apply_preclassified_tcp_entry(&table, &exclude_classifier, server, None, pid, k_own, pid), None);
        // FlowWatcher already inserted Tunnel -> preclassification must not overwrite it.
        assert_eq!(super::apply_preclassified_tcp_entry(&table, &exclude_classifier, server, None, other_pid, k_raced, pid), None);
        assert_eq!(table.lookup(&k_excluded), Some(Disposition::Direct));
        assert_eq!(table.lookup(&k_dead), Some(Disposition::Discard));
        assert_eq!(table.lookup(&k_raced), Some(Disposition::Tunnel));

        // Include mode: listed app pre-existing flow becomes Discard; dead PID stays Direct.
        let include_classifier = super::Classifier::new(&AppRoutingPolicy {
            mode: AppRoutingMode::Include,
            apps: vec![executable],
            package_sids: Vec::new(),
        });
        let include_table = FlowTable::default();
        assert_eq!(super::apply_preclassified_tcp_entry(&include_table, &include_classifier, server, None, other_pid, k_excluded, pid), Some(Disposition::Discard));
        assert_eq!(super::apply_preclassified_tcp_entry(&include_table, &include_classifier, server, None, other_pid, k_dead, 999_999_999), Some(Disposition::Direct));
    }

    #[test]
    fn lookup_or_wait_unblocks_immediately_on_stop_waiting() {
        let table = std::sync::Arc::new(FlowTable::default());
        table.enable_wait();
        let stopper = std::sync::Arc::clone(&table);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            stopper.stop_waiting();
        });
        let started = std::time::Instant::now();
        assert_eq!(
            table.lookup_or_wait(&key(), std::time::Duration::from_secs(2)),
            None
        );
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
        handle.join().expect("stopper thread");
    }

    #[test]
    fn enumerates_live_windows_tcp_socket_with_correct_port_endianness() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let client = std::net::TcpStream::connect(addr).expect("connect");
        let local_port = client.local_addr().expect("client addr").port();
        let buf = super::read_extended_tcp_table(u32::from(super::AF_INET)).expect("tcp4 table");
        let ptr = buf.as_ptr().cast::<super::MIB_TCPTABLE_OWNER_PID>();
        let count = unsafe { (*ptr).dwNumEntries as usize };
        let rows = unsafe { std::slice::from_raw_parts((*ptr).table.as_ptr(), count) };
        let found = rows.iter().any(|row| {
            row.dwOwningPid == std::process::id()
                && super::decode_tcp_port(row.dwLocalPort) == local_port
                && super::decode_tcp_port(row.dwRemotePort) == addr.port()
        });
        assert!(found, "expected live TCP socket in GetExtendedTcpTable");
    }

    #[test]
    fn new_socket_connect_replaces_stale_preexisting_entry() {
        let table = FlowTable::default();
        let direct_reused = key();
        table.insert_preexisting(direct_reused, Disposition::Direct);
        table.insert_socket_connect(direct_reused, Disposition::Tunnel, true);
        assert_eq!(table.lookup(&direct_reused), Some(Disposition::Tunnel));

        let mut discard_reused = key();
        discard_reused.local_port = 51_001;
        table.insert_preexisting(discard_reused, Disposition::Discard);
        table.insert_socket_connect(discard_reused, Disposition::Tunnel, true);
        assert_eq!(table.lookup(&discard_reused), Some(Disposition::Tunnel));
    }

    #[test]
    fn lookup_or_wait_handles_high_concurrent_flow_creation_without_starvation() {
        let table = std::sync::Arc::new(FlowTable::default());
        table.enable_wait();
        let total = 200_u16;
        let writer_table = std::sync::Arc::clone(&table);
        let base = key();
        let writer = std::thread::spawn(move || {
            for offset in 0..total {
                let mut flow = base;
                flow.local_port = 40_000 + offset;
                writer_table.insert_socket_connect(flow, Disposition::Tunnel, true);
            }
        });
        let started = std::time::Instant::now();
        for offset in 0..total {
            let mut flow = base;
            flow.local_port = 40_000 + offset;
            assert_eq!(
                table.lookup_or_wait(&flow, std::time::Duration::from_millis(500)),
                Some(Disposition::Tunnel)
            );
        }
        writer.join().expect("writer thread");
        assert!(started.elapsed() < std::time::Duration::from_millis(500));
    }
}
