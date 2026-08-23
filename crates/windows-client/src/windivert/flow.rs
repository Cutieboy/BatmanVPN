#![doc = "Tracks which process owns each network flow, using the WinDivert flow layer."]

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    thread,
};

use windows_sys::Win32::{
    Foundation::CloseHandle,
    System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

use super::{Address, Handle, Library, EVENT_FLOW_DELETED, EVENT_FLOW_ESTABLISHED, FLAG_RECV_ONLY,
    FLAG_SNIFF, LAYER_FLOW};
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
}

/// The decisions taken so far, shared with the packet path.
///
/// Reads vastly outnumber writes: every diverted packet consults the table,
/// while entries only change when a flow is created or torn down.
#[derive(Default)]
pub(crate) struct FlowTable {
    entries: RwLock<HashMap<FlowKey, Disposition>>,
}

impl FlowTable {
    pub(crate) fn lookup(&self, key: &FlowKey) -> Option<Disposition> {
        self.entries
            .read()
            .ok()
            .and_then(|entries| entries.get(key).copied())
    }

    fn insert(&self, key: FlowKey, disposition: Disposition) {
        if let Ok(mut entries) = self.entries.write() {
            entries.insert(key, disposition);
        }
    }

    fn remove(&self, key: &FlowKey) {
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(key);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.read().map_or(0, |entries| entries.len())
    }
}

/// Watches flow establishment and classifies each flow against the policy.
///
/// The handle is opened in sniffing mode: this layer only observes, and must
/// never delay or drop a connection. A stall here would be indistinguishable
/// from a broken network.
pub(crate) struct FlowWatcher {
    handle: Arc<Handle>,
    table: Arc<FlowTable>,
    stopping: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FlowWatcher {
    /// Starts watching flows for `policy`.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Platform`] when the WinDivert flow handle cannot
    /// be opened.
    pub(crate) fn start(
        library: &Arc<Library>,
        policy: &AppRoutingPolicy,
    ) -> Result<Self, ClientError> {
        // Priority is irrelevant for a sniffing handle, but a distinct value
        // keeps MouseVPN identifiable in `windivertctl` output.
        let handle = Arc::new(library.open("true", LAYER_FLOW, 0, FLAG_SNIFF | FLAG_RECV_ONLY)?);
        let table = Arc::new(FlowTable::default());
        let stopping = Arc::new(AtomicBool::new(false));
        let classifier = Classifier::new(policy);

        let thread = thread::Builder::new()
            .name("mousevpn-flow-watcher".to_owned())
            .spawn({
                let handle = Arc::clone(&handle);
                let table = Arc::clone(&table);
                let stopping = Arc::clone(&stopping);
                move || run(&handle, &table, &classifier, &stopping)
            })
            .map_err(|error| {
                ClientError::Platform(format!("failed to start the flow watcher: {error}"))
            })?;

        Ok(Self {
            handle,
            table,
            stopping,
            thread: Some(thread),
        })
    }

    pub(crate) fn table(&self) -> Arc<FlowTable> {
        Arc::clone(&self.table)
    }
}

impl Drop for FlowWatcher {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        // The watcher parks inside `recv`, so it only observes `stopping`
        // after the shutdown drains the queue and wakes it.
        self.handle.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn run(
    handle: &Handle,
    table: &FlowTable,
    classifier: &Classifier,
    stopping: &AtomicBool,
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
                // tear down a working tunnel.
                eprintln!("MOUSEVPN_FLOW_WARNING={error}");
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
            EVENT_FLOW_ESTABLISHED => {
                table.insert(key, classifier.classify(flow.process_id));
            }
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
/// and whether the address layout this module assumes is the one WinDivert
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
pub fn probe(seconds: u64) -> Result<(), ClientError> {
    let library = Library::load()?;
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
        let path = process_path(flow.process_id)
            .map_or_else(|| "<unknown>".to_owned(), |path| path.display().to_string());
        match decoded {
            Some(key) => println!(
                "{event:<11} pid={:<6} proto={:<3} {}:{} -> {}:{}  {path}",
                flow.process_id,
                key.protocol,
                key.local,
                key.local_port,
                key.remote,
                key.remote_port
            ),
            None => println!(
                "{event:<11} pid={:<6} proto={:<3} UNDECODED ipv6={} local={:08x?} remote={:08x?}  {path}",
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

/// Decides where a process's traffic belongs, caching the answer per PID.
///
/// Resolving an executable path costs a process open and a kernel query. The
/// same PID reappears for every flow a busy application creates, so the answer
/// is memoised. PIDs are recycled by Windows, but only after the process exits,
/// and a stale entry can at worst misroute flows of a process that inherited
/// the number — bounded by clearing the cache on reconnect.
struct Classifier {
    mode: AppRoutingMode,
    apps: Vec<PathBuf>,
    cache: Mutex<HashMap<u32, bool>>,
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

    fn classify(&self, process_id: u32) -> Disposition {
        let listed = self.is_listed(process_id);
        match (self.mode, listed) {
            // Selected applications bypass the tunnel; everything else uses it.
            (AppRoutingMode::Exclude, true) | (AppRoutingMode::Include, false) => {
                Disposition::Direct
            }
            (AppRoutingMode::Exclude, false) | (AppRoutingMode::Include, true) => {
                Disposition::Tunnel
            }
        }
    }

    fn is_listed(&self, process_id: u32) -> bool {
        if let Ok(cache) = self.cache.lock() {
            if let Some(listed) = cache.get(&process_id) {
                return *listed;
            }
        }
        let listed = process_path(process_id).is_some_and(|path| self.matches(&path));
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(process_id, listed);
        }
        listed
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

/// Resolves the executable backing a process id.
///
/// Returns `None` for processes that have already exited or that the helper
/// cannot open, which includes protected system processes.
fn process_path(process_id: u32) -> Option<PathBuf> {
    // SAFETY: a failed open returns null, which is checked before use.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return None;
    }
    let mut buffer = [0_u16; 32_768];
    let mut length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    // SAFETY: `length` describes `buffer`, and the handle is valid until the
    // close below.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process,
            // `PROCESS_NAME_WIN32`: the Win32 path, matching the paths the UI
            // stores. The native NT form would never compare equal to them.
            0,
            buffer.as_mut_ptr(),
            &raw mut length,
        )
    };
    // SAFETY: the handle came from `OpenProcess` and is closed exactly once.
    unsafe {
        CloseHandle(process);
    }
    if ok == 0 {
        return None;
    }
    let path = String::from_utf16_lossy(&buffer[..length as usize]);
    Some(normalize_windows_path(Path::new(&path)))
}

/// Builds a flow key from the WinDivert flow data.
///
/// WinDivert reports flow addresses as IPv4-mapped IPv6 in its host-order
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

#[cfg(test)]
mod tests {
    use super::{
        decode_address, paths_equal, Disposition, FlowKey, FlowTable,
    };
    use std::{
        net::{IpAddr, Ipv4Addr},
        path::Path,
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
    fn tracks_and_forgets_flows() {
        let table = FlowTable::default();
        assert_eq!(table.lookup(&key()), None);
        table.insert(key(), Disposition::Direct);
        assert_eq!(table.lookup(&key()), Some(Disposition::Direct));
        table.remove(&key());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn compares_executable_paths_case_insensitively() {
        assert!(paths_equal(
            Path::new(r"C:\Apps\Browser.exe"),
            Path::new(r"c:\apps\browser.EXE")
        ));
    }
}
