use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicI64, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread::JoinHandle,
};

use anyhow::{anyhow, Result};
use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::SessionParameters;
use mousevpn_transport::UdpTransport;

pub(crate) struct PendingSession {
    pub transport: UdpTransport,
    pub plane: TunnelDataPlane,
    pub config: ValidatedClientConfig,
    pub parameters: SessionParameters,
}

struct RunningSession {
    stopping: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    worker: JoinHandle<()>,
}

enum Entry {
    Pending(Box<PendingSession>),
    Running(RunningSession),
}

static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static REGISTRY: OnceLock<Mutex<HashMap<i64, Entry>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<i64, Entry>> {
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn insert_pending(session: PendingSession) -> Result<i64> {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    registry()
        .lock()
        .map_err(|_| anyhow!("session registry is poisoned"))?
        .insert(handle, Entry::Pending(Box::new(session)));
    Ok(handle)
}

pub(crate) fn take_pending(handle: i64) -> Result<PendingSession> {
    let entry = registry()
        .lock()
        .map_err(|_| anyhow!("session registry is poisoned"))?
        .remove(&handle)
        .ok_or_else(|| anyhow!("unknown session handle"))?;
    match entry {
        Entry::Pending(session) => Ok(*session),
        Entry::Running(session) => {
            registry()
                .lock()
                .ok()
                .map(|mut map| map.insert(handle, Entry::Running(session)));
            Err(anyhow!("session is already running"))
        }
    }
}

pub(crate) fn insert_running(
    handle: i64,
    stopping: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    worker: JoinHandle<()>,
) -> Result<()> {
    registry()
        .lock()
        .map_err(|_| anyhow!("session registry is poisoned"))?
        .insert(
            handle,
            Entry::Running(RunningSession {
                stopping,
                alive,
                worker,
            }),
        );
    Ok(())
}

pub(crate) fn status(handle: i64) -> &'static str {
    let Ok(map) = registry().lock() else {
        return "error";
    };
    match map.get(&handle) {
        Some(Entry::Pending(_)) => "prepared",
        Some(Entry::Running(session)) if session.alive.load(Ordering::Relaxed) => "running",
        Some(Entry::Running(_)) | None => "stopped",
    }
}

pub(crate) fn stop(handle: i64) {
    let entry = registry()
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&handle));
    if let Some(Entry::Running(session)) = entry {
        session.stopping.store(true, Ordering::Relaxed);
        let _ = session.worker.join();
    }
}
