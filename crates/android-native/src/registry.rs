use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, Ordering},
        Mutex, OnceLock,
    },
};

use anyhow::{anyhow, Result};
use mousevpn_config::ValidatedClientConfig;
use mousevpn_data_plane::TunnelDataPlane;
use mousevpn_protocol::SessionParameters;
use mousevpn_transport::UdpTransport;

use crate::session::SpawnedSession;

pub(crate) struct PendingSession {
    pub transport: UdpTransport,
    pub plane: TunnelDataPlane,
    pub config: ValidatedClientConfig,
    pub parameters: SessionParameters,
    pub protector: crate::socket_protector::SocketProtector,
}

enum Entry {
    Pending(Box<PendingSession>),
    Running(SpawnedSession),
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

pub(crate) fn insert_running(handle: i64, session: SpawnedSession) -> Result<()> {
    registry()
        .lock()
        .map_err(|_| anyhow!("session registry is poisoned"))?
        .insert(handle, Entry::Running(session));
    Ok(())
}

pub(crate) fn network_changed(handle: i64) {
    let Ok(map) = registry().lock() else {
        return;
    };
    if let Some(Entry::Running(session)) = map.get(&handle) {
        session.reconnect_requested.store(true, Ordering::Release);
        crate::session::signal(&session.wake);
    }
}

pub(crate) fn status(handle: i64) -> &'static str {
    let Ok(map) = registry().lock() else {
        return "error";
    };
    match map.get(&handle) {
        Some(Entry::Pending(_)) => "prepared",
        Some(Entry::Running(session)) if session.parameters_changed.load(Ordering::Acquire) => {
            "parameters-changed"
        }
        Some(Entry::Running(session)) if session.alive.load(Ordering::Relaxed) => "running",
        Some(Entry::Running(_)) | None => "stopped",
    }
}

pub(crate) fn metrics(handle: i64) -> String {
    let Ok(map) = registry().lock() else {
        return "{}".to_owned();
    };
    let Some(Entry::Running(session)) = map.get(&handle) else {
        return "{}".to_owned();
    };
    let metrics = &session.metrics;
    serde_json::json!({
        "packetsSent": metrics.packets_sent.load(Ordering::Relaxed),
        "bytesSent": metrics.bytes_sent.load(Ordering::Relaxed),
        "packetsReceived": metrics.packets_received.load(Ordering::Relaxed),
        "bytesReceived": metrics.bytes_received.load(Ordering::Relaxed),
        "tunDrops": metrics.tun_drops.load(Ordering::Relaxed),
        "udpSendDrops": metrics.udp_send_drops.load(Ordering::Relaxed),
        "reconnects": metrics.reconnects.load(Ordering::Relaxed),
        "lastReconnectMs": metrics.last_reconnect_ms.load(Ordering::Relaxed),
    })
    .to_string()
}

pub(crate) fn stop(handle: i64) {
    let entry = registry()
        .lock()
        .ok()
        .and_then(|mut map| map.remove(&handle));
    if let Some(Entry::Running(session)) = entry {
        session.stopping.store(true, Ordering::Relaxed);
        crate::session::signal(&session.wake);
        let _ = session.worker.join();
    }
}
