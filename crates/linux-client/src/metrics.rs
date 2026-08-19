use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[derive(Default)]
pub(crate) struct RuntimeMetrics {
    outgoing_packets: AtomicU64,
    incoming_packets: AtomicU64,
    outgoing_drops: AtomicU64,
    keepalives_sent: AtomicU64,
    keepalive_responses: AtomicU64,
    keepalive_timeouts: AtomicU64,
    reconnects: AtomicU64,
    reconnect_failures: AtomicU64,
    peer_unreachable: AtomicU64,
    migrations: AtomicU64,
    keepalive_rtt_total_ms: AtomicU64,
    keepalive_rtt_samples: AtomicU64,
    last_keepalive_rtt_ms: AtomicU64,
    max_keepalive_rtt_ms: AtomicU64,
}

impl RuntimeMetrics {
    pub(crate) fn record_outgoing_packets(&self, count: usize) {
        self.outgoing_packets
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_incoming_packet(&self) {
        self.incoming_packets.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_outgoing_drops(&self, count: usize) {
        self.outgoing_drops
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_keepalive_sent(&self) {
        self.keepalives_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_keepalive_response(&self, elapsed: Duration) {
        let milliseconds = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
        self.keepalive_responses.fetch_add(1, Ordering::Relaxed);
        self.keepalive_rtt_total_ms
            .fetch_add(milliseconds, Ordering::Relaxed);
        self.keepalive_rtt_samples.fetch_add(1, Ordering::Relaxed);
        self.last_keepalive_rtt_ms
            .store(milliseconds, Ordering::Relaxed);
        self.max_keepalive_rtt_ms
            .fetch_max(milliseconds, Ordering::Relaxed);
    }

    pub(crate) fn record_keepalive_timeouts(&self, count: usize) {
        self.keepalive_timeouts
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub(crate) fn record_reconnect(&self) {
        self.reconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_reconnect_failure(&self) {
        self.reconnect_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_peer_unreachable(&self) {
        self.peer_unreachable.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_migration(&self) {
        self.migrations.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn emit(&self, uptime: Duration) {
        eprintln!(
            concat!(
                "MOUSEVPN_METRICS={{",
                "\"uptimeSeconds\":{},",
                "\"outgoingPackets\":{},",
                "\"incomingPackets\":{},",
                "\"outgoingDrops\":{},",
                "\"keepalivesSent\":{},",
                "\"keepaliveResponses\":{},",
                "\"keepaliveTimeouts\":{},",
                "\"reconnects\":{},",
                "\"reconnectFailures\":{},",
                "\"peerUnreachable\":{},",
                "\"migrations\":{},",
                "\"keepaliveRttTotalMs\":{},",
                "\"keepaliveRttSamples\":{},",
                "\"lastKeepaliveRttMs\":{},",
                "\"maxKeepaliveRttMs\":{}",
                "}}"
            ),
            uptime.as_secs(),
            self.outgoing_packets.load(Ordering::Relaxed),
            self.incoming_packets.load(Ordering::Relaxed),
            self.outgoing_drops.load(Ordering::Relaxed),
            self.keepalives_sent.load(Ordering::Relaxed),
            self.keepalive_responses.load(Ordering::Relaxed),
            self.keepalive_timeouts.load(Ordering::Relaxed),
            self.reconnects.load(Ordering::Relaxed),
            self.reconnect_failures.load(Ordering::Relaxed),
            self.peer_unreachable.load(Ordering::Relaxed),
            self.migrations.load(Ordering::Relaxed),
            self.keepalive_rtt_total_ms.load(Ordering::Relaxed),
            self.keepalive_rtt_samples.load(Ordering::Relaxed),
            self.last_keepalive_rtt_ms.load(Ordering::Relaxed),
            self.max_keepalive_rtt_ms.load(Ordering::Relaxed),
        );
    }

    #[cfg(test)]
    pub(crate) fn keepalive_timeouts(&self) -> u64 {
        self.keepalive_timeouts.load(Ordering::Relaxed)
    }
}
