use std::time::{Duration, Instant};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Silence after which the session is treated as dead.
///
/// Keepalives go out every 10 s, so 20 s means two missed replies. The earlier
/// 15 s budget tripped on a single late reply and reconnected a link that was
/// merely slow.
const SESSION_TIMEOUT: Duration = Duration::from_secs(20);
/// Delay before the first retry, doubling up to [`MAX_RECONNECT_BACKOFF`].
const MIN_RECONNECT_BACKOFF: Duration = Duration::from_secs(1);
const MAX_RECONNECT_BACKOFF: Duration = Duration::from_secs(16);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    None,
    Keepalive,
    Reconnect,
}

pub(crate) struct Liveness {
    peer_activity: Instant,
    heartbeat: Instant,
    retry: Option<Instant>,
    backoff: Duration,
    /// Set once the peer is known to be gone, cleared by the next packet from
    /// it. Without it every repeated loss notification restarts the backoff.
    lost: bool,
}

impl Liveness {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            peer_activity: now,
            heartbeat: now,
            retry: None,
            backoff: MIN_RECONNECT_BACKOFF,
            lost: false,
        }
    }

    pub(crate) fn action(&self, now: Instant) -> Action {
        if now.duration_since(self.peer_activity) >= SESSION_TIMEOUT
            && self
                .retry
                .is_none_or(|last| now.duration_since(last) >= self.backoff)
        {
            Action::Reconnect
        } else if now.duration_since(self.heartbeat) >= KEEPALIVE_INTERVAL {
            Action::Keepalive
        } else {
            Action::None
        }
    }

    pub(crate) fn keepalive_sent(&mut self, now: Instant) {
        self.heartbeat = now;
    }

    pub(crate) fn packet_received(&mut self, now: Instant) {
        self.peer_activity = now;
        self.retry = None;
        self.backoff = MIN_RECONNECT_BACKOFF;
        self.lost = false;
    }

    pub(crate) fn reconnect_attempted(&mut self, now: Instant) {
        self.retry = Some(now);
        self.backoff = (self.backoff * 2).min(MAX_RECONNECT_BACKOFF);
    }

    /// Polls quickly while the physical network has no default route yet.
    /// Resume commonly reports link-up before `NetworkManager` has restored the
    /// gateway, and that short state should not grow the handshake backoff.
    pub(crate) fn network_unavailable(&mut self, now: Instant) {
        self.retry = Some(now);
        self.backoff = MIN_RECONNECT_BACKOFF;
    }

    /// Reports that the peer is unreachable, which makes the first attempt due
    /// immediately. Repeated reports before the peer answers again are ignored,
    /// so a stream of ICMP errors cannot bypass the backoff.
    pub(crate) fn connection_lost(&mut self, now: Instant) {
        if self.lost {
            return;
        }
        self.peer_activity = now.checked_sub(SESSION_TIMEOUT).unwrap_or(now);
        self.retry = None;
        self.lost = true;
    }

    pub(crate) fn reconnected(&mut self, now: Instant) {
        self.peer_activity = now;
        self.heartbeat = now;
        self.retry = None;
        self.backoff = MIN_RECONNECT_BACKOFF;
        self.lost = false;
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Liveness, MAX_RECONNECT_BACKOFF};
    use std::time::{Duration, Instant};

    #[test]
    fn schedules_keepalive_and_reconnect() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        assert_eq!(state.action(start + Duration::from_secs(9)), Action::None);
        assert_eq!(
            state.action(start + Duration::from_secs(10)),
            Action::Keepalive
        );
        state.keepalive_sent(start + Duration::from_secs(10));
        assert_eq!(
            state.action(start + Duration::from_secs(20)),
            Action::Reconnect
        );
    }

    #[test]
    fn reconnects_immediately_after_explicit_connection_loss() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start + Duration::from_secs(1));
        assert_eq!(
            state.action(start + Duration::from_secs(1)),
            Action::Reconnect
        );
    }

    #[test]
    fn retries_quickly_at_first_then_backs_off() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start);
        state.reconnect_attempted(start);

        // First retry is seconds away, not the old flat ten.
        assert_eq!(state.action(start + Duration::from_secs(1)), Action::None);
        assert_eq!(
            state.action(start + Duration::from_secs(2)),
            Action::Reconnect
        );

        let mut now = start;
        for _ in 0..10 {
            now += Duration::from_secs(60);
            state.reconnect_attempted(now);
        }
        assert_eq!(state.action(now + MAX_RECONNECT_BACKOFF), Action::Reconnect);
        // Still inside the capped backoff: due keepalives may fire, a reconnect
        // may not.
        assert_ne!(
            state.action(now + MAX_RECONNECT_BACKOFF.saturating_sub(Duration::from_secs(1))),
            Action::Reconnect
        );
    }

    #[test]
    fn a_successful_reconnect_resets_the_backoff() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start);
        for step in 0..5 {
            state.reconnect_attempted(start + Duration::from_secs(step * 60));
        }
        state.reconnected(start + Duration::from_secs(600));
        state.connection_lost(start + Duration::from_secs(601));
        state.reconnect_attempted(start + Duration::from_secs(601));
        assert_eq!(
            state.action(start + Duration::from_secs(603)),
            Action::Reconnect
        );
    }

    #[test]
    fn repeated_loss_notifications_do_not_bypass_backoff() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start);
        state.reconnect_attempted(start);
        // A second burst of ICMP errors must not make the retry due again.
        state.connection_lost(start + Duration::from_millis(500));
        assert_eq!(state.action(start + Duration::from_secs(1)), Action::None);
        assert_eq!(
            state.action(start + Duration::from_secs(2)),
            Action::Reconnect
        );
    }

    #[test]
    fn a_packet_from_the_peer_rearms_loss_reporting() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start);
        state.reconnect_attempted(start);
        state.packet_received(start + Duration::from_secs(1));
        // The peer went away again: the next loss is due at once, not in 2 s.
        state.connection_lost(start + Duration::from_secs(2));
        assert_eq!(
            state.action(start + Duration::from_secs(2)),
            Action::Reconnect
        );
    }

    #[test]
    fn a_packet_from_the_peer_resets_the_retry_backoff() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start);
        for step in 0..5 {
            state.reconnect_attempted(start + Duration::from_secs(step * 60));
        }
        state.packet_received(start + Duration::from_secs(600));
        state.connection_lost(start + Duration::from_secs(601));
        state.reconnect_attempted(start + Duration::from_secs(601));
        assert_eq!(
            state.action(start + Duration::from_secs(603)),
            Action::Reconnect
        );
    }

    #[test]
    fn missing_physical_route_is_polled_quickly() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start);
        state.network_unavailable(start);
        assert_eq!(
            state.action(start + Duration::from_millis(999)),
            Action::None
        );
        assert_eq!(
            state.action(start + Duration::from_secs(1)),
            Action::Reconnect
        );
    }
}
