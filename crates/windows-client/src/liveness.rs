#![cfg_attr(not(windows), allow(dead_code))]

use std::time::{Duration, Instant};

// Windows does not consistently surface an ICMP error when the UDP peer goes
// away. Three missed lightweight probes bound passive recovery to nine seconds
// without treating one delayed response as a dead session.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(3);
const SESSION_TIMEOUT: Duration = Duration::from_secs(9);
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
        self.lost = false;
    }

    pub(crate) fn reconnect_attempted(&mut self, now: Instant) {
        self.retry = Some(now);
        self.backoff = (self.backoff * 2).min(MAX_RECONNECT_BACKOFF);
    }

    pub(crate) fn connection_lost(&mut self, now: Instant) {
        if !self.lost {
            self.peer_activity = now.checked_sub(SESSION_TIMEOUT).unwrap_or(now);
            self.retry = None;
            self.lost = true;
        }
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
        assert_eq!(state.action(start + Duration::from_secs(2)), Action::None);
        assert_eq!(
            state.action(start + Duration::from_secs(3)),
            Action::Keepalive
        );
        state.keepalive_sent(start + Duration::from_secs(3));
        assert_eq!(
            state.action(start + Duration::from_secs(9)),
            Action::Reconnect
        );
    }

    #[test]
    fn backs_off_reconnect_attempts() {
        let start = Instant::now();
        let mut state = Liveness::new(start);
        state.connection_lost(start);
        state.reconnect_attempted(start);
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
    }

    #[test]
    fn success_resets_backoff() {
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
        state.connection_lost(start + Duration::from_millis(500));
        assert_eq!(state.action(start + Duration::from_secs(1)), Action::None);
        assert_eq!(
            state.action(start + Duration::from_secs(2)),
            Action::Reconnect
        );
    }
}
