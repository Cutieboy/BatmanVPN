use std::time::{Duration, Instant};

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const RECONNECT_RETRY_INTERVAL: Duration = Duration::from_secs(10);

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
}

impl Liveness {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            peer_activity: now,
            heartbeat: now,
            retry: None,
        }
    }

    pub(crate) fn action(&self, now: Instant) -> Action {
        if now.duration_since(self.peer_activity) >= SESSION_TIMEOUT
            && self
                .retry
                .is_none_or(|last| now.duration_since(last) >= RECONNECT_RETRY_INTERVAL)
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
    }

    pub(crate) fn reconnect_attempted(&mut self, now: Instant) {
        self.retry = Some(now);
    }

    pub(crate) fn connection_lost(&mut self, now: Instant) {
        self.peer_activity = now.checked_sub(SESSION_TIMEOUT).unwrap_or(now);
        self.retry = None;
    }

    pub(crate) fn reconnected(&mut self, now: Instant) {
        self.peer_activity = now;
        self.heartbeat = now;
        self.retry = None;
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, Liveness};
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
            state.action(start + Duration::from_secs(30)),
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
}
