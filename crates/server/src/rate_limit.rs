use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

struct Counter {
    started: Instant,
    attempts: u32,
}

const DEFAULT_MAX_CLIENTS: usize = 65_536;
const CLEANUP_INTERVAL: u64 = 4_096;

pub(crate) struct HandshakeLimiter {
    clients: HashMap<IpAddr, Counter>,
    maximum_attempts: u32,
    window: Duration,
    maximum_clients: usize,
    operations: u64,
    last_cleanup: Option<Instant>,
}

impl HandshakeLimiter {
    pub fn new(maximum_attempts: u32, window: Duration) -> Self {
        Self {
            clients: HashMap::new(),
            maximum_attempts,
            window,
            maximum_clients: DEFAULT_MAX_CLIENTS,
            operations: 0,
            last_cleanup: None,
        }
    }

    pub fn allow(&mut self, address: IpAddr) -> bool {
        self.allow_at(address, Instant::now())
    }

    fn allow_at(&mut self, address: IpAddr, now: Instant) -> bool {
        self.operations = self.operations.wrapping_add(1);
        let cleanup_due = self
            .last_cleanup
            .is_none_or(|last| now.saturating_duration_since(last) >= self.window)
            || self.operations % CLEANUP_INTERVAL == 0;
        if cleanup_due {
            self.clients
                .retain(|_, counter| now.saturating_duration_since(counter.started) < self.window);
            self.last_cleanup = Some(now);
        }

        if !self.clients.contains_key(&address) && self.clients.len() >= self.maximum_clients {
            // Never evict a live counter: otherwise spoofed sources can continuously
            // reset the rate-limit state of legitimate clients. Expired counters are
            // removed by the cleanup above; while the live set is full, reject newcomers.
            return false;
        }

        let counter = self.clients.entry(address).or_insert(Counter {
            started: now,
            attempts: 0,
        });
        if now.duration_since(counter.started) >= self.window {
            counter.started = now;
            counter.attempts = 0;
        }
        if counter.attempts >= self.maximum_attempts {
            return false;
        }
        counter.attempts += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use super::HandshakeLimiter;

    #[test]
    fn limits_and_resets_each_source() {
        let mut limiter = HandshakeLimiter::new(2, Duration::from_secs(60));
        let address = IpAddr::from([192, 0, 2, 1]);
        let started = std::time::Instant::now();

        assert!(limiter.allow_at(address, started));
        assert!(limiter.allow_at(address, started));
        assert!(!limiter.allow_at(address, started));
        assert!(limiter.allow_at(address, started + Duration::from_secs(60)));
    }

    #[test]
    fn expires_unique_sources_and_enforces_hard_cap() {
        let mut limiter = HandshakeLimiter::new(2, Duration::from_secs(60));
        limiter.maximum_clients = 1_024;
        let started = std::time::Instant::now();

        for index in 0..100_000_u32 {
            let address = IpAddr::from(index.to_be_bytes());
            assert_eq!(limiter.allow_at(address, started), index < 1_024);
        }
        assert_eq!(limiter.clients.len(), 1_024);
        assert!(!limiter.allow_at(IpAddr::from([192, 0, 2, 1]), started));
        assert_eq!(limiter.clients.len(), 1_024);

        let later = started + Duration::from_secs(60);
        assert!(limiter.allow_at(IpAddr::from([192, 0, 2, 1]), later));
        assert_eq!(limiter.clients.len(), 1);
    }
}
