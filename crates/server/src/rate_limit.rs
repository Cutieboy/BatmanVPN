use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

struct Counter {
    started: Instant,
    attempts: u32,
}

pub(crate) struct HandshakeLimiter {
    clients: HashMap<IpAddr, Counter>,
    maximum_attempts: u32,
    window: Duration,
}

impl HandshakeLimiter {
    pub fn new(maximum_attempts: u32, window: Duration) -> Self {
        Self {
            clients: HashMap::new(),
            maximum_attempts,
            window,
        }
    }

    pub fn allow(&mut self, address: IpAddr) -> bool {
        self.allow_at(address, Instant::now())
    }

    fn allow_at(&mut self, address: IpAddr, now: Instant) -> bool {
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
}
