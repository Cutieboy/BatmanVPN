//! What a Mousality client remembers between connections to a server: which
//! camouflage names recently failed, and whether the server answers only
//! version 1.
//!
//! A name that the user's network blocks or throttles used to fail one random
//! connection in every pool-size; a server still on a version 1 agent sends
//! every version 2 hello to the real site. Each now costs one failed attempt.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{LazyLock, Mutex, MutexGuard, PoisonError},
    time::{Duration, Instant},
};

use mousevpn_mousality::{VERSION_1, VERSION_2};

/// How long a name that failed is passed over while other names remain.
const NAME_PENALTY: Duration = Duration::from_secs(10 * 60);
/// How long what a version fallback taught about a server is kept.
const VERSION_MEMORY: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Learned {
    /// Only version 1 authenticated.
    Legacy,
    /// Version 1 failed too, so another fallback would only add a connection;
    /// typically the device clock is off or the key is wrong.
    NoFallback,
}

#[derive(Default)]
struct Memory {
    failed_names: HashMap<(SocketAddr, String), Instant>,
    versions: HashMap<SocketAddr, (Learned, Instant)>,
}

static MEMORY: LazyLock<Mutex<Memory>> = LazyLock::new(Mutex::default);

fn memory() -> MutexGuard<'static, Memory> {
    MEMORY.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Memory {
    fn expire(&mut self, now: Instant) {
        self.failed_names
            .retain(|_, failed| now.duration_since(*failed) < NAME_PENALTY);
        self.versions
            .retain(|_, (_, learned)| now.duration_since(*learned) < VERSION_MEMORY);
    }

    /// A uniformly random name among those that have not failed recently,
    /// or among all of them once every name has.
    fn choose<'a>(&self, endpoint: SocketAddr, names: &[&'a str]) -> &'a str {
        let working: Vec<_> = names
            .iter()
            .copied()
            .filter(|name| {
                !self
                    .failed_names
                    .contains_key(&(endpoint, (*name).to_owned()))
            })
            .collect();
        let candidates = if working.is_empty() { names } else { &working };
        random_index(candidates.len()).map_or("", |index| candidates[index])
    }

    fn succeeded(&mut self, endpoint: SocketAddr, name: &str, version: u8) {
        self.failed_names.remove(&(endpoint, name.to_owned()));
        if version == VERSION_2 {
            self.versions.remove(&endpoint);
        }
    }

    fn failed(&mut self, endpoint: SocketAddr, name: &str, now: Instant) {
        self.failed_names.insert((endpoint, name.to_owned()), now);
    }
}

/// Rejection sampling gives every index the same probability.
fn random_index(length: usize) -> Option<usize> {
    if length == 0 || length > 256 {
        return (length > 0).then_some(0);
    }
    let limit = 256 - 256 % length;
    loop {
        let mut random = [0; 1];
        if getrandom::fill(&mut random).is_err() {
            return Some(0);
        }
        let value = usize::from(random[0]);
        if value < limit {
            return Some(value % length);
        }
    }
}

/// Opens one Mousality connection to `endpoint` through
/// `attempt(server_name, version)`, choosing the name from `names` and the
/// protocol version from what earlier connections showed.
///
/// When a version 2 attempt fails with an error that `unauthenticated`
/// recognises, the same name is tried once more with version 1, and the
/// outcome is remembered for the server. Any failure makes the name less
/// likely to be chosen next time.
///
/// # Errors
///
/// Returns the first attempt's error when no attempt succeeds.
pub fn connect_pooled<T, E>(
    endpoint: SocketAddr,
    names: &[&str],
    mut attempt: impl FnMut(&str, u8) -> Result<T, E>,
    unauthenticated: impl Fn(&E) -> bool,
) -> Result<T, E> {
    let now = Instant::now();
    let (name, learned) = {
        let mut memory = memory();
        memory.expire(now);
        let learned = memory.versions.get(&endpoint).map(|(learned, _)| *learned);
        (memory.choose(endpoint, names), learned)
    };
    let version = if learned == Some(Learned::Legacy) {
        VERSION_1
    } else {
        VERSION_2
    };
    match attempt(name, version) {
        Ok(connected) => {
            memory().succeeded(endpoint, name, version);
            Ok(connected)
        }
        Err(error) if version == VERSION_2 && learned.is_none() && unauthenticated(&error) => {
            let fallback = attempt(name, VERSION_1);
            let mut memory = memory();
            if let Ok(connected) = fallback {
                memory
                    .versions
                    .insert(endpoint, (Learned::Legacy, Instant::now()));
                memory.succeeded(endpoint, name, VERSION_1);
                return Ok(connected);
            }
            memory.versions.insert(endpoint, (Learned::NoFallback, now));
            memory.failed(endpoint, name, now);
            Err(error)
        }
        Err(error) => {
            memory().failed(endpoint, name, now);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashSet};

    use super::*;

    // The memory is process-wide, so every test uses its own endpoint.
    fn endpoint(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    #[test]
    fn a_failed_name_is_passed_over_until_it_works_again() {
        let server = endpoint(1);
        let names = ["a.example", "b.example", "c.example"];
        let bad = RefCell::new(None);
        // Fail whichever name comes first.
        let _ = connect_pooled(
            server,
            &names,
            |name, _| {
                *bad.borrow_mut() = Some(name.to_owned());
                Err::<(), _>(())
            },
            |()| false,
        );
        let bad = bad.into_inner().unwrap();
        for _ in 0..64 {
            let chosen = connect_pooled(
                server,
                &names,
                |name, _| Ok::<_, ()>(name.to_owned()),
                |()| false,
            )
            .unwrap();
            assert_ne!(chosen, bad);
        }
    }

    #[test]
    fn every_name_stays_in_use_once_all_have_failed() {
        let server = endpoint(2);
        let names = ["a.example", "b.example"];
        for _ in 0..32 {
            let _ = connect_pooled(server, &names, |_, _| Err::<(), _>(()), |()| false);
        }
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let _ = connect_pooled(
                server,
                &names,
                |name, _| {
                    seen.insert(name.to_owned());
                    Err::<(), _>(())
                },
                |()| false,
            );
        }
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn a_version_1_server_is_remembered_after_one_fallback() {
        let server = endpoint(3);
        let versions = RefCell::new(Vec::new());
        let legacy_server = |_: &str, version: u8| {
            versions.borrow_mut().push(version);
            if version == VERSION_1 {
                Ok(())
            } else {
                Err("unauthenticated")
            }
        };
        let unauthenticated = |error: &&str| *error == "unauthenticated";
        connect_pooled(server, &["a.example"], legacy_server, unauthenticated).unwrap();
        connect_pooled(server, &["a.example"], legacy_server, unauthenticated).unwrap();
        assert_eq!(*versions.borrow(), [VERSION_2, VERSION_1, VERSION_1]);
    }

    #[test]
    fn a_fallback_that_also_fails_is_not_repeated() {
        let server = endpoint(4);
        let attempts = RefCell::new(0);
        let refusing = |_: &str, _: u8| {
            *attempts.borrow_mut() += 1;
            Err::<(), _>("unauthenticated")
        };
        let unauthenticated = |error: &&str| *error == "unauthenticated";
        assert!(connect_pooled(server, &["a.example"], refusing, unauthenticated).is_err());
        assert!(connect_pooled(server, &["a.example"], refusing, unauthenticated).is_err());
        assert_eq!(*attempts.borrow(), 3);
        // Once version 2 works again, a later failure may fall back again.
        connect_pooled(
            server,
            &["a.example"],
            |_, _| Ok::<_, &str>(()),
            unauthenticated,
        )
        .unwrap();
        assert!(!memory().versions.contains_key(&server));
    }
}
