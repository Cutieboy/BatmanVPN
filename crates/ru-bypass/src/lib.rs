#![doc = "Russian IPv4 networks that `MouseVPN` clients can route around the tunnel."]
//!
//! Russian services increasingly refuse, or report, connections that arrive
//! from VPN servers. Sending traffic for Russian networks straight over the
//! physical link keeps those services on the user's own address and keeps the
//! server addresses out of their lists. Everything else still uses the tunnel.
//!
//! The list is compiled in from `data/ru-ipv4.txt`, which
//! `scripts/update-ru-prefixes.py` regenerates from RIPE NCC statistics. It is
//! sorted and its prefixes never overlap, so lookups are a binary search.

use std::{fmt, net::Ipv4Addr, str::FromStr, sync::OnceLock};

const RUSSIA_IPV4: &str = include_str!("../data/ru-ipv4.txt");

/// One IPv4 network in CIDR form, with no host bits set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ipv4Prefix {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Prefix {
    /// Builds a prefix, refusing a length above 32 or an address with host bits.
    #[must_use]
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        let prefix = Self {
            address,
            prefix_len,
        };
        (prefix_len <= 32 && u32::from(address) & !prefix.mask() == 0).then_some(prefix)
    }

    #[must_use]
    pub const fn address(self) -> Ipv4Addr {
        self.address
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// The network mask, e.g. `255.255.252.0` for a `/22`.
    #[must_use]
    pub fn netmask(self) -> Ipv4Addr {
        Ipv4Addr::from(self.mask())
    }

    #[must_use]
    pub fn contains(self, address: Ipv4Addr) -> bool {
        u32::from(address) & self.mask() == u32::from(self.address)
    }

    fn first(self) -> u32 {
        u32::from(self.address)
    }

    fn last(self) -> u32 {
        self.first() | !self.mask()
    }

    fn mask(self) -> u32 {
        u32::MAX
            .checked_shl(32 - u32::from(self.prefix_len))
            .unwrap_or(0)
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix_len)
    }
}

/// The text was not `a.b.c.d/len` with the host bits clear.
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidPrefix;

impl fmt::Display for InvalidPrefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid IPv4 prefix")
    }
}

impl std::error::Error for InvalidPrefix {}

impl FromStr for Ipv4Prefix {
    type Err = InvalidPrefix;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix_len) = value.split_once('/').ok_or(InvalidPrefix)?;
        let address = address.parse().map_err(|_| InvalidPrefix)?;
        let prefix_len = prefix_len.parse().map_err(|_| InvalidPrefix)?;
        Self::new(address, prefix_len).ok_or(InvalidPrefix)
    }
}

/// Every Russian IPv4 prefix, sorted by address and never overlapping.
#[must_use]
pub fn russia() -> &'static [Ipv4Prefix] {
    static PREFIXES: OnceLock<Vec<Ipv4Prefix>> = OnceLock::new();
    PREFIXES.get_or_init(|| {
        let mut prefixes = data_lines(RUSSIA_IPV4)
            .filter_map(|line| line.parse().ok())
            .collect::<Vec<Ipv4Prefix>>();
        prefixes.sort_unstable();
        prefixes
    })
}

/// Reports whether the address belongs to a Russian network.
#[must_use]
pub fn is_russian(address: Ipv4Addr) -> bool {
    russian_prefix(address).is_some()
}

/// Returns the Russian network the address belongs to, if any.
#[must_use]
pub fn russian_prefix(address: Ipv4Addr) -> Option<Ipv4Prefix> {
    let prefixes = russia();
    let value = u32::from(address);
    // The last prefix starting at or before the address is the only candidate.
    let index = prefixes.partition_point(|prefix| prefix.first() <= value);
    index
        .checked_sub(1)
        .map(|index| prefixes[index])
        .filter(|prefix| prefix.contains(address))
}

/// Returns the prefixes that together cover exactly the IPv4 space the input
/// leaves uncovered.
///
/// `prefixes` must be sorted and must not overlap, as [`russia`] is. Platforms
/// that can only include routes, never exclude them, route the complement into
/// the tunnel instead of the default route.
#[must_use]
pub fn complement(prefixes: &[Ipv4Prefix]) -> Vec<Ipv4Prefix> {
    let mut result = Vec::new();
    let mut next = 0_u64;
    for prefix in prefixes {
        let first = u64::from(prefix.first());
        if first > next {
            push_range(next, first - 1, &mut result);
        }
        next = next.max(u64::from(prefix.last()) + 1);
    }
    if u32::try_from(next).is_ok() {
        push_range(next, u64::from(u32::MAX), &mut result);
    }
    result
}

/// Appends the fewest prefixes covering `first..=last`.
fn push_range(mut first: u64, last: u64, result: &mut Vec<Ipv4Prefix>) {
    while first <= last {
        // The largest block that both starts aligned at `first` and still fits.
        let alignment = if first == 0 {
            32
        } else {
            first.trailing_zeros().min(32)
        };
        let fits = (last - first + 1).ilog2();
        let host_bits = alignment.min(fits);
        let address = u32::try_from(first).unwrap_or(u32::MAX);
        let prefix_len = u8::try_from(32 - host_bits).unwrap_or(32);
        result.push(Ipv4Prefix {
            address: Ipv4Addr::from(address),
            prefix_len,
        });
        first += 1_u64 << host_bits;
    }
}

fn data_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{complement, data_lines, is_russian, russia, Ipv4Prefix, RUSSIA_IPV4};

    fn prefix(value: &str) -> Ipv4Prefix {
        value.parse().unwrap()
    }

    #[test]
    fn every_listed_line_parses() {
        assert_eq!(data_lines(RUSSIA_IPV4).count(), russia().len());
        assert!(russia().len() > 1_000);
    }

    #[test]
    fn list_is_sorted_and_disjoint() {
        for pair in russia().windows(2) {
            assert!(
                pair[0].last() < pair[1].first(),
                "{} overlaps {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn list_never_claims_private_or_special_space() {
        for special in [
            "0.0.0.0/8",
            "10.0.0.0/8",
            "100.64.0.0/10",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "224.0.0.0/3",
        ] {
            let special = prefix(special);
            assert!(
                russia().iter().all(
                    |listed| listed.last() < special.first() || listed.first() > special.last()
                ),
                "{special} is listed"
            );
        }
    }

    #[test]
    fn keeps_russian_anycast_and_ddos_protection_networks() {
        // Geolocation databases place these abroad. Losing them sends the
        // sites behind them through the tunnel, where they report the user
        // as being on a VPN: Rutube (Qrator, 178.248.232.0/21) did in 0.2.5.
        for (address, service) in [
            (Ipv4Addr::new(178, 248, 233, 148), "rutube.ru via Qrator"),
            (Ipv4Addr::new(109, 238, 90, 239), "rutube.ru"),
            (Ipv4Addr::new(89, 248, 230, 8), "static.rutube.ru"),
            (Ipv4Addr::new(77, 88, 8, 8), "Yandex DNS"),
            (Ipv4Addr::new(87, 240, 132, 72), "vk.com"),
            (Ipv4Addr::new(109, 207, 1, 118), "gosuslugi.ru"),
        ] {
            assert!(
                is_russian(address),
                "{service} ({address}) must stay direct"
            );
        }
    }

    #[test]
    fn looks_up_addresses() {
        let first = russia()[0];
        assert!(is_russian(first.address()));
        assert!(is_russian(Ipv4Addr::from(first.last())));
        assert!(!is_russian(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_russian(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_russian(Ipv4Addr::UNSPECIFIED));
        assert!(!is_russian(Ipv4Addr::BROADCAST));
    }

    #[test]
    fn parses_and_rejects_prefixes() {
        assert_eq!(
            prefix("10.1.0.0/16").netmask(),
            Ipv4Addr::new(255, 255, 0, 0)
        );
        assert_eq!(prefix("0.0.0.0/0").netmask(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(prefix("1.2.3.4/32").to_string(), "1.2.3.4/32");
        assert!("10.1.0.1/16".parse::<Ipv4Prefix>().is_err());
        assert!("10.1.0.0/33".parse::<Ipv4Prefix>().is_err());
        assert!("10.1.0.0".parse::<Ipv4Prefix>().is_err());
    }

    #[test]
    fn complement_of_nothing_is_everything() {
        assert_eq!(complement(&[]), vec![prefix("0.0.0.0/0")]);
        assert!(complement(&[prefix("0.0.0.0/0")]).is_empty());
    }

    #[test]
    fn complement_covers_exactly_the_gaps() {
        let holes = [prefix("10.0.0.0/8"), prefix("128.0.0.0/1")];
        assert_eq!(
            complement(&holes),
            vec![
                prefix("0.0.0.0/5"),
                prefix("8.0.0.0/7"),
                prefix("11.0.0.0/8"),
                prefix("12.0.0.0/6"),
                prefix("16.0.0.0/4"),
                prefix("32.0.0.0/3"),
                prefix("64.0.0.0/2"),
            ]
        );
    }

    #[test]
    fn russia_and_its_complement_tile_the_address_space() {
        let mut all = russia().to_vec();
        all.extend(complement(russia()));
        all.sort_unstable();
        let mut next = 0_u64;
        for prefix in &all {
            assert_eq!(
                u64::from(prefix.first()),
                next,
                "gap or overlap at {prefix}"
            );
            next = u64::from(prefix.last()) + 1;
        }
        assert_eq!(next, 1 << 32);
    }
}
