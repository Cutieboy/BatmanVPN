//! Networks a server refuses to carry and tells the client to reach itself.
//!
//! The server, not the client, decides which networks go around the tunnel. A
//! client announces in its handshake payload that it can route networks
//! directly. Only then does the server send it the whole list right after the
//! handshake, and answer any refused packet with the network it belongs to, in
//! case the list was lost or has changed since. The announcement and every
//! list travel inside the Noise encryption: neither is visible on the wire.

use std::{error::Error, fmt, net::Ipv4Addr};

const CAPABILITIES_VERSION: u8 = 1;
/// The client installs networks from [`InnerPacketKind::DirectRoutes`](crate::InnerPacketKind)
/// as direct routes.
const ACCEPTS_DIRECT_ROUTES: u8 = 0x01;

const ROUTE_LEN: usize = 5;
/// Networks in one message, which keeps the datagram well inside 1500 bytes
/// under every wire format.
pub const MAX_DIRECT_ROUTES_PER_MESSAGE: usize = 200;
/// The widest network a hint may move out of the tunnel.
const MIN_DIRECT_PREFIX_LEN: u8 = 8;

/// What a client can do beyond the base protocol, carried in the Noise
/// initiation payload.
///
/// Servers before this field ignore the payload altogether, and an empty
/// payload from an older client decodes as no capabilities.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClientCapabilities {
    pub direct_routes: bool,
}

impl ClientCapabilities {
    #[must_use]
    pub fn encode(self) -> [u8; 2] {
        let mut flags = 0;
        if self.direct_routes {
            flags |= ACCEPTS_DIRECT_ROUTES;
        }
        [CAPABILITIES_VERSION, flags]
    }

    /// Reads the capabilities a client announced. Anything unrecognised,
    /// including a later version, means none: a server must never send what a
    /// client did not ask for.
    #[must_use]
    pub fn decode(input: &[u8]) -> Self {
        match input {
            [CAPABILITIES_VERSION, flags, ..] => Self {
                direct_routes: flags & ACCEPTS_DIRECT_ROUTES != 0,
            },
            _ => Self::default(),
        }
    }
}

/// One IPv4 network the client should reach directly.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DirectRoute {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl DirectRoute {
    /// Builds a network from its first address.
    ///
    /// Returns `None` for a prefix longer than 32 bits or host bits that are
    /// set, which no correct server sends.
    #[must_use]
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Option<Self> {
        if prefix_len > 32 {
            return None;
        }
        let mask = u32::MAX
            .checked_shl(32 - u32::from(prefix_len))
            .unwrap_or(0);
        (u32::from(address) & !mask == 0).then_some(Self {
            address,
            prefix_len,
        })
    }

    #[must_use]
    pub const fn address(self) -> Ipv4Addr {
        self.address
    }

    #[must_use]
    pub const fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Reports whether `address` lies inside this network.
    #[must_use]
    pub fn contains(self, address: Ipv4Addr) -> bool {
        let mask = u32::MAX
            .checked_shl(32 - u32::from(self.prefix_len))
            .unwrap_or(0);
        u32::from(address) & mask == u32::from(self.address)
    }

    /// Reports whether a client may send this network around the tunnel.
    ///
    /// The server is authenticated, but a compromised one must not be able to
    /// pull the client's whole traffic, its own endpoint or local networks out
    /// of the tunnel. A hint is therefore limited to a public network no
    /// larger than a /8 that does not hold `server`.
    #[must_use]
    pub fn is_safe_to_bypass(self, server: Ipv4Addr) -> bool {
        const SPECIAL: [(Ipv4Addr, u8); 9] = [
            (Ipv4Addr::UNSPECIFIED, 8),
            (Ipv4Addr::new(10, 0, 0, 0), 8),
            (Ipv4Addr::new(100, 64, 0, 0), 10),
            (Ipv4Addr::new(127, 0, 0, 0), 8),
            (Ipv4Addr::new(169, 254, 0, 0), 16),
            (Ipv4Addr::new(172, 16, 0, 0), 12),
            (Ipv4Addr::new(192, 168, 0, 0), 16),
            (Ipv4Addr::new(198, 18, 0, 0), 15),
            (Ipv4Addr::new(224, 0, 0, 0), 3),
        ];
        self.prefix_len >= MIN_DIRECT_PREFIX_LEN
            && !self.contains(server)
            && SPECIAL.iter().all(|&(address, prefix_len)| {
                let special = Self {
                    address,
                    prefix_len,
                };
                !special.contains(self.address) && !self.contains(address)
            })
    }
}

/// Why a message carries its networks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectRoutesPart {
    /// The client just sent a packet into one of these networks and it was refused.
    Refused = 0,
    /// Part of the list sent after the handshake; more parts follow.
    List = 1,
    /// The last part of that list, possibly empty. A client that must know
    /// every network before its interface comes up waits for this one.
    ListEnd = 2,
}

/// One [`InnerPacketKind::DirectRoutes`](crate::InnerPacketKind) payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectRoutes {
    pub part: DirectRoutesPart,
    pub routes: Vec<DirectRoute>,
}

impl DirectRoutes {
    /// Writes one message into `output`.
    ///
    /// At most [`MAX_DIRECT_ROUTES_PER_MESSAGE`] networks fit; callers split
    /// longer lists.
    pub fn encode(part: DirectRoutesPart, routes: &[DirectRoute], output: &mut Vec<u8>) {
        debug_assert!(routes.len() <= MAX_DIRECT_ROUTES_PER_MESSAGE);
        output.clear();
        output.push(part as u8);
        for route in routes {
            output.extend_from_slice(&route.address.octets());
            output.push(route.prefix_len);
        }
    }

    /// Decodes one message.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown part, a truncated or oversized payload,
    /// an invalid network, or a refusal or list part without networks.
    pub fn decode(input: &[u8]) -> Result<Self, DirectRouteError> {
        let (&part, networks) = input
            .split_first()
            .ok_or(DirectRouteError::InvalidLength(0))?;
        let part = match part {
            0 => DirectRoutesPart::Refused,
            1 => DirectRoutesPart::List,
            2 => DirectRoutesPart::ListEnd,
            other => return Err(DirectRouteError::UnknownPart(other)),
        };
        if networks.len() % ROUTE_LEN != 0
            || networks.len() / ROUTE_LEN > MAX_DIRECT_ROUTES_PER_MESSAGE
            || (networks.is_empty() && part != DirectRoutesPart::ListEnd)
        {
            return Err(DirectRouteError::InvalidLength(input.len()));
        }
        let routes = networks
            .chunks_exact(ROUTE_LEN)
            .map(|chunk| {
                let address = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
                DirectRoute::new(address, chunk[4]).ok_or(DirectRouteError::InvalidNetwork)
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { part, routes })
    }
}

impl fmt::Display for DirectRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.address, self.prefix_len)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectRouteError {
    InvalidLength(usize),
    InvalidNetwork,
    UnknownPart(u8),
}

impl fmt::Display for DirectRouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(length) => {
                write!(formatter, "direct route payload has {length} bytes")
            }
            Self::InvalidNetwork => formatter.write_str("invalid direct route network"),
            Self::UnknownPart(part) => write!(formatter, "unknown direct route part {part}"),
        }
    }
}

impl Error for DirectRouteError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capabilities_round_trip_and_unknown_payloads_mean_none() {
        let announced = ClientCapabilities {
            direct_routes: true,
        };
        assert_eq!(ClientCapabilities::decode(&announced.encode()), announced);
        assert_eq!(
            ClientCapabilities::decode(&[]),
            ClientCapabilities::default()
        );
        assert_eq!(
            ClientCapabilities::decode(&[2, 0xff]),
            ClientCapabilities::default()
        );
    }

    #[test]
    fn routes_round_trip_and_invalid_networks_are_rejected() {
        let routes = [
            DirectRoute::new(Ipv4Addr::new(77, 88, 0, 0), 18).unwrap(),
            DirectRoute::new(Ipv4Addr::new(5, 255, 255, 0), 24).unwrap(),
        ];
        let mut payload = Vec::new();
        DirectRoutes::encode(DirectRoutesPart::List, &routes, &mut payload);
        assert_eq!(
            DirectRoutes::decode(&payload).unwrap(),
            DirectRoutes {
                part: DirectRoutesPart::List,
                routes: routes.to_vec(),
            }
        );
        DirectRoutes::encode(DirectRoutesPart::ListEnd, &[], &mut payload);
        assert!(DirectRoutes::decode(&payload).unwrap().routes.is_empty());
        assert!(routes[0].contains(Ipv4Addr::new(77, 88, 55, 88)));
        assert!(!routes[0].contains(Ipv4Addr::new(77, 88, 64, 1)));

        let server = Ipv4Addr::new(203, 0, 113, 7);
        assert!(routes[0].is_safe_to_bypass(server));
        for (address, prefix_len) in [
            (Ipv4Addr::UNSPECIFIED, 0),
            (Ipv4Addr::new(128, 0, 0, 0), 1),
            (Ipv4Addr::new(203, 0, 113, 0), 24),
            (Ipv4Addr::new(192, 168, 1, 0), 24),
            (Ipv4Addr::new(10, 0, 0, 0), 8),
            (Ipv4Addr::new(239, 0, 0, 0), 8),
        ] {
            let route = DirectRoute::new(address, prefix_len).unwrap();
            assert!(!route.is_safe_to_bypass(server), "{route}");
        }

        assert!(DirectRoute::new(Ipv4Addr::new(77, 88, 0, 1), 18).is_none());
        assert!(DirectRoute::new(Ipv4Addr::UNSPECIFIED, 33).is_none());
        assert_eq!(
            DirectRoutes::decode(&[]),
            Err(DirectRouteError::InvalidLength(0))
        );
        assert_eq!(
            DirectRoutes::decode(&[0]),
            Err(DirectRouteError::InvalidLength(1))
        );
        assert_eq!(
            DirectRoutes::decode(&[3]),
            Err(DirectRouteError::UnknownPart(3))
        );
        assert_eq!(
            DirectRoutes::decode(&[0, 77, 88, 0, 1, 18]),
            Err(DirectRouteError::InvalidNetwork)
        );
        let oversized = vec![0; 1 + ROUTE_LEN * (MAX_DIRECT_ROUTES_PER_MESSAGE + 1)];
        assert!(DirectRoutes::decode(&oversized).is_err());
    }
}
