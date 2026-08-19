# MouseMorph v2

Status: experimental protocol draft implemented by the Linux, Android and
Windows clients.

MouseMorph is an authenticated outer envelope for MouseVPN UDP datagrams. Its
goal is to remove stable, deployment-independent markers from the wire without
changing the existing Noise IK handshake or tunnel data plane. It is not a
claim of invisibility: an observer can still block an endpoint, all UDP, or use
traffic volume and timing analysis.

The original protocol remains the compatibility baseline. A client config that
does not contain `protocol` uses `legacy`; old clients and servers therefore keep
their existing behaviour.

## Design rules

- Do not invent cryptographic primitives.
- Do not expose a product magic, protocol version, packet kind, session ID or
  sequence number outside authenticated encryption.
- Give every client/server key pair a different outer key and routing tag.
- Rotate routing tags, vary packet lengths, and keep all padding authenticated.
- Silently discard unknown tags, invalid authentication and cover frames.
- Keep legacy framing intact inside the envelope so Noise, replay protection,
  authorization and routing remain shared and independently testable.

## Modes

Every client selects one of the following protocol values. Linux and Windows
persist it in the profile configuration; Android persists the equivalent value
in its profile JSON:

```toml
# Default when omitted.
protocol = "legacy"
```

```toml
protocol = "morph_quiet"
```

```toml
protocol = "morph_balanced"
```

```toml
protocol = "morph_paranoid"
```

The three MouseMorph modes change traffic shape, not cryptographic strength.

| Mode | Data padding | Cover frames before handshake | Handshake jitter |
| --- | --- | ---: | ---: |
| `morph_quiet` | 0–31 random bytes | 0 | none |
| `morph_balanced` | randomized size buckets | 1–2 | 1–4 ms |
| `morph_paranoid` | wider randomized size buckets | 3–5 | 2–12 ms |

Cover traffic is deliberately limited to connection establishment in v2.0. It
must not create a large permanent bandwidth tax or become a more reliable
signature than the packet format it hides.

## Key derivation

No additional secret is provisioned. Both peers calculate the existing X25519
static-static shared secret:

```text
shared = X25519(client_static_secret, server_static_public)
       = X25519(server_static_secret, client_static_public)
```

The 32-byte MouseMorph key is derived with HKDF-SHA256:

```text
salt = "MouseVPN MouseMorph v2 key"
info = server_static_public || client_static_public
key  = HKDF-Expand(HKDF-Extract(salt, shared), info, 32)
```

The ordering in `info` is role-based, not lexical. The derived key is domain
separated from Noise and is never serialized or logged.

Compromise of either long-term private key compromises recorded MouseMorph
envelopes. Tunnel payload confidentiality still follows the Noise session's
properties; MouseMorph is traffic-shaping and metadata protection, not a second
independent VPN.

## Routing tags

Time is divided into profile-specific epochs using Unix time: 30 seconds for
quiet, 5 seconds for balanced, and 1 second for paranoid. Every outer frame
starts with an 8-byte routing tag:

```text
tag = Truncate64(HMAC-SHA256(
    key,
    "MouseVPN MouseMorph v2 route" || profile || direction || epoch_be64
))
```

Profile is `1`, `2`, or `3`; direction is `0` for client-to-server and `1` for
server-to-client. Receivers accept the previous, current and next epoch to
tolerate normal clock skew. Paranoid therefore avoids a stable clear prefix
across more than a short burst, while quiet spends less server CPU rebuilding
route tables.

The server precomputes tags for registered client public keys and performs an
O(1) lookup before attempting AEAD decryption. Unknown tags receive no response.
The registry-derived table is rebuilt at least once per second because it also
contains paranoid routes; newly provisioned devices therefore become
Morph-routable after at most the next one-second refresh under normal operation.

Tag collisions must fail closed. A tag that maps to more than one client is
removed from the routing table for that epoch.

## Outer frame

All integers use network byte order. The UDP payload is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | rotating routing tag |
| 8 | 12 | random ChaCha20-Poly1305 nonce |
| 20 | variable | encrypted inner frame |
| end - 16 | 16 | Poly1305 authentication tag |

Associated data is:

```text
routing_tag || direction
```

The encrypted plaintext is:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | internal format version (`2`) |
| 1 | 1 | frame kind: `0` cover, `1` payload |
| 2 | 1 | profile: `1` quiet, `2` balanced, `3` paranoid |
| 3 | 1 | reserved, must be zero |
| 4 | 2 | inner datagram length |
| 6 | variable | complete legacy MouseVPN datagram |
| remainder | variable | cryptographically random padding |

The internal version and kind are encrypted and therefore do not form a wire
signature. A payload frame must contain exactly one complete legacy datagram. A
cover frame has an inner length of zero; its decrypted padding is ignored.

Nonces are generated independently for every transmission, including handshake
retransmissions. Inner Noise replay protection remains authoritative for data.
The server's existing exact-handshake cache makes duplicated Noise initiations
idempotent.

## Packet sizing

MouseMorph never emits a UDP payload larger than 1472 bytes, which fits a
1500-byte IPv4 path without fragmentation. The fixed MouseMorph overhead is 42
bytes: routing tag, nonce, six encrypted control bytes and the AEAD tag.

`quiet` adds a uniformly selected 0–31 bytes when space permits. `balanced` and
`paranoid` select one of the next fitting profile buckets, rather than padding
every packet to one constant size. Bucket selection and padding contents use the
operating system CSPRNG.

The first implementation caps a Morph session's negotiated tunnel MTU at 1280.
This leaves room for the existing 37-byte MouseVPN data-plane overhead and for
useful padding. TCP learns the smaller MTU through the tunnel interface; an
oversized inner UDP packet may still be dropped and is a known v2.0 limitation.

## Handshake behaviour

1. The client derives its key and current client-to-server routing tag.
2. Balanced/paranoid clients send their configured number of authenticated
   cover frames with short randomized gaps.
3. The normal Noise `HandshakeInit` datagram is placed inside a payload frame.
4. The server resolves the routing tag, authenticates the envelope, and then
   runs the unchanged Noise/authorization path.
5. The response and all session traffic use the same selected profile in the
   opposite direction.

An unauthenticated probe has no known tag and receives no protocol-specific
answer. Possession of a valid client private key is already sufficient to
identify and use that client's MouseVPN access, so it is outside the protection
offered by the outer layer.

## Legacy coexistence

The server uses one UDP socket. It first checks whether the first eight bytes
match a current MouseMorph routing tag. If they do, only authenticated Morph
decoding is attempted. Otherwise the packet is passed to the existing strict
legacy decoder. This ordering avoids ambiguity when a random routing tag begins
with legacy version byte `1`.

Every runtime session remembers whether it was established through legacy or
MouseMorph. Server responses use that same wire mode. A new client can therefore
switch modes while old clients remain connected.

An Android client that moves between Wi-Fi and cellular first creates a new UDP
socket bound to the newly selected physical `Network`, then sends an encrypted
keepalive for the existing session. The server changes the session's source
IP/port only after that keepalive has passed the inner AEAD and replay checks.
Unauthenticated packets therefore cannot redirect a live session. If migration
does not receive a response, the client performs a complete handshake on the
new physical network with exponential retry backoff.

All three GUIs persist the selected value in each stored profile. Profiles that
predate MouseMorph deserialize without the field and remain `legacy`; changing
the mode is disabled while that profile is connecting or connected.

## Implementation boundary

The reusable `mousevpn-morph` crate owns:

- profiles and padding policy;
- rotating tags;
- envelope encoding and authenticated decoding;
- cover-frame generation;
- constants and parser limits.

`mousevpn-crypto` owns the X25519/HKDF key derivation. The configuration crate
owns the user-facing protocol selection. `mousevpn-client-wire` owns the shared
client adapter used by Linux, Android and Windows. Clients and server only adapt
the wire bytes immediately before send and immediately after receive.

## Known limitations and next review

- Size and timing distributions are designed, not measured against real-world
  background traffic yet.
- The server IP address and existence of sustained encrypted UDP remain visible.
- Clock skew beyond one epoch prevents Morph routing.
- There is no fragmentation/reassembly layer in v2.0.
- Cover frames protect handshake shape only; adaptive cover traffic is deferred.
- Code and cryptographic composition require independent review before claims
  of censorship resistance or production readiness.
- Captures from all three modes should be regression-tested for stable fields,
  size distributions and accidental legacy leakage before release.
