# MouseVPN protocol draft 0.1

Status: development draft. Incompatible changes are expected.

## Cryptographic protocol

The protected session uses:

```text
Noise_IK_25519_ChaChaPoly_SHA256
```

This is a standard Noise IK handshake with X25519, ChaCha20-Poly1305 and SHA-256.
The client (initiator) already knows the server's static public key. Both peers
have static X25519 keys. The server must authorize the authenticated client key
against its own allow-list.

MouseVPN defines framing, session lifecycle, routing and transport behavior; it
does not modify the Noise handshake or define new cryptographic primitives.

Each deployment derives a 32-byte `ProtocolContext` as
`SHA-256("MouseVPN deployment context v1\\0" || server_static_public_key)` and
passes it to the Noise prologue. This cryptographically separates installations
and catches configuration mistakes without transmitting a clear-text product or
deployment identifier. It is domain separation, not an additional secret.

## Outer header

All integers use network byte order.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 1 | protocol version (`1`) |
| 1 | 1 | packet kind |
| 2 | 2 | flags, currently zero |
| 4 | 8 | session identifier |
| 12 | 8 | sequence number |

There is deliberately no fixed ASCII product magic in the datagram. A universal
clear-text marker would create an unnecessary filtering signature. The remaining
header is still observable and is not claimed to resist traffic classification.

The 24-byte outer header is routing metadata. It is not currently passed as AEAD
associated data. Therefore authenticated message semantics must live inside the
encrypted Noise payload; receivers must not make security decisions from outer
`kind` or `flags` alone. Binding the final header design cryptographically is a
required task before Linux traffic forwarding.

## Handshake

Noise IK consists of two messages:

```text
client -> server: e, es, s, ss
server -> client: e, ee, se
```

Handshake messages are carried as `HandshakeInit` and `HandshakeResponse` outer
packets. Noise authenticates its transcript. Session IDs, retransmission rules,
cookies and handshake timeouts will be finalized with the UDP integration.

## Transport messages

After the handshake, both peers use Noise stateless transport mode. The outer
64-bit sequence is supplied as the Noise nonce. Each direction has a distinct
cipher key and starts at sequence zero.

Requirements:

- a sender never repeats a sequence under the same directional key;
- sequence exhaustion terminates the session before wraparound;
- receivers accept authenticated reordering within 128 sequence numbers;
- duplicates and packets older than the replay window are rejected;
- failed authentication never advances the replay window;
- a session is replaced before rekeying or counter exhaustion in the MVP.

The encrypted plaintext will start with an authenticated inner message type.
Inner data framing and maximum tunnel MTU are not yet frozen.

## Size limits

Noise messages are limited to 65,535 bytes including the authentication tag.
Actual UDP datagrams will be much smaller and derived from the tunnel MTU.
Implementations must reject oversized messages before allocation where possible.
