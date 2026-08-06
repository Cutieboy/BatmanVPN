# Threat model

This document describes the intended security properties of the first MouseVPN
session protocol. It is a design target, not a security certification.

## Assets

- IP packets carried through the tunnel;
- long-term client and server private keys;
- session keys and packet counters;
- endpoint configuration and DNS settings;
- availability of the client network connection and server.

## Trust assumptions

- The client is provisioned with the authentic server static public key through
  a channel outside this protocol.
- Client and server derive the same deployment-specific Noise prologue from that
  key; this context is not secret and is not a replacement for key pinning.
- The server has an allow-list of client static public keys. Completing a Noise
  handshake proves possession of a key; authorization remains server policy.
- Client and server operating systems, random-number generators and binaries are
  trusted. A compromised endpoint is outside the protocol's protection.
- The selected cryptographic implementation and Noise primitives behave as
  specified. The project does not invent cryptographic algorithms.

## Network attacker

The attacker may observe, delay, drop, duplicate, reorder and modify packets;
inject arbitrary packets; scan the endpoint; and initiate many handshakes. The
attacker may know the protocol and possess their own valid client key.

The first MVP aims to provide:

- mutual authentication of configured static keys;
- confidentiality and integrity of tunnel payloads;
- independent keys for each traffic direction;
- replay rejection within a bounded packet-number window;
- forward secrecy from ephemeral Noise IK keys when long-term keys are
  compromised after a recorded session;
- parser behavior that is bounded and does not panic on attacker-controlled
  input.

## Explicit non-goals

- Hiding the server IP address or the fact that encrypted traffic exists.
- Guaranteed resistance to blocking, traffic analysis or active probing.
- Protecting traffic after either endpoint has been compromised.
- Anonymity from the VPN server or services contacted through it.
- Availability against volumetric denial of service.
- Post-quantum security in the MVP.

## Principal risks and mitigations

| Risk | Initial mitigation |
| --- | --- |
| Man-in-the-middle server | Server public-key pinning on the client |
| Unauthorized client | Server allow-list after authenticated handshake |
| Packet modification | Noise ChaCha20-Poly1305 authentication |
| Packet replay | 128-packet sliding receive window per session |
| Nonce reuse | Monotonic 64-bit sequence per key direction; reconnect before exhaustion |
| Forged high sequence poisons window | Mark sequence only after AEAD verification |
| Parser/length abuse | Fixed header, explicit size limits, fuzz targets |
| Handshake CPU/state exhaustion | Stateless cookie/rate limiting before production exposure |
| Key disclosure in logs | Secret types do not implement value-revealing `Debug` |
| Traffic leak on failure | Linux/Android platform kill switch, tested separately |

## Required review before real use

The handshake transcript, key provisioning, session identifier generation,
rekey rules, cookie mechanism, configuration storage and OS networking changes
must be independently reviewed. The current repository is not production-ready.
