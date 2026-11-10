# Upstream Mousality Protocol & Wire Format Analysis

## 1. Overview of Mousality (Mousality 2.0)

Mousality is a specialized TCP transport designed to bypass DPI and active probing by disguising VPN traffic as a modern web browser browsing a benign website using TLS 1.3.

The key innovation:
1. **Outer TLS 1.3 Camouflage**: Matches Chrome 156 (`JA4 = t13d1517h2_8daaf6152771_cb7bf5808d99`).
2. **Transparent Active Probe Defense**: If a DPI scanner, probe bot, or unauthorized client initiates a connection, the server forwards the connection to a real HTTPS host (e.g., Microsoft CDN).
3. **Record Shaping (XTLS Vision Style)**: Disguises nested TLS handshakes inside the tunnel by padding the first 16 records and the first 8 records after >=0.5s idle gaps.
4. **Multiplexed Datagrams**: Once the outer TLS channel is authenticated, datagrams (Noise packets) are framed into TLS Application Data records without altering packet boundaries.

---

## 2. Handshake Structure

### 2.1 Outer ClientHello
- Real Chrome 156 extension set:
  - Supported Versions (TLS 1.3, TLS 1.2)
  - Key Share (X25519MLKEM768 hybrid, X25519)
  - Signature Algorithms (including ML-DSA `0x0904`–`0x0906`)
  - Trust Anchor IDs (`0xca34`)
  - ALPN (`h2`, `http/1.1`)
  - GREASE extensions and cipher suites
- The server authenticates the client via an embedded sealed token within the hello record (authenticated with the server's public key).
- In version 2, if an older version 1 server responds, the client falls back to version 1 and caches the requirement for 1 hour.

### 2.2 Inner Noise Handshake
Inside the decrypted TLS stream:
- Client sends standard `HandshakeInit` datagram.
- Server returns `HandshakeResponse` datagram.
- Both exchange `SessionParameters` (IP address, MTU, DNS).
- Client announces `ClientCapabilities { direct_routes: bool }`.
- Server distributes direct routes via `DirectRoutes` datagrams (`InnerPacketKind::DirectRoutes = 4`).

---

## 3. Wire Framing & Demultiplexing

```
[ TLS Record Header: 5 bytes (0x17, 0x0303, Length) ]
[ Encrypted TLS Application Data: Up to 16,384 bytes ]
    └── [ Inner BatmanVPN / MouseVPN Datagram ]
            ├── Header: 8 bytes (Session ID + PacketKind)
            └── Encrypted Payload
```

---

## 4. Platform Runtimes & Transport

- In `crates/transport`:
  - `ClientTransport` enum encapsulates either `Udp(UdpTransport)` or `Mousality(MousalityTransport)`.
  - Implements `DatagramTransport` (`send`, `receive`).
  - Threaded I/O handles TLS buffering, keepalives, and timeouts cleanly.
- In `crates/windows-client`:
  - WinDivert filter updated to exclude the Mousality TCP destination from capture:
    `"udp or (tcp and (ip.DstAddr != <server_ip> or tcp.DstPort != 443))"`
- In `crates/android-native`:
  - JNI connects via TCP socket, protects socket via `VpnService.protect()`, and passes it to `MousalityTransport`.
