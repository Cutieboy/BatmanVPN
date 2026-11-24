# Windows BatmanVPN vs Android MouseVPN — Root-Cause Diagnosis

Date: 2026-09-27
Investigator: automated debugging session
Scope: why the Windows BatmanVPN split-tunnel client drops traffic that the
Android MouseVPN (full TUN tunnel) handles correctly.

---

## 1. Summary of the root cause

The Windows client is running in **split-tunnel (WinDivert) mode** because the
saved profile (`settings.toml`) lists 21 applications under `mode = "exclude"`.
The Android client runs a **full TUN tunnel**. These are fundamentally different
data paths.

In the full-tunnel path (both Android and Windows), the tunnel adapter carries
the session MTU, so the TCP/IP stack sizes every segment to fit it. There is no
per-connection decision to make and no race to lose.

In the Windows split-tunnel path there is no adapter. The client instead rewrites
each captured TCP SYN's Maximum Segment Size (MSS) option so both ends of a
connection agree on a segment size that fits the tunnel. That clamp was applied
**only after** the flow had been classified as `Tunnel` by the asynchronous
socket-watcher thread. A SYN that reached the capture loop before its
`EVENT_SOCKET_CONNECT` event was processed escaped **unclamped**, negotiated the
full physical-link segment size, and every subsequent data segment (1440–1500
bytes) then exceeded the tunnel MTU (1280 for `morph_paranoid`) and was dropped
as `PacketExceedsMtu`. The result is a classic path-MTU black hole: small
requests succeed, bulk transfers stall, and there is no ICMP to correct it.

This is the concrete, reproducible divergence between the two clients.

---

## 2. Verified facts

- Saved profile `4dc23545-…` ("Batman"): `server = 138.124.249.21:51820`,
  `protocol = "morph_paranoid"`, `mode = "exclude"` with 21 apps.
- The running binary `D:\Programs\MouseVPN\mousevpn-windows-gui.exe` (v0.1.18,
  product "BatmanVPN") is byte-identical in size/version to the repo release
  build, so the source under investigation is what is running.
- The helper runs `MOUSEVPN_MODE=split_tunnel` (WinDivert), not the Wintun full
  tunnel.
- `morph_paranoid` → server caps tunnel MTU at `morph::SAFE_TUN_MTU = 1280`
  (`server/src/daemon.rs` `session_mtu` → `configured.min(SAFE_TUN_MTU)`).
- Split-tunnel `max_segment_size = tunnel_mtu - 40 = 1240` for morph.
- Log evidence (`%LOCALAPPDATA%\MouseVPN\logs\helper.log`) shows repeated
  `MOUSEVPN_SPLIT_WARNING=dropped N packet(s) larger than the tunnel MTU; last
  was protocol 6, 1440–1500 bytes`. Protocol 6 is TCP; 1440–1500 bytes is the
  full Ethernet-MTU segment size — proof that MSS clamping never fired for those
  flows.
- The drop counter grows monotonically across every session (e.g. "dropped 32",
  "dropped 64", "dropped 128" …), confirming the black hole is ongoing, not a
  one-off.

## 3. Inferences

- The MSS option is only present on the SYN, so once a flow's SYN escapes
  unclamped, no later packet can be clamped. The only correction would be a
  reconnect, which the application does not do.
- The race is real because the socket-watcher thread (`FlowWatcher`) and the
  capture thread (`Diverter::run`) are independent and share no barrier. The
  code comment "its connect event fires before the SYN leaves" describes the
  kernel's event *ordering*, not the user-mode *processing* order.

## 4. Unverified hypotheses (not confirmed)

- The frequent `helper_stderr_closed` / `helper_started` cycles were initially
  suspected to be crashes. However, `helper.previous.log` shows 24 starts and 24
  stops with **zero** `MOUSEVPN_RUNTIME_WARNING` and **zero**
  `MOUSEVPN_RECONNECT_ERROR`, which means every one of those 24 exits was a clean
  `Ok(())` return (i.e. `stopping` was set). These are user/automated
  connect/disconnect cycles, **not** crashes. No panic messages exist in either
  log, and the Windows Application event log contains no MouseVPN/BatmanVPN
  crash entries.
- The `MOUSEVPN_RECONNECT_ERROR=server handshake timed out` bursts are real but
  transient (the session recovers to `reconnected`). Not established as the
  primary user-visible defect.

## 5. Fix implemented

File: `crates/windows-client/src/windivert/divert.rs`

1. Added `Outcome::PassThroughModified` to signal "stays on the physical link
   but was rewritten in place (MSS clamped), so recompute checksums".
2. In `prepare_outbound`, moved the `clamp_mss` call **before** the flow-table
   lookup, so every TCP SYN that reaches the tunnel decision point is clamped
   regardless of whether the flow has been classified yet. Unclassified SYN →
   `PassThroughModified`; classified Tunnel SYN → still `Tunnel` (clamped).
3. In `Diverter::run`, handle `PassThroughModified` by calling
   `calc_checksums` before reinjection (the MSS rewrite invalidates the TCP
   checksum).

Safety: clamping a SYN that later resolves to `Direct` is harmless — the peer
merely uses a smaller segment. Clamping before the verdict closes the race
window that produced the black hole.

### Tests added
- `clamps_an_unclassified_syn_and_marks_it_modified_for_reinjection`
- `leaves_an_unclassified_non_syn_byte_for_byte_alone`
- `clamps_a_classified_syn_and_routes_it_to_the_tunnel`
- `clamps_a_syn_of_an_excluded_flow_and_passes_it_back_modified`

## 6. Validation results

- `cargo test -p mousevpn-windows-client` → **86 passed, 0 failed** (was 82
  before the change; 4 new tests pass).
- `cargo build -p mousevpn-windows-client --release` → succeeds.
- `cargo check -p mousevpn-windows-gui --release` → succeeds (full GUI compiles
  against the changed library).

Live end-to-end validation was **not** performed: it requires rebuilding and
redeploying the GUI/helper binary and interrupting the currently-connected VPN
session (which is actively passing traffic). See "Next action".

## 7. Errors, contradictions and failed experiments encountered

1. First `cargo check` failed with `ring … stddef.h: No such file or directory`
   because the MSVC build environment variables were not set in the shell. Fixed
   by pointing `INCLUDE`/`LIB` at the installed Build Tools and Windows SDK
   (`C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\…` and
   `C:\Program Files (x86)\Windows Kits\10\…`). This is an environment issue,
   not a code issue.
2. First new test `clamps_a_classified_syn_and_routes_it_to_the_tunnel` failed
   because it reused a UDP flow key; corrected to insert a TCP flow key matching
   the SYN packet's 5-tuple.
3. An edit-strip of the UTF-8 BOM on line 1 of `divert.rs` produced a cosmetic
   diff (`#![doc …]` no longer carries the BOM). Harmless; Rust ignores it.
4. The `tun_name = "MouseVPN"` field in the saved profile is ignored by the
   Windows client, which hardcodes `ADAPTER_NAME = "MouseVPN"` in
   `network.rs`. A branding inconsistency, not a networking defect.

## 8. Remaining uncertainties / blockers

- The exact server `tun.mtu` configuration is not directly inspectable from the
  client, so the claim "morph tunnel MTU = 1280" is inferred from the server
  code (`session_mtu`) rather than observed on the wire. It does not change the
  conclusion: with any tunnel MTU below 1500, an unclamped flow produces
  segments the tunnel drops.
- The helper connect/disconnect churn (24 clean exits in `helper.previous.log`)
  has not been attributed to a specific user action or automated trigger.
- Live validation of the fix is pending a rebuild + redeploy.

## 9. Next action (if not fully solved)

Rebuild the release GUI/helper binary and redeploy it, then reconnect and
confirm the `MOUSEVPN_SPLIT_WARNING=dropped … larger than the tunnel MTU`
messages no longer appear for TCP (protocol 6) flows. The unit tests already
prove the clamp now fires for unclassified SYNs, but a live run is the
authoritative confirmation.

Build command (from repo root, with MSVC env set):
```
cargo build -p mousevpn-windows-gui --release
```
then replace `D:\Programs\MouseVPN\mousevpn-windows-gui.exe` and reconnect.