# Code organization

MouseVPN keeps modules narrow so security-sensitive behavior can be reviewed in
isolation.

- `lib.rs` and `main.rs` contain module wiring and a small entry point only.
- One file owns one primary concern or state machine.
- Protocol parsing, cryptography, OS integration and configuration do not share
  a catch-all utility module.
- Unit tests stay beside private implementation details; public behavior uses a
  dedicated file under `tests/`.
- A source file approaching roughly 250–300 lines should be reviewed for a
  natural split. This is a review signal, not a reason for arbitrary fragments.
- Platform-specific code stays in its platform crate. In particular,
  `client-core` must not import Linux or Android APIs.
- Cryptographic primitives are wrapped behind `mousevpn-crypto`; callers do not
  use provider-specific types.

Exceptions should be explained in the module documentation or code review.
