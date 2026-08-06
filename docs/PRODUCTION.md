# Production deployment status

Production deployment is intentionally gated. The cryptographic session, UDP
transport, multi-user authorization, platform-independent IPv4 data plane and
initial long-running Linux packet loops are implemented. The following items
must be complete before exposing a server:

- persistent encrypted user/device registry;
- graceful server shutdown;
- persistent virtual IPv4 lease allocation per active device;
- handshake cookies and rate limiting;
- keepalive, reconnect and key rotation;
- configuration files with strict permission checks;
- rollback-tested client routes, DNS and kill switch;
- systemd hardening and backup/restore procedure;
- end-to-end tests in isolated Linux network namespaces.

## Draft server networking

`deploy/server/mousevpn.nft` contains an isolated nftables table for forwarding
`10.77.0.0/24` from `mousevpn0` to the public interface with masquerading. Edit
the `mousevpn_wan` definition before use. It does not open an input UDP port;
that remains the host firewall administrator's decision.

`deploy/server/99-mousevpn-forwarding.conf` enables IPv4 forwarding and keeps
IPv6 forwarding disabled until IPv6 is supported end to end.

`deploy/server/mousevpn-server.service.in` is a hardened systemd draft with a
dedicated `mousevpn` account and `CAP_NET_ADMIN`. It must not be installed or
enabled until the remaining production gates are complete.

These files must not be loaded on a production host yet. They are reviewable
network policy drafts, not an installer.

The target VPS already carries AmneziaVPN traffic. Before any mutation, deployment
must inventory its UDP listeners, tunnel interfaces, policy-routing tables and
complete nftables ruleset. MouseVPN uses its own table and port and must not
replace, flush or introduce a drop policy that affects Amnezia chains.

The first client test must not run in the same network namespace as an active
Amnezia full tunnel. Disconnect Amnezia first, or later isolate one VPN in a
separate network namespace. The client refuses an existing IPv4 split-default
route, but that check cannot recognize every policy-routing layout used by other
VPN clients.

## Draft client kill switch

`deploy/client/mousevpn-killswitch.nft` permits loopback, the TUN interface and
the single UDP path to the server, then drops other output. Its documentation IP
and interface names are deliberately invalid for a real deployment. Automatic
installation requires a transactional route manager that can restore the prior
state after crashes.

The runtime client creates only `table inet mousevpn_client_runtime`. Normal
`Ctrl+C` and `SIGTERM` remove its routes and this table. After an uncatchable
`SIGKILL`, recover only MouseVPN's isolated table with:

```sh
sudo nft delete table inet mousevpn_client_runtime
```

Never flush the complete nftables ruleset: that could remove Amnezia and host
firewall policy.

## Intended rollout

1. Build a release binary from a tagged commit and record checksums.
2. Create a dedicated unprivileged service account.
3. Grant only the capabilities required for TUN/network configuration.
4. Validate nftables and routes inside a network namespace.
5. Deploy to a staging VPS and test IP, IPv6 and DNS leak behavior.
6. Issue one device key per friend and test revocation.
7. Promote the same artifacts to the production VPS.

The admin API remains bound to loopback. Access it remotely only through SSH
until mutual TLS is implemented.
