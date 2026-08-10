# Admin API

The administration API is embedded into `mousevpn-server`. By default it binds
to the private tunnel address `10.77.0.1:9797` and is unreachable until a
MouseVPN client connects. Do not expose this plain HTTP listener publicly.

## Bootstrap and authentication

`mousevpn-server generate-example` creates the initial owner client and writes
`public_endpoint` into the server TOML. Create a random bearer token on the VPS:

```sh
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/mousevpn/admin.token'
sudo chown mousevpn:mousevpn /etc/mousevpn/admin.token
```

The admin listener is disabled when the token file does not exist. Once the
owner is connected, open `http://10.77.0.1:9797/`. For bootstrap diagnostics an
SSH tunnel can target the same private listener:

```sh
ssh -L 9797:10.77.0.1:9797 root@SERVER
```

API calls use `Authorization: Bearer TOKEN`. The web UI keeps this token only in
the browser tab's `sessionStorage`.

## Endpoints

- `GET /v1/health` — authenticated health check;
- `GET /v1/devices` — list registered devices;
- `POST /v1/devices` — create an independently revocable Android or Linux key;
- `DELETE /v1/devices/{public_key}` — revoke a key immediately;
- `GET /v1/traffic?hours=24` — hourly totals and per-device traffic for
  the selected period (1–744 hours), plus current-hour, 24-hour and 7-day totals.

Example creation request:

```sh
curl -sS http://10.77.0.1:9797/v1/devices \
  -H "Authorization: Bearer $MOUSEVPN_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"name":"Alice phone","platform":"android","profile_password":"LONG_PASSWORD"}'
```

The creation response is the only response containing the private client
material. It includes a Linux TOML and, when a profile password was provided,
an encrypted `MV1.…` token compatible with the Android app.

The persistent public device registry lives at
`/var/lib/mousevpn/devices.toml`. Updates are atomically replaced on disk.
Revocation flips an atomic authorization flag held by active sessions, so no
registry lock, Base64 decoding, or disk access occurs on the packet hot path.

Hourly traffic history lives in the SQLite/WAL database
`/var/lib/mousevpn/traffic.sqlite` and is retained for 400 days. On first start,
an existing `traffic.toml` is imported automatically and kept as a fallback
copy. The server counts successfully forwarded inner IPv4 bytes (not UDP,
encryption or keepalive overhead) with per-device atomic counters and upserts
only the current hourly rows every 10 seconds. Set `MOUSEVPN_TRAFFIC_STORE` to
override the database path; an old value ending in `.toml` is mapped to a
sibling `.sqlite` database and migrated. A crash can lose at most the currently
unflushed interval; normal API reports include pending counters.

## Opt-in public endpoint

For fleets where every VPN node is administered directly by its public IP,
install `deploy/server/mousevpn-admin-public.conf` as a systemd drop-in and
open TCP/9797 with connection limiting:

```sh
sudo install -d /etc/systemd/system/mousevpn-server.service.d
sudo install -m 0644 deploy/server/mousevpn-admin-public.conf \
  /etc/systemd/system/mousevpn-server.service.d/admin-public.conf
sudo ufw limit 9797/tcp comment 'MouseVPN admin API'
sudo systemctl daemon-reload
sudo systemctl restart mousevpn-server
```

On a host without UFW/firewalld, also install the provided nftables limiter:

```sh
sudo install -m 0644 deploy/server/mousevpn-admin-public.nft \
  /etc/mousevpn/mousevpn-admin-public.nft
sudo install -m 0644 deploy/server/mousevpn-admin-public-nft.conf \
  /etc/systemd/system/mousevpn-server.service.d/admin-public-nft.conf
```

Each node must use its own random 32-byte `admin.token`. The current endpoint
is plain HTTP: the token prevents unauthorized API calls, but does not encrypt
responses containing newly generated private client material. Treat this mode
as an explicit operational tradeoff and prefer a pinned-TLS management client
before deploying it over untrusted networks.
