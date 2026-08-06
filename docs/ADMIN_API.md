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
- `DELETE /v1/devices/{public_key}` — revoke a key immediately.

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
