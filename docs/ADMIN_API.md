# Admin API

The MVP administration API binds only to `127.0.0.1:9797` and keeps state in
memory. Do not expose it directly to the internet. Remote administration should
use an SSH tunnel until mutual TLS and persistent encrypted storage exist.

Set a bearer token of at least 32 bytes and start the service:

```sh
export MOUSEVPN_ADMIN_TOKEN="$(openssl rand -hex 32)"
cargo run -p mousevpn-admin-api
```

Create a user:

```sh
curl -sS -X POST http://127.0.0.1:9797/v1/users \
  -H "Authorization: Bearer $MOUSEVPN_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"alice","max_sessions":2}'
```

Provision a device key (the secret is returned only in this response):

```sh
curl -sS -X POST http://127.0.0.1:9797/v1/users/1/devices \
  -H "Authorization: Bearer $MOUSEVPN_ADMIN_TOKEN"
```

Revoke one device using its URL-safe Base64 public key:

```sh
curl -sS -X DELETE \
  "http://127.0.0.1:9797/v1/devices/PUBLIC_KEY" \
  -H "Authorization: Bearer $MOUSEVPN_ADMIN_TOKEN"
```

Revoke a user, every device key and every active session:

```sh
curl -sS -X DELETE http://127.0.0.1:9797/v1/users/1 \
  -H "Authorization: Bearer $MOUSEVPN_ADMIN_TOKEN"
```

The generated client secret must be delivered through an authenticated channel
and stored once on that device. The server retains only its public key.
