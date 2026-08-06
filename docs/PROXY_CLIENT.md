# Linux SOCKS5 proxy client

`mousevpn-proxy-client` runs the normal encrypted MouseVPN tunnel but routes
only its own SOCKS5 connections through it. The host default route and system
DNS remain unchanged. It is intended for a browser and Telegram Desktop on
Linux.

The listener is deliberately restricted to IPv4 loopback. It has no password
because processes on other computers cannot connect to it. Do not publish port
1080 or replace `127.0.0.1` with a public address.

## Build

Install Rust and the Linux tools used by the client, then build:

```sh
cargo build --release --bin mousevpn-proxy-client
```

The resulting binary is `target/release/mousevpn-proxy-client`. Give every
computer its own independently revocable client TOML; never reuse a phone or
another computer's key.

## Start

The TUN device and marked policy route require root privileges:

```sh
sudo ./mousevpn-proxy-client \
  --config /etc/mousevpn/friend-linux-proxy.toml
```

The default SOCKS5 address is `127.0.0.1:1080`. A different loopback port can be
selected explicitly:

```sh
sudo ./mousevpn-proxy-client \
  --config /etc/mousevpn/friend-linux-proxy.toml \
  --listen 127.0.0.1:1081
```

Stop it with `Ctrl+C`. Normal shutdown removes the TUN interface and policy
route.

## Browser and Telegram

Firefox manual proxy settings:

- SOCKS host: `127.0.0.1`;
- port: `1080`;
- SOCKS v5;
- enable "Proxy DNS when using SOCKS v5".

Chromium can be launched for a quick test with:

```sh
chromium --proxy-server="socks5://127.0.0.1:1080"
```

In Telegram Desktop open **Settings → Advanced → Connection type → Use custom
proxy → SOCKS5** and set host `127.0.0.1`, port `1080`, leaving username and
password empty.

Test the browser path while the client is running:

```sh
curl --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
```

The `socks5h` form is important: it sends the domain through the proxy. The
client resolves it using the DNS address negotiated inside MouseVPN.

## Recovery after a forced kill

`Ctrl+C` cleans up automatically. If the process was killed with `SIGKILL` or
the computer lost power, remove only MouseVPN's dedicated proxy rule and table:

```sh
sudo ip -4 rule del priority 10000 fwmark 0x4d5650 lookup 51821
sudo ip -4 route flush table 51821
```

Do not flush all policy rules or firewall tables.

## Current limitations

- SOCKS5 `CONNECT` for TCP is supported; UDP ASSOCIATE is not yet supported.
- IPv4 targets and domain names are supported; IPv6 is not.
- Applications must have native SOCKS5 support or be launched through a
  SOCKS-aware wrapper.
