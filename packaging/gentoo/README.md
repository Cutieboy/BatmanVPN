# MouseVPN on Gentoo

`build-gentoo.sh` turns this checkout into a normal Portage package and merges
it. It is the only supported way to build the ebuild here, because the ebuild
expects a source tarball that already carries every crate.

```sh
./packaging/gentoo/build-gentoo.sh
```

What it does:

1. stages the tracked files of the working tree into
   `/var/tmp/mousevpn-gentoo/mousevpn-<version>`;
2. runs `cargo vendor --locked` there, so the build itself needs no network
   and works with the default `FEATURES="network-sandbox"`;
3. packs `mousevpn-<version>-vendored.tar.xz` and copies it into `DISTDIR`;
4. publishes a small overlay in `/var/db/repos/mousevpn`, registers it in
   `/etc/portage/repos.conf/mousevpn.conf` and accepts `~amd64` for the three
   packages it contains;
5. generates the Manifest and runs `emerge =net-vpn/mousevpn-<version>`.

Steps 1–2 run as the invoking user. Steps 3–5 use `sudo`, so the command asks
for a password once.

Useful options:

```sh
# Prepare everything but do not merge.
./packaging/gentoo/build-gentoo.sh --no-install

# Reuse the tarball from a previous run.
./packaging/gentoo/build-gentoo.sh --skip-vendor

# Pick USE flags, then pass extra arguments to emerge.
./packaging/gentoo/build-gentoo.sh --use "client server -gui" -- --ask
```

## USE flags

| Flag       | Default | Installs                                                     |
| ---------- | ------- | ------------------------------------------------------------ |
| `client`   | on      | `mousevpn-linux-client`, `mousevpn-proxy-client` and the two systemd units |
| `gui`      | off     | `mousevpn-linux-gui` and its desktop entry                   |
| `server`   | off     | `mousevpn-server`, `mousevpn-device` and the server units     |

`mousevpn-profile` is always installed.

`gui` pulls in `net-libs/webkit-gtk:4.1` and `x11-libs/gtk+:3`. On a machine
without WebKitGTK that is a multi-hour build, which is why the flag is off by
default. The terminal client and the desktop client use the same runtime and
the same `/etc/mousevpn/*.toml` files.

## After the merge

Configuration lives in `/etc/mousevpn`, which the package creates with mode
`0700`. Install the client TOML issued for this device with mode `0600`:

```sh
sudo install -m 0600 ~/owner.toml /etc/mousevpn/home.toml
```

Connect once in the foreground:

```sh
sudo mousevpn-linux-client --config /etc/mousevpn/home.toml
```

Or run it as a service, where the instance name is the file name without
`.toml`:

```sh
sudo systemctl enable --now mousevpn-client@home.service
```

Route only a browser or Telegram through the tunnel, leaving the host default
route and DNS alone — SOCKS5 on `127.0.0.1:1080`:

```sh
sudo systemctl enable --now mousevpn-proxy-client@home.service
```

Change the port with a drop-in:
`systemctl edit mousevpn-proxy-client@home.service` and set
`Environment=MOUSEVPN_PROXY_PORT=1081`.

The client changes DNS through `resolvectl` only, so `systemd-resolved` has to
be active:

```sh
systemctl is-active systemd-resolved
```

## Rebuilding after a change

Re-run the script. It restages the working tree, so committed and uncommitted
changes to tracked files are both picked up, and `emerge` reinstalls the same
version. Bump the version by copying the ebuild to a new file name and passing
`--version`.

## Removing it

```sh
sudo emerge --deselect --unmerge net-vpn/mousevpn
sudo rm -f /etc/portage/repos.conf/mousevpn.conf \
	/etc/portage/package.accept_keywords/mousevpn \
	/etc/portage/package.use/mousevpn
sudo rm -rf /var/db/repos/mousevpn
```

`/etc/mousevpn` and its private keys are left in place.
