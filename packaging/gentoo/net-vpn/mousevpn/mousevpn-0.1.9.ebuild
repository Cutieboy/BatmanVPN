# Copyright 2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

# The workspace declares rust-version = "1.85" in Cargo.toml.
RUST_MIN_VER="1.85.0"

inherit cargo desktop systemd

DESCRIPTION="Encrypted UDP tunnel VPN: Linux client, SOCKS5 proxy client and server"
HOMEPAGE="https://github.com/Zumka1991/MouseVPN"

# The tarball is produced from a checkout by packaging/gentoo/build-gentoo.sh.
# It carries the sources together with a complete `cargo vendor` tree, so the
# build never needs the network and works with FEATURES="network-sandbox".
SRC_URI="${P}-vendored.tar.xz"
S="${WORKDIR}/${P}"

# MouseVPN itself.
LICENSE="|| ( Apache-2.0 MIT )"
# Vendored crates, collected from the `license` field of every crate in the
# vendor tree. Dual-licensed crates are covered by this flat list rather than
# by an || ( ) group each; every name here belongs to @FREE.
LICENSE+="
	0BSD Apache-2.0 Apache-2.0-with-LLVM-exceptions Boost-1.0 BSD BSD-1 BSD-2
	CC0-1.0 ISC MIT MIT-0 MPL-2.0 Unicode-3.0 Unlicense ZLIB
"
SLOT="0"
KEYWORDS="~amd64"

IUSE="+client gui server"
REQUIRED_USE="|| ( client gui server )"

# The distfile is generated locally and is not fetchable from a mirror.
RESTRICT="fetch mirror"

# Runtime tools the Linux runtime shells out to: `ip`, `nft` and `resolvectl`.
RDEPEND="
	client? (
		net-firewall/nftables
		sys-apps/iproute2
		sys-apps/systemd
	)
	gui? (
		net-firewall/nftables
		net-libs/webkit-gtk:4.1
		sys-apps/iproute2
		sys-apps/systemd
		sys-auth/polkit
		x11-libs/gtk+:3
	)
	server? (
		acct-group/mousevpn
		acct-user/mousevpn
		net-firewall/iptables
		net-firewall/nftables
		sys-apps/iproute2
	)
"
DEPEND="
	gui? (
		net-libs/libsoup:3.0
		net-libs/webkit-gtk:4.1
		x11-libs/gtk+:3
	)
"
BDEPEND="virtual/pkgconfig"

QA_FLAGS_IGNORED="usr/bin/mousevpn-.*"

src_unpack() {
	default

	# Use the vendor tree shipped inside the tarball instead of the crate
	# archives cargo.eclass would normally place in ${ECARGO_VENDOR}.
	ECARGO_VENDOR="${S}/vendor"
	cargo_gen_config
}

src_configure() {
	local packages=()
	if use client; then
		packages+=(
			--package mousevpn-linux-client
			--package mousevpn-proxy-client
		)
	fi
	if use gui; then
		packages+=( --package mousevpn-linux-gui )
	fi
	if use server; then
		packages+=(
			--package mousevpn-server
			--package mousevpn-device-cli
		)
	fi
	# The MV1 profile exporter is small and useful on every install.
	packages+=( --package mousevpn-profile-cli )

	cargo_src_configure "${packages[@]}"
}

src_test() {
	# The client, platform and server tests need a TUN device, nftables and
	# CAP_NET_ADMIN, none of which exist inside the sandbox. Run the pure
	# protocol, crypto and configuration tests only.
	cargo_src_test \
		--package mousevpn-protocol \
		--package mousevpn-crypto \
		--package mousevpn-morph \
		--package mousevpn-data-plane \
		--package mousevpn-config \
		--package mousevpn-client-core \
		--package mousevpn-client-wire \
		--package mousevpn-transport
}

src_install() {
	local build="$(cargo_target_dir)"

	dobin "${build}/mousevpn-profile"

	if use client; then
		dobin "${build}/mousevpn-linux-client"
		dobin "${build}/mousevpn-proxy-client"
		systemd_dounit "${FILESDIR}/mousevpn-client@.service"
		systemd_dounit "${FILESDIR}/mousevpn-proxy-client@.service"
	fi

	if use gui; then
		dobin "${build}/mousevpn-linux-gui"
		newicon -s 512 linux-gui/src-tauri/icons/icon.png mousevpn.png
		domenu "${FILESDIR}/mousevpn.desktop"
	fi

	if use server; then
		dobin "${build}/mousevpn-server"
		dobin "${build}/mousevpn-device"

		# The shipped units point at /usr/local, where the upstream manual
		# installs hand-built files.
		sed -e 's|/usr/local/bin/|/usr/bin/|' \
			deploy/server/mousevpn-server.service.in > "${T}/mousevpn-server.service" || die
		sed -e 's|/usr/local/libexec/|/usr/libexec/|' \
			deploy/server/mousevpn-network.service > "${T}/mousevpn-network.service" || die
		systemd_dounit "${T}/mousevpn-server.service"
		systemd_dounit "${T}/mousevpn-network.service"
		exeinto /usr/libexec
		doexe deploy/server/mousevpn-network
	fi

	# Client and server TOML files hold private keys.
	keepdir /etc/mousevpn
	fperms 0700 /etc/mousevpn

	dodoc README.md MANUAL.md ROADMAP.md
	docinto docs
	dodoc docs/*.md
	# nftables and sysctl drafts: read and adapt them before use.
	docinto deploy
	dodoc deploy/client/*.nft
	if use server; then
		dodoc deploy/server/*.nft deploy/server/*.conf
	fi
}

pkg_postinst() {
	elog "Configuration files belong in /etc/mousevpn (mode 0700, root only)."
	elog
	if use client; then
		elog "Install the client TOML issued for this device as"
		elog "/etc/mousevpn/<name>.toml with mode 0600, then connect by hand:"
		elog "    mousevpn-linux-client --config /etc/mousevpn/home.toml"
		elog "Or run it as a service, where <name> is /etc/mousevpn/<name>.toml:"
		elog "    systemctl enable --now mousevpn-client@home.service"
		elog
		elog "Route only a browser or Telegram through the tunnel instead:"
		elog "    systemctl enable --now mousevpn-proxy-client@home.service"
		elog "    # SOCKS5 on 127.0.0.1:1080"
		elog
		elog "Export a copy/paste MV1.… profile for a phone or the GUI:"
		elog "    mousevpn-profile --config /etc/mousevpn/home.toml --name Home"
		elog
		elog "The client needs systemd-resolved for DNS; check it with"
		elog "    systemctl is-active systemd-resolved"
		elog
	fi
	if use server; then
		elog "Review /usr/share/doc/${PF}/deploy before enabling"
		elog "mousevpn-network.service and mousevpn-server.service: the"
		elog "nftables and sysctl drafts must be adapted to this host."
		elog
	fi
	elog "MouseVPN is an early MVP without an independent security audit."
	elog "Do not present it as anonymous or unblockable software."
}
