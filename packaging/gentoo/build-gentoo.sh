#!/usr/bin/env bash
# Build MouseVPN as a Gentoo package and install it with emerge.
#
# The script stages the checkout, vendors every crate into the source tarball
# so that the ebuild builds offline under FEATURES="network-sandbox", publishes
# a small binary-free overlay and then merges net-vpn/mousevpn.
#
# Everything up to the tarball runs as the invoking user. Only the steps that
# touch DISTDIR, the overlay and Portage configuration use sudo.
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd -- "${script_dir}/../.." && pwd)"

version="0.1.9"
overlay_dir="/var/db/repos/mousevpn"
repo_name="mousevpn"
work_dir="${TMPDIR:-/var/tmp}/mousevpn-gentoo"
use_flags=""
install_package=1
skip_vendor=0
tarball_only=0
emerge_args=()

usage() {
	cat <<-EOF
		usage: ${0##*/} [options] [-- emerge arguments]

		  --version <X.Y.Z>   package version to build (default: ${version})
		  --use "<flags>"     USE flags for net-vpn/mousevpn, for example
		                      --use "client -gui server"; written to
		                      /etc/portage/package.use/mousevpn
		  --overlay <dir>     overlay location (default: ${overlay_dir})
		  --work <dir>        staging directory (default: ${work_dir})
		  --skip-vendor       reuse an existing tarball in the work directory
		  --tarball-only      stop after the vendored tarball, touch nothing else
		  --no-install        prepare the overlay and distfile, skip emerge
		  -h, --help          this text

		Anything after -- is passed to emerge, for example:
		  ${0##*/} -- --ask --verbose
	EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version) version="$2"; shift 2 ;;
		--use) use_flags="$2"; shift 2 ;;
		--overlay) overlay_dir="$2"; shift 2 ;;
		--work) work_dir="$2"; shift 2 ;;
		--skip-vendor) skip_vendor=1; shift ;;
		--tarball-only) tarball_only=1; shift ;;
		--no-install) install_package=0; shift ;;
		-h|--help) usage; exit 0 ;;
		--) shift; emerge_args=("$@"); break ;;
		*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
	esac
done

package="mousevpn-${version}"
ebuild_file="${script_dir}/net-vpn/mousevpn/${package}.ebuild"
tarball="${work_dir}/${package}-vendored.tar.xz"
stage_dir="${work_dir}/${package}"

as_root() {
	if [[ ${EUID} -eq 0 ]]; then
		"$@"
	else
		sudo "$@"
	fi
}

step() { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }

for tool in cargo git tar xz emerge ebuild portageq; do
	command -v "${tool}" >/dev/null || { echo "missing required tool: ${tool}" >&2; exit 1; }
done

[[ -f ${ebuild_file} ]] || { echo "no ebuild for version ${version}: ${ebuild_file}" >&2; exit 1; }

if [[ ${skip_vendor} -eq 0 ]]; then
	step "Staging the checkout in ${stage_dir}"
	rm -rf "${stage_dir}"
	mkdir -p "${stage_dir}"
	# Tracked files only, taken from the working tree, so local edits are
	# packaged but build output and the CodeGraph index are not.
	git -C "${repo_dir}" ls-files -z \
		| tar -C "${repo_dir}" --null --files-from=- -cf - \
		| tar -C "${stage_dir}" -xf -

	step "Vendoring crates (this needs network access once)"
	# The build inside Portage runs offline; every crate has to be in the
	# tarball. The generated config is discarded: cargo.eclass writes its own.
	( cd "${stage_dir}" && cargo vendor --locked --versioned-dirs vendor >/dev/null )

	step "Packing ${tarball}"
	rm -f "${tarball}"
	tar -C "${work_dir}" -cf - "${package}" | xz -T0 -3 > "${tarball}"
fi

[[ -f ${tarball} ]] || { echo "tarball is missing: ${tarball}" >&2; exit 1; }
printf 'tarball: %s (%s)\n' "${tarball}" "$(du -h "${tarball}" | cut -f1)"

if [[ ${tarball_only} -eq 1 ]]; then
	step "Tarball only, nothing installed"
	exit 0
fi

distdir="$(portageq distdir)"
step "Installing the distfile into ${distdir}"
as_root install -o portage -g portage -m 0644 "${tarball}" "${distdir}/"

step "Publishing the overlay in ${overlay_dir}"
as_root mkdir -p "${overlay_dir}/metadata" "${overlay_dir}/profiles"
as_root tee "${overlay_dir}/metadata/layout.conf" >/dev/null <<-EOF
	masters = gentoo
	thin-manifests = true
	sign-commits = false
	sign-manifests = false
	cache-formats = md5-dict
EOF
printf '%s\n' "${repo_name}" | as_root tee "${overlay_dir}/profiles/repo_name" >/dev/null

for category in net-vpn acct-user acct-group; do
	[[ -d ${script_dir}/${category} ]] || continue
	as_root rm -rf "${overlay_dir}/${category}"
	as_root cp -a "${script_dir}/${category}" "${overlay_dir}/${category}"
done
as_root chown -R root:root "${overlay_dir}"

as_root mkdir -p /etc/portage/repos.conf
as_root tee /etc/portage/repos.conf/mousevpn.conf >/dev/null <<-EOF
	[${repo_name}]
	location = ${overlay_dir}
	auto-sync = false
	priority = 50
EOF

step "Accepting the ~amd64 keyword"
as_root mkdir -p /etc/portage/package.accept_keywords
as_root tee /etc/portage/package.accept_keywords/mousevpn >/dev/null <<-EOF
	net-vpn/mousevpn ~amd64
	acct-user/mousevpn ~amd64
	acct-group/mousevpn ~amd64
EOF

if [[ -n ${use_flags} ]]; then
	step "Setting USE=\"${use_flags}\""
	as_root mkdir -p /etc/portage/package.use
	printf 'net-vpn/mousevpn %s\n' "${use_flags}" \
		| as_root tee /etc/portage/package.use/mousevpn >/dev/null
fi

step "Generating the Manifest"
as_root ebuild "${overlay_dir}/net-vpn/mousevpn/${package}.ebuild" manifest

if [[ ${install_package} -eq 0 ]]; then
	step "Prepared, not installed"
	echo "Install it with:"
	echo "    sudo emerge --verbose =net-vpn/${package}"
	exit 0
fi

step "Merging =net-vpn/${package}"
as_root emerge --verbose "${emerge_args[@]}" "=net-vpn/${package}"

step "Installed"
qlist -I net-vpn/mousevpn >/dev/null 2>&1 && qlist net-vpn/mousevpn | grep '^/usr/bin/' || true
