#!/bin/sh
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CLIENT="$PROJECT_DIR/target/release/mousevpn-linux-client"
CONFIG=${MOUSEVPN_CLIENT_CONFIG:-"${XDG_CONFIG_HOME:-"$HOME/.config"}/mousevpn/client.toml"}
LOG=/tmp/mousevpn-diagnostic.log

: >"$LOG"
chmod 0600 "$LOG"

section() {
    printf '\n--- %s ---\n' "$1" >>"$LOG"
}

capture() {
    "$@" >>"$LOG" 2>&1 || printf 'command exited with status %s\n' "$?" >>"$LOG"
}

section preflight
capture date --iso-8601=seconds
capture ip -4 route show table main
capture ip -brief address

if [ ! -x "$CLIENT" ]; then
    printf 'client binary is missing: %s\n' "$CLIENT" >>"$LOG"
    printf 'Diagnostic saved to %s\n' "$LOG"
    exit 1
fi

if ip -4 route show table main | grep -Eq '^(0\.0\.0\.0/1|128\.0\.0\.0/1).*amn0'; then
    printf 'Amnezia split-default routes are still active; diagnostic stopped safely.\n' >>"$LOG"
    printf 'Diagnostic saved to %s\n' "$LOG"
    exit 2
fi

sudo -v || {
    printf 'sudo authentication failed\n' >>"$LOG"
    printf 'Diagnostic saved to %s\n' "$LOG"
    exit 3
}

section client
sudo timeout --signal=INT --kill-after=3s 40s "$CLIENT" --config "$CONFIG" >>"$LOG" 2>&1 &
CLIENT_JOB=$!
sleep 3

section tunnel_state
capture ip -brief address show mousevpn0
capture ip -4 route show table main
capture ip -s link show mousevpn0
capture resolvectl status mousevpn0

section numeric_connectivity
capture ping -n -c 2 -W 2 1.1.1.1
capture curl -sS -4 --max-time 5 --resolve api.ipify.org:443:104.26.13.205 https://api.ipify.org

section dns_connectivity
capture curl -sS -4 --max-time 5 https://api.ipify.org

wait "$CLIENT_JOB"
CLIENT_STATUS=$?
printf 'client wrapper exited with status %s\n' "$CLIENT_STATUS" >>"$LOG"

section cleanup_state
capture ip -4 route show table main
capture ip -brief address
capture resolvectl status
capture sudo nft list table inet mousevpn_client_runtime

printf 'Diagnostic saved to %s\n' "$LOG"
