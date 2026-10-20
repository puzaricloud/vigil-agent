#!/bin/sh
# Vigil server agent installer (POSIX sh). Safe to re-run.
#
#   curl -fsSL https://puzaricloud.in/install-server-agent.sh | sh -s -- --token vgs_xxx [--url https://puzaricloud.in] [--name web-1]
#   curl -fsSL https://puzaricloud.in/install-server-agent.sh | sh -s -- --uninstall
#
# What it does: checks python3 (installs it with apt-get/dnf/yum/apk when missing and running as root), downloads
# vigil-server-agent.py from the Vigil URL to /usr/local/bin/vigil-server-agent, writes /etc/vigil-agent.json (0600)
# with url/token/name, then runs `vigil-server-agent --install`, which registers a systemd service (Linux) or a
# LaunchDaemon (macOS). The agent only needs outbound HTTPS to the Vigil URL.
set -eu

URL="https://puzaricloud.in"
TOKEN=""
NAME=""
ACTION="install"
BIN="/usr/local/bin/vigil-server-agent"
CONF="/etc/vigil-agent.json"

usage() {
    echo "usage: install-server-agent.sh --token vgs_xxx [--url https://puzaricloud.in] [--name web-1] | --uninstall"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --token) TOKEN="$2"; shift 2 ;;
        --token=*) TOKEN="${1#--token=}"; shift ;;
        --url) URL="$2"; shift 2 ;;
        --url=*) URL="${1#--url=}"; shift ;;
        --name) NAME="$2"; shift 2 ;;
        --name=*) NAME="${1#--name=}"; shift ;;
        --uninstall) ACTION="uninstall"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done
URL="${URL%/}"

fail() { echo "ERROR: $*" >&2; exit 1; }
info() { echo "==> $*"; }

if [ "$(id -u)" -ne 0 ]; then
    fail "run as root (sudo). Example: curl -fsSL $URL/install-server-agent.sh | sudo sh -s -- --token vgs_xxx"
fi

if [ "$ACTION" = "uninstall" ]; then
    if [ -f "$BIN" ] && command -v python3 >/dev/null 2>&1; then
        python3 "$BIN" --uninstall || true
    fi
    for f in /etc/systemd/system/vigil-server-agent.service /Library/LaunchDaemons/in.puzaricloud.vigil-agent.plist "$BIN" "$CONF"; do
        [ -e "$f" ] && rm -f "$f" && echo "removed $f"
    done
    command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true
    info "Vigil server agent removed."
    exit 0
fi

[ -n "$TOKEN" ] || [ -f "$CONF" ] || fail "--token is required (find it under Servers > Add server in Vigil)"

# --- python3 ------------------------------------------------------------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    info "python3 not found, installing"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q python3
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q python3
    elif command -v apk >/dev/null 2>&1; then
        apk add --no-cache python3
    else
        fail "python3 is missing and no known package manager was found; install Python 3.8+ and re-run."
    fi
    command -v python3 >/dev/null 2>&1 || fail "python3 still not available after install"
fi
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "0.0")
case "$PYV" in
    3.[0-7]|2.*|0.0) fail "python3 >= 3.8 required (found $PYV)" ;;
esac
info "python3 $PYV"

# --- download the agent -------------------------------------------------------------------------------------------
TMP=$(mktemp "${TMPDIR:-/tmp}/vigil-agent.XXXXXX")
trap 'rm -f "$TMP"' EXIT
SRC="$URL/vigil-server-agent.py"
info "downloading $SRC"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$TMP" "$SRC" || fail "download failed: $SRC"
elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TMP" "$SRC" || fail "download failed: $SRC"
else
    fail "need curl or wget to download the agent"
fi
head -c 200 "$TMP" | grep -q "Vigil server monitoring agent" || fail "downloaded file does not look like the Vigil agent"
python3 -m py_compile "$TMP" 2>/dev/null || fail "downloaded agent does not compile with python3 $PYV"
install -m 0755 "$TMP" "$BIN"
info "installed $BIN"

# --- config -------------------------------------------------------------------------------------------------------
if [ -n "$TOKEN" ]; then
    if [ -f "$CONF" ]; then
        # keep the rest of an existing config (interval, watch lists, commands...), just refresh url/token/name
        python3 - "$CONF" "$URL" "$TOKEN" "$NAME" <<'PY'
import json, sys
path, url, token, name = sys.argv[1:5]
try:
    cfg = json.load(open(path))
except Exception:
    cfg = {}
cfg.update(url=url, token=token)
if name:
    cfg["name"] = name
json.dump(cfg, open(path, "w"), indent=2)
PY
        info "updated $CONF"
    else
        umask 077
        if [ -n "$NAME" ]; then
            printf '{\n  "url": "%s",\n  "token": "%s",\n  "interval": 30,\n  "name": "%s"\n}\n' "$URL" "$TOKEN" "$NAME" > "$CONF"
        else
            printf '{\n  "url": "%s",\n  "token": "%s",\n  "interval": 30\n}\n' "$URL" "$TOKEN" > "$CONF"
        fi
        umask 022
        info "wrote $CONF"
    fi
else
    info "keeping existing $CONF"
fi
chmod 600 "$CONF"

# --- service ------------------------------------------------------------------------------------------------------
info "registering the service"
python3 "$BIN" --install || fail "service setup failed; run 'python3 $BIN --once' to see the error"

echo
echo "Vigil server agent installed and running."
if [ -d /run/systemd/system ]; then
    echo "  status:  systemctl status vigil-server-agent"
    echo "  logs:    journalctl -u vigil-server-agent -f"
elif [ "$(uname -s)" = "Darwin" ]; then
    echo "  status:  sudo launchctl print system/in.puzaricloud.vigil-agent"
    echo "  logs:    tail -f /var/log/vigil-agent.log"
fi
echo "  test:    python3 $BIN --once"
echo "  remove:  curl -fsSL $URL/install-server-agent.sh | sudo sh -s -- --uninstall"
echo "The server should appear in Vigil within a minute."
