#!/usr/bin/env python3
"""Vigil server monitoring agent. Single file, standard library only, Python 3.8+.

    curl -fsSL https://puzaricloud.in/install-server-agent.sh | sh -s -- --token vgs_xxx
    python3 vigil-server-agent.py --print                      # collect once, print the JSON report, don't send
    VIGIL_URL=https://puzaricloud.in VIGIL_TOKEN=vgs_... python3 vigil-server-agent.py --once

Every `interval` seconds (default 30; the server may change it) the agent collects host facts, CPU, memory, disks and
disk I/O, network counters, TCP socket states and listening ports, processes (top CPU / memory, distinct names),
systemd/launchd service states, docker containers, a security summary (pending updates, reboot flag, firewall, sshd
auth settings, logins), the numbers printed by custom shell commands and regex match counts from watched log files,
and POSTs it as JSON (gzip-compressed when large) to Vigil. Linux (/proc, /sys) is the primary target; macOS has a
reduced best-effort fallback. Rates (bytes/s, iops, cpu%) are deltas against the previous sample, so they are null
in the very first report.

v1.1 adds application/network observability: "network" (per-peer TCP flows from `ss -tin`, bytes as per-interval deltas,
reverse DNS), "http" (root + Linux: an AF_PACKET sniffer that pairs plaintext HTTP requests with responses and TLS
ClientHellos with the first server data record, plus nginx/apache/caddy access logs) and "traces" (a loopback SDK
listener on 127.0.0.1:9111 accepting POST /v1/spans). `--capture-test 10` sniffs for 10 s and prints the http dict.

Only outbound HTTPS to the Vigil URL is needed. Root is recommended (socket owners, firewall, journal, all processes)
but the agent runs unprivileged with reduced data. Config: /etc/vigil-agent.json, ~/.vigil-agent.json or
$VIGIL_CONFIG; VIGIL_URL / VIGIL_TOKEN env and CLI flags override the file. v1.1 keys: "capture_http": true,
"capture_ports": [], "access_logs": [], "sdk_listener": true, "sdk_port": 9111, "reverse_dns": true, "network_flows": true.

v1.3 reports each log source's access state ("sources": ok / denied / missing) so unreadable files are visible in the dashboard.
v1.2 adds "logs_ship" (raw lines from config "log_ship" file globs and "journal_units" via journalctl, level-tagged, stack traces
joined, "log_ship_max_lines" per interval, the rest counted as dropped), "kubernetes" (auto-detected in-cluster: this node's pods,
conditions, restarts, kubelet cpu/mem; the DaemonSet in install-k8s.yaml mounts the host at /host and sets "proc_root"), "database"
(config "databases": postgresql/mysql/redis health through psql/mysql/redis-cli; passwords go through env, never argv or reports),
"packages" (dpkg/apk/rpm inventory, the full list only when its hash changed or once per 24 h) and "runtimes". `--db-test` runs the
database collector once and prints it.
"""
import argparse
import collections
import datetime
import glob
import gzip
import hashlib
import http.server
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.5"
UA = "VigilServerAgent/" + VERSION
IS_LINUX = sys.platform.startswith("linux")
IS_MAC = sys.platform == "darwin"
BIN = "/usr/local/bin/vigil-server-agent"
CONF = "/etc/vigil-agent.json"
UNIT = "/etc/systemd/system/vigil-server-agent.service"
PLIST = "/Library/LaunchDaemons/in.puzaricloud.vigil-agent.plist"
PSEUDO_FS = {"proc", "sysfs", "tmpfs", "devtmpfs", "squashfs", "overlay", "autofs", "nsfs", "tracefs", "debugfs", "securityfs",
             "pstore", "bpf", "hugetlbfs", "mqueue", "configfs", "ramfs", "devpts", "binfmt_misc", "rpc_pipefs", "fusectl",
             "efivarfs", "selinuxfs", "cgroup", "cgroup2", "sysfs", "devfs", "none"}
WHOLE_DISK = re.compile(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|nvme\d+n\d+|mmcblk\d+|md\d+)$")
SIZE_UNITS = {"b": 1, "kb": 1000, "kib": 1024, "mb": 1000 ** 2, "mib": 1024 ** 2, "gb": 1000 ** 3, "gib": 1024 ** 3, "tb": 1000 ** 4, "tib": 1024 ** 4}
NUM_RE = re.compile(r"-?\d+(?:\.\d+)?")
TCP_STATES = {"01": "established", "06": "time_wait", "0A": "listen"}
PROC, SYS, HOST_ROOT = "/proc", "/sys", ""       # set_host_root("/host") when the host is mounted read-only (Kubernetes DaemonSet, config "proc_root")
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"

def set_host_root(proc_root):
    """proc_root e.g. /host/proc: Linux collectors read /proc, /sys and /etc/os-release under that host mount when it exists."""
    global PROC, SYS, HOST_ROOT
    proc_root = (proc_root or "").rstrip("/")
    if not proc_root or not os.path.isfile(proc_root + "/stat"): return
    PROC = proc_root
    HOST_ROOT = os.path.dirname(proc_root) if os.path.basename(proc_root) == "proc" else ""
    if HOST_ROOT and os.path.isdir(HOST_ROOT + "/sys/class"): SYS = HOST_ROOT + "/sys"

# ----------------------------------------------------------------------------- helpers
def read(path, limit=4 * 1024 * 1024):
    with open(path, "r", errors="replace") as f:
        return f.read(limit)

def try_read(path, default=None):
    try: return read(path)
    except Exception: return default

def run(cmd, timeout=5, shell=False):
    """Run a command with a timeout. Returns (rc, stdout); rc is None when it timed out or could not start."""
    try:
        p = subprocess.run(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return p.returncode, p.stdout.decode(errors="replace")
    except Exception: return None, ""

def which(name):
    return shutil.which(name) is not None

def first_number(text):
    m = NUM_RE.search(text or "")
    if not m: return None
    return float(m.group(0)) if "." in m.group(0) else int(m.group(0))

def pct(part, whole):
    return round(part * 100.0 / whole, 1) if whole else 0.0

LOG_STREAM = sys.stdout                      # --print / --capture-test switch this to stderr so stdout stays valid JSON

def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%S"), msg, flush=True, file=LOG_STREAM)

def is_root():
    return hasattr(os, "geteuid") and os.geteuid() == 0

# ----------------------------------------------------------------------------- pure parsers (Linux /proc text -> dicts)
def parse_proc_stat(text):
    out = {"cpu": None, "per_core": [], "ctxt": 0, "btime": 0, "running": 0, "blocked": 0}
    for line in text.splitlines():
        p = line.split()
        if not p: continue
        if p[0] == "cpu": out["cpu"] = [int(x) for x in p[1:]]
        elif p[0].startswith("cpu"):
            out["per_core"].append([int(x) for x in p[1:]])
        elif p[0] in ("ctxt", "btime", "procs_running", "procs_blocked"):
            out[{"procs_running": "running", "procs_blocked": "blocked"}.get(p[0], p[0])] = int(p[1])
    return out

def cpu_delta(prev, cur):
    """Percentages from two /proc/stat cpu rows: user nice system idle iowait irq softirq steal ..."""
    d = [max(0, c - p) for p, c in zip(prev + [0] * 8, cur + [0] * 8)]
    total = float(sum(d[:8])) or 1.0
    idle = d[3] + d[4]
    return {"pct": round((total - idle) * 100 / total, 1), "user": round((d[0] + d[1]) * 100 / total, 1),
            "system": round((d[2] + d[5] + d[6]) * 100 / total, 1), "iowait": round(d[4] * 100 / total, 1), "steal": round(d[7] * 100 / total, 1)}

def parse_meminfo(text):
    out = {}
    for line in text.splitlines():
        p = line.replace(":", " ").split()
        if len(p) >= 2 and p[1].lstrip("-").isdigit(): out[p[0]] = int(p[1]) * (1024 if len(p) > 2 and p[2].lower() == "kb" else 1)
    return out

def parse_diskstats(text):
    """Whole block devices only: name -> (reads, sectors_read, writes, sectors_written, io_ms)."""
    out = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 14 and WHOLE_DISK.match(p[2]): out[p[2]] = (int(p[3]), int(p[5]), int(p[7]), int(p[9]), int(p[12]))
    return out

def parse_net_dev(text):
    out = {}
    for line in text.splitlines()[2:]:
        if ":" not in line: continue
        name, rest = line.split(":", 1)
        f = rest.split()
        if len(f) >= 16:
            out[name.strip()] = {"rx_bytes": int(f[0]), "rx_errors": int(f[2]), "rx_dropped": int(f[3]), "tx_bytes": int(f[8]), "tx_errors": int(f[10])}
    return out

def parse_proc_net_tcp(text):
    """/proc/net/tcp{,6} -> {"established": n, "time_wait": n, "listen": [(port, inode), ...], "ports": {local port: [inode, ...]} (all states)}"""
    out = {"established": 0, "time_wait": 0, "listen": [], "ports": {}}
    for line in text.splitlines()[1:]:
        p = line.split()
        if len(p) < 10: continue
        state, port, inode = TCP_STATES.get(p[3].upper()), int(p[1].rsplit(":", 1)[1], 16), int(p[9])
        if inode: out["ports"].setdefault(port, []).append(inode)
        if state == "listen":
            out["listen"].append((port, inode))
        elif state:
            out[state] += 1
    return out

def parse_pid_stat(text):
    """/proc/[pid]/stat -> pid, comm, state, ticks (utime+stime), starttime (ticks since boot), rss (pages)."""
    lp, rp = text.index("("), text.rindex(")")
    f = text[rp + 1:].split()
    return {"pid": int(text[:lp].strip()), "comm": text[lp + 1:rp], "state": f[0], "ticks": int(f[11]) + int(f[12]),
            "starttime": int(f[19]), "rss": int(f[21])}

def parse_mounts(text):
    """/proc/mounts -> [(device, mount, fs)] real filesystems only, one entry per device (shortest mount point)."""
    best = {}
    for line in text.splitlines():
        p = line.split()
        if len(p) < 3: continue
        dev, mnt, fs = p[0], p[1].replace("\\040", " ").replace("\\011", "\t"), p[2]
        if fs in PSEUDO_FS or fs.startswith("cgroup") or fs.startswith("fuse.") or dev in PSEUDO_FS: continue
        if mnt.startswith(("/proc", "/sys", "/dev/", "/run/", "/snap/", "/var/lib/docker/", "/var/lib/snapd/")): continue
        if dev not in best or len(mnt) < len(best[dev][1]): best[dev] = (dev, mnt, fs)
    return sorted(best.values(), key=lambda t: t[1])

def linux_mounts(proc, host_root, reader=None):
    """Real filesystems in host terms: [(device, mount point as the host sees it, fs)].
    Bare metal / VM (no host_root): <proc>/mounts, unchanged. In a container with the host mounted read-only (Kubernetes
    DaemonSet, Coolify/Dokploy/CapRover templates: proc_root=/host/proc), <proc>/mounts is a symlink to the *reader's*
    own mount table, so read host PID 1's table (<proc>/1/mounts) instead. If that is not readable, fall back to the
    container's own table and keep only mounts at or under host_root, with that prefix stripped."""
    reader = reader or (lambda path: try_read(path, None))
    if not host_root:
        return parse_mounts(reader(proc + "/mounts") or "")
    hosted = parse_mounts(reader(proc + "/1/mounts") or "")
    if hosted:
        return hosted
    lines = []
    for line in (reader("/proc/self/mounts") or "").splitlines():
        p = line.split()
        if len(p) < 3: continue
        if p[1] == host_root: p[1] = "/"
        elif p[1].startswith(host_root + "/"): p[1] = p[1][len(host_root):]
        else: continue
        lines.append(" ".join(p))
    return parse_mounts("\n".join(lines))

def os_release_kv(text):
    kv = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip().strip('"').strip("'")
    return kv

def parse_os_release(text):
    kv = os_release_kv(text)
    return kv.get("PRETTY_NAME") or ((kv.get("NAME", "") + " " + kv.get("VERSION", "")).strip() or None)

def parse_sshd_config(texts):
    """Files in sshd precedence order (first value wins, Match blocks ignored) -> (password_auth bool, root_login str)."""
    vals = {}
    for text in texts:
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            parts = re.split(r"[\s=]+", line, maxsplit=1)
            if not line or len(parts) != 2: continue
            key = parts[0].lower()
            if key == "match": break
            if key in ("passwordauthentication", "permitrootlogin") and key not in vals: vals[key] = parts[1].strip().lower()
    return vals.get("passwordauthentication", "yes") != "no", vals.get("permitrootlogin", "prohibit-password")

def parse_size(text):
    m = re.match(r"\s*([\d.]+)\s*([a-zA-Z]*)", text or "")
    if not m: return None
    return int(float(m.group(1)) * SIZE_UNITS.get(m.group(2).lower() or "b", 1))

def parse_pct(text):
    v = first_number(text)
    return round(float(v), 2) if v is not None else None

def parse_docker_time(text):
    """docker ps CreatedAt, e.g. '2024-09-15 10:00:00 +0000 UTC' -> unix ts."""
    m = re.match(r"(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4})", text or "")
    try: return int(datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S %z").timestamp())
    except Exception: return None

def docker_state(d):
    s = d.get("State")
    if s: return s.lower()
    st = (d.get("Status") or "").lower()
    for word, state in (("paused", "paused"), ("restarting", "restarting"), ("up", "running"), ("exited", "exited"), ("dead", "dead"), ("created", "created")):
        if st.startswith(word) or ("(" + word + ")") in st: return state
    return "unknown"

def count_pkg_lines(text):
    return sum(1 for l in text.splitlines() if len(l.split()) == 3 and "." in l.split()[0] and not l.startswith(("Obsoleting", "Security", "Last metadata")))

# ----------------------------------------------------------------------------- v1.1 pure parsers: ss flows, http/tls payloads, path templates, access logs, aggregation
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ", b"HEAD ", b"OPTIONS ")
METHOD_NAMES = {m[:-1].decode() for m in HTTP_METHODS}
TLS_VERSIONS = {0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{25,}$")
SS_INFO_RE = re.compile(r"\b(bytes_sent|bytes_received):(\d+)|\brtt:([\d.]+)/[\d.]+")
SS_PROC_RE = re.compile(r'users:\(\("([^"]+)",pid=(\d+)')
HTTP_STATUS_RE = re.compile(rb"^HTTP/1\.[01] (\d{3})")
COMBINED_RE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]*\] "([A-Z]+) (\S+)(?: [^"]*)?" (\d{3}) (\d+|-)')
URL_RE = re.compile(r"^(\w+)://([^/:?#]+)(?::(\d+))?([^?#]*)")
EVENT_KEYS = ("dir", "source", "host", "ip", "port", "process", "method", "path", "status", "ms", "bytes", "tls", "tls_version", "at")
SOURCE_RANK = {"sdk": 0, "capture": 1, "log": 2}

def split_hostport(s):
    """ss address 'ip:port', '[v6]:port', '*:port', '[::ffff:1.2.3.4]:80' -> (ip, port or None)."""
    host, _, port = s.rpartition(":")
    host = host.strip("[]").split("%", 1)[0]
    if host.startswith("::ffff:") and "." in host: host = host[7:]
    return (host or "*"), (int(port) if port.isdigit() else None)

def is_loopback(ip):
    return ip.startswith("127.") or ip == "::1" or ip.startswith("::ffff:127.")

def ss_info(c, line):
    for m in SS_INFO_RE.finditer(line):
        if m.group(3): c["rtt_ms"] = float(m.group(3))
        else: c[m.group(1)] = int(m.group(2))

def parse_ss_output(text, now):
    """`ss -tinH [-p]` (socket line + indented info line) -> [{"state","local_ip","local_port","peer_ip","peer_port","bytes_sent",
    "bytes_received","rtt_ms","process","pid","ts"}]. Byte counters are cumulative per connection."""
    conns, cur = [], None
    for line in text.splitlines():
        if not line.strip(): continue
        if line[0].isspace():
            if cur is not None: ss_info(cur, line)
            continue
        p = line.split()
        if len(p) < 5: continue
        (lip, lport), (pip, pport) = split_hostport(p[3]), split_hostport(p[4])
        cur = {"state": p[0], "local_ip": lip, "local_port": lport, "peer_ip": pip, "peer_port": pport, "bytes_sent": 0, "bytes_received": 0,
               "rtt_ms": None, "process": None, "pid": None, "ts": now}
        m = SS_PROC_RE.search(line)
        if m: cur["process"], cur["pid"] = m.group(1), int(m.group(2))
        ss_info(cur, line)
        conns.append(cur)
    return conns

def aggregate_network(conns, listen_ports, prev, dns):
    """conns from parse_ss_output; listen_ports {port: process}; prev {(local port, peer ip, peer port): (sent, received)} from the previous
    interval; dns {ip: host}. -> (the "network" report key, snapshot for the next call). Bytes are per-interval deltas (new connections
    count fully); LISTEN / TIME-WAIT sockets and loopback peers are skipped."""
    snap, out, inc, remote = {}, {}, {}, set()
    for c in conns:
        pip, pport, lport = c["peer_ip"], c["peer_port"], c["local_port"]
        if not pport or lport is None or pip == "*" or is_loopback(pip) or c["state"] in ("LISTEN", "TIME-WAIT"): continue
        key, sent, recv = (lport, pip, pport), c["bytes_sent"], c["bytes_received"]
        snap[key] = (sent, recv)
        if key in prev and prev[key][0] <= sent and prev[key][1] <= recv: sent, recv = sent - prev[key][0], recv - prev[key][1]
        remote.add(pip)
        if lport in listen_ports:
            e = inc.setdefault(lport, {"port": lport, "process": c["process"] or listen_ports.get(lport), "conns": 0, "clients": {}, "bytes_in": 0, "bytes_out": 0})
            e["conns"] += 1; e["bytes_in"] += recv; e["bytes_out"] += sent
            e["clients"][pip] = e["clients"].get(pip, 0) + 1
        else:
            e = out.setdefault((pip, pport, c["process"]), {"host": dns.get(pip), "ip": pip, "port": pport, "process": c["process"], "conns": 0, "bytes_out": 0, "bytes_in": 0, "rtts": []})
            e["conns"] += 1; e["bytes_out"] += sent; e["bytes_in"] += recv
            if c["rtt_ms"] is not None: e["rtts"].append(c["rtt_ms"])
    outgoing = sorted(out.values(), key=lambda e: -e["conns"])[:100]
    for e in outgoing:
        rtts = e.pop("rtts")
        e["rtt_ms"] = round(sum(rtts) / len(rtts), 1) if rtts else None
    incoming = []
    for e in sorted(inc.values(), key=lambda e: e["port"]):
        clients = e.pop("clients")
        e["clients"] = len(clients)
        e["top_clients"] = [{"ip": ip, "conns": n} for ip, n in sorted(clients.items(), key=lambda kv: (-kv[1], kv[0]))[:10]]
        incoming.append(e)
    totals = {"outgoing_conns": sum(e["conns"] for e in out.values()), "incoming_conns": sum(e["conns"] for e in inc.values()), "unique_remote_hosts": len(remote)}
    return {"outgoing": outgoing, "incoming": incoming, "totals": totals}, snap

def parse_http_request(payload):
    """Start of a plaintext HTTP/1.x request -> {"method","path","host"} or None. Query string stripped; Host header from the first 2 KB."""
    if not payload.startswith(HTTP_METHODS): return None
    head = payload[:2048].decode("latin-1")
    p = head.split("\n", 1)[0].rstrip("\r").split(" ")
    if len(p) < 3 or not p[2].startswith("HTTP/"): return None
    target = p[1]
    if "://" in target:                                  # absolute-form (proxy) request
        rest = target.split("://", 1)[1]
        target = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    m = re.search(r"\r?\n[Hh][Oo][Ss][Tt]:[ \t]*([^\r\n]+)", head)
    host = re.sub(r":\d+$", "", m.group(1).strip().lower()) if m else None      # drop :port, keep [v6] brackets
    return {"method": p[0], "path": target.split("?", 1)[0].split("#", 1)[0] or "/", "host": host or None}

def parse_http_response(payload):
    """Start of an HTTP/1.x response -> {"status": int} or None."""
    m = HTTP_STATUS_RE.match(payload)
    return {"status": int(m.group(1))} if m else None

def tls_extensions(data):
    """TLS extensions block (after its 2-byte length) -> {type: bytes}."""
    exts, i = {}, 0
    while i + 4 <= len(data):
        t, n = int.from_bytes(data[i:i + 2], "big"), int.from_bytes(data[i + 2:i + 4], "big")
        exts[t] = data[i + 4:i + 4 + n]
        i += 4 + n
    return exts

def tls_hello(payload, htype):
    """TLS record carrying handshake type htype -> (record version, handshake body) or None."""
    if len(payload) < 44 or payload[0] != 0x16 or payload[5] != htype: return None
    return int.from_bytes(payload[1:3], "big"), payload[9:9 + int.from_bytes(payload[6:9], "big")]

def parse_tls_client_hello(payload):
    """ClientHello record -> {"sni": host|None, "version": highest offered "1.x"} or None (supported_versions 0x2b beats the legacy field)."""
    r = tls_hello(payload, 0x01)
    if not r: return None
    rec_ver, b = r
    try:
        ver, i = int.from_bytes(b[0:2], "big"), 34
        i += 1 + b[i]                                                     # session id
        i += 2 + int.from_bytes(b[i:i + 2], "big")                        # cipher suites
        i += 1 + b[i]                                                     # compression methods
        exts = tls_extensions(b[i + 2:i + 2 + int.from_bytes(b[i:i + 2], "big")])
    except (IndexError, ValueError): return None
    sni, d, sv = None, exts.get(0), exts.get(0x2b)
    if d and len(d) >= 5 and d[2] == 0:
        sni = d[5:5 + int.from_bytes(d[3:5], "big")].decode("ascii", "replace").lower() or None
    if sv and len(sv) >= 3:
        offered = [int.from_bytes(sv[j:j + 2], "big") for j in range(1, 1 + sv[0], 2)]
        ver = max([v for v in offered if v in TLS_VERSIONS] or [ver])
    return {"sni": sni, "version": TLS_VERSIONS.get(ver) or TLS_VERSIONS.get(rec_ver)}

def parse_tls_server_hello(payload):
    """ServerHello record -> {"version": "1.3"|"1.2"|...} or None; TLS 1.3 is signalled in supported_versions (0x2b)."""
    r = tls_hello(payload, 0x02)
    if not r: return None
    rec_ver, b = r
    try:
        ver, i = int.from_bytes(b[0:2], "big"), 34
        i += 1 + b[i] + 3                                                 # session id, cipher suite, compression
        sv = tls_extensions(b[i + 2:i + 2 + int.from_bytes(b[i:i + 2], "big")]).get(0x2b)
        if sv and len(sv) >= 2: ver = int.from_bytes(sv[:2], "big")
    except (IndexError, ValueError): return None
    return {"version": TLS_VERSIONS.get(ver) or TLS_VERSIONS.get(rec_ver)}

def template_path(path):
    """/users/123/x/550e8400-e29b-41d4-a716-446655440000 -> /users/{id}/x/{uuid}; hex >= 16 -> {hash}; long base64-ish -> {token}; query stripped."""
    segs = []
    for s in (path or "/").split("?", 1)[0].split("#", 1)[0][:300].split("/"):
        if s.isdigit(): s = "{id}"
        elif UUID_RE.match(s): s = "{uuid}"
        elif HEX_RE.match(s): s = "{hash}"
        elif TOKEN_RE.match(s): s = "{token}"
        segs.append(s)
    return "/".join(segs) or "/"

def parse_access_log_line(line, fmt):
    """nginx/apache combined line (optionally followed by nginx $request_time) or caddy JSON -> {"ip","method","path","host","status","bytes","ms"} or None."""
    if fmt == "caddy": return parse_caddy_json_line(line)
    m = COMBINED_RE.match(line)
    if not m: return None
    rest = re.sub(r'"[^"]*"', "", line[m.end():])                        # drop referer / ua / x-forwarded-for, keep bare numbers
    t = re.search(r"(?:^|\s)(\d+\.\d+)(?=\s|$)", rest)
    return {"ip": m.group(1), "method": m.group(2), "path": m.group(3).split("?", 1)[0], "host": None, "status": int(m.group(4)),
            "bytes": int(m.group(5)) if m.group(5).isdigit() else 0, "ms": round(float(t.group(1)) * 1000, 1) if t else None}

def parse_caddy_json_line(line):
    try: d = json.loads(line)
    except ValueError: return None
    r = d.get("request") if isinstance(d, dict) else None
    if not isinstance(r, dict) or "status" not in d: return None
    dur = d.get("duration")
    ip = r.get("remote_ip") or (r.get("remote_addr") or "").rsplit(":", 1)[0].strip("[]") or None
    return {"ip": ip, "method": r.get("method") or "GET", "path": (r.get("uri") or "/").split("?", 1)[0], "host": r.get("host"), "status": int(d.get("status") or 0),
            "bytes": int(d.get("size") or 0), "ms": round(float(dur) * 1000, 1) if isinstance(dur, (int, float)) else None}

def percentiles(samples):
    """-> (p50, p95, max) rounded to 0.1 ms, or (None, None, None)."""
    if not samples: return None, None, None
    s = sorted(samples)
    return round(s[int(0.5 * (len(s) - 1))], 1), round(s[int(0.95 * (len(s) - 1))], 1), round(s[-1], 1)

def aggregate_http(events):
    """events: dicts with EVENT_KEYS (dir in|out, source capture|log|sdk, host, ip, port, process, method, path, status, ms, bytes, tls, tls_version, at)
    -> {"incoming","outgoing","slow"} per the v1.1 schema. Paths are templated; up to 2000 latency samples per endpoint; top 200 per direction.
    Incoming precedence per (method, path): sdk > capture > log. Outgoing: an SDK entry is dropped when capture saw the same host."""
    groups = {}
    for ev in events:
        tpath = template_path(ev.get("path")) if ev.get("path") else ""
        method, tls = ev.get("method") or "", bool(ev.get("tls"))
        if ev["dir"] == "in": key = ("in", ev.get("source"), ev.get("port") or 0, ev.get("process"), ev.get("host"), method, tpath, tls)
        else: key = ("out", ev.get("source"), ev.get("host") or ev.get("ip"), ev.get("port") or 0, ev.get("process"), method, tpath, tls)
        g = groups.get(key)
        if g is None: g = groups[key] = {"count": 0, "errors_4xx": 0, "errors_5xx": 0, "bytes": 0, "ms": [], "ip": ev.get("ip"), "tls_version": None}
        g["count"] += 1
        g["bytes"] += ev.get("bytes") or 0
        st = ev.get("status")
        if st is not None and 400 <= st < 500: g["errors_4xx"] += 1
        elif st is not None and st >= 500: g["errors_5xx"] += 1
        if ev.get("ms") is not None and len(g["ms"]) < 2000: g["ms"].append(ev["ms"])
        if ev.get("tls_version") and not g["tls_version"]: g["tls_version"] = ev["tls_version"]
    incoming, outgoing, claimed_in = [], [], {}
    captured_hosts = {k[2] for k in groups if k[0] == "out" and k[1] == "capture"}
    for key, g in sorted(groups.items(), key=lambda kv: (SOURCE_RANK.get(kv[0][1], 3), -kv[1]["count"])):
        p50, p95, mx = percentiles(g["ms"])
        base = {"count": g["count"], "errors_4xx": g["errors_4xx"], "errors_5xx": g["errors_5xx"], "p50_ms": p50, "p95_ms": p95, "max_ms": mx, "bytes": g["bytes"], "source": key[1], "hist": latency_hist(g["ms"])}
        if key[0] == "in":
            _, source, port, process, host, method, tpath, tls = key
            if claimed_in.setdefault((method, tpath), source) != source: continue
            incoming.append(dict(port=port, process=process, host=host, method=method, path=tpath, tls=tls, tls_version=g["tls_version"], **base))
        else:
            _, source, host, port, process, method, tpath, tls = key
            if source != "capture" and host in captured_hosts: continue
            outgoing.append(dict(host=host, ip=g["ip"], port=port, process=process, method=method, path=tpath, tls=tls, tls_version=g["tls_version"], **base))
    incoming.sort(key=lambda e: -e["count"])
    outgoing.sort(key=lambda e: -e["count"])
    slow = sorted((ev for ev in events if ev.get("ms") is not None), key=lambda ev: (not ((ev.get("status") or 0) >= 500), -ev["ms"]))[:20]
    slow = [{"at": round(ev.get("at") or 0, 3), "direction": ev["dir"], "host": ev.get("host") or (ev.get("ip") if ev["dir"] == "out" else None), "method": ev.get("method") or "",
             "path": template_path(ev.get("path")) if ev.get("path") else "", "status": ev.get("status"), "ms": round(ev["ms"], 1), "process": ev.get("process")} for ev in slow]
    return {"incoming": incoming[:200], "outgoing": outgoing[:200], "slow": slow}

def span_error(s):
    st = s.get("status")
    return bool(s.get("error")) or (isinstance(st, int) and st >= 500)

def span_target(s):
    a = s.get("attrs") or {}
    t = a.get("peer.host") or a.get("http.host") or a.get("db.system")
    if not t and a.get("http.url"):
        m = URL_RE.match(str(a["http.url"]))
        t = m.group(2) if m else None
    return str(t or s.get("name") or "?")

HIST_BUCKETS = (25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)

def latency_hist(samples):
    """Counts per latency bucket (<=25 ... <=10000, >10000 ms); the server computes Apdex from it for any threshold."""
    h = [0] * (len(HIST_BUCKETS) + 1)
    for ms in samples:
        for i, b in enumerate(HIST_BUCKETS):
            if ms <= b: h[i] += 1; break
        else: h[-1] += 1
    return h

SPAN_ATTRS = ("http.method", "http.route", "http.url", "http.host", "http.status", "db.system", "db.statement", "peer.host", "peer.port", "messaging.system", "error.type", "error.message", "user.id", "request.id")
RAW_SPAN_CAP, RAW_BYTES_CAP = 2500, 600_000

def raw_spans(spans):
    """v1.5: ship the spans themselves (attribute whitelist, values <= 300 chars) so the server builds endpoints, slow queries,
    outbound calls, N+1 issues and stored traces. Over the cap, whole traces are dropped (fastest first) rather than partial ones."""
    out = []
    for s in spans:
        a = s.get("attrs") or {}
        out.append({"trace_id": s.get("trace_id"), "span_id": s.get("span_id"), "parent_id": s.get("parent_id"), "service": s.get("service"), "name": str(s.get("name") or "")[:200],
                    "kind": s.get("kind"), "start_ms": s.get("start_ms"), "duration_ms": s.get("duration_ms"), "status": s.get("status"), "error": s.get("error"),
                    "attrs": {k: (a[k][:300] if isinstance(a[k], str) else a[k]) for k in SPAN_ATTRS if a.get(k) is not None}})
    if len(out) > RAW_SPAN_CAP or len(json.dumps(out)) > RAW_BYTES_CAP:
        by_trace = {}
        for s in out: by_trace.setdefault(s.get("trace_id"), []).append(s)
        def worst(ss):
            root = next((x for x in ss if not x.get("parent_id")), ss[0])
            return (not (root.get("error") or (isinstance(root.get("status"), int) and root["status"] >= 500)), -float(root.get("duration_ms") or 0))
        kept, n, size = [], 0, 0
        for tid, ss in sorted(by_trace.items(), key=lambda kv: worst(kv[1])):
            chunk = len(json.dumps(ss))
            if n + len(ss) > RAW_SPAN_CAP or size + chunk > RAW_BYTES_CAP: continue
            kept += ss; n += len(ss); size += chunk
        out = kept
    return out

def aggregate_traces(spans):
    """SDK spans (each tagged with "service") -> the "traces" report key: endpoints from server spans, dependencies from client/db/cache/queue
    spans, and the 30 worst traces (root error / 5xx first, then longest root) with <= 40 spans each, start_ms relative to the root."""
    ends, deps, by_trace, services = {}, {}, {}, set()
    for s in spans:
        svc, a, kind = str(s.get("service") or "?"), s.get("attrs") or {}, s.get("kind") or "internal"
        services.add(svc)
        e = None
        if kind == "server":
            route = a.get("http.route")
            name = ((str(a["http.method"]) + " ") if route and a.get("http.method") else "") + str(route or s.get("name") or "?")
            e = ends.setdefault((svc, name), {"service": svc, "name": name, "count": 0, "errors": 0, "ms": []})
        elif kind in ("client", "db", "cache", "queue"):
            target = span_target(s)
            e = deps.setdefault((svc, target, kind), {"service": svc, "target": target, "kind": "http" if kind == "client" else kind, "count": 0, "errors": 0, "ms": []})
        if e is not None:
            e["count"] += 1
            e["errors"] += 1 if span_error(s) else 0
            if len(e["ms"]) < 2000: e["ms"].append(float(s.get("duration_ms") or 0))
        if s.get("trace_id"): by_trace.setdefault(str(s["trace_id"]), []).append(s)
    endpoints = sorted(ends.values(), key=lambda e: -e["count"])[:200]
    for e in endpoints: e["p50_ms"], e["p95_ms"], _ = percentiles(e.pop("ms"))
    dependencies = sorted(deps.values(), key=lambda e: -e["count"])[:200]
    for e in dependencies: _, e["p95_ms"], _ = percentiles(e.pop("ms"))
    traces = []
    for tid, ss in by_trace.items():
        root = next((s for s in ss if not s.get("parent_id")), None) or min(ss, key=lambda s: s.get("start_ms") or 0)
        a, t0 = root.get("attrs") or {}, float(root.get("start_ms") or 0)
        st = root.get("status") if root.get("status") is not None else a.get("http.status")
        traces.append({"trace_id": tid, "service": root.get("service"), "root": {"name": root.get("name"), "status": st, "ms": round(float(root.get("duration_ms") or 0), 1), "at": round(t0 / 1000.0, 3)},
                       "spans": [{"name": s.get("name"), "kind": s.get("kind"), "start_ms": round(float(s.get("start_ms") or t0) - t0, 1), "ms": round(float(s.get("duration_ms") or 0), 1),
                                  "status": s.get("status"), "error": s.get("error"), "parent": s.get("parent_id")} for s in sorted(ss, key=lambda s: s.get("start_ms") or 0)[:40]],
                       "_err": span_error(root)})
    traces.sort(key=lambda t: (not t["_err"], -t["root"]["ms"]))
    for t in traces: del t["_err"]
    return {"sdk_services": sorted(services), "spans": len(spans), "endpoints": endpoints, "dependencies": dependencies, "traces": traces[:30]}

def spans_to_http_events(spans):
    """SDK server spans -> incoming http events (source "sdk"); client spans with an http.url/http.host -> outgoing events."""
    out = []
    for s in spans:
        a, name = s.get("attrs") or {}, str(s.get("name") or "")
        m = URL_RE.match(str(a.get("http.url") or ""))
        st = s.get("status") if s.get("status") is not None else a.get("http.status")
        method = str(a.get("http.method") or (name.split(" ")[0] if name.split(" ")[0] in METHOD_NAMES else ""))
        ev = {"source": "sdk", "process": s.get("service"), "method": method, "status": st if isinstance(st, int) else None, "ms": float(s.get("duration_ms") or 0),
              "bytes": 0, "at": float(s.get("start_ms") or 0) / 1000.0, "ip": None, "tls_version": None}
        if s.get("kind") == "server":
            ev.update(dir="in", port=0, tls=False, host=a.get("http.host") or (m.group(2) if m else None),
                      path=a.get("http.route") or (m.group(4) if m else None) or (name.split(" ", 1)[1] if " " in name else name))
        elif s.get("kind") == "client" and (m or a.get("http.host")):
            scheme = m.group(1).lower() if m else "http"
            ev.update(dir="out", host=a.get("http.host") or m.group(2), tls=scheme == "https", path=(m.group(4) if m else "") or "/",
                      port=int(m.group(3)) if m and m.group(3) else int(a.get("peer.port") or (443 if scheme == "https" else 80)))
        else: continue
        out.append(ev)
    return out

PROM_LINE = re.compile(r"^([A-Za-z_:][A-Za-z0-9_:]*)(\{[^}]*\})?\s+([-+]?(?:\d+\.?\d*(?:[eE][-+]?\d+)?|NaN|[-+]?Inf))(?:\s+\d+)?\s*$")

# ----------------------------------------------------------------------------- v1.2 pure parsers: log lines, journal json, kubernetes, database output, packages
LINE_MAX = 2000
LEVEL_RES = (("error", re.compile(r"\b(?:ERROR|CRITICAL|FATAL|EMERG(?:ENCY)?|ALERT|PANIC|ERR)\b", re.I)), ("warn", re.compile(r"\bWARN(?:ING)?\b", re.I)),
             ("info", re.compile(r"\bINFO\b", re.I)), ("debug", re.compile(r"\b(?:DEBUG|TRACE)\b", re.I)))
PRIORITY_LEVEL = {0: "error", 1: "error", 2: "error", 3: "error", 4: "warn", 5: "info", 6: "info", 7: "debug"}
EXC_RE = re.compile(r"^[\w.]*(?:Error|Exception|Warning|Exit|Interrupt|Fault|Timeout)\b|^(?:During handling of the above|The above exception)")
APK_RE = re.compile(r"^(.+?)-(\d[^-]*-r\d+)$")
DSN_PW_RE = re.compile(r"(://[^:/@\s]*:)[^@\s]*@")

def detect_level(line):
    """error | warn | info | debug | None from the words in a log line (ERROR/CRITICAL/FATAL, WARN, INFO, DEBUG; case-insensitive)."""
    for level, rx in LEVEL_RES:
        if rx.search(line): return level
    return None

def join_multiline(lines):
    """Continuation lines (leading whitespace, 'at ', Java 'Caused by:' / '... n more', a Python 'Traceback' header and the exception line closing it) are
    appended with newlines to the previous line; blank lines are dropped; every joined line is capped at LINE_MAX chars."""
    out, cont = [], False
    for line in lines:
        line = line.rstrip("\r")
        if not line.strip(): continue
        is_cont = line[0] in " \t" or line.startswith(("at ", "Caused by: ", "... ", "Traceback (most recent call last):")) or (cont and EXC_RE.match(line) is not None)
        if is_cont and out:
            if len(out[-1]) < LINE_MAX: out[-1] = (out[-1] + "\n" + line)[:LINE_MAX]
        else: out.append(line[:LINE_MAX])
        cont = is_cont
    return out

def parse_journal_json_line(line):
    """`journalctl -o json` line -> {"ts": s, "us": µs, "unit", "priority", "level", "message"} or None. MESSAGE may be a byte array when not UTF-8."""
    try: d = json.loads(line)
    except ValueError: return None
    if not isinstance(d, dict): return None
    msg = d.get("MESSAGE")
    if isinstance(msg, list): msg = bytes(b for b in msg if isinstance(b, int) and 0 <= b < 256).decode(errors="replace")
    msg = "" if msg is None else str(msg)
    try: us = int(d.get("__REALTIME_TIMESTAMP") or 0)
    except (TypeError, ValueError): us = 0
    try: prio = int(d["PRIORITY"]) if d.get("PRIORITY") is not None else None
    except (TypeError, ValueError): prio = None
    return {"ts": round(us / 1e6, 3), "us": us, "unit": d.get("_SYSTEMD_UNIT") or d.get("UNIT"), "priority": prio,
            "level": PRIORITY_LEVEL.get(prio) or detect_level(msg), "message": msg}

def k8s_age(ts_text, now):
    try: return max(0, int(now - datetime.datetime.strptime(ts_text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp()))
    except Exception: return None

def parse_k8s_pods(obj, restarts_prev, now=None):
    """/api/v1/pods list -> (pods per the schema, <= 300 with unhealthy ones first; totals; {"ns/name": restarts}). restarts_1h is the growth of
    each pod's restart count against restarts_prev (the snapshot taken about an hour ago); pods absent from it count fully when younger than 1 h."""
    now, pods, cur, r1h = now or time.time(), [], {}, 0
    for item in (obj.get("items") or []) if isinstance(obj, dict) else []:
        meta, spec, st = item.get("metadata") or {}, item.get("spec") or {}, item.get("status") or {}
        images = {c.get("name"): c.get("image") for c in spec.get("containers") or []}
        containers, restarts = [], 0
        for cs in st.get("containerStatuses") or []:
            state = cs.get("state") or {}
            kind = next((k for k in ("running", "waiting", "terminated") if k in state), "waiting")
            reason = (state.get(kind) or {}).get("reason")
            if not reason and kind != "running": reason = ((cs.get("lastState") or {}).get("terminated") or {}).get("reason")
            n = int(cs.get("restartCount") or 0)
            restarts += n
            containers.append({"name": cs.get("name"), "image": cs.get("image") or images.get(cs.get("name")), "ready": bool(cs.get("ready")), "restarts": n,
                               "state": kind, "reason": reason or None, "cpu_millicores": None, "mem_bytes": None})
        owner, key, age = (meta.get("ownerReferences") or [{}])[0], "%s/%s" % (meta.get("namespace"), meta.get("name")), k8s_age(meta.get("creationTimestamp"), now)
        cur[key] = restarts
        if key in restarts_prev: r1h += max(0, restarts - restarts_prev[key])
        elif age is not None and age <= 3600: r1h += restarts
        pods.append({"namespace": meta.get("namespace"), "name": meta.get("name"), "phase": st.get("phase") or "Unknown", "restarts": restarts, "age_s": age,
                     "owner": ("%s/%s" % (owner["kind"], owner.get("name"))) if owner.get("kind") else None, "containers": containers})
    phases = collections.Counter(p["phase"] for p in pods)
    pods.sort(key=lambda p: (p["phase"] == "Running" and all(c["ready"] for c in p["containers"]), -p["restarts"], p["namespace"] or "", p["name"] or ""))
    totals = {"pods": len(pods), "running": phases.get("Running", 0), "pending": phases.get("Pending", 0), "failed": phases.get("Failed", 0), "restarts_1h": r1h}
    return pods[:300], totals, cur

def kubelet_usage(d):
    cpu, mem = (d.get("cpu") or {}).get("usageNanoCores"), (d.get("memory") or {}).get("workingSetBytes")
    return {"cpu_millicores": round(cpu / 1e6, 1) if isinstance(cpu, (int, float)) else None, "mem_bytes": int(mem) if isinstance(mem, (int, float)) else None}

def parse_kubelet_summary(obj):
    """kubelet /stats/summary -> {"ns/pod": {"cpu_millicores", "mem_bytes", "containers": {name: {"cpu_millicores", "mem_bytes"}}}}."""
    out = {}
    for p in (obj.get("pods") or []) if isinstance(obj, dict) else []:
        ref = p.get("podRef") or {}
        e = out["%s/%s" % (ref.get("namespace"), ref.get("name"))] = dict(kubelet_usage(p), containers={})
        for c in p.get("containers") or []: e["containers"][c.get("name")] = kubelet_usage(c)
    return out

def parse_k8s_node(obj):
    """/api/v1/nodes/<name> -> (role, {condition type: bool}, InternalIP or None)."""
    obj = obj if isinstance(obj, dict) else {}
    labels, st = (obj.get("metadata") or {}).get("labels") or {}, obj.get("status") or {}
    role = "control-plane" if any(l.startswith(("node-role.kubernetes.io/control-plane", "node-role.kubernetes.io/master")) for l in labels) else "worker"
    conds = {c["type"]: c.get("status") == "True" for c in st.get("conditions") or [] if c.get("type")}
    return role, conds, next((a.get("address") for a in st.get("addresses") or [] if a.get("type") == "InternalIP"), None)

def parse_dsn(dsn):
    """postgresql://user:p%40ss@host:5432/db?x=y -> {"scheme","user","password","host","port","db","query"}. The userinfo is split on the LAST '@'
    so unescaped '@' ':' '/' inside passwords survive; %XX escapes are decoded; host "" means the client's default (unix socket / localhost)."""
    scheme, _, rest = str(dsn or "").partition("://")
    userinfo, sep, hostpart = rest.rpartition("@")
    hostpart, _, query = hostpart.partition("?")
    hostport, _, db = hostpart.partition("/")
    user, has_pw, password = userinfo.partition(":")
    if hostport.startswith("["): host, _, port = hostport[1:].partition("]"); port = port.lstrip(":")
    else: host, _, port = hostport.partition(":")
    uq = urllib.parse.unquote
    return {"scheme": scheme.lower(), "user": uq(user), "password": uq(password) if has_pw else "", "host": uq(host), "port": int(port) if port.isdigit() else None,
            "db": uq(db.split("#", 1)[0]), "query": query}

def strip_secrets(text, secrets=()):
    """Passwords in DSNs (scheme://user:PW@) and every string in secrets (3+ chars, shorter ones would mangle ordinary words) -> '***'."""
    text = DSN_PW_RE.sub(r"\1***@", str(text))
    for s in secrets:
        if s and len(str(s)) >= 3: text = text.replace(str(s), "***")
    return text

def num(v):
    try: return float(v) if "." in str(v) or "e" in str(v).lower() else int(v)
    except (TypeError, ValueError): return None

def parse_pg_stat_lines(text):
    """psql -A -t -F '|' output of tagged SELECTs ("SELECT 'stat', a, b") -> {tag: [fields]}; 'top' rows (calls|mean|total|query) collect in a list."""
    out = {"top": []}
    for line in text.splitlines():
        if "|" not in line: continue
        tag = line.split("|", 1)[0]
        if tag == "top":
            f = line.split("|", 4)
            if len(f) == 5: out["top"].append(f[1:])
        else: out[tag] = line.split("|")[1:]
    return out

def parse_mysql_kv(text):
    """`mysql -N -B` rows of 'Name<TAB>Value' (SHOW GLOBAL STATUS / VARIABLES, 2-column SELECTs) -> {name: value}; other rows ignored."""
    out = {}
    for line in text.splitlines():
        p = line.split("\t")
        if len(p) == 2 and p[0]: out[p[0]] = p[1]
    return out

def parse_replica_lag(text):
    """`SHOW REPLICA|SLAVE STATUS\\G` -> Seconds_Behind_Source|Master as float, or None (not a replica / NULL)."""
    m = re.search(r"Seconds_Behind_(?:Source|Master):\s*(\S+)", text or "")
    return num(m.group(1)) if m and m.group(1).upper() != "NULL" else None

def redis_info_to_dict(text):
    """redis INFO text -> {field: value str}; keyspace lines db0:keys=1,... are kept raw and summed into "_keys"."""
    out, keys = {}, 0
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line: continue
        k, v = line.split(":", 1)
        out[k] = v
        m = re.match(r"^db\d+$", k) and re.match(r"keys=(\d+)", v)
        if m: keys += int(m.group(1))
    out["_keys"] = str(keys)
    return out

def parse_dpkg_lines(text):
    """'name version' per line (dpkg-query -W -f, rpm -qa --qf) -> sorted [(name, version)]."""
    return sorted({(p[0], p[1]) for p in (l.split() for l in text.splitlines()) if len(p) >= 2})

def parse_apk_lines(text):
    """`apk info -v` lines 'name-1.2.3-r0' -> sorted [(name, version)]."""
    return sorted({m.groups() for m in (APK_RE.match(l.strip()) for l in text.splitlines()) if m})

def package_hash(items):
    return hashlib.sha1("\n".join("%s %s" % nv for nv in sorted(items)).encode()).hexdigest()

def packages_payload(items, ecosystem, release, state, now):
    """-> the "packages" key; updates state in place. The item list (<= 5000) is included when the sha1 of the sorted list differs from
    state["pkg_hash"] or the last full send (state["pkg_sent"]) is older than 24 h; otherwise only ecosystem/release/count/hash."""
    h = package_hash(items)
    out = {"ecosystem": ecosystem, "release": release, "count": len(items), "hash": h}
    if h != state.get("pkg_hash") or now - (state.get("pkg_sent") or 0) >= 86400:
        out["items"] = [{"name": n, "version": v} for n, v in items[:5000]]
        state.update(pkg_hash=h, pkg_sent=now)
    return out

# ----------------------------------------------------------------------------- slow, cached collectors (updates, public ip)
class Cache:
    """Refreshes a slow value at most every ttl seconds, in a background thread unless sync=True."""

    def __init__(self, fn, ttl):
        self.fn, self.ttl, self.value, self.ts, self.thread = fn, ttl, None, 0, None

    def get(self, sync=False):
        if time.time() - self.ts >= self.ttl:
            if sync:
                self.refresh()
            elif not (self.thread and self.thread.is_alive()):
                self.thread = threading.Thread(target=self.refresh, daemon=True)
                self.thread.start()
        return self.value

    def refresh(self):
        try: self.value = self.fn()
        except Exception: self.value = None
        self.ts = time.time()

def fetch_public_ip():
    req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=5, context=ssl.create_default_context()) as r:
        ip = r.read(64).decode().strip()
    return ip if re.match(r"^[0-9a-fA-F.:]+$", ip) else None

def check_updates():
    """-> {"updates_pending", "security_updates", "checked"}; apt list is cheap, dnf/yum check-update is slow (rc 100 = updates)."""
    res = {"updates_pending": None, "security_updates": None, "checked": int(time.time())}
    if which("apt"):
        rc, out = run(["apt", "list", "--upgradable"], timeout=25)
        if rc == 0:
            lines = [l for l in out.splitlines() if "/" in l]
            res.update(updates_pending=len(lines), security_updates=sum(1 for l in lines if "-security" in l))
        return res
    for tool in ("dnf", "yum"):
        if which(tool):
            rc, out = run([tool, "-q", "check-update"], timeout=60)
            if rc in (0, 100):
                res["updates_pending"] = count_pkg_lines(out) if rc == 100 else 0
                rc2, out2 = run([tool, "-q", "check-update", "--security"], timeout=60)
                if rc2 in (0, 100): res["security_updates"] = count_pkg_lines(out2) if rc2 == 100 else 0
            return res
    return res

def reboot_required():
    if os.path.exists("/var/run/reboot-required") or os.path.exists("/run/reboot-required"): return True
    if which("needs-restarting"):
        rc, _ = run(["needs-restarting", "-r"], timeout=15)
        return None if rc is None else rc == 1
    return False if which("apt") else None

def firewall_state():
    tools = [t for t in ("ufw", "firewall-cmd", "nft", "iptables") if which(t)]
    fallback = None
    if "ufw" in tools:
        rc, out = run(["ufw", "status"], timeout=5)
        if rc == 0 and "Status: active" in out: return "ufw active"
        fallback = "ufw inactive" if rc == 0 else None
    if "firewall-cmd" in tools:
        rc, out = run(["firewall-cmd", "--state"], timeout=5)
        if rc == 0 and "running" in out: return "firewalld active"
    if "nft" in tools:
        rc, out = run(["nft", "list", "ruleset"], timeout=5)
        if rc == 0 and out.strip(): return "nftables"
    if "iptables" in tools:
        rc, out = run(["iptables", "-S"], timeout=5)
        if rc == 0 and len(out.strip().splitlines()) > 3: return "iptables"
        if rc == 0: return fallback or "none"
    if fallback: return fallback
    return "none" if not tools else "unknown"

def failed_logins_24h():
    if which("journalctl"):
        rc, out = run(["journalctl", "-u", "ssh", "-u", "sshd", "--since", "24 hours ago", "--no-pager", "-q"], timeout=10)
        if rc == 0 and (out or is_root()): return out.count("Failed password")
    now = time.time()
    days = {time.strftime("%b %e", time.localtime(now - d * 86400)).replace("  ", " ") for d in (0, 1)} | {time.strftime("%Y-%m-%d", time.localtime(now - d * 86400)) for d in (0, 1)}
    for path in ("/var/log/auth.log", "/var/log/secure"):
        try:
            with open(path, "rb") as f:
                f.seek(0, 2)
                f.seek(max(0, f.tell() - 8 * 1024 * 1024))
                text = f.read().decode(errors="replace")
        except Exception: continue
        return sum(1 for l in text.splitlines() if "Failed password" in l and any(l.replace("  ", " ").startswith(d) for d in days))
    return None

# ----------------------------------------------------------------------------- v1.1 runtime: reverse dns, port owners, packet capture, sdk listener
BPF_TCP = [(0x28, 0, 0, 0x0c), (0x15, 0, 2, 0x86dd), (0x30, 0, 0, 0x14), (0x15, 3, 4, 0x06), (0x15, 0, 3, 0x0800), (0x30, 0, 0, 0x17),
           (0x15, 0, 1, 0x06), (0x06, 0, 0, 0x40000), (0x06, 0, 0, 0)]          # tcpdump -dd "tcp"
SO_ATTACH_FILTER = 26
ACCESS_LOG_PATHS = ("/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/httpd/access_log")

def hex_ip(h):
    """/proc/net/tcp{,6} hex address (host-order 32-bit words) -> dotted / colon string."""
    words = [bytes.fromhex(h[i:i + 8]) for i in range(0, len(h), 8)]
    raw = b"".join(w[::-1] if sys.byteorder == "little" else w for w in words)
    return socket.inet_ntoa(raw) if len(raw) == 4 else socket.inet_ntop(socket.AF_INET6, raw)

def local_addresses():
    """The machine's own IPs: /proc/net/if_inet6, `ip -o -4 addr`, /proc/net/fib_trie LOCAL routes, listening-socket addresses (macOS: ifconfig)."""
    ips = {"127.0.0.1", "::1"}
    for line in try_read(PROC + "/net/if_inet6", "").splitlines():
        p = line.split()
        if p and len(p[0]) == 32:
            try: ips.add(hex_ip(p[0]))
            except Exception: pass
    rc, out = run(["ip", "-o", "-4", "addr"], timeout=3) if IS_LINUX else run(["ifconfig"], timeout=3)
    ips.update(m.split("/")[0] for m in re.findall(r"inet6? ([0-9a-fA-F.:]+)", out or ""))
    prev = None
    for line in try_read(PROC + "/net/fib_trie", "").splitlines():
        if "LOCAL" in line and prev: ips.add(prev)
        m = re.search(r"\|-- (\d+\.\d+\.\d+\.\d+)", line)
        prev = m.group(1) if m else None
    for path in (PROC + "/net/tcp", PROC + "/net/tcp6"):
        for line in try_read(path, "").splitlines()[1:]:
            p = line.split()
            if len(p) >= 4 and p[3] == "0A" and set(p[1].split(":")[0]) != {"0"}:
                try: ips.add(hex_ip(p[1].split(":")[0]))
                except Exception: pass
    return ips

def inode_owners(want, deadline=2.0):
    """socket inode -> pid (str) by scanning /proc/*/fd (root only; bounded by deadline seconds)."""
    owner, stop = {}, time.time() + deadline
    if not want or not IS_LINUX: return owner
    for d in os.listdir(PROC):
        if not d.isdigit() or time.time() > stop: continue
        try:
            for fd in os.listdir(PROC + "/%s/fd" % d):
                try: link = os.readlink(PROC + "/%s/fd/%s" % (d, fd))
                except OSError: continue
                if link.startswith("socket:[") and int(link[8:-1]) in want: owner[int(link[8:-1])] = d
        except OSError: continue
    return owner

def parse_packet(frame):
    """Ethernet (+802.1Q) / IPv4 | IPv6 (next header 6 only) / TCP -> (src, sport, dst, dport, payload) or None when not TCP or empty payload."""
    if len(frame) < 34: return None
    et, off = int.from_bytes(frame[12:14], "big"), 14
    if et == 0x8100: et, off = int.from_bytes(frame[16:18], "big"), 18
    if et == 0x0800:
        if frame[off + 9] != 6: return None
        src, dst = socket.inet_ntoa(frame[off + 12:off + 16]), socket.inet_ntoa(frame[off + 16:off + 20])
        end, off = off + int.from_bytes(frame[off + 2:off + 4], "big"), off + (frame[off] & 0x0F) * 4
    elif et == 0x86DD and len(frame) >= off + 40:
        if frame[off + 6] != 6: return None
        src, dst = socket.inet_ntop(socket.AF_INET6, frame[off + 8:off + 24]), socket.inet_ntop(socket.AF_INET6, frame[off + 24:off + 40])
        end, off = off + 40 + int.from_bytes(frame[off + 4:off + 6], "big"), off + 40
    else: return None
    if len(frame) < off + 20: return None
    sport, dport = int.from_bytes(frame[off:off + 2], "big"), int.from_bytes(frame[off + 2:off + 4], "big")
    payload = frame[off + (frame[off + 12] >> 4) * 4:min(end, len(frame))]
    return (src, sport, dst, dport, payload) if payload else None

class ReverseDNS:
    """Background reverse lookups (socket.gethostbyaddr under a 1 s default-timeout guard); cached 1 h; at most 30 new lookups per resolve() call."""

    def __init__(self):
        self.cache, self.pending, self.lock, self.thread = {}, [], threading.Lock(), None

    def resolve(self, ips):
        now = time.time()
        with self.lock:
            new = [ip for ip in ips if (ip not in self.cache or now - self.cache[ip][1] > 3600) and ip not in self.pending][:30]
            self.pending += new
            if self.pending and not (self.thread and self.thread.is_alive()):
                self.thread = threading.Thread(target=self.work, daemon=True)
                self.thread.start()
            return {ip: self.cache[ip][0] for ip in ips if ip in self.cache}

    def work(self):
        while True:
            with self.lock:
                if not self.pending: return
                ip = self.pending.pop(0)
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(1.0)
            try: host = socket.gethostbyaddr(ip)[0]
            except Exception: host = None
            finally: socket.setdefaulttimeout(old)
            with self.lock:
                self.cache[ip] = (host, time.time())
                if len(self.cache) > 5000:
                    for k in sorted(self.cache, key=lambda k: self.cache[k][1])[:1000]: del self.cache[k]

class PortOwners:
    """Local TCP port -> process name via /proc/net/tcp{,6} inodes and /proc/*/fd (root); refreshed at most every ttl seconds."""

    def __init__(self, ttl=5.0):
        self.ttl, self.ts, self.map = ttl, 0, {}

    def refresh(self):
        if time.time() - self.ts < self.ttl or not (IS_LINUX and is_root()): return
        self.ts = time.time()
        ports = {}
        for path in (PROC + "/net/tcp", PROC + "/net/tcp6"):
            for port, inodes in parse_proc_net_tcp(try_read(path, ""))["ports"].items(): ports.setdefault(port, []).extend(inodes)
        owner, comm, m = inode_owners({i for v in ports.values() for i in v}), {}, {}
        for port, inodes in ports.items():
            pid = next((owner[i] for i in inodes if i in owner), None)
            if pid is None: continue
            if pid not in comm: comm[pid] = (try_read(PROC + "/%s/comm" % pid, "") or "").strip() or None
            m[port] = comm[pid]
        self.map = m

    def process(self, port): return self.map.get(port)

class Capture:
    """AF_PACKET sniffer thread (Linux, root): pairs plaintext HTTP requests with responses and TLS ClientHellos with the first server
    application-data record, producing http events drained once per interval. status: off | on | unavailable | overloaded."""

    def __init__(self, owners, only_ports=()):
        self.owners, self.only, self.lock = owners, {int(p) for p in only_ports or []}, threading.Lock()
        self.events, self.packets, self.errors, self.status = [], 0, 0, "off"
        self.thread, self.stop, self.resume = None, threading.Event(), threading.Event()
        self.pending, self.npending, self.swept = collections.OrderedDict(), 0, 0      # conn key -> deque of in-flight requests
        self.local, self.local_ts, self.keep = set(), 0, None

    def running(self): return self.thread is not None and self.thread.is_alive()

    def ensure(self, want):
        if want and not self.running() and self.status != "unavailable": self.start()
        elif not want and self.running(): self.halt()
        elif not want: self.status = "off"

    def start(self):
        if not (IS_LINUX and is_root() and hasattr(socket, "AF_PACKET")):
            self.status = "unavailable"
            return
        self.stop.clear()
        self.status, self.thread = "on", threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def halt(self):
        self.stop.set()
        self.resume.set()
        self.status = "off"

    def open_socket(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        try:                                                                  # classic BPF "tcp"; without it we just see more packets
            import ctypes
            prog = b"".join(struct.pack("HBBI", *ins) for ins in BPF_TCP)
            self.keep = ctypes.create_string_buffer(prog, len(prog))
            s.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, struct.pack("HL", len(BPF_TCP), ctypes.addressof(self.keep)))
        except Exception: pass
        s.settimeout(1.0)
        return s

    def is_local(self, ip): return ip in self.local or ip.startswith("127.")

    def run(self):
        try: s = self.open_socket()
        except Exception as e:
            self.status = "unavailable"
            log("http capture unavailable: %s: %s" % (type(e).__name__, e))
            return
        self.local, self.local_ts = local_addresses(), time.monotonic()          # needed before the first packet to tell in from out
        sec, n_sec, over = int(time.monotonic()), 0, 0
        while not self.stop.is_set():
            try: frame = s.recv(65535)
            except socket.timeout: self.sweep(time.monotonic()); continue
            except Exception: self.errors += 1; continue
            now = time.monotonic()
            if int(now) != sec:
                over, sec, n_sec = (over + 1 if n_sec > 20000 else 0), int(now), 0
                self.sweep(now)
                if over >= 5:                                                 # > 20k pkt/s for 5 s: pause until the interval is drained
                    self.status, over = "overloaded", 0
                    self.resume.clear()
                    s.close()
                    self.resume.wait()
                    if self.stop.is_set(): return
                    s, self.status = self.open_socket(), "on"
                    continue
            n_sec += 1
            self.packets += 1
            try: self.handle(frame, now)
            except Exception: self.errors += 1
        s.close()

    def sweep(self, now):
        if now - self.swept < 5: return
        self.swept = now
        for k in list(self.pending):
            q = self.pending[k]
            while q and now - q[0]["t0"] > 60: q.popleft(); self.npending -= 1
            if not q: del self.pending[k]
        if now - self.local_ts > 60: self.local, self.local_ts = local_addresses(), now

    def handle(self, frame, now):
        pk = parse_packet(frame)
        if pk is None: return
        src, sport, dst, dport, payload = pk
        key = (src, sport, dst, dport) if (src, sport) <= (dst, dport) else (dst, dport, src, sport)
        q = self.pending.get(key)
        if payload.startswith(HTTP_METHODS):
            req = parse_http_request(payload)
            if req: self.open_request(key, src, sport, dst, dport, now, req, len(payload), False)
        elif payload.startswith(b"HTTP/1."):
            resp = parse_http_response(payload)
            if resp and q: self.finish(key, q, (src, sport), now, resp["status"], len(payload))
        elif payload[0] == 0x16 and len(payload) > 5 and payload[5] == 0x01:
            ch = parse_tls_client_hello(payload)
            if ch: self.open_request(key, src, sport, dst, dport, now, {"method": "", "path": "", "host": ch["sni"]}, len(payload), True)
        elif q and payload[0] in (0x16, 0x17) and q[0]["tls"] and q[0]["server"] == (src, sport):
            i = 0
            while i + 5 <= len(payload):                                      # walk the TLS records in this segment
                t, n = payload[i], int.from_bytes(payload[i + 3:i + 5], "big")
                if t == 0x16 and len(payload) > i + 5 and payload[i + 5] == 0x02:
                    sh = parse_tls_server_hello(payload[i:])
                    if sh: q[0]["tls_version"] = sh["version"]
                elif t == 0x17:
                    self.finish(key, q, (src, sport), now, None, len(payload))
                    break
                i += 5 + n
        elif q: q[0]["bytes"] += len(payload)

    def open_request(self, key, src, sport, dst, dport, now, req, nbytes, tls):
        direction = "out" if self.is_local(src) and not self.is_local(dst) else "in"
        lport = sport if direction == "out" else dport
        if self.only and lport not in self.only: return
        self.owners.refresh()
        rec = {"t0": now, "at": time.time(), "dir": direction, "source": "capture", "method": req["method"], "path": req["path"], "host": req.get("host"),
               "port": dport, "lport": lport, "ip": dst if direction == "out" else src, "process": self.owners.process(lport), "bytes": nbytes, "tls": tls,
               "tls_version": None, "server": (dst, dport), "status": None, "ms": None}     # port = the server's port (local for in, remote for out)
        q = self.pending.get(key)
        if q is None: q = self.pending[key] = collections.deque()
        q.append(rec)
        self.pending.move_to_end(key)
        self.npending += 1
        while self.npending > 5000:                                           # evict the least recently active connection's oldest request
            k, dq = next(iter(self.pending.items()))
            dq.popleft()
            self.npending -= 1
            if not dq: del self.pending[k]

    def finish(self, key, q, sender, now, status, nbytes):
        rec = next((r for r in q if r["server"] == sender), None)             # FIFO: oldest request on this connection from the server side
        if rec is None: return
        q.remove(rec)
        self.npending -= 1
        if not q: del self.pending[key]
        rec["bytes"] += nbytes
        rec["ms"], rec["status"] = round((now - rec["t0"]) * 1000, 2), status
        if rec["process"] is None: rec["process"] = self.owners.process(rec["lport"])
        with self.lock:
            if len(self.events) < 100000: self.events.append({k: rec[k] for k in EVENT_KEYS})

    def drain(self):
        """-> (events, packets, parse errors, status) for the interval just ended; releases the reader after an overload pause."""
        with self.lock:
            events, self.events = self.events, []
            packets, self.packets = self.packets, 0
            errors, self.errors = self.errors, 0
        status = self.status
        if status == "overloaded": self.resume.set()
        return events, packets, errors, status

class SpanBuffer:
    def __init__(self, cap=50000):
        self.spans, self.cap, self.lock = [], cap, threading.Lock()

    def add(self, service, spans):
        with self.lock:
            good = [dict(s, service=service) for s in spans if isinstance(s, dict)]
            self.spans += good
            del self.spans[:-self.cap]
            return len(good)

    def take(self):
        with self.lock: out, self.spans = self.spans, []
        return out

class SdkHandler(http.server.BaseHTTPRequestHandler):
    """POST /v1/spans {"service", "spans": [...]} -> 202 {"accepted": n}; GET /health -> {"ok": true, "agent": VERSION}."""
    buffer, timeout = None, 10

    def log_message(self, *a): return None

    def reply(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        for k, v in (("Content-Type", "application/json"), ("Content-Length", str(len(data)))): self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/health": self.reply(200, {"ok": True, "agent": VERSION})
        else: self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/v1/spans": return self.reply(404, {"error": "not found"})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 2 * 1024 * 1024: return self.reply(413, {"error": "body too large (max 2 MB)"})
        try:
            raw = self.rfile.read(n)
            if self.headers.get("Content-Encoding") == "gzip": raw = gzip.decompress(raw)
            body = json.loads(raw.decode())
            spans = body.get("spans") or []
            if not isinstance(spans, list): raise ValueError("spans must be a list")
        except Exception as e: return self.reply(400, {"error": "bad request: %s" % e})
        self.reply(202, {"accepted": self.buffer.add(str(body.get("service") or "unknown")[:100], spans)})

def start_sdk_listener(port, buffer):
    """ThreadingHTTPServer on 127.0.0.1:port in a daemon thread; None (logged once) when the port cannot be bound."""
    handler = type("VigilSdkHandler", (SdkHandler,), {"buffer": buffer})
    try:
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", int(port)), handler)
        srv.daemon_threads = True
    except OSError as e:
        log("sdk listener disabled: cannot bind 127.0.0.1:%s (%s)" % (port, e))
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

# ----------------------------------------------------------------------------- v1.2 runtime: kubernetes api, database clients, package inventory, runtimes
PG_SQL = ["SELECT 'ver', current_setting('server_version')",
          "SELECT 'stat', sum(xact_commit + xact_rollback), sum(blks_hit), sum(blks_read), sum(deadlocks) FROM pg_stat_database WHERE datname = current_database()",
          "SELECT 'act', count(*), count(*) FILTER (WHERE state = 'active'), count(*) FILTER (WHERE wait_event_type = 'Lock'), "
          "count(*) FILTER (WHERE state = 'active' AND now() - query_start > interval '5 seconds') FROM pg_stat_activity WHERE backend_type = 'client backend'",
          "SELECT 'max', current_setting('max_connections')", "SELECT 'size', pg_database_size(current_database())",
          "SELECT 'lag', CASE WHEN pg_is_in_recovery() THEN extract(epoch FROM now() - pg_last_xact_replay_timestamp()) "
          "ELSE (SELECT extract(epoch FROM max(replay_lag)) FROM pg_stat_replication) END",
          "SELECT 'ext', count(*) FROM pg_extension WHERE extname = 'pg_stat_statements'"]
PG_TOP = ("SELECT 'top', calls, round(mean_exec_time::numeric, 2), round(total_exec_time::numeric, 1), left(regexp_replace(query, '\\s+', ' ', 'g'), 200) "
          "FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 10")
MYSQL_SQL = ("SHOW GLOBAL STATUS; SHOW GLOBAL VARIABLES WHERE Variable_name IN ('max_connections', 'version', 'performance_schema'); "
             "SELECT 'db_size', COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE DATABASE() IS NULL OR table_schema = DATABASE()")
MYSQL_TOP = ("SELECT COUNT_STAR, ROUND(AVG_TIMER_WAIT / 1e9, 2), ROUND(SUM_TIMER_WAIT / 1e9, 1), LEFT(REPLACE(DIGEST_TEXT, '\\n', ' '), 200) "
             "FROM performance_schema.events_statements_summary_by_digest WHERE SCHEMA_NAME IS NOT NULL ORDER BY SUM_TIMER_WAIT DESC LIMIT 10")
DB_KEYS = ("version", "connections", "max_connections", "active_queries", "waiting_locks", "cache_hit_pct", "tps", "db_size_bytes", "replication_lag_s", "slow_queries", "deadlocks")

def run_env(cmd, env, timeout=10):
    """Like run() with extra environment and captured stderr -> (rc, stdout, stderr); rc None when the binary is missing or the call timed out."""
    try:
        p = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=dict(os.environ, **env))
        return p.returncode, p.stdout.decode(errors="replace"), p.stderr.decode(errors="replace")
    except subprocess.TimeoutExpired: return None, "", "timed out after %ss" % timeout
    except FileNotFoundError: return None, "", "%s not installed" % cmd[0]
    except Exception as e: return None, "", "%s: %s" % (type(e).__name__, e)

def db_fail(rc, err, tool):
    lines = [l.strip() for l in (err or "").splitlines() if l.strip()]
    raise RuntimeError(" ".join(lines)[:200] if lines else ("%s not installed" % tool if rc is None else "%s failed (rc=%s)" % (tool, rc)))

def host_args(dsn, hflag, pflag):
    return ([hflag, dsn["host"]] if dsn["host"] else []) + ([pflag, str(dsn["port"])] if dsn["port"] else [])

def per_sec(prev, key, value, now):
    """Rate of a cumulative counter against the previous sample dict {"ts", key: value}; None on the first sample or after a reset."""
    if not prev or value is None or prev.get(key) is None or now - prev["ts"] <= 0 or value < prev[key]: return None
    return round((value - prev[key]) / (now - prev["ts"]), 1)

def per_interval(prev, key, value):
    return (value - prev[key]) if prev and value is not None and prev.get(key) is not None and value >= prev[key] else None

def db_empty(system, name):
    return dict({"system": system, "name": name, "ok": False, "error": None}, **{k: None for k in DB_KEYS}, top_queries=[])

def db_postgres(name, dsn, prev, now):
    out = db_empty("postgresql", name)
    base = ["psql", "-X", "-A", "-t", "-w", "-F", "|"] + host_args(dsn, "-h", "-p") + (["-U", dsn["user"]] if dsn["user"] else []) + (["-d", dsn["db"]] if dsn["db"] else [])
    env = {"PGPASSWORD": dsn["password"], "PGCONNECT_TIMEOUT": "5"}
    rc, txt, err = run_env(base + [a for q in PG_SQL for a in ("-c", q)], env)
    r = parse_pg_stat_lines(txt)
    if "ver" not in r: db_fail(rc, err, "psql")
    out.update(ok=True, version=r["ver"][0].split()[0] if r["ver"] and r["ver"][0] else None)
    st, act = (r.get("stat") or []) + [None] * 4, (r.get("act") or []) + [None] * 4
    xact, hit, rd, dl = (num(v) for v in st[:4])
    out.update(connections=num(act[0]), active_queries=num(act[1]), waiting_locks=num(act[2]), slow_queries=num(act[3]),
               max_connections=num((r.get("max") or [None])[0]), db_size_bytes=num((r.get("size") or [None])[0]),
               replication_lag_s=round(num((r.get("lag") or [None])[0]) or 0, 3) if num((r.get("lag") or [None])[0]) is not None else None,
               cache_hit_pct=round(hit * 100.0 / (hit + rd), 1) if hit is not None and rd is not None and hit + rd > 0 else None,
               tps=per_sec(prev, "xact", xact, now), deadlocks=per_interval(prev, "deadlocks", dl))
    if (r.get("ext") or [""])[0] == "1":
        rc, txt, err = run_env(base + ["-c", PG_TOP], env)
        out["top_queries"] = [{"query": q[:200], "calls": num(c), "mean_ms": num(m), "total_ms": num(t)} for c, m, t, q in parse_pg_stat_lines(txt)["top"]][:10]
    return out, {"ts": now, "xact": xact, "deadlocks": dl}

def db_mysql(name, dsn, prev, now):
    out = db_empty("mysql", name)
    base = ["mysql", "--connect-timeout=5", "-N", "-B"] + host_args(dsn, "-h", "-P") + (["-u", dsn["user"]] if dsn["user"] else []) + ([dsn["db"]] if dsn["db"] else [])
    env = {"MYSQL_PWD": dsn["password"]}
    rc, txt, err = run_env(base + ["-e", MYSQL_SQL], env)
    kv = parse_mysql_kv(txt)
    if "Threads_connected" not in kv: db_fail(rc, err, "mysql")
    q, rq, rd, slow, dl = (num(kv.get(k)) for k in ("Questions", "Innodb_buffer_pool_read_requests", "Innodb_buffer_pool_reads", "Slow_queries", "Innodb_deadlocks"))
    out.update(ok=True, version=kv.get("version"), connections=num(kv.get("Threads_connected")), max_connections=num(kv.get("max_connections")),
               active_queries=max(0, (num(kv.get("Threads_running")) or 1) - 1), waiting_locks=num(kv.get("Innodb_row_lock_current_waits")),
               cache_hit_pct=round((1 - rd / float(rq)) * 100, 1) if rq and rd is not None else None, tps=per_sec(prev, "questions", q, now),
               db_size_bytes=num(kv.get("db_size")), slow_queries=per_interval(prev, "slow", slow), deadlocks=per_interval(prev, "deadlocks", dl))
    rc, txt, err = run_env(base + ["-E", "-e", "SHOW REPLICA STATUS"], env)
    if rc != 0: rc, txt, err = run_env(base + ["-E", "-e", "SHOW SLAVE STATUS"], env)
    out["replication_lag_s"] = parse_replica_lag(txt) if rc == 0 else None
    if (kv.get("performance_schema") or "").upper() == "ON":
        rc, txt, err = run_env(base + ["-e", MYSQL_TOP], env)
        rows = [l.split("\t", 3) for l in txt.splitlines()] if rc == 0 else []
        out["top_queries"] = [{"query": r[3][:200], "calls": num(r[0]), "mean_ms": num(r[1]), "total_ms": num(r[2])} for r in rows if len(r) == 4][:10]
    return out, {"ts": now, "questions": q, "slow": slow, "deadlocks": dl}

def db_redis(name, dsn, prev, now):
    out = db_empty("redis", name)
    base = ["redis-cli"] + host_args(dsn, "-h", "-p") + (["-n", dsn["db"]] if dsn["db"].isdigit() else []) + (["--user", dsn["user"]] if dsn["user"] else []) + (["--tls"] if dsn["scheme"] == "rediss" else [])
    env = {"REDISCLI_AUTH": dsn["password"]} if dsn["password"] else {}
    rc, txt, err = run_env(base + ["INFO"], env)
    info = redis_info_to_dict(txt)
    if "redis_version" not in info: db_fail(rc, (err.strip() or txt.strip()).splitlines()[-1] if (err.strip() or txt.strip()) else "", "redis-cli")
    hits, misses, cmds = (num(info.get(k)) for k in ("keyspace_hits", "keyspace_misses", "total_commands_processed"))
    dh, dm = per_interval(prev, "hits", hits), per_interval(prev, "misses", misses)
    if dh is not None and dm is not None and dh + dm > 0: hit_rate = round(dh * 100.0 / (dh + dm), 1)
    else: hit_rate = round(hits * 100.0 / (hits + misses), 1) if hits is not None and misses is not None and hits + misses > 0 else None
    ops = per_sec(prev, "cmds", cmds, now)
    if ops is None: ops = num(info.get("instantaneous_ops_per_sec"))
    rc2, cfg, _ = run_env(base + ["CONFIG", "GET", "maxclients"], env, timeout=5)
    rc3, sl, _ = run_env(base + ["SLOWLOG", "LEN"], env, timeout=5)
    out.update(ok=True, version=info.get("redis_version"), connections=num(info.get("connected_clients")), max_connections=num(cfg.split()[-1]) if rc2 == 0 and len(cfg.split()) >= 2 else None,
               waiting_locks=num(info.get("blocked_clients")), cache_hit_pct=hit_rate, tps=ops, db_size_bytes=num(info.get("used_memory")),
               replication_lag_s=num(info.get("master_last_io_seconds_ago")) if info.get("role") == "slave" else None, slow_queries=first_number(sl) if rc3 == 0 else None)
    out["redis"] = {"used_memory": num(info.get("used_memory")), "maxmemory": num(info.get("maxmemory")), "hit_rate_pct": hit_rate, "connected_clients": num(info.get("connected_clients")),
                    "evicted_keys": num(info.get("evicted_keys")), "ops_per_sec": ops, "keyspace": num(info.get("_keys"))}
    return out, {"ts": now, "hits": hits, "misses": misses, "cmds": cmds}

DB_DRIVERS = {"postgresql": db_postgres, "postgres": db_postgres, "mysql": db_mysql, "mariadb": db_mysql, "redis": db_redis, "rediss": db_redis}

def k8s_get(url, token, ctx, timeout=8):
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/json", "User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return json.loads(r.read(32 * 1024 * 1024).decode())

def package_inventory():
    """-> (ecosystem, release, sorted [(name, version)]) via dpkg-query / apk / rpm (against the host's database under HOST_ROOT when set), or None."""
    osr = os_release_kv(try_read(HOST_ROOT + "/etc/os-release", ""))
    have = lambda p: not HOST_ROOT or os.path.exists(HOST_ROOT + p)
    if which("dpkg-query") and have("/var/lib/dpkg/status"):
        eco, cmd, parse = "Ubuntu" if osr.get("ID") == "ubuntu" else "Debian", ["dpkg-query"] + (["--admindir=" + HOST_ROOT + "/var/lib/dpkg"] if HOST_ROOT else []) + ["-W", "-f=${Package} ${Version}\\n"], parse_dpkg_lines
    elif which("apk") and have("/lib/apk/db/installed"): eco, cmd, parse = "Alpine", ["apk"] + (["--root", HOST_ROOT] if HOST_ROOT else []) + ["info", "-v"], parse_apk_lines
    elif which("rpm") and have("/var/lib/rpm"): eco, cmd, parse = "RHEL", ["rpm"] + (["--dbpath", HOST_ROOT + "/var/lib/rpm"] if HOST_ROOT else []) + ["-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\\n"], parse_dpkg_lines
    else: return None
    rc, txt = run(cmd, timeout=60)
    items = parse(txt) if rc == 0 else []
    return (eco, osr.get("VERSION_ID") or None, items) if items else None

def detect_runtimes():
    """{"python", "node", "docker", "openssl", "kernel"} versions of the tools on PATH (the kernel from uname)."""
    out = {}
    for key, cmd, rx in (("python", ["python3", "--version"], r"(\d+\.\d+(?:\.\d+)?)"), ("node", ["node", "--version"], r"v?(\d+\.\d+(?:\.\d+)?)"),
                         ("docker", ["docker", "--version"], r"version (\d+\.\d+(?:\.\d+)?)"), ("openssl", ["openssl", "version"], r"(\d+\.\d+\.\d+\w*)")):
        if not which(cmd[0]): continue
        m = re.search(rx, run(cmd, timeout=5)[1] or "")
        if m: out[key] = m.group(1)
    out["kernel"] = platform.release()
    return out

# ----------------------------------------------------------------------------- the agent
class Agent:
    def __init__(self, cfg, config_path):
        self.cfg = cfg
        set_host_root(cfg.get("proc_root") or os.environ.get("VIGIL_PROC_ROOT") or "/host/proc")
        self.cluster = str(cfg.get("cluster") or os.environ.get("CLUSTER_NAME") or "default")
        if not cfg.get("name") and os.environ.get("KUBERNETES_SERVICE_HOST") and os.environ.get("NODE_NAME"): cfg["name"] = self.cluster + "/" + os.environ["NODE_NAME"]
        self.url = cfg["url"].rstrip("/")
        self.token = cfg["token"]
        self.interval = max(5, int(cfg.get("interval") or 30))
        self.server_cfg = {}
        self.prev = {}                      # counters from the previous sample, for rates
        self.prev_procs = (0, {})           # (ts, {pid: ticks})
        self.queue, self.backoff, self.next_try = [], 0, 0
        self.updates = Cache(check_updates, 3600)
        self.public_ip = Cache(fetch_public_ip, 3600)
        self.state_path = self.pick_state_path(config_path)
        self.state = {}                     # persisted: {"logs": tail offsets, "pkg_hash", "pkg_sent"}
        try:
            with open(self.state_path) as f: self.state = json.load(f)
        except Exception: pass
        if not isinstance(self.state, dict): self.state = {}
        self.logstate = self.state.setdefault("logs", {})
        self.hz = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        self.page = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        self.users = {}
        self.notes = {}                     # per-collect notes merged into report["errors"]
        self.listen_ports = {}              # port -> process from the last c_net, for flow direction
        self.net_prev = {}                  # ss byte counters from the previous sample
        self.dns = ReverseDNS()
        self.owners = PortOwners()
        self.capture = Capture(self.owners, cfg.get("capture_ports") or [])
        self.spans, self.sdk, self.sdk_failed, self.sdk_spans = SpanBuffer(), None, False, []
        self.journal_us = {}                # journal unit -> µs timestamp of the last shipped entry
        self.k8s_hist = []                  # [(ts, {"ns/pod": restarts})] for restarts_1h
        self.db_prev = {}                   # database name -> counters from the previous interval
        self.pkgs = Cache(package_inventory, 900)
        self.runtimes = Cache(detect_runtimes, 3600)

    @staticmethod
    def pick_state_path(config_path):
        for cand in ("/var/lib/vigil-agent/state.json", os.path.expanduser("~/.vigil-agent-state.json")):
            try:
                os.makedirs(os.path.dirname(cand), exist_ok=True)
                if os.access(os.path.dirname(cand), os.W_OK): return cand
            except Exception: continue
        return None

    def save_state(self):
        if self.state_path:
            try:
                tmp = self.state_path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(self.state, f)
                os.replace(tmp, self.state_path)
            except Exception: pass

    def watched(self, key):
        return sorted(set(self.cfg.get(key) or []) | set(self.server_cfg.get(key) or []))

    def rate(self, key, cur, now):
        """Per-second deltas of a flat counter dict since the previous sample (None on the first sample)."""
        prev = self.prev.get(key)
        self.prev[key] = (now, cur)
        if not prev or now - prev[0] <= 0: return None
        dt = now - prev[0]
        return {k: (v - prev[1][k]) / dt for k, v in cur.items() if k in prev[1] and v >= prev[1][k]}

    # ---- collection entry point
    def collect(self, sync=False):
        now = time.time()
        report = {"agent_version": VERSION, "ts": int(now), "interval": self.interval, "errors": {}}
        self.notes = {}
        if self.cfg.get("name"): report["name"] = self.cfg["name"]
        collectors = [("host", self.c_host), ("cpu", self.c_cpu), ("mem", self.c_mem), ("disks", self.c_disks), ("disk_io", self.c_disk_io),
                      ("net", self.c_net), ("processes", self.c_processes), ("services", self.c_services), ("docker", self.c_docker),
                      ("security", self.c_security), ("custom", self.c_custom), ("logs", self.c_logs),
                      ("network", self.c_network), ("http", self.c_http), ("traces", self.c_traces), ("logs_ship", self.c_logs_ship),
                      ("kubernetes", self.c_kubernetes), ("database", self.c_database), ("packages", self.c_packages), ("runtimes", self.c_runtimes),
                      ("prom", self.c_prom)]
        if IS_LINUX and "cpu" not in self.prev:       # prime the CPU / process counters so the first report has cpu%
            self.prev["cpu"] = (now, parse_proc_stat(try_read(PROC + "/stat", "")))
            self.prev_procs = (now, self.linux_proc_ticks())
            time.sleep(0.5)
        for key, fn in collectors:
            if key == "docker" and not (self.cfg.get("collect_docker", True) and self.server_cfg.get("watch_containers", True)):
                continue
            if key == "security" and not self.cfg.get("collect_security", True): continue
            try:
                val = fn(sync) if key in ("host", "security", "packages") else fn()
                if val is not None: report[key] = val
            except Exception as e: report["errors"][key] = ("%s: %s" % (type(e).__name__, e))[:200]
        report["errors"].update(self.notes)
        if not report["errors"]:
            del report["errors"]
        return report

    # ---- host
    def c_host(self, sync=False):
        fqdn = socket.getfqdn()
        h = {"hostname": socket.gethostname(), "fqdn": fqdn if not fqdn.endswith(".arpa") else socket.gethostname(), "arch": platform.machine(), "cpu_count": os.cpu_count(),
             "kernel": platform.release(), "timezone": self.timezone(), "public_ip": None}
        if self.cfg.get("public_ip", True): h["public_ip"] = self.public_ip.get(sync)
        if IS_LINUX:
            h["os"] = parse_os_release(try_read(HOST_ROOT + "/etc/os-release", "")) or platform.platform()
            m = re.search(r"model name\s*:\s*(.+)", try_read(PROC + "/cpuinfo", ""))
            h["cpu_model"] = m.group(1).strip() if m else None
            h["mem_total"] = parse_meminfo(try_read(PROC + "/meminfo", "")).get("MemTotal")
            h["boot_time"] = parse_proc_stat(try_read(PROC + "/stat", "")).get("btime") or None
            h["virtualization"] = self.linux_virt()
        elif IS_MAC:
            h["os"] = "macOS " + platform.mac_ver()[0]
            h["cpu_model"] = run(["sysctl", "-n", "machdep.cpu.brand_string"])[1].strip() or None
            h["mem_total"] = first_number(run(["sysctl", "-n", "hw.memsize"])[1])
            h["boot_time"] = first_number(run(["sysctl", "-n", "kern.boottime"])[1].replace("{ sec = ", ""))
            h["virtualization"] = "unknown" if (run(["sysctl", "-n", "kern.hv_vmm_present"])[1].strip() == "1") else "none"
        else:
            h.update(os=platform.platform(), cpu_model=None, mem_total=None, boot_time=None, virtualization="unknown")
        h["uptime_s"] = int(time.time() - h["boot_time"]) if h.get("boot_time") else None
        return h

    @staticmethod
    def timezone():
        tz = try_read("/etc/timezone", "").strip()
        if not tz:
            try: tz = os.readlink("/etc/localtime").split("zoneinfo/", 1)[-1]
            except Exception: tz = time.tzname[0]
        return tz

    @staticmethod
    def linux_virt():
        if os.path.exists("/.dockerenv"): return "docker"
        cg = try_read(PROC + "/1/cgroup", "")
        if "docker" in cg or "containerd" in cg: return "docker"
        if "lxc" in cg or os.environ.get("container") == "lxc": return "lxc"
        if which("systemd-detect-virt"):
            rc, out = run(["systemd-detect-virt"], timeout=3)
            v = out.strip()
            if v:
                return {"qemu": "kvm", "amazon": "kvm", "google": "kvm", "lxc-libvirt": "lxc", "podman": "docker", "containerd": "docker"}.get(v, v)
        dmi = (try_read(SYS + "/class/dmi/id/product_name", "") + " " + try_read(SYS + "/class/dmi/id/sys_vendor", "")).lower()
        for word, v in (("kvm", "kvm"), ("qemu", "kvm"), ("amazon", "kvm"), ("google", "kvm"), ("digitalocean", "kvm"), ("vmware", "vmware"), ("xen", "xen"), ("virtualbox", "oracle"), ("microsoft", "microsoft")):
            if word in dmi: return v
        if "hypervisor" in try_read(PROC + "/cpuinfo", ""): return "unknown"
        return "none" if dmi.strip() else "unknown"

    # ---- cpu
    def c_cpu(self):
        now = time.time()
        if IS_LINUX:
            cur = parse_proc_stat(read(PROC + "/stat"))
            prev = self.prev.get("cpu")
            self.prev["cpu"] = (now, cur)
            out = {"pct": None, "user": None, "system": None, "iowait": None, "steal": None, "per_core": None, "ctx_switches_ps": None}
            if prev and cur["cpu"] and prev[1].get("cpu"):
                out.update(cpu_delta(prev[1]["cpu"], cur["cpu"]))
                out["per_core"] = [cpu_delta(p, c)["pct"] for p, c in zip(prev[1]["per_core"], cur["per_core"])]
                if now - prev[0] > 0: out["ctx_switches_ps"] = int((cur["ctxt"] - prev[1]["ctxt"]) / (now - prev[0]))
        else:
            out = {"pct": None, "user": None, "system": None, "iowait": None, "steal": None, "per_core": None, "ctx_switches_ps": None}
            rc, txt = run(["top", "-l", "2", "-n", "0", "-s", "1"], timeout=6)
            m = re.findall(r"CPU usage: ([\d.]+)% user, ([\d.]+)% sys, ([\d.]+)% idle", txt)
            if m:
                u, s, _ = (float(x) for x in m[-1])
                out.update(pct=round(u + s, 1), user=round(u, 1), system=round(s, 1))
            else:
                rc, txt = run(["ps", "-A", "-o", "%cpu="], timeout=5)
                out["pct"] = round(sum(float(x) for x in txt.split() if NUM_RE.match(x)) / (os.cpu_count() or 1), 1)
        try:
            l1, l5, l15 = os.getloadavg()
            out.update(load1=round(l1, 2), load5=round(l5, 2), load15=round(l15, 2))
        except Exception:
            out.update(load1=None, load5=None, load15=None)
        return out

    # ---- memory
    def c_mem(self):
        if IS_LINUX:
            mi = parse_meminfo(read(PROC + "/meminfo"))
            total = mi.get("MemTotal", 0)
            avail = mi.get("MemAvailable", mi.get("MemFree", 0) + mi.get("Buffers", 0) + mi.get("Cached", 0))
            swap_t, swap_u = mi.get("SwapTotal", 0), mi.get("SwapTotal", 0) - mi.get("SwapFree", 0)
            return {"total": total, "used": total - avail, "available": avail, "cached": mi.get("Cached", 0) + mi.get("SReclaimable", 0),
                    "buffers": mi.get("Buffers", 0), "pct": pct(total - avail, total), "swap_total": swap_t, "swap_used": swap_u, "swap_pct": pct(swap_u, swap_t)}
        rc, txt = run(["vm_stat"], timeout=5)
        page = first_number(re.search(r"page size of (\d+)", txt).group(1)) if "page size" in txt else 4096
        pages = {m.group(1).strip().lower(): int(m.group(2)) for m in re.finditer(r"^(?:Pages |)([A-Za-z -]+):\s+(\d+)\.", txt, re.M)}
        total = first_number(run(["sysctl", "-n", "hw.memsize"])[1]) or 0
        used = (pages.get("active", 0) + pages.get("wired down", 0) + pages.get("occupied by compressor", 0)) * page
        rc, sw = run(["sysctl", "-n", "vm.swapusage"], timeout=5)
        m = re.search(r"total = ([\d.]+)M\s+used = ([\d.]+)M", sw)
        swap_t, swap_u = (int(float(m.group(1)) * 1048576), int(float(m.group(2)) * 1048576)) if m else (0, 0)
        return {"total": total, "used": used, "available": max(0, total - used), "cached": pages.get("file-backed pages", 0) * page, "buffers": 0,
                "pct": pct(used, total), "swap_total": swap_t, "swap_used": swap_u, "swap_pct": pct(swap_u, swap_t)}

    # ---- disks
    def c_disks(self):
        out = []
        if IS_LINUX: mounts = linux_mounts(PROC, HOST_ROOT)
        else:
            fstype = dict(re.findall(r"^\S+ on (.+?) \((\w+)", run(["mount"], timeout=5)[1], re.M))
            mounts = []
            for line in run(["df", "-k"], timeout=5)[1].splitlines()[1:]:
                p = line.split()
                if len(p) >= 9 and p[0].startswith("/dev/") and (not p[-1].startswith("/System/Volumes/") or p[-1] == "/System/Volumes/Data"):
                    mounts.append((p[0], p[-1], fstype.get(p[-1], "apfs")))
        for dev, mnt, fs in mounts[:64]:
            try: st = os.statvfs((HOST_ROOT + mnt) if HOST_ROOT and IS_LINUX else mnt)
            except Exception: continue
            total, free = st.f_frsize * st.f_blocks, st.f_frsize * st.f_bavail
            if total <= 0: continue
            inodes = pct(st.f_files - st.f_ffree, st.f_files) if st.f_files else None
            out.append({"mount": mnt, "device": dev, "fs": fs, "total": total, "used": total - free, "pct": pct(total - free, total), "inodes_pct": inodes})
        return out

    # ---- disk io (Linux only)
    def c_disk_io(self):
        if not IS_LINUX: return None
        now = time.time()
        stats = parse_diskstats(read(PROC + "/diskstats"))
        flat = {}
        for dev, (r, rs, w, ws, ms) in stats.items():
            flat.update({dev + ".r": r, dev + ".rs": rs, dev + ".w": w, dev + ".ws": ws, dev + ".ms": ms})
        rates = self.rate("diskio", flat, now)
        out = {"read_bps": None, "write_bps": None, "read_iops": None, "write_iops": None, "util_pct": None, "per_device": {}}
        if rates is None: return out
        tot = [0, 0, 0, 0]
        util = 0.0
        for dev in stats:
            r = {"read_bps": int(rates.get(dev + ".rs", 0) * 512), "write_bps": int(rates.get(dev + ".ws", 0) * 512),
                 "read_iops": round(rates.get(dev + ".r", 0), 1), "write_iops": round(rates.get(dev + ".w", 0), 1),
                 "util_pct": round(min(100.0, rates.get(dev + ".ms", 0) / 10.0), 1)}
            out["per_device"][dev] = r
            tot = [tot[0] + r["read_bps"], tot[1] + r["write_bps"], tot[2] + r["read_iops"], tot[3] + r["write_iops"]]
            util = max(util, r["util_pct"])
        out.update(read_bps=tot[0], write_bps=tot[1], read_iops=round(tot[2], 1), write_iops=round(tot[3], 1), util_pct=util)
        return out

    # ---- network
    def c_net(self):
        now = time.time()
        if IS_LINUX:
            ifaces = parse_net_dev(read(PROC + "/net/dev"))
            tcp = {"established": 0, "time_wait": 0, "listen": []}
            for path in (PROC + "/net/tcp", PROC + "/net/tcp6"):
                t = parse_proc_net_tcp(try_read(path, ""))
                tcp["established"] += t["established"]
                tcp["time_wait"] += t["time_wait"]
                tcp["listen"] += t["listen"]
            listening = self.linux_listening(tcp["listen"])
        else: ifaces, tcp, listening = self.mac_net()
        self.listen_ports = {l["port"]: l["process"] for l in listening}
        flat = {}
        for name, c in ifaces.items():
            flat[name + ".rx"], flat[name + ".tx"] = c["rx_bytes"], c["tx_bytes"]
        rates = self.rate("net", flat, now)
        per = {}
        rx = tx = 0
        for name, c in ifaces.items():
            if name == "lo" or name.startswith(("lo0", "veth", "br-", "docker")): continue
            e = {"rx_bps": None, "tx_bps": None, "rx_errors": c.get("rx_errors", 0), "tx_errors": c.get("tx_errors", 0), "rx_dropped": c.get("rx_dropped", 0)}
            if rates is not None and name + ".rx" in rates:
                e["rx_bps"], e["tx_bps"] = int(rates[name + ".rx"]), int(rates[name + ".tx"])
                rx, tx = rx + e["rx_bps"], tx + e["tx_bps"]
            per[name] = e
        return {"rx_bps": rx if rates is not None else None, "tx_bps": tx if rates is not None else None, "per_iface": per,
                "tcp_established": tcp["established"], "tcp_time_wait": tcp["time_wait"], "listening": listening}

    def linux_listening(self, pairs):
        """(port, inode) -> [{"port","proto","process"}]; inode->pid via /proc/*/fd (root), else process null."""
        owner = inode_owners({inode for _, inode in pairs if inode}) if is_root() else {}
        out, seen = [], set()
        for port, inode in sorted(pairs):
            if port in seen: continue
            seen.add(port)
            name = None
            if inode in owner: name = (try_read(PROC + "/%s/comm" % owner[inode], "") or "").strip() or None
            out.append({"port": port, "proto": "tcp", "process": name})
        return out[:200]

    @staticmethod
    def mac_net():
        ifaces = {}
        for line in run(["netstat", "-ib"], timeout=5)[1].splitlines()[1:]:
            p = line.split()
            if len(p) >= 10 and p[2].startswith("<Link#") and p[0].rstrip("*") not in ifaces:
                p[0] = p[0].rstrip("*")
                nums = [x for x in p[-7:] if x.lstrip("-").isdigit() or x == "-"]
                if len(nums) >= 6:
                    ifaces[p[0]] = {"rx_bytes": int(nums[2]), "rx_errors": int(nums[1]) if nums[1] != "-" else 0, "rx_dropped": 0,
                                    "tx_bytes": int(nums[5]), "tx_errors": int(nums[4]) if nums[4] != "-" else 0}
        tcp, listening, seen = {"established": 0, "time_wait": 0, "listen": []}, [], set()
        for line in run(["netstat", "-an", "-p", "tcp"], timeout=5)[1].splitlines():
            p = line.split()
            if len(p) < 6 or not p[0].startswith("tcp"): continue
            if p[5] == "ESTABLISHED":
                tcp["established"] += 1
            elif p[5] == "TIME_WAIT":
                tcp["time_wait"] += 1
            elif p[5] == "LISTEN":
                port = p[3].rsplit(".", 1)[-1]
                if port.isdigit() and int(port) not in seen:
                    seen.add(int(port))
                    listening.append({"port": int(port), "proto": "tcp", "process": None})
        return ifaces, tcp, sorted(listening, key=lambda x: x["port"])[:200]

    # ---- processes
    def linux_proc_ticks(self):
        ticks = {}
        for d in os.listdir(PROC):
            if d.isdigit():
                try:
                    ticks[int(d)] = parse_pid_stat(read(PROC + "/%s/stat" % d))["ticks"]
                except Exception: pass
        return ticks

    def username(self, uid):
        if uid not in self.users:
            try:
                import pwd
                self.users[uid] = pwd.getpwuid(uid).pw_name
            except Exception: self.users[uid] = str(uid)
        return self.users[uid]

    def c_processes(self):
        now = time.time()
        procs = []
        if IS_LINUX:
            mem_total = parse_meminfo(read(PROC + "/meminfo")).get("MemTotal", 1)
            btime = parse_proc_stat(read(PROC + "/stat")).get("btime", 0)
            prev_t, prev_ticks = self.prev_procs
            ticks = {}
            for d in os.listdir(PROC):
                if not d.isdigit(): continue
                try:
                    st = parse_pid_stat(read(PROC + "/%s/stat" % d))
                    uid = os.stat(PROC + "/%s" % d).st_uid
                except Exception: continue
                ticks[st["pid"]] = st["ticks"]
                cpu = None
                if st["pid"] in prev_ticks and now - prev_t > 0:
                    cpu = round((st["ticks"] - prev_ticks[st["pid"]]) * 100.0 / ((now - prev_t) * self.hz), 1)
                rss = st["rss"] * self.page
                procs.append({"pid": st["pid"], "name": st["comm"], "user": self.username(uid), "cpu_pct": cpu, "mem_pct": pct(rss, mem_total),
                              "rss": rss, "cmd": None, "started": int(btime + st["starttime"] / self.hz) if btime else None, "state": st["state"]})
            self.prev_procs = (now, ticks)
        else:
            for line in run(["ps", "-axo", "pid=,user=,%cpu=,%mem=,rss=,state=,command="], timeout=5)[1].splitlines():
                p = line.split(None, 6)
                if len(p) < 7 or not p[0].isdigit(): continue
                cmd = p[6].strip()
                procs.append({"pid": int(p[0]), "name": os.path.basename(cmd.split(" -", 1)[0].split()[0]) if cmd else "?", "user": p[1],
                              "cpu_pct": float(p[2]), "mem_pct": float(p[3]), "rss": int(p[4]) * 1024, "cmd": cmd[:200], "started": None, "state": p[5][:1]})
        states = [p.pop("state") for p in procs]
        top_cpu = sorted(procs, key=lambda p: p["cpu_pct"] or 0, reverse=True)[:10]
        top_mem = sorted(procs, key=lambda p: p["rss"], reverse=True)[:10]
        if IS_LINUX:
            for p in {id(x): x for x in top_cpu + top_mem}.values():
                p["cmd"] = (try_read(PROC + "/%d/cmdline" % p["pid"], "") or "").replace("\0", " ").strip()[:200] or "[%s]" % p["name"]
        watch = self.watched("watch_processes")
        names = sorted({p["name"] for p in procs})
        names = [n for n in names if n in watch] + [n for n in names if n not in watch]
        watched = {}
        for w in watch:
            ms = [p for p in procs if p["name"] == w or (p.get("cmd") or "").startswith(w)]
            watched[w] = {"running": bool(ms), "count": len(ms), "cpu_pct": round(sum(p["cpu_pct"] or 0 for p in ms), 1), "rss": sum(p["rss"] for p in ms)}
        return {"total": len(procs), "running": states.count("R"), "sleeping": sum(1 for s in states if s in "SDI"), "zombie": states.count("Z"),
                "top_cpu": top_cpu, "top_mem": top_mem, "names": names[:500], "watched": watched}

    # ---- services
    def c_services(self):
        watch = self.watched("watch_services")
        if IS_LINUX and os.path.isdir("/run/systemd/system") and which("systemctl"):
            rc, out = run(["systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--plain"], timeout=5)
            failed = [l.split()[0].replace(".service", "") for l in out.splitlines() if l.strip() and rc == 0]
            failed = [f for f in failed if not f.startswith("●")]
            watched = {}
            if watch:
                rc, out = run(["systemctl", "is-active"] + watch, timeout=5)
                lines = out.splitlines()
                for i, name in enumerate(watch):
                    s = lines[i].strip() if i < len(lines) else "unknown"
                    s = {"activating": "active", "reloading": "active", "deactivating": "inactive"}.get(s, s)
                    if s == "inactive" and run(["systemctl", "show", "-p", "LoadState", "--value", name], timeout=3)[1].strip() == "not-found":
                        s = "not-found"
                    watched[name] = s if s in ("active", "inactive", "failed", "not-found") else "unknown"
            return {"manager": "systemd", "failed": failed, "watched": watched}
        if IS_MAC and which("launchctl"):
            jobs = {}
            for line in run(["launchctl", "list"], timeout=5)[1].splitlines()[1:]:
                p = line.split("\t")
                if len(p) >= 3:
                    jobs[p[2].strip()] = (p[0].strip(), p[1].strip())
            watched = {}
            for name in watch:
                if name not in jobs: watched[name] = "not-found"
                else:
                    watched[name] = "active" if jobs[name][0].isdigit() else ("failed" if jobs[name][1] not in ("0", "-") else "inactive")
            return {"manager": "launchd", "failed": [], "watched": watched}
        return {"manager": "none", "failed": [], "watched": {n: "unknown" for n in watch}}

    # ---- docker
    def c_docker(self):
        if not which("docker"): return {"available": False}
        rc, out = run(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=5)
        if rc != 0: return {"available": False}
        containers = []
        for line in out.splitlines():
            try: d = json.loads(line)
            except ValueError: continue
            containers.append({"id": (d.get("ID") or "")[:12], "name": d.get("Names"), "image": d.get("Image"), "state": docker_state(d), "status": d.get("Status"),
                               "restarts": None, "cpu_pct": None, "mem": None, "mem_pct": None, "created": parse_docker_time(d.get("CreatedAt"))})
        running = [c for c in containers if c["state"] == "running"][:50]
        if running:
            rc, out = run(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=8)
            stats = {}
            for line in out.splitlines():
                try:
                    s = json.loads(line)
                    stats[s.get("Name")] = s
                except ValueError: pass
            for c in running:
                s = stats.get(c["name"])
                if s:
                    c.update(cpu_pct=parse_pct(s.get("CPUPerc")), mem=parse_size((s.get("MemUsage") or "").split("/")[0]), mem_pct=parse_pct(s.get("MemPerc")))
            rc, out = run(["docker", "inspect", "--format", "{{.RestartCount}}"] + [c["id"] for c in running], timeout=5)
            if rc == 0:
                for c, v in zip(running, out.split()): c["restarts"] = int(v) if v.isdigit() else None
        return {"available": True, "containers": containers}

    # ---- security
    def c_security(self, sync=False):
        out = {"updates_pending": None, "security_updates": None, "reboot_required": None, "firewall": "unknown", "ssh_password_auth": None,
               "ssh_root_login": None, "last_update_check": None, "users_logged_in": None, "failed_logins_24h": None, "world_writable_dirs": None}
        rc, who = run(["who"], timeout=5)
        if rc == 0: out["users_logged_in"] = len([l for l in who.splitlines() if l.strip()])
        if not IS_LINUX: return out
        upd = self.updates.get(sync) or {}
        out.update(updates_pending=upd.get("updates_pending"), security_updates=upd.get("security_updates"), last_update_check=upd.get("checked"))
        out["reboot_required"] = reboot_required()
        out["firewall"] = firewall_state()
        texts = [t for t in [try_read(p) for p in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf"))] + [try_read("/etc/ssh/sshd_config")] if t is not None]
        if texts: out["ssh_password_auth"], out["ssh_root_login"] = parse_sshd_config(texts)
        out["failed_logins_24h"] = failed_logins_24h()
        return out

    # ---- custom commands and log watch
    def c_custom(self):
        cmds = self.cfg.get("commands") or {}
        out = {}
        for name, cmd in list(cmds.items())[:50]:
            rc, txt = run(["sh", "-c", str(cmd)], timeout=10)
            v = first_number(txt) if rc == 0 else None
            if v is not None:
                out[str(name)] = v
        return out or None

    def tail(self, name, path):
        """New bytes appended to path since the last call (state keyed by name; handles rotation / truncation; a file seen for the first
        time starts at its end). None when unreadable. Max 5 MB per call."""
        st = self.logstate.get(name) or {}
        try: s = os.stat(path)
        except Exception: return None
        offset = st.get("offset", 0)
        if st.get("inode") != s.st_ino or s.st_size < offset:      # rotated / truncated / first time seen
            offset = 0 if st.get("inode") else s.st_size
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                data = f.read(5 * 1024 * 1024)
        except Exception: return None
        self.logstate[name] = {"inode": s.st_ino, "offset": offset + len(data)}
        return data

    def c_logs(self):
        out = {}
        for lw in (self.cfg.get("log_watch") or [])[:50]:
            name, path, pattern = lw.get("name"), lw.get("path"), lw.get("pattern")
            if not (name and path and pattern): continue
            try: rx = re.compile(pattern)
            except Exception: continue
            data = self.tail(name, path)
            if data is None: continue
            out[name] = sum(1 for line in data.decode(errors="replace").splitlines() if rx.search(line))
        return out or None

    # ---- v1.1: network flows, http capture + access logs, sdk traces
    def start_background(self):
        """Capture and SDK listener threads (idempotent). Called before the first collect so --print also reports their state."""
        self.capture.ensure(bool(self.cfg.get("capture_http", True)))
        if self.sdk is None and self.cfg.get("sdk_listener", True) and not self.sdk_failed:
            self.sdk = start_sdk_listener(self.cfg.get("sdk_port") or 9111, self.spans)
            self.sdk_failed = self.sdk is None

    def c_network(self):
        if not (self.cfg.get("network_flows", True) and self.server_cfg.get("network_flows", True)): return None
        empty = {"outgoing": [], "incoming": [], "totals": {"outgoing_conns": 0, "incoming_conns": 0, "unique_remote_hosts": 0}}
        if not (IS_LINUX and which("ss")): self.notes["network"] = "ss not available on this platform; flows not collected"; return empty
        rc, out = run(["ss", "-tinH"] + (["-p"] if is_root() else []), timeout=5)
        if rc != 0: self.notes["network"] = "ss failed (rc=%s)" % rc; return empty
        conns = parse_ss_output(out, time.time())
        dns = {}
        if self.cfg.get("reverse_dns", True):
            dns = self.dns.resolve(sorted({c["peer_ip"] for c in conns if c["local_port"] not in self.listen_ports and c["peer_port"] and not is_loopback(c["peer_ip"])}))
        net, self.net_prev = aggregate_network(conns, self.listen_ports, self.net_prev, dns)
        return net

    def c_http(self):
        self.capture.ensure(bool(self.cfg.get("capture_http", True) and self.server_cfg.get("capture_http", True)))
        events, packets, errors, status = self.capture.drain()
        log_events, logs = self.access_logs()
        self.sdk_spans = self.spans.take()
        agg = aggregate_http(events + log_events + spans_to_http_events(self.sdk_spans))
        out = {"capture": status, "packets": packets, "incoming": agg["incoming"], "outgoing": agg["outgoing"], "slow": agg["slow"], "logs": logs}
        if errors: out["errors"], self.notes["http"] = errors, "%d packets failed to parse" % errors
        return out

    def access_logs(self):
        """Auto-detected nginx/apache/caddy access logs + config "access_logs" -> (incoming http events with source "log", [{path, format, lines}])."""
        paths = list(ACCESS_LOG_PATHS) + sorted(glob.glob("/var/log/caddy/*.log")) + [str(p) for p in self.cfg.get("access_logs") or []]
        events, logs, now = [], [], time.time()
        for path in list(dict.fromkeys(paths))[:20]:
            if not os.path.isfile(path): continue
            data = self.tail("access:" + path, path)
            if data is None: continue
            fmt = "caddy" if "caddy" in path or data[:1] == b"{" else ("apache" if "apache" in path or "httpd" in path else "nginx")
            n = 0
            for line in data.decode(errors="replace").splitlines():
                r = parse_access_log_line(line, fmt)
                if not r: continue
                n += 1
                events.append({"dir": "in", "source": "log", "host": r["host"], "ip": r["ip"], "port": 0, "process": fmt, "method": r["method"], "path": r["path"],
                               "status": r["status"], "ms": r["ms"], "bytes": r["bytes"], "tls": False, "tls_version": None, "at": now})
            logs.append({"path": path, "format": fmt, "lines": n})
        return events, logs

    def c_traces(self):
        if self.sdk is None: return None
        spans, self.sdk_spans = self.sdk_spans, []
        if not spans: return None
        agg = aggregate_traces(spans)
        agg["spans_raw"] = raw_spans(spans)     # v1.5: server-side APM (queries, outbound, N+1, stored traces); old summary kept as fallback
        return agg

    # ---- v1.2: log shipping, kubernetes, databases, packages, runtimes
    # ---- v1.4: Prometheus exporter scraping (node_exporter, blackbox, app /metrics ...): text format -> {series: value}
    def c_prom(self):
        targets = (self.cfg.get("prom_scrape") or []) + (self.server_cfg.get("prom_scrape") or [])
        if not targets: return None
        cap = int(self.server_cfg.get("prom_series") or self.cfg.get("prom_series") or 100)
        out, errors = {}, []
        for t in targets[:20]:
            url = t.get("url") if isinstance(t, dict) else str(t)
            job = (t.get("job") if isinstance(t, dict) else "") or (urllib.parse.urlparse(url).hostname or "exporter")
            keep = t.get("match") if isinstance(t, dict) else None   # optional list of metric name prefixes
            try:
                req = urllib.request.Request(url, headers={"Accept": "text/plain", "User-Agent": UA})
                with urllib.request.urlopen(req, timeout=8, context=ssl.create_default_context() if url.startswith("https") else None) as r:
                    text = r.read(4 * 1024 * 1024).decode("utf-8", "replace")
            except Exception as e:
                errors.append("%s: %s" % (job, str(e)[:80])); continue
            for line in text.splitlines():
                if not line or line[0] == "#": continue
                m = PROM_LINE.match(line)
                if not m: continue
                name, labels, val = m.group(1), m.group(2) or "", m.group(3)
                if keep and not any(name.startswith(k) for k in keep): continue
                try: v = float(val)
                except ValueError: continue
                if v != v: continue
                key = "%s:%s%s" % (job, name, labels) if labels else "%s:%s" % (job, name)
                out[key[:120]] = v
                if len(out) >= cap: break
            if len(out) >= cap: break
        if errors: self.notes["prom"] = "; ".join(errors)[:300]
        return out or None

    def ship_sources(self):
        """(file path specs, journal units, max lines per interval): local config unioned with what the server pushed; the server's cap wins."""
        def paths(v): return [str(x.get("path") if isinstance(x, dict) else x) for x in (v if isinstance(v, list) else []) if (x.get("path") if isinstance(x, dict) else x)]
        cap = self.server_cfg.get("log_ship_max_lines") or self.cfg.get("log_ship_max_lines") or 500
        return sorted(set(paths(self.cfg.get("log_ship")) + paths(self.server_cfg.get("log_ship")))), self.watched("journal_units"), max(1, int(cap))

    def c_logs_ship(self):
        """Ship new lines from the configured files and journal units. Every configured source is reported with its access state
        (ok / denied / missing) so the dashboard can show exactly which files this agent can and cannot read."""
        specs, units, cap = self.ship_sources()
        if not specs and not units: return None
        lines, dropped, now, sources, denied = [], 0, round(time.time(), 3), [], []
        for spec in specs:
            files = sorted(glob.glob(spec))[:100] if any(ch in spec for ch in "*?[") else [spec]
            if not [f for f in files if os.path.isfile(f)]:
                sources.append({"path": spec, "state": "missing", "note": "no such file"}); continue
            for path in files:
                if not os.path.isfile(path): continue
                if not os.access(path, os.R_OK):
                    sources.append({"path": path, "state": "denied", "note": "permission denied for user %s" % self.run_as()}); denied.append(path); continue
                data = self.tail("ship:" + path, path)
                if data is None:
                    sources.append({"path": path, "state": "denied", "note": "open failed for user %s" % self.run_as()}); denied.append(path); continue
                sources.append({"path": path, "state": "ok"})
                if not data: continue
                joined = join_multiline(data.decode(errors="replace").splitlines())
                dropped += max(0, len(joined) - cap)
                lines += [{"ts": now, "file": path, "source": "file", "level": detect_level(l), "line": l} for l in joined[-cap:]]
        if units:
            if not which("journalctl"):
                sources += [{"path": "journal:" + u, "state": "missing", "note": "journalctl not installed"} for u in units]
            else:
                rc, txt = run(["journalctl", "-n", "1", "-q", "--no-pager"], timeout=10)
                if rc != 0 or "permission" in (txt or "").lower() or "No journal files" in (txt or ""):
                    sources += [{"path": "journal:" + u, "state": "denied", "note": "journal not readable by user %s (add it to the systemd-journal group)" % self.run_as()} for u in units]
                    denied += ["journal:" + u for u in units]
                else:
                    sources += [{"path": "journal:" + u, "state": "ok"} for u in units]
                    lines += self.journal_lines(units, cap)
        if denied: self.notes["logs"] = ("%d log source(s) not readable: %s" % (len(denied), ", ".join(denied)))[:300]
        dropped += max(0, len(lines) - cap)
        return {"lines": lines[-cap:], "dropped": dropped, "sources": sources[:150]}

    def run_as(self):
        try:
            import pwd
            return pwd.getpwuid(os.geteuid()).pw_name
        except Exception: return "uid %s" % getattr(os, "geteuid", lambda: "?")()

    def journal_lines(self, units, cap):
        """New entries per unit since the last call (units seen for the first time start now, no backlog); PRIORITY -> level."""
        out, now_us = [], int(time.time() * 1e6)
        for unit in units[:20]:
            last = self.journal_us.get(unit)
            if last is None: self.journal_us[unit] = now_us; continue
            rc, txt = run(["journalctl", "-u", unit, "--since", "@%d" % (last // 1000000), "-o", "json", "--no-pager", "-q", "-n", str(cap * 2)], timeout=10)
            if rc != 0: continue
            for e in (parse_journal_json_line(l) for l in txt.splitlines()):
                if not e or e["us"] <= last: continue
                self.journal_us[unit] = max(self.journal_us[unit], e["us"])
                out.append({"ts": e["ts"], "source": "journal", "unit": e["unit"] or unit, "level": e["level"], "line": e["message"][:LINE_MAX]})
        return out

    def c_kubernetes(self):
        host, token = os.environ.get("KUBERNETES_SERVICE_HOST"), (try_read(SA_DIR + "/token") or "").strip()
        if not (host and token): return None
        node, now = os.environ.get("NODE_NAME") or socket.gethostname(), time.time()
        api = "https://%s:%s" % ("[" + host + "]" if ":" in host else host, os.environ.get("KUBERNETES_SERVICE_PORT") or "443")
        ctx = ssl.create_default_context(cafile=SA_DIR + "/ca.crt") if os.path.isfile(SA_DIR + "/ca.crt") else ssl.create_default_context()
        pods_obj = k8s_get(api + "/api/v1/pods?fieldSelector=spec.nodeName%3D" + urllib.parse.quote(node), token, ctx, timeout=15)
        role, conds, ip = "worker", {}, None
        try: role, conds, ip = parse_k8s_node(k8s_get(api + "/api/v1/nodes/" + urllib.parse.quote(node), token, ctx))
        except Exception as e: self.notes["kubernetes"] = ("node: %s: %s" % (type(e).__name__, e))[:200]
        self.k8s_hist = [(t, snap) for t, snap in self.k8s_hist if now - t <= 3600]
        pods, totals, cur = parse_k8s_pods(pods_obj, self.k8s_hist[0][1] if self.k8s_hist else {}, now)
        self.k8s_hist.append((now, cur))
        kctx = ssl.create_default_context()                              # kubelet serving certs are usually self-signed; the SA token still authenticates us
        kctx.check_hostname, kctx.verify_mode = False, ssl.CERT_NONE
        try: usage = parse_kubelet_summary(k8s_get("https://%s:10250/stats/summary" % (ip or node), token, kctx))
        except Exception as e:
            usage = {}
            if not (isinstance(e, urllib.error.HTTPError) and e.code in (401, 403)): self.notes["kubelet"] = ("%s: %s" % (type(e).__name__, e))[:200]
        for p in pods:
            u = usage.get("%s/%s" % (p["namespace"], p["name"]))
            for c in (p["containers"] if u else []): c.update(u["containers"].get(c["name"]) or {})
        return {"detected": True, "cluster": self.cluster, "node": node, "role": role, "node_conditions": conds, "pods": pods, "totals": totals}

    def c_database(self):
        dbs = self.cfg.get("databases")
        if not isinstance(dbs, list) or not dbs: return None
        out, now = [], time.time()
        for i, d in enumerate(dbs[:10]):
            d = d if isinstance(d, dict) else {}
            dsn, name = parse_dsn(d.get("dsn") or ""), str(d.get("name") or "db%d" % (i + 1))
            system = str(d.get("system") or dsn["scheme"] or "").lower()
            try:
                fn = DB_DRIVERS.get(system)
                if fn is None: raise ValueError("unknown system %r (postgresql|mysql|redis)" % system)
                res, self.db_prev[name] = fn(name, dsn, self.db_prev.get(name), now)
            except Exception as e:
                res = db_empty({"postgres": "postgresql", "mariadb": "mysql", "rediss": "redis"}.get(system, system or "unknown"), name)
                res["error"] = strip_secrets(str(e) if isinstance(e, RuntimeError) else "%s: %s" % (type(e).__name__, e), [dsn["password"]])[:200]
            out.append(res)
        return out

    def c_packages(self, sync=False):
        if not (IS_LINUX and self.cfg.get("packages", True) and self.server_cfg.get("packages", True)): return None
        inv = self.pkgs.get(sync)
        if not inv: return None
        eco, rel, items = inv
        return packages_payload(items, eco, rel, self.state, time.time())

    def c_runtimes(self):
        return self.runtimes.get(sync=True) or None

    # ---- transport
    def post(self, path, body):
        data = json.dumps(body, separators=(",", ":")).encode()
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json", "X-Agent-Version": VERSION, "User-Agent": UA}
        if len(data) > 4096:
            data = gzip.compress(data)
            headers["Content-Encoding"] = "gzip"
        req = urllib.request.Request(self.url + path, data=data, method="POST", headers=headers)
        with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as r:
            return json.loads(r.read().decode() or "{}")

    def apply_response(self, resp):
        if not isinstance(resp, dict): return
        if resp.get("interval"): self.interval = max(5, int(resp["interval"]))
        cfg = resp.get("config")
        if isinstance(cfg, dict): self.server_cfg = cfg

    def deliver(self, report, once=False):
        """Send one report, or the queued backlog + this one via /batch; handles 401/402/backoff per the Vigil contract."""
        now = time.time()
        summary = "cpu=%s%% mem=%s%% disk=%s%%" % ((report.get("cpu") or {}).get("pct"), (report.get("mem") or {}).get("pct"),
                                                    max([d["pct"] for d in report.get("disks") or []] or [None]))
        if now + 1 < self.next_try and not once:
            self.enqueue(report)
            log("queued %s (retry in %ds, queued=%d)" % (summary, self.next_try - now, len(self.queue)))
            return
        try:
            if self.queue: resp = self.post("/api/v1/servers/report/batch", self.queue + [report])
            else: resp = self.post("/api/v1/servers/report", report)
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log("ERROR: Vigil rejected the token (401). Check /etc/vigil-agent.json or VIGIL_TOKEN. Exiting.")
                sys.exit(2)
            if e.code == 402:
                log("Vigil plan limit reached (402): %s. Retrying in 10 minutes." % e.read(300).decode(errors="replace").strip())
                if once: sys.exit(3)
                self.enqueue(report)
                self.next_try = now + 600
                return
            self.fail(report, "HTTP %s %s" % (e.code, e.read(200).decode(errors="replace").strip()), once)
            return
        except Exception as e:
            self.fail(report, "%s: %s" % (type(e).__name__, e), once)
            return
        n = len(self.queue) + 1
        self.queue, self.backoff, self.next_try = [], 0, 0
        self.apply_response(resp)
        log("sent %s %s(interval=%ds, queued=0)" % (summary, "batch of %d " % n if n > 1 else "", self.interval))

    def enqueue(self, report):
        self.queue.append(report)
        del self.queue[:-20]

    def fail(self, report, why, once):
        self.enqueue(report)
        self.backoff = min(300, max(5, self.backoff * 2))
        self.next_try = time.time() + self.backoff
        log("send failed: %s (queued=%d, retry in %ds)" % (why, len(self.queue), self.backoff))
        if once:
            sys.exit(1)

    def loop(self, once=False):
        log("vigil-server-agent %s starting: url=%s interval=%ds host=%s root=%s" % (VERSION, self.url, self.interval, socket.gethostname(), is_root()))
        self.start_background()
        log("http capture=%s sdk listener=%s" % (self.capture.status, ("127.0.0.1:%s" % (self.cfg.get("sdk_port") or 9111)) if self.sdk else "off"))
        while True:
            t0 = time.time()
            report = self.collect(sync=once)
            self.deliver(report, once)
            self.save_state()
            if once: return
            time.sleep(max(1.0, self.interval - (time.time() - t0)))

# ----------------------------------------------------------------------------- config, install, CLI
def load_config(path):
    cfg = {}
    candidates = [path] if path else [os.environ.get("VIGIL_CONFIG"), CONF, os.path.expanduser("~/.vigil-agent.json")]
    for cand in candidates:
        if cand and os.path.isfile(cand):
            try:
                cfg = json.load(open(cand))
                cfg["_path"] = cand
                break
            except Exception as e:
                sys.exit("ERROR: cannot parse config %s: %s" % (cand, e))
    if os.environ.get("VIGIL_URL"): cfg["url"] = os.environ["VIGIL_URL"]
    if os.environ.get("VIGIL_TOKEN"): cfg["token"] = os.environ["VIGIL_TOKEN"]
    return cfg


SYSTEMD_UNIT = """[Unit]
Description=Vigil server monitoring agent
Documentation=https://puzaricloud.in
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart={python} {bin}
Restart=always
RestartSec=10
Environment=PYTHONUNBUFFERED=1
Nice=10

[Install]
WantedBy=multi-user.target
"""

LAUNCHD_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>in.puzaricloud.vigil-agent</string>
  <key>ProgramArguments</key><array><string>{python}</string><string>{bin}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/vigil-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/vigil-agent.log</string>
</dict></plist>
"""

def install(args, cfg):
    if not is_root():
        sys.exit("ERROR: --install must run as root (sudo).")
    if not os.path.exists(CONF):
        url, token = args.url or cfg.get("url") or "https://puzaricloud.in", args.token or cfg.get("token")
        if not token:
            sys.exit("ERROR: no config at %s; pass --token vgs_... (and optionally --url)." % CONF)
        body = {"url": url, "token": token, "interval": int(args.interval or 30)}
        if args.name: body["name"] = args.name
        with open(CONF, "w") as f:
            json.dump(body, f, indent=2)
        os.chmod(CONF, 0o600)
        print("wrote " + CONF)
    else:
        print("kept existing " + CONF)
    src = os.path.abspath(__file__)
    if src != BIN:
        shutil.copyfile(src, BIN)
    os.chmod(BIN, 0o755)
    print("installed " + BIN)
    python = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else (shutil.which("python3") or sys.executable)
    if IS_LINUX:
        if not os.path.isdir("/run/systemd/system"):
            sys.exit("ERROR: systemd not found; run '%s %s' under your own supervisor." % (python, BIN))
        with open(UNIT, "w") as f:
            f.write(SYSTEMD_UNIT.format(python=python, bin=BIN))
        print("wrote " + UNIT)
        for cmd in (["systemctl", "daemon-reload"], ["systemctl", "enable", "vigil-server-agent"], ["systemctl", "restart", "vigil-server-agent"]):
            rc, _ = run(cmd, timeout=30)
            print("%s -> %s" % (" ".join(cmd), "ok" if rc == 0 else "FAILED (rc=%s)" % rc))
        print("Agent running. Status: systemctl status vigil-server-agent   Logs: journalctl -u vigil-server-agent -f")
    elif IS_MAC:
        with open(PLIST, "w") as f:
            f.write(LAUNCHD_PLIST.format(python=python, bin=BIN))
        os.chmod(PLIST, 0o644)
        print("wrote " + PLIST)
        run(["launchctl", "bootout", "system/in.puzaricloud.vigil-agent"], timeout=15)
        rc, _ = run(["launchctl", "bootstrap", "system", PLIST], timeout=15)
        if rc != 0: rc, _ = run(["launchctl", "load", "-w", PLIST], timeout=15)
        print("launchctl load -> %s" % ("ok" if rc == 0 else "FAILED (rc=%s)" % rc))
        print("Agent running. Logs: tail -f /var/log/vigil-agent.log")
    else:
        sys.exit("ERROR: unsupported platform for --install; run '%s %s' under your own supervisor." % (python, BIN))

def uninstall():
    if not is_root():
        sys.exit("ERROR: --uninstall must run as root (sudo).")
    if IS_LINUX and os.path.isdir("/run/systemd/system"):
        run(["systemctl", "disable", "--now", "vigil-server-agent"], timeout=30)
        run(["systemctl", "daemon-reload"], timeout=30)
    if IS_MAC:
        run(["launchctl", "bootout", "system/in.puzaricloud.vigil-agent"], timeout=15)
        run(["launchctl", "unload", PLIST], timeout=15)
    for path in (UNIT, PLIST, BIN, CONF, "/var/lib/vigil-agent/state.json"):
        if os.path.exists(path):
            os.remove(path)
            print("removed " + path)
    print("Vigil server agent uninstalled.")

def capture_test(seconds):
    """Run the packet capture thread alone for N seconds and print the aggregated "http" dict (Linux + root)."""
    cap = Capture(PortOwners(), [])
    cap.start()
    log("http capture status=%s, sniffing for %ds (linux=%s root=%s)" % (cap.status, seconds, IS_LINUX, is_root()))
    time.sleep(max(1, seconds))
    events, packets, errors, status = cap.drain()
    cap.halt()
    agg = aggregate_http(events)
    print(json.dumps({"capture": status, "packets": packets, "errors": errors, "events": len(events), "incoming": agg["incoming"], "outgoing": agg["outgoing"],
                      "slow": agg["slow"], "logs": []}, indent=1))

def main():
    global LOG_STREAM
    ap = argparse.ArgumentParser(description="Vigil server monitoring agent")
    ap.add_argument("--once", action="store_true", help="collect and send one report, then exit")
    ap.add_argument("--print", action="store_true", help="collect and print the JSON report, don't send")
    ap.add_argument("--config", help="config file path (default /etc/vigil-agent.json or ~/.vigil-agent.json)")
    ap.add_argument("--url", help="Vigil base URL (overrides config / VIGIL_URL)")
    ap.add_argument("--token", help="server token vgs_... (overrides config / VIGIL_TOKEN)")
    ap.add_argument("--interval", type=int, help="seconds between reports (server may override)")
    ap.add_argument("--name", help="display name override (used by --install)")
    ap.add_argument("--install", action="store_true", help="install as a systemd service (Linux) or LaunchDaemon (macOS)")
    ap.add_argument("--uninstall", action="store_true", help="stop and remove the service, binary, config and state")
    ap.add_argument("--capture-test", type=int, metavar="SECONDS", help="sniff HTTP/TLS for N seconds and print the aggregated http dict (Linux, root)")
    ap.add_argument("--db-test", action="store_true", help="run the database collector once (config \"databases\") and print the result")
    ap.add_argument("--version", action="version", version="vigil-server-agent " + VERSION)
    args = ap.parse_args()
    if args.print or args.capture_test or args.db_test: LOG_STREAM = sys.stderr
    if args.uninstall: return uninstall()
    if args.capture_test: return capture_test(args.capture_test)
    cfg = load_config(args.config)
    if args.url: cfg["url"] = args.url
    if args.token: cfg["token"] = args.token
    if args.interval: cfg["interval"] = args.interval
    if args.install: return install(args, cfg)
    cfg.setdefault("url", "https://puzaricloud.in")
    if not (args.print or args.db_test) and not cfg.get("token"):
        sys.exit("ERROR: no token. Set VIGIL_TOKEN, pass --token, or create /etc/vigil-agent.json (see --help).")
    cfg.setdefault("token", "")
    agent = Agent(cfg, cfg.get("_path"))
    if args.db_test:
        print(json.dumps(agent.c_database(), indent=1))
        return
    if args.print:
        agent.start_background()
        print(json.dumps(agent.collect(sync=True), indent=1, sort_keys=False))
        agent.save_state()
        return
    try:
        agent.loop(once=args.once)
    except KeyboardInterrupt:
        agent.save_state()


if __name__ == "__main__":
    main()
