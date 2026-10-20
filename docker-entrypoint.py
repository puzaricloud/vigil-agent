#!/usr/bin/env python3
"""Container entrypoint for the Vigil agent image.

Writes a small config with the server name (VIGIL_NAME, else the host's /host/etc/hostname when the host root is
mounted at /host) and runs the bundled agent. VIGIL_URL and VIGIL_TOKEN are read by the agent itself.
"""
import json
import os
import sys

name = os.environ.get("VIGIL_NAME", "").strip()
if not name and os.path.isfile("/host/etc/hostname"):
    with open("/host/etc/hostname") as f:
        name = f.read().strip()
os.makedirs("/etc/vigil", exist_ok=True)
with open("/etc/vigil/agent.json", "w") as f:
    json.dump({"name": name} if name else {}, f)
os.environ.setdefault("VIGIL_CONFIG", "/etc/vigil/agent.json")
os.environ.setdefault("VIGIL_PROC_ROOT", "/host/proc")
os.execv(sys.executable, [sys.executable, "/usr/local/bin/vigil-server-agent"] + sys.argv[1:])
