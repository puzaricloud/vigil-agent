#!/bin/sh
# Maintainer helper (not needed by users): refresh the agent and installer from the Vigil source tree.
#   ./sync-from-vigil.sh ~/vigil
set -eu
SRC="${1:-$HOME/vigil}/app/static"
cp "$SRC/vigil-server-agent.py" vigil-server-agent.py
cp "$SRC/install-server-agent.sh" install.sh
grep -m1 '^VERSION = ' vigil-server-agent.py
