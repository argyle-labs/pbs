#!/usr/bin/env bash
# Creates and configures a pbs LXC on Proxmox VE. Run on the host as root.
set -euo pipefail
VMID="${1:?Usage: $0 <vmid> [options]}"
# TODO: pct create / config / install pbs. Mirror jellyfin/lxc/provision.sh.
echo "[provision] pbs LXC $VMID — not yet implemented"
