#!/bin/bash
# PBS normally runs under systemd as two units: proxmox-backup (api, root) and
# proxmox-backup-proxy (User=backup, After=proxmox-backup). Both are Type=notify;
# without systemd the sd_notify call is a no-op, so they run fine standalone —
# we just have to reproduce the ordering and the privilege split ourselves.
set -euo pipefail

PBS_LIBEXEC=/usr/lib/x86_64-linux-gnu/proxmox-backup

# Recreated on every start: /run is tmpfs, and the volumes may arrive empty.
install -d -o backup -g backup -m 0755 /run/proxmox-backup /var/lib/proxmox-backup
install -d -o root   -g root   -m 0755 /var/log/proxmox-backup
install -d -o root   -g root   -m 0755 /etc/proxmox-backup

term() {
  echo "entrypoint: shutting down" >&2
  [[ -n "${PROXY_PID:-}" ]] && kill -TERM "$PROXY_PID" 2>/dev/null || true
  [[ -n "${API_PID:-}"   ]] && kill -TERM "$API_PID"   2>/dev/null || true
  wait || true
}
trap term SIGTERM SIGINT

# api first — it mints authkey/certs on first run and owns the config surface
# the proxy reads. Starting the proxy before it exists yields auth failures.
"$PBS_LIBEXEC/proxmox-backup-api" &
API_PID=$!

for _ in $(seq 1 60); do
  [[ -S /run/proxmox-backup/api.sock ]] && break
  kill -0 "$API_PID" 2>/dev/null || { echo "entrypoint: api exited during startup" >&2; exit 1; }
  sleep 1
done
[[ -S /run/proxmox-backup/api.sock ]] || { echo "entrypoint: api socket never appeared" >&2; exit 1; }

"$PBS_LIBEXEC/proxmox-backup-proxy" &
PROXY_PID=$!

# Exit as soon as EITHER daemon dies so the container restarts as a unit,
# rather than limping along serving requests with half of PBS running.
wait -n "$API_PID" "$PROXY_PID"
term
exit 1
