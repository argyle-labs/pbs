#!/bin/bash
# PBS normally runs under systemd as two units: proxmox-backup (api, root) and
# proxmox-backup-proxy (User=backup, After=proxmox-backup). Both are Type=notify;
# without systemd the sd_notify call is a no-op, so they run fine standalone —
# we just have to reproduce the ordering and the privilege split ourselves.
set -euo pipefail

PBS_LIBEXEC=/usr/lib/x86_64-linux-gnu/proxmox-backup

# ── Identity remap (PUID/PGID) ───────────────────────────────────────────────
# PBS runs its proxy as `backup`, uid/gid 34 on a stock install. On a NAS whose
# shares are owned by a fixed account — Unraid is nobody:users = 99:100 — every
# file PBS writes then lands as a bare numeric 34, outside the host permission
# model entirely, and tools that reason about share ownership stop working.
#
# Remap the backup account to the host's expected ids instead. PBS only checks
# that it is running AS the backup user, so which uid that resolves to is ours
# to choose. Defaults to 34/34, i.e. unchanged from a stock install.
PUID="${PUID:-34}"
PGID="${PGID:-34}"

OLD_UID="$(id -u backup)"
OLD_GID="$(id -g backup)"

if [[ "$OLD_GID" != "$PGID" ]]; then
  groupmod -o -g "$PGID" backup
fi
if [[ "$OLD_UID" != "$PUID" ]]; then
  usermod -o -u "$PUID" backup
fi

if [[ "$OLD_UID" != "$PUID" || "$OLD_GID" != "$PGID" ]]; then
  echo "entrypoint: backup remapped ${OLD_UID}:${OLD_GID} -> ${PUID}:${PGID}" >&2
  # Re-stamp ONLY what the old identity owned. Targeted rather than chown -R so
  # root-owned files keep their ownership: authkey.key is root:root 0600, while
  # authkey.pub and csrf.key are root:backup 0640 — the group moves, the owner
  # must not.
  #
  # EVERY persistent path the old uid could own has to be covered, not just the
  # config dir. The proxy runs as `backup` and writes /var/log/proxmox-backup/{api,
  # tasks}, so leaving those on the old uid kills it on startup with
  #   Error: open "/var/log/proxmox-backup/api/access.log" failed - EACCES
  # and the container crash-loops. /var/lib is included for the same reason: the
  # dir itself is re-chowned below, but anything already inside it is not.
  #
  # Datastore mounts are deliberately NOT listed. They come from outside, can hold
  # millions of chunk files, and their ownership belongs to whoever provisioned the
  # share — walking them here would stall every start.
  for state_dir in /etc/proxmox-backup /var/log/proxmox-backup /var/lib/proxmox-backup; do
    [[ -d "$state_dir" ]] || continue
    find "$state_dir" -uid "$OLD_UID" -exec chown -h "$PUID" {} + 2>/dev/null || true
    find "$state_dir" -gid "$OLD_GID" -exec chgrp -h "$PGID" {} + 2>/dev/null || true
  done
fi

# PBS logs to syslog, which a container has no daemon for; it warns once
# ("Unable to open syslog") and carries on writing to stdout, which is what
# `docker logs` wants anyway. Harmless, but noted so it isn't mistaken for a
# fault later.

# Ownership is enforced on every start, not just first run: /run is tmpfs, and a
# freshly created Docker volume arrives root-owned regardless of what the image
# set at build time. Modes mirror a real PBS install exactly — the api refuses to
# start otherwise ("configuration directory permission problem - wrong user").
mkdir -p /etc/proxmox-backup /run/proxmox-backup /var/lib/proxmox-backup /var/log/proxmox-backup

# 0700 backup:backup — PBS checks this directory's owner explicitly.
chown backup:backup /etc/proxmox-backup
chmod 0700          /etc/proxmox-backup

chown backup:backup /run/proxmox-backup /var/lib/proxmox-backup
chmod 0755          /run/proxmox-backup /var/lib/proxmox-backup

# Logs are root-owned on a stock install; the proxy drops privileges and still
# writes here via its own files, so don't hand the directory to `backup`.
chown root:root /var/log/proxmox-backup
chmod 0755      /var/log/proxmox-backup

# PBS keeps its config-version cache in shared memory under /run/proxmox-backup
# and requires that path to be tmpfs. On a stock install /run already is; in a
# container it lands on the overlay unless the runtime supplies a tmpfs, and the
# only symptom is traffic control silently failing to load. Warn loudly rather
# than let it degrade quietly.
if ! mountpoint -q /run/proxmox-backup 2>/dev/null \
   && ! grep -qE ' /run/proxmox-backup tmpfs ' /proc/mounts 2>/dev/null; then
  echo "entrypoint: WARNING /run/proxmox-backup is not tmpfs — traffic control will not load." >&2
  echo "entrypoint: run with --tmpfs /run/proxmox-backup:rw,nosuid,nodev,mode=0755" >&2
fi

# Deliberately NOT recursive: files inside carry their own ownership on a real
# install (authkey.key is root:root 0600, authkey.pub/csrf.key are root:backup
# 0640). A restored config volume must keep those exactly as they were.

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

# Readiness marker is api.pid, NOT a socket file: PBS's control channel is an
# ABSTRACT unix socket (@/run/proxmox-backup/control-<pid>.sock), which never
# appears on the filesystem, so there is nothing to stat for.
for _ in $(seq 1 60); do
  [[ -f /run/proxmox-backup/api.pid ]] && break
  kill -0 "$API_PID" 2>/dev/null || { echo "entrypoint: api exited during startup" >&2; exit 1; }
  sleep 1
done
[[ -f /run/proxmox-backup/api.pid ]] || { echo "entrypoint: api never became ready" >&2; exit 1; }

# The proxy REFUSES to run as root — it checks its own uid/gid and exits with
# "proxy not running as backup user or group". systemd does this via User=backup;
# without systemd we drop privileges ourselves. --init-groups matters: the backup
# user also belongs to `tape`, and PBS expects those supplementary groups.
setpriv --reuid=backup --regid=backup --init-groups \
  "$PBS_LIBEXEC/proxmox-backup-proxy" &
PROXY_PID=$!

# Exit as soon as EITHER daemon dies so the container restarts as a unit,
# rather than limping along serving requests with half of PBS running.
wait -n "$API_PID" "$PROXY_PID"
term
exit 1
