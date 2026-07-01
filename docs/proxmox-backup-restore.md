# Proxmox VM & LXC Backup and Restore

Backup and restore procedures for all VMs and LXCs across <host> and <host>.

---

## Overview

| Method | What | When |
|--------|------|------|
| `vzdump` | Full VM/LXC snapshot backup | On-demand or scheduled |
| Proxmox Backup Server (VM 106) | Incremental, deduplicated backups | Future — PBS not yet configured |
| Application-level backups | Service config exports | Per-service (see [service-backups.md](service-backups.md)) |

Default vzdump backup location: `/var/lib/vz/dump/` on each Proxmox host (or NFS-backed storage).

---

## Backup Command Reference

```bash
# LXC snapshot backup (suspend briefly to get consistent state)
vzdump <vmid> --mode snapshot --compress zstd --storage <storage>

# VM snapshot backup
vzdump <vmid> --mode snapshot --compress zstd --storage <storage>

# Stop the container/VM first for guaranteed consistency (slower, causes downtime)
vzdump <vmid> --mode stop --compress zstd --storage <storage>

# List available backups
ls /var/lib/vz/dump/

# Restore an LXC
pct restore <new-vmid> /var/lib/vz/dump/<backup>.tar.zst --storage local-lvm

# Restore a VM
qmrestore /var/lib/vz/dump/<backup>.vma.zst <new-vmid> --storage local-lvm
```

---

## <host> — VM 103: opnsense

**Status:** stopped
**Storage:** local-lvm (32 GB disk)

### Backup
```bash
# Run on <host>
vzdump 103 --mode stop --compress zstd --storage local
```

### Restore
```bash
# On <host> — restores to VMID 103 (use different ID if 103 is taken)
qmrestore /var/lib/vz/dump/vzdump-qemu-103-*.vma.zst 103 --storage local-lvm --force
qm start 103
```

### Notes
- Not in active use. Kept as a router failover option.
- 6 NICs mapped to vmbr0–5 for full VLAN routing capability.
- OPNsense config can be exported from UI: System → Configuration → Backups.

---

---

## <host> — VM 102: <host>

**Status:** running
**Storage:** local (100 GB qcow2)

### Backup
```bash
# Run on <host>
vzdump 102 --mode snapshot --compress zstd --storage local
```

Appdata is also backed up at the application level nightly:
```bash
# Runs at 3 AM daily (cron on <host>)
/usr/local/bin/backup-appdata.sh
# Output: /mnt/<host>/backups/appdata_<host>/ab_YYYYMMDD_HHMMSS/{sabnzbd,sonarr,...}.tar.gz
# Retention: 7 most recent sets
```

### Restore — Full VM
```bash
# On <host>
qmrestore /var/lib/vz/dump/vzdump-qemu-102-*.vma.zst 102 --storage local --force
qm start 102
```

### Restore — Docker appdata only (faster, no VM downtime)
```bash
# On <host> (<ip>)
BACKUP=/mnt/<host>/backups/appdata_<host>/ab_<YYYYMMDD_HHMMSS>

# Stop containers first
sudo docker stop sabnzbd qbittorrent sonarr radarr radarr4k bazarr prowlarr huntarr

# Restore each service config
for svc in sabnzbd qbittorrent sonarr radarr radarr4k bazarr prowlarr huntarr; do
  tar xzf "$BACKUP/${svc}.tar.gz" -C /opt/appdata/
done

# Restart containers
sudo docker start sabnzbd qbittorrent sonarr radarr radarr4k bazarr prowlarr huntarr
```

See [<host>-setup.md](<host>-setup.md) for full rebuild from scratch.

---

## <host> — VM 105: haos-17.1

**Status:** running
**Storage:** local-lvm (32 GB, SSD)

### Backup
```bash
# Run on <host>
vzdump 105 --mode snapshot --compress zstd --storage local-lvm
```

Additionally, Home Assistant has built-in backups: Settings → System → Backups.
HA backups can be configured to auto-upload to a network share or cloud.

### Restore — Full VM
```bash
# On <host>
qmrestore /var/lib/vz/dump/vzdump-qemu-105-*.vma.zst 105 --storage local-lvm --force
qm start 105
```

### Restore — HA config only (no VM downtime)
In HA web UI: Settings → System → Backups → Upload backup → Restore.

### Notes
- OVMF BIOS + q35 machine type — restore must use same settings.
- VMID 105 disk uses local-lvm; the EFI disk is also on local-lvm (vm-105-disk-1).

---

## <host> — VM 106: proxmox-backup-server

**Status:** stopped (not yet configured)
**Storage:** local-lvm (32 GB)

### Backup
```bash
vzdump 106 --mode stop --compress zstd --storage local-lvm
```

### Restore
```bash
qmrestore /var/lib/vz/dump/vzdump-qemu-106-*.vma.zst 106 --storage local-lvm --force
qm start 106
```

### Notes
- Once PBS is set up, it should become the primary backup target for all other VMs/LXCs.
- PBS provides deduplication, incremental backups, and encryption.

---

## <host> — LXC 100: mqtt

**Status:** running
**Storage:** local-lvm (2 GB)

### Backup
```bash
# Run on <host>
vzdump 100 --mode snapshot --compress zstd --storage local-lvm
```

### Restore
```bash
pct restore 100 /var/lib/vz/dump/vzdump-lxc-100-*.tar.zst \
  --storage local-lvm \
  --rootfs local-lvm:2 \
  --hostname mqtt \
  --force

# Reapply static IP (if not preserved from backup)
# Edit /etc/pve/lxc/100.conf:
#   net0: name=eth0,bridge=vmbr0,gw=<ip>,hwaddr=<mac>,ip=<ip>/24,type=veth

pct start 100
```

### Notes
- Mosquitto config lives at `/etc/mosquitto/` inside the LXC.
- No persistent state beyond config — low-risk to recreate from scratch if needed.

---

## <host> — LXC 101: adguard

**Status:** running
**Storage:** local-lvm (4 GB)

### Backup
```bash
vzdump 101 --mode snapshot --compress zstd --storage local-lvm
```

Application-level backup (preferred for config-only restore):
```bash
# backup-configs.sh handles this automatically via pct exec
pct exec 101 -- cat /opt/AdGuardHome/AdGuardHome.yaml
# Output is committed to the <repo> git repo as a ~2.5K archive
# AdGuard Home has no native backup directory setting — no UI option exists
```

### Restore — Full LXC
```bash
pct restore 101 /var/lib/vz/dump/vzdump-lxc-101-*.tar.zst \
  --storage local-lvm \
  --rootfs local-lvm:4 \
  --hostname adguard \
  --force

pct start 101
```

### Restore — Config only
```bash
# Pull AdGuardHome.yaml from the <repo> git repo (backups/configs/)
# Copy it into the running LXC and restart the service
pct exec 101 -- sh -c 'cp /path/to/AdGuardHome.yaml /opt/AdGuardHome/AdGuardHome.yaml'
pct exec 101 -- systemctl restart AdGuardHome
# Note: AdGuard Home has no UI restore path — config is restored by file copy only
```

### Notes
- Static IP <ip> — must preserve MAC `<mac>` or update OPNsense DHCP lease.
- AdGuard serves DNS for the whole LAN — restoring quickly is critical.

---

## <host> — LXC 104: <host>

**Status:** running
**Storage:** local-lvm (3 GB)

### Backup
```bash
vzdump 104 --mode snapshot --compress zstd --storage local-lvm
```

NPM Plus stores its database and SSL certs in its data volume (inside the LXC at `/opt/npm/`).

### Restore
```bash
pct restore 104 /var/lib/vz/dump/vzdump-lxc-104-*.tar.zst \
  --storage local-lvm \
  --rootfs local-lvm:3 \
  --hostname <host> \
  --force

pct start 104
```

### Notes
- Static IP <ip> — critical for proxy routing. Preserve MAC `<mac>`.
- Cloudflare API token for Let's Encrypt DNS challenge is stored in NPM config.
- After restore, verify proxy hosts and SSL certs are intact in the web UI.

---

## <host> — LXC 107: <host>

**Status:** running
**Storage:** local-lvm (1 GB)

### Backup
```bash
vzdump 107 --mode snapshot --compress zstd --storage local-lvm
```

Application-level backup (Zigbee2MQTT config + database):
```bash
# Config lives inside LXC at /opt/zigbee2mqtt/
# Backups write to /mnt/backups/ (<host> bind mount) — configured in configuration.yaml:
#   advanced:
#     backup:
#       path: /mnt/backups
```

### Restore — Full LXC
```bash
pct restore 107 /var/lib/vz/dump/vzdump-lxc-107-*.tar.zst \
  --storage local-lvm \
  --rootfs local-lvm:1 \
  --hostname <host> \
  --force

# Reapply USB passthrough to new LXC config:
cat >> /etc/pve/lxc/107.conf << 'EOF'
lxc.cap.drop:
lxc.cgroup2.devices.allow: c 188:* rwm
lxc.cgroup2.devices.allow: c 189:* rwm
lxc.mount.entry: /dev/zigbee dev/ttyUSB0 none bind,optional,create=file
EOF

pct start 107
```

### Notes
- Zigbee USB dongle is at `/dev/zigbee` on <host> (symlinked by udev rule from ttyUSB*).
- Static IP <ip> — preserve MAC or update OPNsense static lease.
- After restore, verify Zigbee coordinator is detected and devices re-pair if needed.

---

## <host> — LXC 108: zwave-js-ui

**Status:** running
**Storage:** local-lvm (4 GB)

### Backup

PBS snapshot runs daily. Config backup via `backup-configs.sh` on <host> tars the store dir directly:

```bash
# Store dir (set via STORE_DIR in /opt/.env inside LXC):
/opt/zwave-js-ui/mnt/user/appdata/zwave-js-ui/
```

Security keys, serial port config, node names, and device mappings are all in `settings.json` inside this dir. **This file must be present in backups — losing it requires re-pairing all S2 devices.**

### Restore — From PBS snapshot (preferred)
```bash
pct stop 108
pct restore 108 pbs:backup/ct/108/<timestamp> --storage local-lvm --force
pct start 108
```

Verify USB passthrough config is intact after restore:
```bash
grep ttyACM /etc/pve/lxc/108.conf
```

If missing, reapply:
```bash
cat >> /etc/pve/lxc/108.conf << 'EOF'
lxc.cap.drop:
lxc.cgroup2.devices.allow: c 188:* rwm
lxc.cgroup2.devices.allow: c 189:* rwm
lxc.cgroup2.devices.allow: c 166:* rwm
lxc.mount.entry: /dev/ttyACM0 dev/ttyACM0 none bind,optional,create=file
EOF
```

### Restore — Config only (from backup-configs.sh tarball)
```bash
# Extract settings.json into the store dir
tar xzf zwave-js-ui.tar.gz -C /tmp/zwave-restore
pct exec 108 -- bash -c "cp /tmp/... /opt/zwave-js-ui/mnt/user/appdata/zwave-js-ui/settings.json"
pct exec 108 -- systemctl restart zwave-js-ui
```

### Notes
- Z-Wave stick is at `/dev/ttyACM0` on <host>.
- Static DHCP lease for MAC `<mac>` → <ip> in OPNsense.
- Z-Wave device inclusion state is in the stick's NVM (survives LXC restore). Security keys in `settings.json` must match what was used during pairing.

---

## <host> — LXC 109: unifi

**Status:** running
**Storage:** local-lvm (8 GB)

### Backup
```bash
vzdump 109 --mode snapshot --compress zstd --storage local-lvm
```

Unifi Network Application also has built-in backups:
- UI: Settings → System → Backups → Download backup
- Auto-backup: Settings → System → Backups → Auto-backup (saves inside LXC at `/data/backup/`)

### Restore — Full LXC
```bash
pct restore 109 /var/lib/vz/dump/vzdump-lxc-109-*.tar.zst \
  --storage local-lvm \
  --rootfs local-lvm:8 \
  --hostname unifi \
  --force

pct start 109
```

### Restore — Unifi config only
```bash
# In Unifi UI: Settings → System → Backups → Restore
# Or via SSH into LXC, place .unf backup in /data/backup/ and restore from UI
```

### Notes
- Static IP <ip> — preserve MAC `<mac>` or update OPNsense static lease.
- Unifi controller manages APs/switches — losing it means no wireless config changes until restored.
- Devices continue working without the controller; only management is lost.

---

## <host> — LXC 110: plex

**Status:** running
**Storage:** local-lvm (108 GB)

### Backup

Use the application-level backup script on the LXC — do NOT use `vzdump` for this LXC. The rootfs contains 63 GB of BIF files (chapter scrubber thumbnails) that are excluded from backups intentionally to keep backup size practical.

```bash
# Run the backup script directly, or let the systemd timer handle it (runs at 5 AM)
pct exec 110 -- /usr/local/bin/backup-plex.sh
```

Backups land at `<host>:/mnt/user/backups/plex/` (~15 GB per backup, 7-day retention).

See [plex.md](../services/plex.md#backup) for script setup, exclusion details, and restore steps.

### Restore — Full LXC
```bash
pct restore 110 /var/lib/vz/dump/vzdump-lxc-110-*.tar.zst \
  --storage local-lvm \
  --rootfs local-lvm:108 \
  --hostname plex \
  --force

# Reapply GPU passthrough and NFS mount:
cat >> /etc/pve/lxc/110.conf << 'EOF'
dev0: /dev/dri/renderD128,gid=993
dev1: /dev/dri/card0,gid=44
mp0: /mnt/<host>/data,mp=/mnt/data
EOF

pct start 110
```

### Notes
- Static IP <ip> — preserve MAC `<mac>` or update OPNsense static lease.
- GPU passthrough (`renderD128`, `card0`) must be re-added to config after restore.
- NFS mount `/mnt/<host>/data` → `/mnt/data` must be re-added as `mp0`.
- Media itself lives on <host> — only Plex metadata/database needs backup.

---

## Scheduled Backup Strategy (Recommended)

Set up in Proxmox UI (Datacenter → Backup) or via cron on each host:

```bash
# Example: nightly backup of all running LXCs on <host> at 2 AM
# Add to /etc/cron.d/vzdump-nightly on <host>:
0 2 * * * root vzdump --all --mode snapshot --compress zstd --storage local-lvm \
  --exclude 102 \   # <host> — handled by appdata backup script
  --mailto ""       # no email (use ntfy instead)
```

| VMID | Name              | Priority | Backup frequency |
|------|-------------------|----------|-----------------|
| 100  | mqtt              | low      | weekly |
| 101  | adguard           | high     | daily |
| 104  | <host>           | high     | daily |
| 105  | haos              | high     | daily |
| 107  | zigbee2mqtt       | medium   | weekly |
| 108  | zwave-js-ui       | medium   | weekly |
| 109  | unifi             | medium   | weekly |
| 110  | plex              | low      | monthly (config only) |
| 102  | <host>             | medium   | weekly (appdata daily via script) |
