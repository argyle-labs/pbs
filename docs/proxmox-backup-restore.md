# Proxmox Backup Server — Operator Notes

Operator reference for using Proxmox Backup Server (PBS) as a backup target for
Proxmox VE guests (VMs and LXCs). These notes are generic and apply to any PBS
deployment managed through this plugin.

---

## Overview

PBS provides incremental, deduplicated, and optionally encrypted backups for
Proxmox VE guests. Once a PBS datastore is added to a Proxmox VE node as a
storage target, `vzdump` (and the Datacenter → Backup UI) can write directly to
it, and restores can pull snapshots back from it.

| Method | What | When |
|--------|------|------|
| `vzdump` to a PBS datastore | Incremental, deduplicated guest backup | On-demand or scheduled |
| `vzdump` to local/NFS storage | Full VM/LXC snapshot archive | When PBS is unavailable |

---

## Command Reference

Replace the placeholder values (`<vmid>`, `<pbs-datastore>`, `<timestamp>`,
`<node-storage>`) with your own.

```bash
# Back up a guest to a PBS datastore (incremental + deduplicated)
vzdump <vmid> --mode snapshot --compress zstd --storage <pbs-datastore>

# Stop the guest first for guaranteed consistency (slower, causes downtime)
vzdump <vmid> --mode stop --compress zstd --storage <pbs-datastore>

# List available PBS snapshots for a guest (from the PVE node)
pvesm list <pbs-datastore>

# Restore an LXC from a PBS snapshot
pct restore <new-vmid> <pbs-datastore>:backup/ct/<vmid>/<timestamp> \
  --storage <node-storage> --force

# Restore a VM from a PBS snapshot
qmrestore <pbs-datastore>:backup/vm/<vmid>/<timestamp> <new-vmid> \
  --storage <node-storage> --force
```

---

## Restore Notes

- After restoring a guest, re-check node-specific configuration that is not part
  of the guest image: static IP / MAC assignments, USB or GPU passthrough
  entries, and bind mounts in `/etc/pve/<lxc|qemu>/<vmid>.conf`.
- For application-level restores that do not require full guest downtime, stop
  only the affected service containers, restore their config from the snapshot,
  then restart them. Refer to each service's own documentation for its config
  locations. For example:

  ```bash
  sudo docker stop app-a app-b        # your service containers
  # restore each service's config from the snapshot, then:
  sudo docker start app-a app-b
  ```

- Encrypted datastores require the encryption key to be present on the restoring
  node before a snapshot can be read.

---

## Scheduled Backups

Configure recurring backups to a PBS datastore in the Proxmox VE UI
(Datacenter → Backup), or with cron on the node:

```bash
# Nightly backup of all running guests to a PBS datastore at 2 AM
# /etc/cron.d/vzdump-nightly on the PVE node:
0 2 * * * root vzdump --all --mode snapshot --compress zstd \
  --storage <pbs-datastore> --mailto ""
```

Set retention (prune) policy on the PBS datastore itself so old snapshots are
reclaimed automatically. Deduplication means incremental snapshots are cheap;
retention controls how far back history is kept.
