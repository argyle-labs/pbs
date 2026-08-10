# PBS diagnostics — proposed capabilities

Field notes from the 2026-08-10 fleet incident. Written as an implementation spec
for detection/guardrails this plugin should add, not as shipped behaviour.

---

## 1. Do NOT file-sync a PBS datastore (the footgun)

**Context.** When the primary NAS was failed over to a replica, the replica's
copy of the PBS datastore path was **empty**, and it was wired into a bidirectional
file-sync (Syncthing `sendreceive`) folder. Two independent hazards:

1. A PBS datastore is a **chunkstore** (`.chunks/`, fixed/dynamic index files,
   `.gc-status`). File-level sync tools give no consistency guarantees over a live
   chunkstore and can corrupt it or race garbage collection.
2. A `sendreceive` folder with an **empty** local side can propagate deletions to
   the peer — i.e. delete the real backups.

**Guidance the plugin should encode.** PBS datastores replicate via **PBS-native
sync jobs** (`proxmox-backup-manager sync-job`) or remote/pull sync — never via
Syncthing/rsync of the raw datastore. Detect a datastore `path` that also appears
as a file-sync folder root and **warn loudly**.

## 2. Never fail a datastore over to an empty target

**Detection.** Before treating a replica datastore as a valid failover target,
verify it is **non-empty and current**: chunk count > 0, a recent
`snapshot`/backup index, and (ideally) a passing `verify`. A datastore whose path
resolves to an empty directory is not a failover target — mounting it as one hides
the real backups behind an empty store and risks propagating that emptiness.

## 3. Long-running / stuck garbage collection on degraded storage

**Symptom.** A `garbage_collection` task on `pbs-share` running for 15h+ with no
progress.

**Cause.** GC walks the entire chunkstore; if the backing storage is degraded
(the NAS ZFS corruption / deadman in the incident), GC stalls on slow or wedged
I/O rather than finishing.

**Detection.** Read `/var/log/proxmox-backup/tasks/active` (or the tasks API) and
flag any `garbage_collection` / `verify` / `backup` task whose runtime exceeds a
sane bound with no advancing progress. Correlate with the backing store's health
(the unraid/nfs plugins' storage diagnostics) — a stuck PBS task is often a
**symptom** of a sick datastore volume, not a PBS bug. Surface both together.

## 4. Datastore backing-mount health

A PBS datastore is only as available as the volume under its `path`. If that path
is an NFS mount of a NAS, the datastore inherits every NFS failure mode (hang vs
down, stale handles, release-on-reboot). Prefer a **health-checked** mount with a
bounded read probe over an unbounded `hard` mount, so a NAS reboot degrades the
datastore to "unavailable" rather than hanging every PBS task. (See the nfs
plugin's `failover-and-release.md`.)
