<p align="center">
  <img src="assets/icon-256.png" width="120" alt="pbs" />
</p>

# pbs

Proxmox Backup Server is a dedicated backup solution for VMs, containers, and hosts.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (appliance integration).

This plugin connects orca to a pbs install, and **can deploy one**: it declares the `docker` / `podman` runtimes and ships the container image this repo builds (`docker/Dockerfile`). Point orca at an existing pbs, or let `service.deploy` stand one up.

---

## Run it without orca

Install pbs per the upstream project: <https://www.proxmox.com/en/proxmox-backup-server>. It listens on port `8007` by default; this plugin talks to that endpoint (host, credentials/token).

### Container image

Proxmox ships PBS for bare metal and VMs only — there is **no official container image**. This repo builds one from Debian 13 plus Proxmox's own `pbs-no-subscription` repo, so the packages are first-party and no third-party image enters the supply chain.

```
ghcr.io/argyle-labs/pbs:4.2
```

Run it directly:

```sh
docker run -d --name pbs -p 8007:8007 \
  --tmpfs /run/proxmox-backup:rw,nosuid,nodev,mode=0755 \
  -v pbs-config:/etc/proxmox-backup \
  -v pbs-lib:/var/lib/proxmox-backup \
  -v pbs-logs:/var/log/proxmox-backup \
  -v /srv/backups:/mnt/datastore/primary \
  ghcr.io/argyle-labs/pbs:4.2
```

`/etc/proxmox-backup` **must** persist: it holds `authkey.key` and `proxy.pem`, which are the server's identity. Keep them and existing PVE clients stay trusted across a container recreate; lose them and every client has to re-verify a new fingerprint.

PBS normally runs as two systemd units (`proxmox-backup` as root, `proxmox-backup-proxy` as `backup`, ordered after it). The image's entrypoint reproduces that ordering and privilege split under `tini`, and exits if either daemon dies so the container restarts as a whole rather than serving with half of PBS up.

### Running on a NAS (Unraid, Synology, TrueNAS)

PBS runs its proxy as `backup`, uid/gid **34** on a stock install. On a NAS whose shares are owned by a fixed account — Unraid uses `nobody:users` = **99:100** — every file PBS writes lands as a bare numeric `34`, outside the host's permission model, and tools that reason about share ownership stop working.

Set `PUID`/`PGID` to the host's expected ids:

```sh
docker run -d --name pbs -p 8007:8007 \
  -e PUID=99 -e PGID=100 \
  --tmpfs /run/proxmox-backup:rw,nosuid,nodev,mode=0755 \
  -v pbs-config:/etc/proxmox-backup \
  -v /mnt/user/pbs:/mnt/datastore/primary \
  ghcr.io/argyle-labs/pbs:4.2
```

The entrypoint remaps the `backup` account at start and re-stamps anything the old identity owned in `/etc/proxmox-backup`. It defaults to `34`/`34`, i.e. unchanged from a stock install.

Note this only governs **new** writes. An existing datastore written under a different uid keeps that ownership until you `chown` it.

The `--tmpfs /run/proxmox-backup` is **required**, not optional: PBS keeps its config-version cache in shared memory there and needs that path on tmpfs. Without it the server still starts and serves, but traffic control silently fails to load (`path "/run/proxmox-backup/shmem" is not on tmpfs`). The entrypoint warns when it is missing.

When orca deploys the workload it mounts this tmpfs at 16m, but it cannot yet set `mode` or `nosuid,nodev`: orca's deploy `Mount` has no field for tmpfs options. Until it does, the mount uses the runtime's defaults.

Datastore contents are mounted in from outside and are never part of the image or the config volume.

**The config backup is secret-grade.** orca's self-config backup of this plugin's workload covers `/etc/proxmox-backup` and `/var/lib/proxmox-backup`, which include `token.shadow` (API token secret hashes), `authkey.key` (the ticket signing key), `tfa.json` and the tape encryption keys. Anyone who can read that backup can mint PBS tickets, so store it only on a destination you would trust with the server itself.


See [proxmox-backup-restore.md](docs/proxmox-backup-restore.md) for worked operator notes.

## With orca

`service.*` deploys and backs up pbs itself. Managing a running server goes through the `pbs.*` verbs, which call the PBS REST API on `:8007` with an API token:

- `pbs.create|update|delete|list|detail` — register an endpoint: routes, token id (`user@realm!tokenid`), and either a certificate fingerprint pin or an explicit `insecure`. The token secret is passed by reference, never as a value: write it first with `orca secrets upsert --name pbs.<name>.staged --value-stdin`, then pass `token_secret_ref: pbs.<name>.staged`. Only that name, for the endpoint being created or updated, is accepted, and the staged copy is deleted once stored. On update the secret is written before the row, so a new token id never sits beside the old token's secret. If the secret write succeeds and the row write fails while the update changes `token_id`, the endpoint is left with the old token id and the new secret and cannot authenticate. The old secret is already overwritten, so there is no rollback; re-run the same update, which works because the staged copy is deleted only on success. The secret and the pin are kept in orca's secrets domain (`pbs.<endpoint>.token_secret`, `pbs.<endpoint>.fingerprint`), never on the endpoint row.
- `pbs.datastore.list|detail` — datastores, usage, group/snapshot counts, GC state.
- `pbs.namespace.list|create|delete`
- `pbs.task.list|detail` — tasks and their logs, read through the API.
- `pbs.host.enroll|revoke` — per backup client host: namespace `hosts/<host>`, user `<host>@pbs`, token `<host>@pbs!backup`, and `DatastoreBackup` + `DatastorePowerUser` on `/datastore/<ds>/hosts/<host>` only (PowerUser lets the host prune its own group). Enrol reports drift (missing pieces, out-of-scope ACLs, a token whose stored secret PBS now rejects) and fixes it on execute. A disabled or expired token or user whose secret orca holds is re-enabled but not regenerated, because PBS rejects an inactive token before checking its secret; re-run enrol after enabling to verify the secret. If orca holds no secret, the token is regenerated and enabled together. The minted secret is stored as orca secret `pbs.<endpoint>.host_<host>_token` the moment PBS returns it and is never printed. If it can't be stored, enrol stops before any later step; re-running regenerates it. The names `admin`, `root` and `orca` are reserved, the user behind the endpoint's own token is refused, and an existing `<host>@pbs` user orca did not create is only taken over with `adopt: true`. Revoke keeps the namespace and its backups unless `delete_data` is set.
- `pbs.sync_job.list|create|update|run`, `pbs.verify_job.list|create|update|run` — schedules are evaluated in the server's zone (UTC for the container image), so next and last runs are shown in UTC and in the server's zone, plus at `utc_offset` (e.g. `-06:00`) when given. There is no automatic host-local time: the plugin can run on any orca host and orca's time primitives expose no local zone. `update` sends only the fields that differ and echoes the job's config digest.
- `pbs.snapshot.list` — per-snapshot verify state. A snapshot whose verification failed is never used as an incremental base.
- `pbs.gc.detail|run` — includes the pending removals: unreferenced chunks kept because they were touched within 24h 5min of the last GC start.
- `pbs.group.list|delete` — across one or more datastores. Delete needs either named datastores or `all_datastores` (which also deletes replicas on sync targets), and refuses if a confirmed group's snapshot count or last backup changed, or the group vanished, since the dry run. That check is a fresh read just before the DELETE; PBS has no conditional delete, so a backup that finishes in the few milliseconds between them is removed with the group.
- `pbs.prune` — keeps the last 10 per group unless other `keep_*` options are given. Needs `backup_type` or an explicit `all_groups`. The plan comes from PBS's own prune dry run; PBS re-applies the keep rules at execute, so a snapshot taken after the dry run can shift which ones go.

Every verb that changes PBS is a dry run unless called with `execute: true`, and executing needs an admin caller. `pbs.host.enroll`, `pbs.host.revoke`, `pbs.namespace.delete`, `pbs.group.delete` and `pbs.prune` also need `items`: the change targets from the dry run. Each item is `<action> <target>`, so a step whose action changed since the dry run (an `enable-token` that became `regenerate-token`) is not confirmed; destructive items also carry what they delete (`#g<groups>.s<snapshots>@<last backup>` for a namespace, `#<snapshots>@<last backup>` for a group). Execute acts only on items still planned and reports the rest as skipped, except that a confirmed delete whose contents changed or vanished is refused outright and nothing in that call runs, so revoke keeps the user and token too. That check is a fresh read just before the first write; PBS has no conditional delete, so a backup finishing between the read and the DELETE is removed with the rest. On the CLI, `--items` is comma-separated; no item contains a comma.

`execute` needs a request-authenticated admin; daemon-internal or anonymous calls are refused.

### Backing up the server's own config

The plugin registers a `pbs-config` backup kind with orca's backup domain. `backup.run --kind pbs-config` copies `/etc/proxmox-backup` of every PBS container on the host, read from its config volume (`<volume root>/<instance>-config/_data`; the volume root defaults to `/var/lib/docker/volumes`, override with `ORCA_PBS_VOLUME_ROOT`). That covers `datastore.cfg`, `user.cfg`, `acl.cfg`, `token.shadow`, the sync, verify and prune job configs, `remote.cfg` and the server identity. Lock files, `.bak-*` rotations and symlinks are skipped, and datastore contents are never included. Each backup is a file tree plus a manifest recording every directory's and file's permission bits and owner, and every file's size and SHA-256.

The volume is writable by the container, so every path in it is opened from a directory handle one component at a time, never following a symlink. Device nodes and FIFOs are never opened. The whole config is read into memory while the backup holds PBS's own config lock files shared (PBS takes them with `flock`, so its writers wait out the reads), every source file is checked again, and the locks are released before anything is written. If anything changed during the read, it is retried once and otherwise refused. Each file is hashed from the bytes read off the source, and the written copy is checked against those hashes. Reads are capped at 16 MiB per file and 256 MiB in total. A backup is refused if `user.cfg`, `acl.cfg`, `authkey.*` or `proxy.*` is missing; API tokens without a secret in `token.shadow` are named in the backup's note.

This is the server's config only. The `service.*` workload backup of the same container (above) also archives `/var/lib/proxmox-backup`; this kind is the one to schedule and restore a server from.

**Targets for this kind must be root-only.** The backup holds token hashes and the ticket signing key. Every payload file is set to `0600` and every directory to `0700`; on a target that ignores modes (CIFS) the backup's note says so, and the share's own permissions are all that protects it. Every restore, live or scratch, first checks the backup record's checksum against the payload's manifest and refuses a backup whose checksum is missing or wrong. **That checksum detects corruption, not tampering:** it is stored in the backup store beside the backup it covers, so anyone who can write to the store can replace both. Until [orca#478](https://gitea.scottkey.me/argyle-labs/orca/issues/478) holds the checksum in orca's database or keys it, keep the store writable by root only. Restore output says the same in its `integrity` field.

- `pbs.config_backup.detail` lists the file set per instance and gives each instance's `schedule` row (`pbs-config-backup-<instance>`, nightly at 03:10, clear of the old 02:40 script while both run) with the command that writes it: `orca config upsert schedule pbs-config-backup-<instance> '…' --execute`. Retention is keep-last 10. orca prunes by the retention of the target that receives the backup, so set `keep_last: 10` on that target. Watch `backup.list --kind pbs-config`: the newest backup of each instance should never be more than a day old.
- `pbs.config_restore` restores a backup into a scratch directory and verifies the copy: every checksum, the datastores in `datastore.cfg`, and the API tokens in `user.cfg`. `payload` must be a `pbs-config` payload directory inside a backup store (the `path` from `backup.list`); that check catches pointing at the wrong directory and is not a security boundary. `dest` must not exist; it is created `0700`. The dry run verifies the backup in place, lists the files it would write, and reports anything that would block execute.
- `backup.restore --kind pbs-config` restores onto the live config volume: **stop the container, restore, start it.** The restore refuses while any container mounts the volume by name or by path, and treats container state it cannot read or parse as running; it checks again after replacing the files. It verifies the backup first and writes nothing if verification fails. It checks each file against the manifest as it stages it, fsyncs them all, sets the originals aside, then replaces them, and on any reported error puts the originals back and removes directories it created. It never writes through a symlink. Files and the directories it creates get the owner recorded in the backup; a directory that already exists keeps its owner and only takes the recorded mode. It then checks every restored file's contents, owner and mode, and every directory's mode. Files the backup does not hold are left in place.
- `pbs.config_recover --instance <i> --action rollback|finish` settles a restore that was cut off (a crash or power loss mid-restore leaves `.orca-restore-*`, `.orca-prev-*` and an `.orca-swap-*` marker at the config root, and the next restore refuses until they are settled). The marker records how far the restore got. `rollback` puts the originals back and removes directories the restore created; `finish` completes the restore and is refused unless the restore had reached the swap, so a restore that was still staging or already rolling back can only be rolled back. The marker lives in the container-writable volume, so recovery treats it as a pointer only. `finish` reads the manifest again from the backup slot the marker names. It refuses unless that slot is in a backup store outside docker's data root (the parent of the volume root, whose volumes and image layers are all writable by containers), still verifies, is a backup of this instance and matches the marker byte for byte. The dry run shows that slot, and `finish` must be given it as `--payload <slot path>`. If retention prunes the slot while a restore is interrupted, `finish` can no longer verify it and only `rollback` remains. It writes each staged file's checked bytes to a new file and renames that into place, re-applies directory modes (it never changes a directory's owner), then checks the result as a restore does and reports it. `rollback` only acts on files carrying the marker's tag. A file the marker says the restore added is left in place and named in the plan, and a set-aside original that is a symlink is refused. Instance names must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`, and walks stop at 32 directory levels. If a swap fails and the rollback cannot be recorded in the marker, the restore puts nothing back and leaves both actions open. Leftovers with no marker are removed. A directory named like a leftover is never removed automatically; recovery says so and leaves it to you. Dry run by default; needs the container stopped.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor and the `pbs.*` API verbs.
- `tests/fixtures/` — PBS API responses the unit tests decode.
- `docs/` — standalone operator notes.
- [CAPABILITIES.md](CAPABILITIES.md) — the service-backend contract checklist.
- `assets/` — plugin icon.
