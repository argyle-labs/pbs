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

- `pbs.create|update|delete|list|detail` — register an endpoint: routes, token id (`user@realm!tokenid`), and either a certificate fingerprint pin or an explicit `insecure`. The token secret is passed by reference, never as a value: write it first with `orca secrets upsert --name pbs.<name>.staged --value-stdin`, then pass `token_secret_ref: pbs.<name>.staged`. Only that name, for the endpoint being created or updated, is accepted, and the staged copy is deleted once stored. On update the secret is written before the row, so a new token id never sits beside the old token's secret. If the secret write succeeds and the row write fails, the endpoint is left with the old token id and the new secret and cannot authenticate. The old secret is already overwritten, so there is no rollback; re-run the same update, which works because the staged copy is deleted only on success. The secret and the pin are kept in orca's secrets domain (`pbs.<endpoint>.token_secret`, `pbs.<endpoint>.fingerprint`), never on the endpoint row.
- `pbs.datastore.list|detail` — datastores, usage, group/snapshot counts, GC state.
- `pbs.namespace.list|create|delete`
- `pbs.task.list|detail` — tasks and their logs, read through the API.
- `pbs.host.enroll|revoke` — per backup client host: namespace `hosts/<host>`, user `<host>@pbs`, token `<host>@pbs!backup`, and `DatastoreBackup` + `DatastorePowerUser` on `/datastore/<ds>/hosts/<host>` only (PowerUser lets the host prune its own group). Enrol reports drift (missing pieces, out-of-scope ACLs, a token whose stored secret PBS now rejects) and fixes it on execute. A disabled or expired token or user whose secret orca holds is re-enabled but not regenerated, because PBS rejects an inactive token before checking its secret; re-run enrol after enabling to verify the secret. If orca holds no secret, the token is regenerated and enabled together. The minted secret is stored as orca secret `pbs.<endpoint>.host_<host>_token` the moment PBS returns it and is never printed. If it can't be stored, enrol stops before any later step; re-running regenerates it. The names `admin`, `root` and `orca` are reserved, the user behind the endpoint's own token is refused, and an existing `<host>@pbs` user orca did not create is only taken over with `adopt: true`. Revoke keeps the namespace and its backups unless `delete_data` is set.
- `pbs.sync_job.list|create|update|run`, `pbs.verify_job.list|create|update|run` — schedules are evaluated in the server's zone (UTC for the container image), so next and last runs are shown in UTC and in the server's zone, plus at `utc_offset` (e.g. `-06:00`) when given. There is no automatic host-local time: the plugin can run on any orca host and orca's time primitives expose no local zone. `update` sends only the fields that differ and echoes the job's config digest.
- `pbs.snapshot.list` — per-snapshot verify state. A snapshot whose verification failed is never used as an incremental base.
- `pbs.gc.detail|run` — includes the pending removals: unreferenced chunks kept because they were touched within 24h 5min of the last GC start.
- `pbs.group.list|delete` — across one or more datastores. Delete needs either named datastores or `all_datastores` (which also deletes replicas on sync targets), and refuses if a confirmed group's snapshot count or last backup changed since the dry run. That check is a fresh read just before the DELETE; PBS has no conditional delete, so a backup that finishes in the few milliseconds between them is removed with the group.
- `pbs.prune` — keeps the last 10 per group unless other `keep_*` options are given. Needs `backup_type` or an explicit `all_groups`. The plan comes from PBS's own prune dry run; PBS re-applies the keep rules at execute, so a snapshot taken after the dry run can shift which ones go.

Every verb that changes PBS is a dry run unless called with `execute: true`, and executing needs an admin caller. `pbs.host.enroll`, `pbs.host.revoke`, `pbs.namespace.delete`, `pbs.group.delete` and `pbs.prune` also need `items`: the change targets from the dry run. Each item is `<action> <target>`, so a step whose action changed since the dry run (an `enable-token` that became `regenerate-token`) is not confirmed; destructive items also carry what they delete (`#g<groups>.s<snapshots>@<last backup>` for a namespace, `#<snapshots>@<last backup>` for a group). Execute acts only on items still planned and reports the rest as skipped, except that a confirmed delete whose contents changed is refused outright and nothing in that call runs, so revoke keeps the user and token too. That check is a fresh read just before the first write; PBS has no conditional delete, so a backup finishing between the read and the DELETE is removed with the rest. On the CLI, `--items` is comma-separated; no item contains a comma.

**Known gap ([orca#763](https://gitea.scottkey.me/argyle-labs/orca/issues/763)):** orca does not yet pass the caller identity to plugins, so `execute` currently always fails with "no caller identity". The check fails closed on purpose; dry runs work.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor and the `pbs.*` API verbs.
- `tests/fixtures/` — PBS API responses the unit tests decode.
- `docs/` — standalone operator notes.
- [CAPABILITIES.md](CAPABILITIES.md) — the service-backend contract checklist.
- `assets/` — plugin icon.
