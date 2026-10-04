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

Datastore contents are mounted in from outside and are never part of the image or the config volume.


See [proxmox-backup-restore.md](docs/proxmox-backup-restore.md) for worked operator notes.

## With orca

`service.*` deploys and backs up pbs itself. Managing a running server goes through the `pbs.*` verbs, which call the PBS REST API on `:8007` with an API token:

- `pbs.create|update|delete|list|detail` — register an endpoint: routes, token id (`user@realm!tokenid`), and either a certificate fingerprint pin or an explicit `insecure`. The token secret and the pin are kept in orca's secrets domain (`pbs.<endpoint>.token_secret`, `pbs.<endpoint>.fingerprint`), never on the endpoint row.
- `pbs.datastore.list|detail` — datastores, usage, group/snapshot counts, GC state.
- `pbs.namespace.list|create|delete`
- `pbs.task.list|detail` — tasks and their logs, read through the API.
- `pbs.host.enroll|revoke` — per backup client host: namespace `hosts/<host>`, user `<host>@pbs`, token `<host>@pbs!backup`, and `DatastoreBackup` + `DatastorePowerUser` on `/datastore/<ds>/hosts/<host>` only (PowerUser lets the host prune its own group). Enrol reports drift (missing pieces, out-of-scope ACLs, a token whose stored secret PBS now rejects) and fixes it on execute. The minted secret is stored as orca secret `pbs.<endpoint>.host_<host>_token` and is never printed. Revoke keeps the namespace and its backups unless `delete_data` is set.
- `pbs.sync_job.list|create|update|run`, `pbs.verify_job.list|create|update|run` — schedules are evaluated in the server's zone (UTC for the container image), so next and last runs are shown in both UTC and local time (`utc_offset` overrides the orca host's zone). `update` sends only the fields that differ.
- `pbs.snapshot.list` — per-snapshot verify state. A snapshot whose verification failed is never used as an incremental base.
- `pbs.gc.detail|run` — includes the pending removals: unreferenced chunks kept because they were touched within 24h 5min of the last GC start.
- `pbs.group.list|delete` — across one or more datastores. Delete needs either named datastores or `all_datastores`.
- `pbs.prune` — keeps the last 10 per group unless other `keep_*` options are given. The plan comes from PBS's own prune dry run.

Every verb that changes PBS is a dry run unless called with `execute: true`, and executing needs an admin caller.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor and the `pbs.*` API verbs.
- `tests/fixtures/` — PBS API responses the unit tests decode.
- `docs/` — standalone operator notes.
- [CAPABILITIES.md](CAPABILITIES.md) — the service-backend contract checklist.
- `assets/` — plugin icon.
