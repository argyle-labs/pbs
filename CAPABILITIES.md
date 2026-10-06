# pbs — ServiceBackend contract

Pure-Rust plugin (**no bash/compose/provision scripts**) driven by the single
generic `service.*` surface — no per-plugin tools. Runtimes: **docker,podman,lxc,vm**.

## Per-plugin code (the only work this repo owns)
- [x] `provider` / `runtimes` / `default_port` / `capabilities` / `data_paths` — declarative descriptor
- [x] `workload_spec(runtime)` — docker/podman implemented (image, `<instance>-config`/`-lib`/`-logs` volumes, 16m `/run/proxmox-backup` tmpfs, published port); lxc/vm still unimplemented
- [ ] `configure` — apply pbs config via its upstream API
- [ ] `status` — health + rich diagnostics returned in the typed `ServiceStatus.info`
- [x] `pbs-config` backup kind ([`config_backup`](src/config_backup.rs)) — `/etc/proxmox-backup` for `backup.run` / `backup.restore`, plus `pbs.config_backup.detail`, the `pbs.config_restore` scratch restore and `pbs.config_recover`. The slot checksum restores check sits in the backup store beside the backup, so it detects corruption, not tampering by anyone with write access to the store, until orca#478 holds it in orca's database or keys it

> Declarative descriptor is implemented and the plugin **registers + loads live**
> in orca today (`service.list` shows it). `workload_spec`/`configure`/`status`
> are being filled in per plugin.

## Provided generically by orca (NO code here)
- `deploy` — `service.deploy` → `deploy_target.launch(WorkloadSpec)`
- `backup` / `restore` — pluggable `BackupMethod` (tar; **PBS** for Proxmox guests)
- single `service.*` tool surface, exposed over CLI / REST / MCP
