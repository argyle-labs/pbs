<p align="center">
  <img src="assets/icon-256.png" width="120" alt="pbs" />
</p>

# pbs

Proxmox Backup Server is a dedicated backup solution for VMs, containers, and hosts.

A first-party [orca](https://github.com/argyle-labs/orca) plugin (appliance integration).

This plugin **connects orca to an existing pbs install** — there's nothing to deploy here. Stand up pbs from the upstream project, then point orca at it.

---

## Run it without orca

Install pbs per the upstream project: <https://www.proxmox.com/en/proxmox-backup-server>. It listens on port `8007` by default; this plugin talks to that endpoint (host, credentials/token) — no container is deployed.


See [proxmox-backup-restore.md](docs/proxmox-backup-restore.md) for worked operator notes.

## With orca

orca drives this plugin through its generic surface — rich, pbs-specific data comes back in the typed `service.status` payload, never bespoke tools.

## Layout

- `src/` — the plugin (pure Rust): the `ServiceBackend` descriptor + `configure` / `status`.
- `docs/` — standalone operator notes.
- [CAPABILITIES.md](CAPABILITIES.md) — the service-backend contract checklist.
- `assets/` — plugin icon.
