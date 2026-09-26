//! pbs service backend — Proxmox Backup Server.
//!
//! Implements `ServiceBackend` so the generic `service.*` tools
//! (deploy/backup/restore/configure/status/connect/sync) drive pbs. No
//! `#[orca_tool]`s — the only orca dep is `plugin-toolkit`. Modeled on the
//! nfs StorageBackend. See orca/docs/PLUGIN-PROGRAM.md.
#![allow(clippy::disallowed_types)]

use plugin_toolkit::service::{
    BoxFuture, Endpoint, Mount, Runtime, ServiceBackend, ServiceCapability, ServiceError,
    ServiceStatus, WorkloadSpec,
};

/// Image published from `docker/Dockerfile` in this repo. Upstream ships PBS for
/// bare metal / VM only, so we build from Proxmox's own `pbs-no-subscription`
/// packages rather than depend on a third-party image.
///
/// Defaults to the Gitea registry because that is the one every build actually
/// reaches: CI pushes Gitea and ghcr as separate steps, and the ghcr push has
/// failed on every merge since #12 (`permission_denied: token does not match
/// expected scopes` — the org token lacks `write:packages`). Pointing deploys at
/// ghcr meant `service.deploy` would pull a tag that does not exist.
const DEFAULT_IMAGE: &str = "gitea.scottkey.me/argyle-labs/pbs";
/// Tracks the PBS minor series the image is built against.
const IMAGE_TAG: &str = "4.2";

/// Fully-qualified image reference for the workload.
///
/// `ORCA_PBS_IMAGE` overrides it outright (including any tag), so a host that
/// resolves from a different registry — a public mirror, or an air-gapped copy —
/// does not need a rebuild. Without the override the default above is used.
fn image_ref() -> String {
    resolve_image(std::env::var("ORCA_PBS_IMAGE").ok())
}

/// Pure half of [`image_ref`], so the override is testable without mutating the
/// process environment (which leaks across parallel tests).
fn resolve_image(override_value: Option<String>) -> String {
    override_value
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| format!("{DEFAULT_IMAGE}:{IMAGE_TAG}"))
}

/// pbs backend. Holds only the provider name; per-instance endpoint/creds
/// come from the `Endpoint` the generic `service.*` tools hand each op.
#[derive(Debug, Clone)]
pub struct PbsBackend {
    provider: &'static str,
}

impl PbsBackend {
    pub fn new(provider: &'static str) -> Self {
        Self { provider }
    }
}

impl ServiceBackend for PbsBackend {
    fn provider(&self) -> &str {
        self.provider
    }

    /// Runtimes pbs can be placed on. `service.deploy` hands the
    /// `workload_spec` below to a matching deploy target — this backend never
    /// drives pct/docker itself (that mechanic lives in the deploy-target domain).
    fn runtimes(&self) -> Vec<Runtime> {
        vec![Runtime::Docker, Runtime::Podman, Runtime::Lxc, Runtime::Vm]
    }

    fn capabilities(&self) -> Vec<ServiceCapability> {
        vec![
            ServiceCapability::Deploy,
            ServiceCapability::Backup,
            ServiceCapability::Restore,
            ServiceCapability::Configure,
            ServiceCapability::Status,
        ]
    }

    fn default_port(&self) -> u16 {
        8007
    }

    /// In-workload paths holding config/data. This is ALL pbs declares for
    /// backup — the generic pluggable backup (tar for containers/LXC, PBS for
    /// Proxmox guests when available) snapshots these. No backup/restore code
    /// here; those are inherited from ServiceBackend's defaults.
    fn data_paths(&self) -> Vec<String> {
        // PBS keeps its whole config surface — datastore.cfg, user.cfg, acl.cfg,
        // plus `authkey.key` and `proxy.pem` — under one directory. Those keys
        // ARE the server identity: restore them and existing clients keep their
        // trust, lose them and every PVE host must re-verify a new fingerprint.
        // Datastore *contents* are deliberately not listed: they are the backups
        // themselves, mounted in from outside and never captured by this path.
        vec!["/etc/proxmox-backup".to_string()]
    }

    fn workload_spec<'a>(
        &'a self,
        runtime: Runtime,
        ep: &'a Endpoint,
    ) -> BoxFuture<'a, Result<WorkloadSpec, ServiceError>> {
        Box::pin(async move {
            match runtime {
                Runtime::Docker | Runtime::Podman => Ok(WorkloadSpec {
                    name: ep.name.clone(),
                    image: Some(image_ref()),
                    env: Vec::new(),
                    mounts: vec![
                        // Config + server identity. Named volume rather than a
                        // host path so recreating the container is lossless.
                        Mount {
                            source: format!("{}-config", ep.name),
                            target: "/etc/proxmox-backup".to_string(),
                            read_only: false,
                        },
                        Mount {
                            source: format!("{}-logs", ep.name),
                            target: "/var/log/proxmox-backup".to_string(),
                            read_only: false,
                        },
                    ],
                    // Datastore mounts are deliberately absent: which paths hold
                    // backups is per-install, so they are supplied as endpoint
                    // config and merged by the deploy target, not hardcoded here.
                    ports: vec![format!("{}:8007", ep.publish_port(8007))],
                }),
                Runtime::Lxc | Runtime::Vm => {
                    Err(ServiceError::unimplemented("pbs.workload_spec (lxc/vm)"))
                }
            }
        })
    }

    fn configure<'a>(
        &'a self,
        _ep: &'a Endpoint,
        _config: &'a str,
    ) -> BoxFuture<'a, Result<(), ServiceError>> {
        // TODO: apply pbs-specific config idempotently.
        Box::pin(async move { Err(ServiceError::unimplemented("pbs.configure")) })
    }

    fn status<'a>(
        &'a self,
        _ep: &'a Endpoint,
    ) -> BoxFuture<'a, Result<ServiceStatus, ServiceError>> {
        // TODO: real health/diagnostics.
        Box::pin(async move { Err(ServiceError::unimplemented("pbs.status")) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declares_provider() {
        let b = PbsBackend::new("pbs");
        assert_eq!(b.provider(), "pbs");
    }

    #[test]
    fn docker_is_a_declared_runtime() {
        assert!(PbsBackend::new("pbs").runtimes().contains(&Runtime::Docker));
    }

    #[tokio::test]
    async fn docker_workload_spec_carries_config_volume_and_port() {
        let b = PbsBackend::new("pbs");
        let ep = Endpoint {
            name: "pbs-willow".to_string(),
            ..Default::default()
        };
        let spec = b.workload_spec(Runtime::Docker, &ep).await.unwrap();

        assert_eq!(spec.name, "pbs-willow");
        assert_eq!(
            spec.image.as_deref(),
            Some("gitea.scottkey.me/argyle-labs/pbs:4.2")
        );
        // Falls back to the default port when the endpoint declares no lan_v4 route.
        assert_eq!(spec.ports, vec!["8007:8007".to_string()]);

        // The config volume is what preserves authkey/proxy.pem across a
        // container recreate — without it every client re-verifies a new cert.
        let cfg = spec
            .mounts
            .iter()
            .find(|m| m.target == "/etc/proxmox-backup")
            .expect("config mount");
        assert_eq!(cfg.source, "pbs-willow-config");
        assert!(!cfg.read_only);
    }

    #[test]
    fn resolve_image_defaults_to_the_registry_ci_actually_publishes_to() {
        assert_eq!(resolve_image(None), "gitea.scottkey.me/argyle-labs/pbs:4.2");
    }

    #[test]
    fn resolve_image_honours_an_override() {
        assert_eq!(
            resolve_image(Some("ghcr.io/argyle-labs/pbs:9.9".to_string())),
            "ghcr.io/argyle-labs/pbs:9.9"
        );
    }

    #[test]
    fn resolve_image_ignores_a_blank_override() {
        // An unset-but-present env var must not yield a bare ":4.2".
        assert_eq!(
            resolve_image(Some("   ".to_string())),
            "gitea.scottkey.me/argyle-labs/pbs:4.2"
        );
    }

    #[tokio::test]
    async fn lxc_and_vm_remain_unimplemented() {
        let b = PbsBackend::new("pbs");
        let ep = Endpoint::default();
        assert!(b.workload_spec(Runtime::Lxc, &ep).await.is_err());
        assert!(b.workload_spec(Runtime::Vm, &ep).await.is_err());
    }
}
