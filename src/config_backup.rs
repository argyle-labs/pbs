//! `pbs-config` backup KIND: the server's own `/etc/proxmox-backup`.
//!
//! orca's backup domain drives it: `backup.run --kind pbs-config` captures each
//! instance into a target (smb/fs/…), prunes per that target's retention, and
//! `backup.restore` writes a capture back. Captures are a plain file tree plus
//! a manifest of sizes, SHA-256 and owner/mode, never the datastore contents.
//!
//! The kind reads the config volume straight off the host running the
//! container (`<volume root>/<instance>-config/_data`), so it only finds
//! instances on that host and runs nowhere else.
//!
//! `pbs.config_backup.detail` shows the file set and the schedule row;
//! `pbs.config_restore` restores a capture into a scratch directory and
//! verifies it, dry run by default.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::backend_def::backup_kind_backend_def;
use plugin_toolkit::backup::{dispatch_kind_op, BackupKindPlugin};
use plugin_toolkit::contract::backup::{BackupOutcome, Retention};
use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{self, Value};

use crate::plan;

pub const KIND: &str = "pbs-config";
const BACKUP_PREFIX: &str = "pbs.__backup_pbs_config";

const DEFAULT_VOLUME_ROOT: &str = "/var/lib/docker/volumes";
const MANIFEST: &str = "manifest.json";
const FILES_DIR: &str = "files";
const MANIFEST_VERSION: u32 = 1;

/// Fleet retention policy for config backups.
pub const KEEP_LAST: u32 = 10;
/// Nightly at 02:40, the slot the hand-made willow script used.
pub const SCHEDULE_CRON: &str = "40 2 * * *";
pub const SCHEDULE_NAME: &str = "pbs-config-backup";

/// Files without which a restored server is not the same server: its users,
/// ACLs and token secrets, and the keys and certificate clients have pinned.
/// A capture missing any of them is refused.
pub const REQUIRED: &[&str] = &[
    "user.cfg",
    "acl.cfg",
    "authkey.key",
    "authkey.pub",
    "proxy.key",
    "proxy.pem",
];

/// Lock files, rotated backups and the `.lock`/`.lck` siblings PBS creates
/// next to a config file hold no state of their own.
pub(crate) fn transient(name: &str) -> bool {
    name.starts_with('.') || name.ends_with(".lock") || name.contains(".bak-")
}

pub fn retention() -> Retention {
    Retention::keep_last(KEEP_LAST)
}

/// `backup.run` is execute-gated, so the row opts in; the scheduler dispatches
/// with no caller, which the gate allows.
pub fn schedule_row() -> Value {
    json!({
        "job": "backup.run",
        "cron": SCHEDULE_CRON,
        "args": {"kind": KIND, "execute": true},
    })
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FileEntry {
    /// Path relative to the config directory, `/`-separated.
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub version: u32,
    pub instance: String,
    /// Directory the capture was read from.
    pub source: String,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    pub fn read(payload: &Path) -> Result<Self> {
        let path = payload.join(MANIFEST);
        let raw = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        let m: Manifest =
            serde_json::from_slice(&raw).with_context(|| format!("parse {}", path.display()))?;
        if m.version != MANIFEST_VERSION {
            bail!(
                "{}: manifest version {} is not {MANIFEST_VERSION}",
                path.display(),
                m.version
            );
        }
        Ok(m)
    }
}

/// What a restored config directory would bring back.
#[orca_struct]
#[derive(Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Verification {
    pub files_checked: usize,
    /// Datastores defined in `datastore.cfg`.
    pub datastores: Vec<String>,
    /// API tokens defined in `user.cfg`.
    pub tokens: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

impl Verification {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Every non-transient file under `dir`, relative and sorted.
pub fn collect(dir: &Path) -> Result<Vec<String>> {
    let mut out = Vec::new();
    walk(dir, "", &mut out)?;
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if transient(&name) {
            continue;
        }
        let rel = format!("{prefix}{name}");
        let ty = entry.file_type()?;
        if ty.is_dir() {
            walk(&entry.path(), &format!("{rel}/"), out)?;
        } else if ty.is_file() {
            out.push(rel);
        }
    }
    Ok(())
}

pub fn missing_required(files: &[String]) -> Vec<String> {
    REQUIRED
        .iter()
        .filter(|r| !files.iter().any(|f| f == *r))
        .map(|r| r.to_string())
        .collect()
}

/// Copy `source` into `payload/files` and write the manifest.
pub fn capture(source: &Path, payload: &Path, instance: &str) -> Result<Manifest> {
    let names = collect(source)?;
    let missing = missing_required(&names);
    if !missing.is_empty() {
        bail!(
            "{} is not a complete PBS config directory; missing {}",
            source.display(),
            missing.join(", ")
        );
    }
    let files_root = payload.join(FILES_DIR);
    let mut files = Vec::with_capacity(names.len());
    for rel in names {
        let from = source.join(&rel);
        let to = files_root.join(&rel);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&from, &to).with_context(|| format!("copy {}", from.display()))?;
        let meta = fs::metadata(&from)?;
        files.push(FileEntry {
            sha256: plugin_toolkit::hash::sha256_file(&to)?,
            size: meta.len(),
            mode: meta.mode() & 0o7777,
            uid: meta.uid(),
            gid: meta.gid(),
            path: rel,
        });
    }
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        instance: instance.to_string(),
        source: source.display().to_string(),
        files,
    };
    fs::write(
        payload.join(MANIFEST),
        serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

/// Check `dir` holds exactly what `manifest` recorded, and that what it holds
/// is a server that would come back with its datastores and working tokens.
pub fn verify(dir: &Path, manifest: &Manifest) -> Verification {
    let mut v = Verification::default();
    for f in &manifest.files {
        let path = dir.join(&f.path);
        match plugin_toolkit::hash::sha256_file(&path) {
            Ok(sum) if sum == f.sha256 => v.files_checked += 1,
            Ok(_) => v.problems.push(format!("{}: checksum mismatch", f.path)),
            Err(_) => v
                .problems
                .push(format!("{}: missing or unreadable", f.path)),
        }
    }
    let names: Vec<String> = manifest.files.iter().map(|f| f.path.clone()).collect();
    for m in missing_required(&names) {
        v.problems.push(format!("{m}: not in the backup"));
    }
    let read = |name: &str| fs::read_to_string(dir.join(name)).unwrap_or_default();
    v.datastores = section_ids(&read("datastore.cfg"), "datastore");
    v.tokens = section_ids(&read("user.cfg"), "token");
    // A token whose secret hash is gone exists but can never authenticate.
    let shadow: serde_json::Map<String, Value> =
        serde_json::from_str(&read("token.shadow")).unwrap_or_default();
    for t in &v.tokens {
        if !shadow.contains_key(t) {
            v.problems
                .push(format!("token {t}: no secret in token.shadow"));
        }
    }
    v
}

/// Ids of the `<kind>: <id>` section headers in a PBS section-config file.
fn section_ids(text: &str, kind: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix(kind)?.strip_prefix(':'))
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect()
}

/// Write the captured files into `dest` with their recorded modes. With
/// `owners`, also their recorded uid/gid: the proxy runs as `backup` and
/// cannot read a root-owned `authkey.pub`. Each file lands by rename, so PBS
/// never reads a half-written one.
pub fn materialize(payload: &Path, dest: &Path, manifest: &Manifest, owners: bool) -> Result<()> {
    let files_root = payload.join(FILES_DIR);
    fs::create_dir_all(dest)?;
    for f in &manifest.files {
        let to = dest.join(&f.path);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = to.with_file_name(format!(
            ".{}.orca-restore",
            to.file_name().unwrap_or_default().to_string_lossy()
        ));
        fs::copy(files_root.join(&f.path), &tmp).with_context(|| format!("stage {}", f.path))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(f.mode))?;
        if owners {
            std::os::unix::fs::chown(&tmp, Some(f.uid), Some(f.gid))
                .with_context(|| format!("chown {} to {}:{}", f.path, f.uid, f.gid))?;
        }
        fs::rename(&tmp, &to).with_context(|| format!("place {}", f.path))?;
    }
    Ok(())
}

fn volume_root() -> PathBuf {
    std::env::var("ORCA_PBS_VOLUME_ROOT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VOLUME_ROOT))
}

/// The backup KIND over one container-runtime volume root.
pub struct PbsConfigKind {
    volume_root: PathBuf,
}

impl PbsConfigKind {
    /// `ORCA_PBS_VOLUME_ROOT` overrides the docker default, for podman or a
    /// relocated docker data root.
    pub fn from_env() -> Self {
        Self::at(volume_root())
    }

    pub fn at(volume_root: impl Into<PathBuf>) -> Self {
        Self {
            volume_root: volume_root.into(),
        }
    }

    pub fn config_dir(&self, instance: &str) -> PathBuf {
        self.volume_root
            .join(crate::config_volume(instance))
            .join("_data")
    }

    /// Instances whose config volume holds a PBS server identity.
    pub fn find(&self) -> Result<Vec<String>> {
        let entries = match fs::read_dir(&self.volume_root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(e).with_context(|| format!("read {}", self.volume_root.display()))
            }
        };
        let mut out = Vec::new();
        for entry in entries {
            let name = entry?.file_name().to_string_lossy().into_owned();
            let Some(instance) = name.strip_suffix("-config") else {
                continue;
            };
            let dir = self.config_dir(instance);
            if dir.join("authkey.pub").is_file() && dir.join("user.cfg").is_file() {
                out.push(instance.to_string());
            }
        }
        out.sort();
        Ok(out)
    }
}

impl BackupKindPlugin for PbsConfigKind {
    fn kind(&self) -> &str {
        KIND
    }

    fn title(&self) -> String {
        "PBS server config".to_string()
    }

    fn instances(&self) -> Result<Vec<String>, String> {
        self.find().map_err(|e| format!("{e:#}"))
    }

    fn backup(&self, payload_dir: &Path, instance: &str) -> Result<BackupOutcome, String> {
        let source = self.config_dir(instance);
        let manifest = capture(&source, payload_dir, instance).map_err(|e| format!("{e:#}"))?;
        let raw = fs::read(payload_dir.join(MANIFEST)).map_err(|e| e.to_string())?;
        Ok(BackupOutcome {
            checksum: Some(format!("sha256:{}", sha256_hex(&raw))),
            note: Some(format!(
                "{} files from {}",
                manifest.files.len(),
                source.display()
            )),
            unchanged: false,
        })
    }

    /// Verify the capture, write it over the live config volume, then verify
    /// the volume. Files the capture does not hold are left in place. PBS
    /// loads its keys at start, so the container needs a restart afterwards.
    fn restore(&self, payload_dir: &Path, instance: &str) -> Result<(), String> {
        let manifest = Manifest::read(payload_dir).map_err(|e| format!("{e:#}"))?;
        let captured = verify(&payload_dir.join(FILES_DIR), &manifest);
        if !captured.ok() {
            return Err(format!(
                "backup failed verification, nothing restored: {}",
                captured.problems.join("; ")
            ));
        }
        let live = self.config_dir(instance);
        if !live.is_dir() {
            return Err(format!(
                "{} does not exist; deploy the container first so its config volume exists",
                live.display()
            ));
        }
        materialize(payload_dir, &live, &manifest, true).map_err(|e| format!("{e:#}"))?;
        let restored = verify(&live, &manifest);
        if !restored.ok() {
            return Err(format!(
                "restored config failed verification: {}",
                restored.problems.join("; ")
            ));
        }
        tracing::info!(
            instance,
            datastores = ?restored.datastores,
            tokens = ?restored.tokens,
            "[pbs-config] restored {} files; restart the container to load them",
            restored.files_checked
        );
        Ok(())
    }
}

pub fn backend_def() -> BackendDef {
    backup_kind_backend_def(KIND, BACKUP_PREFIX)
}

/// Dispatcher for `pbs.__backup_pbs_config.*`; `None` for anything else.
pub fn dispatcher(tool: &str, args: Value) -> Option<Result<Value, Value>> {
    let op = tool
        .strip_prefix(BACKUP_PREFIX)
        .and_then(|s| s.strip_prefix('.'))?;
    Some(dispatch_kind_op(&PbsConfigKind::from_env(), op, args))
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.config_backup.detail
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBackupDetailArgs {
    /// Only this instance. Default: every one found on this host.
    #[arg(long)]
    #[serde(default)]
    pub instance: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InstanceFiles {
    pub instance: String,
    pub source: String,
    /// What a backup would capture.
    pub files: Vec<String>,
    /// Required files absent from the source; a backup refuses until fixed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_required: Vec<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBackupDetailOutput {
    pub kind: String,
    pub instances: Vec<InstanceFiles>,
    /// Name and payload of the `schedule` config row that runs the backup.
    pub schedule_name: String,
    pub schedule: Value,
    /// The CLI line that writes the schedule row.
    pub apply_schedule: String,
    /// The retention to set on the target receiving this kind: orca prunes
    /// by the target's retention, not the kind's.
    pub retention: Retention,
}

/// The file set each PBS instance on this host would back up, and the
/// schedule row and retention that run it.
#[orca_tool(domain = "pbs", verb = "config_backup.detail", role = "read")]
pub async fn pbs_config_backup_detail(
    args: ConfigBackupDetailArgs,
    _ctx: &ToolCtx,
) -> Result<ConfigBackupDetailOutput> {
    config_backup_detail(&PbsConfigKind::from_env(), args.instance.as_deref())
}

fn config_backup_detail(
    kind: &PbsConfigKind,
    instance: Option<&str>,
) -> Result<ConfigBackupDetailOutput> {
    let instances = match instance {
        Some(i) => vec![i.to_string()],
        None => kind.find()?,
    };
    let mut out = Vec::with_capacity(instances.len());
    for i in instances {
        let source = kind.config_dir(&i);
        let files = collect(&source)?;
        out.push(InstanceFiles {
            missing_required: missing_required(&files),
            source: source.display().to_string(),
            instance: i,
            files,
        });
    }
    let schedule = schedule_row();
    Ok(ConfigBackupDetailOutput {
        kind: KIND.to_string(),
        instances: out,
        apply_schedule: format!("orca config upsert schedule {SCHEDULE_NAME} '{schedule}'"),
        schedule_name: SCHEDULE_NAME.to_string(),
        schedule,
        retention: retention(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.config_restore
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRestoreArgs {
    /// A `pbs-config` backup's payload directory (`path` in `backup.list`).
    #[arg(long)]
    pub payload: String,
    /// Scratch directory to restore into. Must be absent or empty, so a live
    /// config directory is never a valid destination.
    #[arg(long)]
    pub dest: String,
    /// Apply the change. Without it the verb verifies the backup and returns
    /// its plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRestoreOutput {
    pub dry_run: bool,
    pub dest: String,
    /// Of the backup itself on a dry run; of the restored copy on execute.
    pub verification: Verification,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<ExecutionPlan>,
}

/// Restore a `pbs-config` backup into a scratch directory and verify the
/// copy: every file's checksum, the datastores it defines and that each API
/// token still has its secret. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "config_restore",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_config_restore(
    args: ConfigRestoreArgs,
    ctx: &ToolCtx,
) -> Result<ConfigRestoreOutput> {
    config_restore(&args, ctx.caller().as_ref())
}

fn config_restore(
    args: &ConfigRestoreArgs,
    caller: Option<&CallerIdentity>,
) -> Result<ConfigRestoreOutput> {
    const TOOL: &str = "pbs.config_restore";
    let payload = Path::new(&args.payload);
    let dest = Path::new(&args.dest);
    let manifest = Manifest::read(payload)?;
    let captured = verify(&payload.join(FILES_DIR), &manifest);
    if !args.execute {
        let changes = manifest
            .files
            .iter()
            .map(|f| {
                PlannedChange::new(f.path.clone(), "write")
                    .with_detail(format!("{} bytes, mode {:o}", f.size, f.mode))
            })
            .collect();
        let summary = format!(
            "restore {} files of {} into {}",
            manifest.files.len(),
            manifest.instance,
            dest.display()
        );
        let plan = ExecutionPlan::generic(TOOL, serde_json::to_value(args)?.into())
            .detailed(summary, changes);
        return Ok(ConfigRestoreOutput {
            dry_run: true,
            dest: args.dest.clone(),
            verification: captured,
            plan: Some(plan),
        });
    }
    plan::authorize_execute(TOOL, caller)?;
    if !captured.ok() {
        bail!(
            "{TOOL}: backup failed verification, nothing restored: {}",
            captured.problems.join("; ")
        );
    }
    if fs::read_dir(dest).is_ok_and(|mut d| d.next().is_some()) {
        bail!(
            "{TOOL}: {} is not empty; restore into an absent or empty scratch directory",
            dest.display()
        );
    }
    materialize(payload, dest, &manifest, false)?;
    let restored = verify(dest, &manifest);
    if !restored.ok() {
        bail!(
            "{TOOL}: restored copy in {} failed verification: {}",
            dest.display(),
            restored.problems.join("; ")
        );
    }
    Ok(ConfigRestoreOutput {
        dry_run: false,
        dest: args.dest.clone(),
        verification: restored,
        plan: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::backup::wire::{OP_BACKUP, OP_INSTANCES, OP_RESTORE};

    const USER_CFG: &str = "user: root@pam\n\tenable true\n\ntoken: root@pam!orca\n\tenable true\n";
    const DATASTORE_CFG: &str =
        "datastore: willow-primary\n\tpath /mnt/datastore/primary\n\ndatastore: offsite\n\tpath /mnt/datastore/offsite\n";

    /// A config dir shaped like the live willow listing, contents invented.
    fn seed(dir: &Path) {
        let live = include_str!("../tests/fixtures/etc_proxmox_backup.ls");
        for name in live
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            if let Some(d) = name.strip_suffix('/') {
                fs::create_dir_all(dir.join(d)).unwrap();
                continue;
            }
            fs::write(dir.join(name), format!("{name}\n")).unwrap();
        }
        fs::write(dir.join("acme/accounts"), "acct\n").unwrap();
        fs::write(dir.join("user.cfg"), USER_CFG).unwrap();
        fs::write(dir.join("datastore.cfg"), DATASTORE_CFG).unwrap();
        fs::write(dir.join("token.shadow"), r#"{"root@pam!orca":"$5$hash"}"#).unwrap();
        fs::set_permissions(dir.join("authkey.key"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn volume(root: &Path, instance: &str) -> PathBuf {
        let dir = root.join(format!("{instance}-config/_data"));
        fs::create_dir_all(&dir).unwrap();
        seed(&dir);
        dir
    }

    #[test]
    fn file_set_is_every_live_file_minus_locks_and_rotations() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let files = collect(src.path()).unwrap();
        assert_eq!(
            files,
            [
                "acl.cfg",
                "acme/accounts",
                "authkey.key",
                "authkey.pub",
                "csrf.key",
                "datastore.cfg",
                "domains.cfg",
                "proxy.key",
                "proxy.pem",
                "prune.cfg",
                "remote.cfg",
                "shadow.json",
                "sync.cfg",
                "token.shadow",
                "user.cfg",
                "verification.cfg",
            ]
        );
        assert!(missing_required(&files).is_empty());
    }

    #[test]
    fn every_required_file_is_restore_critical() {
        for r in REQUIRED {
            assert!(crate::RESTORE_CRITICAL.contains(r), "{r}");
        }
    }

    #[test]
    fn manifest_records_checksum_mode_and_owner_and_round_trips() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), out.path(), "pbs").unwrap();
        assert_eq!(m.version, MANIFEST_VERSION);
        assert_eq!(m.instance, "pbs");
        assert_eq!(m.files.len(), collect(src.path()).unwrap().len());

        let key = m.files.iter().find(|f| f.path == "authkey.key").unwrap();
        assert_eq!(key.mode, 0o600);
        assert_eq!(key.size, "authkey.key\n".len() as u64);
        assert_eq!(key.sha256, sha256_hex(b"authkey.key\n"));
        let meta = fs::metadata(src.path().join("authkey.key")).unwrap();
        assert_eq!((key.uid, key.gid), (meta.uid(), meta.gid()));

        assert_eq!(Manifest::read(out.path()).unwrap(), m);
        assert!(out.path().join("files/acme/accounts").is_file());
    }

    #[test]
    fn manifest_of_another_version_is_refused() {
        let out = tempfile::tempdir().unwrap();
        fs::write(
            out.path().join(MANIFEST),
            r#"{"version":2,"instance":"pbs","source":"/x","files":[]}"#,
        )
        .unwrap();
        let err = Manifest::read(out.path()).unwrap_err();
        assert!(format!("{err:#}").contains("version 2"), "{err:#}");
    }

    #[test]
    fn capture_refuses_a_dir_without_the_server_identity() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        fs::remove_file(src.path().join("proxy.pem")).unwrap();
        let err = capture(src.path(), out.path(), "pbs").unwrap_err();
        assert!(format!("{err:#}").contains("proxy.pem"), "{err:#}");
        assert!(!out.path().join(MANIFEST).exists());
    }

    #[test]
    fn verify_reports_datastores_and_tokens() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), out.path(), "pbs").unwrap();
        let v = verify(&out.path().join(FILES_DIR), &m);
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.files_checked, m.files.len());
        assert_eq!(v.datastores, ["willow-primary", "offsite"]);
        assert_eq!(v.tokens, ["root@pam!orca"]);
    }

    #[test]
    fn verify_catches_tampering_loss_and_orphaned_tokens() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), out.path(), "pbs").unwrap();
        let files = out.path().join(FILES_DIR);
        fs::write(files.join("acl.cfg"), "changed\n").unwrap();
        fs::remove_file(files.join("proxy.key")).unwrap();
        fs::write(files.join("token.shadow"), "{}").unwrap();
        let v = verify(&files, &m);
        let p = v.problems.join("\n");
        assert!(p.contains("acl.cfg: checksum mismatch"), "{p}");
        assert!(p.contains("proxy.key: missing"), "{p}");
        assert!(p.contains("token root@pam!orca: no secret"), "{p}");
    }

    #[test]
    fn section_ids_ignore_properties_and_other_kinds() {
        assert_eq!(section_ids(USER_CFG, "user"), ["root@pam"]);
        assert_eq!(section_ids(USER_CFG, "token"), ["root@pam!orca"]);
        assert!(section_ids("", "datastore").is_empty());
    }

    #[test]
    fn retention_is_keep_last_ten_and_nothing_else() {
        let r = retention();
        assert_eq!(r, Retention::keep_last(10));
        assert!(!r.is_unbounded());
        assert!(r.keep_daily.is_none() && r.max_total_bytes.is_none());
    }

    #[test]
    fn schedule_row_runs_this_kind_nightly_with_execute() {
        let row = schedule_row();
        assert_eq!(row["job"], "backup.run");
        assert_eq!(row["cron"], "40 2 * * *");
        assert_eq!(row["args"], json!({"kind": "pbs-config", "execute": true}));
    }

    #[test]
    fn instances_are_config_volumes_holding_a_pbs_identity() {
        let root = tempfile::tempdir().unwrap();
        volume(root.path(), "pbs");
        fs::create_dir_all(root.path().join("sonarr-config/_data")).unwrap();
        fs::create_dir_all(root.path().join("pbs-lib/_data")).unwrap();
        assert_eq!(PbsConfigKind::at(root.path()).find().unwrap(), ["pbs"]);
        assert!(PbsConfigKind::at(root.path().join("absent"))
            .find()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn detail_lists_the_file_set_and_the_schedule() {
        let root = tempfile::tempdir().unwrap();
        volume(root.path(), "pbs");
        let out = config_backup_detail(&PbsConfigKind::at(root.path()), None).unwrap();
        assert_eq!(out.kind, KIND);
        assert_eq!(out.instances.len(), 1);
        assert!(out.instances[0].files.contains(&"token.shadow".to_string()));
        assert!(out.instances[0].missing_required.is_empty());
        assert!(out
            .apply_schedule
            .starts_with("orca config upsert schedule pbs-config-backup '{"));
        assert_eq!(out.retention.keep_last, Some(KEEP_LAST));
    }

    #[test]
    fn kind_backs_up_and_restores_over_the_wire() {
        let root = tempfile::tempdir().unwrap();
        let live = volume(root.path(), "pbs");
        let payload = tempfile::tempdir().unwrap();
        let kind = PbsConfigKind::at(root.path());

        assert_eq!(
            dispatch_kind_op(&kind, OP_INSTANCES, json!({})).unwrap(),
            json!(["pbs"])
        );
        let args = json!({"payload_dir": payload.path(), "instance": "pbs"});
        let outcome = dispatch_kind_op(&kind, OP_BACKUP, args.clone()).unwrap();
        assert!(outcome["checksum"].as_str().unwrap().starts_with("sha256:"));

        // A rebuilt container: fresh identity, no datastores, no tokens.
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        fs::remove_file(live.join("datastore.cfg")).unwrap();
        fs::write(live.join("user.cfg"), "user: root@pam\n").unwrap();
        dispatch_kind_op(&kind, OP_RESTORE, args).unwrap();

        let v = verify(&live, &Manifest::read(payload.path()).unwrap());
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.datastores, ["willow-primary", "offsite"]);
        assert_eq!(v.tokens, ["root@pam!orca"]);
        let mode = fs::metadata(live.join("authkey.key")).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn kind_restore_refuses_a_corrupt_backup_and_leaves_live_alone() {
        let root = tempfile::tempdir().unwrap();
        let live = volume(root.path(), "pbs");
        let payload = tempfile::tempdir().unwrap();
        let kind = PbsConfigKind::at(root.path());
        kind.backup(payload.path(), "pbs").unwrap();
        fs::write(payload.path().join("files/user.cfg"), "user: evil@pam\n").unwrap();
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();

        let err = kind.restore(payload.path(), "pbs").unwrap_err();
        assert!(err.contains("nothing restored"), "{err}");
        assert_eq!(
            fs::read_to_string(live.join("authkey.key")).unwrap(),
            "fresh\n"
        );
    }

    fn restore_args(payload: &Path, dest: &Path, execute: bool) -> ConfigRestoreArgs {
        ConfigRestoreArgs {
            payload: payload.display().to_string(),
            dest: dest.display().to_string(),
            execute,
        }
    }

    fn backed_up() -> (tempfile::TempDir, tempfile::TempDir) {
        let src = tempfile::tempdir().unwrap();
        let payload = tempfile::tempdir().unwrap();
        seed(src.path());
        capture(src.path(), payload.path(), "pbs").unwrap();
        (src, payload)
    }

    #[test]
    fn restore_dry_run_verifies_and_plans_without_writing() {
        let (_src, payload) = backed_up();
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("drill");
        let out = config_restore(&restore_args(payload.path(), &dest, false), None).unwrap();
        assert!(out.dry_run);
        assert!(out.verification.ok());
        assert_eq!(out.verification.datastores, ["willow-primary", "offsite"]);
        let plan = out.plan.unwrap();
        assert!(plan.changes.iter().any(|c| c.target == "token.shadow"));
        assert!(!dest.exists(), "a dry run wrote the destination");
    }

    #[test]
    fn restore_execute_needs_an_admin_caller() {
        let (_src, payload) = backed_up();
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("drill");
        let err = config_restore(&restore_args(payload.path(), &dest, true), None).unwrap_err();
        assert!(err.to_string().contains("no caller identity"), "{err}");
        assert!(!dest.exists());
    }

    #[test]
    fn restore_execute_writes_scratch_and_verifies_it() {
        let (_src, payload) = backed_up();
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("drill");
        let out = config_restore(
            &restore_args(payload.path(), &dest, true),
            Some(&plan::admin()),
        )
        .unwrap();
        assert!(!out.dry_run);
        assert!(out.verification.ok());
        assert_eq!(out.verification.tokens, ["root@pam!orca"]);
        assert_eq!(
            fs::read_to_string(dest.join("datastore.cfg")).unwrap(),
            DATASTORE_CFG
        );
    }

    #[test]
    fn restore_execute_refuses_a_non_empty_destination() {
        let (src, payload) = backed_up();
        let err = config_restore(
            &restore_args(payload.path(), src.path(), true),
            Some(&plan::admin()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("not empty"), "{err}");
    }

    #[test]
    fn dispatcher_claims_only_its_prefix() {
        assert!(dispatcher("pbs.datastore.list", json!({})).is_none());
        assert!(dispatcher("pbs.__backup_pbs_config.title", json!({})).is_some());
        let def = backend_def();
        assert_eq!(def.domain, "backup_kind");
        assert_eq!((def.name.as_str(), def.kind.as_str()), (KIND, KIND));
        assert_eq!(def.invoke_prefix, BACKUP_PREFIX);
    }
}
