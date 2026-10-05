//! `pbs-config` backup KIND: the server's own `/etc/proxmox-backup`.
//!
//! orca's backup domain drives it: `backup.run --kind pbs-config` captures each
//! instance into a target (smb/fs/…), prunes per that target's retention, and
//! `backup.restore` writes a capture back. Captures are a plain file tree plus
//! a manifest of sizes, SHA-256 and owner/mode, never the datastore contents.
//!
//! The kind reads the config volume straight off the host running the
//! container (`<volume root>/<instance>-config/_data`), so it only finds
//! instances on that host and runs nowhere else. It runs as root over a
//! directory the container can write, so every file is opened without
//! following symlinks and every restored path is checked to stay inside it.
//!
//! `pbs.config_backup.detail` shows the file set and the schedule row;
//! `pbs.config_restore` restores a capture into a scratch directory and
//! verifies it, dry run by default.

use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use plugin_toolkit::abi::BackendDef;
use plugin_toolkit::backend_def::backup_kind_backend_def;
use plugin_toolkit::backup::{dispatch_kind_op, BackupKindPlugin};
use plugin_toolkit::contract::backup::{BackupOutcome, Retention, STAGE_LOCK_FILE};
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
/// The store's own record of a slot, beside its `payload/`.
const SLOT_MANIFEST: &str = "manifest.json";
const MANIFEST_VERSION: u32 = 1;
const PERMISSION_BITS: u32 = 0o777;

/// Fleet retention policy for config backups.
pub const KEEP_LAST: u32 = 10;
/// Nightly at 03:10, clear of the 02:40 slot the hand-made willow script runs
/// in until it is retired.
pub const SCHEDULE_CRON: &str = "10 3 * * *";

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

pub fn schedule_name(instance: &str) -> String {
    format!("pbs-config-backup-{instance}")
}

/// `backup.run` is execute-gated, so the row opts in; the scheduler dispatches
/// with no caller, which the gate allows.
pub fn schedule_row(instance: &str) -> Value {
    json!({
        "job": "backup.run",
        "cron": SCHEDULE_CRON,
        "args": {"kind": KIND, "instance": instance, "execute": true},
    })
}

/// `config.upsert` is itself a dry run without `--execute`.
pub fn apply_schedule(instance: &str) -> String {
    format!(
        "orca config upsert schedule {} '{}' --execute",
        schedule_name(instance),
        schedule_row(instance)
    )
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
    /// Read and validate: a manifest names the paths a restore writes as
    /// root, so every path must be a plain relative path, listed once, and no
    /// mode may carry setuid, setgid or sticky bits.
    pub fn read(payload: &Path) -> Result<Self> {
        let path = payload.join(MANIFEST);
        let file = open_nofollow(&path)?;
        let m: Manifest = serde_json::from_reader(io::BufReader::new(file))
            .with_context(|| format!("parse {}", path.display()))?;
        if m.version != MANIFEST_VERSION {
            bail!(
                "{}: manifest version {} is not {MANIFEST_VERSION}",
                path.display(),
                m.version
            );
        }
        let mut seen = HashSet::new();
        for f in &m.files {
            check_rel(&f.path)?;
            if !seen.insert(f.path.as_str()) {
                bail!("manifest lists {:?} twice", f.path);
            }
            if f.mode & !PERMISSION_BITS != 0 {
                bail!(
                    "manifest gives {:?} mode {:o}; only permission bits are restored",
                    f.path,
                    f.mode
                );
            }
        }
        Ok(m)
    }
}

/// A relative, `/`-separated path with no empty, `.` or `..` segment.
fn check_rel(p: &str) -> Result<()> {
    let bad = p.is_empty()
        || p.contains('\0')
        || p.starts_with('/')
        || p.split('/').any(|s| s.is_empty() || s == "." || s == "..");
    if bad {
        bail!("unsafe path {p:?} in manifest");
    }
    Ok(())
}

/// `dest/rel`, refused unless it is strictly inside `dest`.
fn target(dest: &Path, rel: &str) -> Result<PathBuf> {
    check_rel(rel)?;
    let joined = dest.join(rel);
    let inside = joined.starts_with(dest)
        && joined
            .strip_prefix(dest)
            .is_ok_and(|r| r.components().all(|c| matches!(c, Component::Normal(_))));
    if !inside {
        bail!("{rel:?} escapes {}", dest.display());
    }
    Ok(joined)
}

fn open_nofollow(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

/// Create `path` exclusively, never through a symlink, readable by its owner
/// only until the caller sets the final mode.
fn create_nofollow(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("create {}", path.display()))
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
    /// Tokens with no secret in `token.shadow`: they exist but can never
    /// authenticate. Reported, not fatal, since the source server had them so.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub orphan_tokens: Vec<String>,
    /// Integrity failures: a missing file or a checksum, owner or mode
    /// mismatch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

impl Verification {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Every non-transient regular file under `dir`, relative and sorted.
/// Symlinks are skipped, never followed.
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
        let mut from = open_nofollow(&source.join(&rel))?;
        let meta = from.metadata()?;
        if !meta.is_file() {
            bail!("{rel} is no longer a regular file");
        }
        let to = files_root.join(&rel);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent)?;
        }
        io::copy(&mut from, &mut create_nofollow(&to)?).with_context(|| format!("copy {rel}"))?;
        files.push(FileEntry {
            sha256: plugin_toolkit::hash::sha256_file(&to)?,
            size: meta.len(),
            mode: meta.mode() & PERMISSION_BITS,
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

/// Make the payload root-only: it holds token hashes and the ticket signing
/// key. Returns a warning when the target ignores modes (CIFS does).
pub fn lock_down(payload: &Path) -> Result<Option<String>> {
    let mut loose = Vec::new();
    lock_down_at(payload, payload, &mut loose)?;
    Ok((!loose.is_empty()).then(|| {
        format!(
            "target ignored chmod on {} path(s) (e.g. {}); the backup may be readable beyond root",
            loose.len(),
            loose[0]
        )
    }))
}

fn lock_down_at(root: &Path, path: &Path, loose: &mut Vec<String>) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    let want = if meta.is_dir() { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(want))?;
    if fs::symlink_metadata(path)?.mode() & PERMISSION_BITS != want {
        let rel = path.strip_prefix(root).unwrap_or(path);
        loose.push(format!("/{}", rel.display()));
    }
    if meta.is_dir() {
        for entry in fs::read_dir(path)? {
            lock_down_at(root, &entry?.path(), loose)?;
        }
    }
    Ok(())
}

/// Check `dir` holds exactly what `manifest` recorded, and that what it holds
/// is a server that would come back with its datastores and working tokens.
pub fn verify(dir: &Path, manifest: &Manifest) -> Verification {
    let mut v = Verification::default();
    for f in &manifest.files {
        // Hashed through the no-follow fd; the toolkit's `sha256_file` opens
        // by path.
        let sum = target(dir, &f.path).and_then(|p| {
            let mut buf = Vec::new();
            io::Read::read_to_end(&mut open_nofollow(&p)?, &mut buf)?;
            Ok(sha256_hex(&buf))
        });
        match sum {
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
    let read = |name: &str| {
        open_nofollow(&dir.join(name))
            .ok()
            .and_then(|f| io::read_to_string(f).ok())
            .unwrap_or_default()
    };
    v.datastores = section_ids(&read("datastore.cfg"), "datastore");
    v.tokens = section_ids(&read("user.cfg"), "token");
    let shadow: serde_json::Map<String, Value> =
        serde_json::from_str(&read("token.shadow")).unwrap_or_default();
    v.orphan_tokens = v
        .tokens
        .iter()
        .filter(|t| !shadow.contains_key(*t))
        .cloned()
        .collect();
    v
}

/// Owner and mode of every restored file against the manifest.
pub fn verify_meta(dir: &Path, manifest: &Manifest) -> Vec<String> {
    let mut problems = Vec::new();
    for f in &manifest.files {
        let Ok(meta) = target(dir, &f.path).and_then(|p| Ok(fs::symlink_metadata(p)?)) else {
            problems.push(format!("{}: missing", f.path));
            continue;
        };
        let (mode, uid, gid) = (meta.mode() & PERMISSION_BITS, meta.uid(), meta.gid());
        if (mode, uid, gid) != (f.mode, f.uid, f.gid) {
            problems.push(format!(
                "{}: {uid}:{gid} {mode:o}, backup has {}:{} {:o}",
                f.path, f.uid, f.gid, f.mode
            ));
        }
    }
    problems
}

/// Ids of the `<kind>: <id>` section headers in a PBS section-config file.
fn section_ids(text: &str, kind: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.strip_prefix(kind)?.strip_prefix(':'))
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .collect()
}

struct Staged {
    tmp: PathBuf,
    to: PathBuf,
    /// Hard link to the file being replaced, for rollback.
    prev: Option<PathBuf>,
    /// The original is out of place, held only by `prev`.
    displaced: bool,
}

type Rename<'a> = &'a dyn Fn(&Path, &Path) -> io::Result<()>;

/// Write the captured files into `dest`, which must already exist, with their
/// recorded modes and, with `owners`, their uid/gid (the proxy runs as
/// `backup` and cannot read a root-owned `authkey.pub`).
///
/// Every file is staged and fsynced before any is replaced, the replaced
/// files are hard-linked aside, and a failed swap renames them back, so the
/// directory ends up either fully restored or as it was.
pub fn materialize(payload: &Path, dest: &Path, manifest: &Manifest, owners: bool) -> Result<()> {
    let tag = plugin_toolkit::id::new_short();
    materialize_with(payload, dest, manifest, owners, &tag, &|a, b| {
        fs::rename(a, b)
    })
}

fn materialize_with(
    payload: &Path,
    dest: &Path,
    manifest: &Manifest,
    owners: bool,
    tag: &str,
    rename: Rename,
) -> Result<()> {
    let meta = fs::symlink_metadata(dest).with_context(|| format!("stat {}", dest.display()))?;
    if !meta.is_dir() {
        bail!("{} is not a directory", dest.display());
    }
    let mut staged = Vec::with_capacity(manifest.files.len());
    let result = stage(payload, dest, manifest, owners, tag, &mut staged)
        .and_then(|()| set_aside(&mut staged, tag))
        .and_then(|()| swap(&mut staged, rename));
    match result {
        Ok(()) => {
            for s in &staged {
                if let Some(p) = &s.prev {
                    discard(p);
                }
            }
            sync_parents(&staged)
        }
        Err(e) => {
            let kept = clean_up(&staged);
            if kept.is_empty() {
                Err(e)
            } else {
                Err(e.context(format!(
                    "rollback incomplete; originals kept at {}",
                    kept.join(", ")
                )))
            }
        }
    }
}

fn stage(
    payload: &Path,
    dest: &Path,
    manifest: &Manifest,
    owners: bool,
    tag: &str,
    staged: &mut Vec<Staged>,
) -> Result<()> {
    let files_root = payload.join(FILES_DIR);
    for f in &manifest.files {
        let to = target(dest, &f.path)?;
        ensure_dirs(dest, &f.path)?;
        let name = to.file_name().unwrap_or_default().to_string_lossy();
        let tmp = to.with_file_name(format!(".{name}.orca-restore-{tag}"));
        let mut out = create_nofollow(&tmp)?;
        staged.push(Staged {
            tmp,
            to,
            prev: None,
            displaced: false,
        });
        io::copy(
            &mut open_nofollow(&target(&files_root, &f.path)?)?,
            &mut out,
        )
        .with_context(|| format!("stage {}", f.path))?;
        out.set_permissions(fs::Permissions::from_mode(f.mode))?;
        if owners {
            std::os::unix::fs::fchown(&out, Some(f.uid), Some(f.gid))
                .with_context(|| format!("chown {} to {}:{}", f.path, f.uid, f.gid))?;
        }
        out.sync_all()?;
    }
    Ok(())
}

/// Create the parent directories of `rel` under `dest`, refusing any
/// existing component that is a symlink or not a directory.
fn ensure_dirs(dest: &Path, rel: &str) -> Result<()> {
    let mut cur = dest.to_path_buf();
    let segs: Vec<&str> = rel.split('/').collect();
    for seg in &segs[..segs.len() - 1] {
        cur.push(seg);
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => bail!("{} is a symlink or not a directory", cur.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&cur)?,
            Err(e) => return Err(e).with_context(|| format!("stat {}", cur.display())),
        }
    }
    Ok(())
}

fn set_aside(staged: &mut [Staged], tag: &str) -> Result<()> {
    for s in staged {
        match fs::symlink_metadata(&s.to) {
            Ok(m) if m.is_file() => {
                let name = s.to.file_name().unwrap_or_default().to_string_lossy();
                let prev = s.to.with_file_name(format!(".{name}.orca-prev-{tag}"));
                fs::hard_link(&s.to, &prev)
                    .with_context(|| format!("set aside {}", s.to.display()))?;
                s.prev = Some(prev);
            }
            Ok(_) => bail!("{} is a symlink or not a regular file", s.to.display()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("stat {}", s.to.display())),
        }
    }
    Ok(())
}

fn swap(staged: &mut [Staged], rename: Rename) -> Result<()> {
    for i in 0..staged.len() {
        if let Err(e) = rename(&staged[i].tmp, &staged[i].to) {
            let failed = staged[i].to.display().to_string();
            for s in staged[..i].iter_mut().rev() {
                let back = match &s.prev {
                    Some(prev) => fs::rename(prev, &s.to),
                    None => fs::remove_file(&s.to),
                };
                s.displaced = back.is_err();
            }
            return Err(e).with_context(|| format!("replace {failed}; rolled back"));
        }
        staged[i].displaced = true;
    }
    Ok(())
}

/// Remove temp files and the set-aside links whose original is back in
/// place. Returns the set-aside paths still holding an original.
fn clean_up(staged: &[Staged]) -> Vec<String> {
    let mut kept = Vec::new();
    for s in staged {
        discard(&s.tmp);
        if let Some(prev) = &s.prev {
            if s.displaced {
                kept.push(prev.display().to_string());
            } else {
                discard(prev);
            }
        }
    }
    kept
}

fn discard(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(path = %path.display(), error = %e, "could not remove"),
    }
}

fn sync_parents(staged: &[Staged]) -> Result<()> {
    let parents: HashSet<&Path> = staged.iter().filter_map(|s| s.to.parent()).collect();
    for p in parents {
        File::open(p)?
            .sync_all()
            .with_context(|| format!("fsync {}", p.display()))?;
    }
    Ok(())
}

/// Names of running docker containers that mount `volume`, read from the
/// daemon's on-disk state. A missing state directory is an error: the check
/// fails closed.
fn running_with_volume(containers_dir: &Path, volume: &str) -> Result<Vec<String>> {
    let entries = fs::read_dir(containers_dir).with_context(|| {
        format!(
            "cannot confirm no container uses {volume}: read {}",
            containers_dir.display()
        )
    })?;
    let mut out = Vec::new();
    for entry in entries {
        let Ok(raw) = fs::read(entry?.path().join("config.v2.json")) else {
            continue;
        };
        let c: Value = serde_json::from_slice(&raw).unwrap_or_default();
        let running = c["State"]["Running"].as_bool().unwrap_or(false);
        let mounts = c["MountPoints"].as_object().into_iter().flatten();
        if running && mounts.map(|(_, m)| m).any(|m| m["Name"] == volume) {
            out.push(
                c["Name"]
                    .as_str()
                    .unwrap_or("?")
                    .trim_start_matches('/')
                    .to_string(),
            );
        }
    }
    Ok(out)
}

fn volume_root() -> PathBuf {
    std::env::var("ORCA_PBS_VOLUME_ROOT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VOLUME_ROOT))
}

/// The backup KIND over one docker volume root.
pub struct PbsConfigKind {
    volume_root: PathBuf,
}

impl PbsConfigKind {
    /// `ORCA_PBS_VOLUME_ROOT` overrides the docker default, for a relocated
    /// docker data root.
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

    /// Docker keeps container state in `containers/` beside `volumes/`.
    fn containers_dir(&self) -> PathBuf {
        self.volume_root
            .parent()
            .unwrap_or(&self.volume_root)
            .join("containers")
    }

    /// Instances whose config volume holds a PBS server identity.
    pub fn find(&self) -> Result<Vec<String>> {
        let entries = match fs::read_dir(&self.volume_root) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
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

    fn backup_into(&self, payload_dir: &Path, instance: &str) -> Result<BackupOutcome> {
        let source = self.config_dir(instance);
        let manifest = capture(&source, payload_dir, instance)?;
        let v = verify(&payload_dir.join(FILES_DIR), &manifest);
        if !v.ok() {
            bail!(
                "capture failed verification (was the config changing?): {}",
                v.problems.join("; ")
            );
        }
        let warning = lock_down(payload_dir)?;
        let raw = fs::read(payload_dir.join(MANIFEST))?;
        let mut note = format!("{} files from {}", manifest.files.len(), source.display());
        if !v.orphan_tokens.is_empty() {
            note.push_str(&format!(
                "; tokens without a secret: {}",
                v.orphan_tokens.join(", ")
            ));
        }
        if let Some(w) = warning {
            note.push_str("; ");
            note.push_str(&w);
        }
        Ok(BackupOutcome {
            checksum: Some(format!("sha256:{}", sha256_hex(&raw))),
            note: Some(note),
            unchanged: false,
        })
    }

    fn restore_from(&self, payload_dir: &Path, instance: &str) -> Result<Verification> {
        let volume = crate::config_volume(instance);
        let running = running_with_volume(&self.containers_dir(), &volume)?;
        if !running.is_empty() {
            bail!(
                "stop {} first: PBS must not run while {volume} is restored",
                running.join(", ")
            );
        }
        let manifest = Manifest::read(payload_dir)?;
        let captured = verify(&payload_dir.join(FILES_DIR), &manifest);
        if !captured.ok() {
            bail!(
                "backup failed verification, nothing restored: {}",
                captured.problems.join("; ")
            );
        }
        let live = self.config_dir(instance);
        if !live.is_dir() {
            bail!(
                "{} does not exist; deploy the container first so its config volume exists",
                live.display()
            );
        }
        materialize(payload_dir, &live, &manifest, true)?;
        let mut restored = verify(&live, &manifest);
        restored.problems.extend(verify_meta(&live, &manifest));
        if !restored.ok() {
            bail!(
                "restored config failed verification: {}",
                restored.problems.join("; ")
            );
        }
        Ok(restored)
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
        self.backup_into(payload_dir, instance)
            .map_err(|e| format!("{e:#}"))
    }

    /// Needs the container stopped. Verifies the capture, replaces the files
    /// it holds in the live config volume, then verifies contents, owners and
    /// modes. Files the capture does not hold are left in place.
    fn restore(&self, payload_dir: &Path, instance: &str) -> Result<(), String> {
        let v = self
            .restore_from(payload_dir, instance)
            .map_err(|e| format!("{e:#}"))?;
        tracing::info!(
            instance,
            datastores = ?v.datastores,
            tokens = ?v.tokens,
            "[pbs-config] restored {} files; start the container",
            v.files_checked
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
    /// Name and payload of the `schedule` config row that runs the backup.
    pub schedule_name: String,
    pub schedule: Value,
    /// The CLI line that writes the schedule row.
    pub apply_schedule: String,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigBackupDetailOutput {
    pub kind: String,
    pub instances: Vec<InstanceFiles>,
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
            schedule_name: schedule_name(&i),
            schedule: schedule_row(&i),
            apply_schedule: apply_schedule(&i),
            instance: i,
            files,
        });
    }
    Ok(ConfigBackupDetailOutput {
        kind: KIND.to_string(),
        instances: out,
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
    /// Scratch directory to restore into. Must not exist; it is created.
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
    /// Why execute would refuse.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<ExecutionPlan>,
}

/// Resolve `payload` and require it to be a `pbs-config` slot inside a
/// backup store: `<root>/pbs-config/<instance>/<id>/payload`, where `<root>`
/// holds the store's stage lock and the slot its manifest.
fn store_payload(payload: &str) -> Result<PathBuf> {
    let p = fs::canonicalize(payload).with_context(|| format!("resolve {payload}"))?;
    let refuse = || anyhow!("{payload} is not a {KIND} backup payload inside a backup store");
    let slot = p
        .parent()
        .filter(|_| p.ends_with("payload"))
        .ok_or_else(refuse)?;
    let root = slot
        .ancestors()
        .nth(3)
        .filter(|r| r.join(STAGE_LOCK_FILE).is_file())
        .ok_or_else(refuse)?;
    let kind_dir = p
        .strip_prefix(root)
        .ok()
        .and_then(|r| r.components().next());
    if kind_dir != Some(Component::Normal(KIND.as_ref())) || !slot.join(SLOT_MANIFEST).is_file() {
        return Err(refuse());
    }
    Ok(p)
}

/// Restore a `pbs-config` backup into a new scratch directory and verify the
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
    let payload = store_payload(&args.payload)?;
    let dest = Path::new(&args.dest);
    let manifest = Manifest::read(&payload)?;
    let captured = verify(&payload.join(FILES_DIR), &manifest);
    let mut blockers = Vec::new();
    if fs::symlink_metadata(dest).is_ok() {
        blockers.push(format!("{} already exists", dest.display()));
    }
    if !captured.ok() {
        blockers.push("the backup failed verification".to_string());
    }
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
            blockers,
            plan: Some(plan),
        });
    }
    plan::authorize_execute(TOOL, caller)?;
    if !blockers.is_empty() {
        bail!("{TOOL}: refusing: {}", blockers.join("; "));
    }
    fs::create_dir(dest).with_context(|| format!("create {}", dest.display()))?;
    fs::set_permissions(dest, fs::Permissions::from_mode(0o700))?;
    materialize(&payload, dest, &manifest, false)?;
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
        blockers: Vec::new(),
        plan: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::backup::wire::{OP_BACKUP, OP_INSTANCES, OP_RESTORE};

    const USER_CFG: &str = "user: root@pam\n\tenable true\n\ntoken: root@pam!orca\n\tenable true\n";
    const DATASTORE_CFG: &str = "datastore: willow-primary\n\tpath /mnt/datastore/primary\n\ndatastore: offsite\n\tpath /mnt/datastore/offsite\n";

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

    /// `<tmp>/volumes/<instance>-config/_data` beside an empty `containers/`.
    fn host(instance: &str) -> (tempfile::TempDir, PbsConfigKind, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let live = tmp.path().join(format!("volumes/{instance}-config/_data"));
        fs::create_dir_all(&live).unwrap();
        fs::create_dir_all(tmp.path().join("containers")).unwrap();
        seed(&live);
        let kind = PbsConfigKind::at(tmp.path().join("volumes"));
        (tmp, kind, live)
    }

    fn container(tmp: &Path, name: &str, running: bool, volume: &str) {
        let dir = tmp.join("containers").join(name);
        fs::create_dir_all(&dir).unwrap();
        let state = json!({
            "Name": format!("/{name}"),
            "State": {"Running": running},
            "MountPoints": {"/etc/proxmox-backup": {"Name": volume, "Type": "volume"}},
        });
        fs::write(dir.join("config.v2.json"), state.to_string()).unwrap();
    }

    fn manifest_with(files: Value) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let m = json!({"version": 1, "instance": "pbs", "source": "/x", "files": files});
        fs::write(dir.path().join(MANIFEST), m.to_string()).unwrap();
        dir
    }

    fn entry(path: &str, mode: u32) -> Value {
        json!({"path": path, "size": 0, "sha256": "", "mode": mode, "uid": 0, "gid": 0})
    }

    fn leftovers(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for e in fs::read_dir(dir).unwrap() {
            let name = e.unwrap().file_name().to_string_lossy().into_owned();
            if name.contains(".orca-") {
                out.push(name);
            }
        }
        out
    }

    #[test]
    fn file_set_is_every_live_file_minus_locks_and_rotations() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        std::os::unix::fs::symlink("/etc/passwd", src.path().join("planted")).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(MANIFEST),
            r#"{"version":2,"instance":"pbs","source":"/x","files":[]}"#,
        )
        .unwrap();
        let err = Manifest::read(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("version 2"), "{err:#}");
    }

    #[test]
    fn manifest_refuses_traversal_absolute_and_odd_paths() {
        for bad in ["../x", "/etc/x", "acme/../../x", "./x", "a//b", "", "a\0b"] {
            let dir = manifest_with(json!([entry(bad, 0o600)]));
            let err = Manifest::read(dir.path()).unwrap_err();
            assert!(
                format!("{err:#}").contains("unsafe path"),
                "{bad:?}: {err:#}"
            );
        }
        let dir = manifest_with(json!([entry("user.cfg", 0o600), entry("user.cfg", 0o600)]));
        assert!(format!("{:#}", Manifest::read(dir.path()).unwrap_err()).contains("twice"));
    }

    #[test]
    fn target_never_leaves_dest() {
        let dest = Path::new("/srv/restore");
        assert_eq!(
            target(dest, "acme/accounts").unwrap(),
            dest.join("acme/accounts")
        );
        assert!(target(dest, "../x").is_err());
        assert!(target(dest, "/etc/x").is_err());
    }

    #[test]
    fn manifest_refuses_setuid_setgid_and_sticky() {
        for mode in [0o4755, 0o2755, 0o1777] {
            let dir = manifest_with(json!([entry("user.cfg", mode)]));
            let err = Manifest::read(dir.path()).unwrap_err();
            assert!(
                format!("{err:#}").contains("only permission bits"),
                "{err:#}"
            );
        }
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
        assert!(v.orphan_tokens.is_empty());
    }

    #[test]
    fn verify_catches_tampering_and_loss() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), out.path(), "pbs").unwrap();
        let files = out.path().join(FILES_DIR);
        fs::write(files.join("acl.cfg"), "changed\n").unwrap();
        fs::remove_file(files.join("proxy.key")).unwrap();
        let p = verify(&files, &m).problems.join("\n");
        assert!(p.contains("acl.cfg: checksum mismatch"), "{p}");
        assert!(p.contains("proxy.key: missing"), "{p}");
    }

    #[test]
    fn verify_does_not_follow_a_symlinked_file() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), out.path(), "pbs").unwrap();
        let files = out.path().join(FILES_DIR);
        fs::copy(files.join("acl.cfg"), out.path().join("elsewhere")).unwrap();
        fs::remove_file(files.join("acl.cfg")).unwrap();
        std::os::unix::fs::symlink(out.path().join("elsewhere"), files.join("acl.cfg")).unwrap();
        let p = verify(&files, &m).problems.join("\n");
        assert!(p.contains("acl.cfg: missing or unreadable"), "{p}");
    }

    #[test]
    fn section_ids_ignore_properties_and_other_kinds() {
        assert_eq!(section_ids(USER_CFG, "user"), ["root@pam"]);
        assert_eq!(section_ids(USER_CFG, "token"), ["root@pam!orca"]);
        assert!(section_ids("", "datastore").is_empty());
    }

    #[test]
    fn instances_are_config_volumes_holding_a_pbs_identity() {
        let (tmp, kind, _) = host("pbs");
        fs::create_dir_all(tmp.path().join("volumes/sonarr-config/_data")).unwrap();
        fs::create_dir_all(tmp.path().join("volumes/pbs-lib/_data")).unwrap();
        assert_eq!(kind.find().unwrap(), ["pbs"]);
        assert!(PbsConfigKind::at(tmp.path().join("absent"))
            .find()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn detail_gives_a_schedule_row_per_instance_that_applies_and_runs_it() {
        let (_tmp, kind, _) = host("pbs");
        let out = config_backup_detail(&kind, None).unwrap();
        assert_eq!(out.retention, Retention::keep_last(10));
        let i = &out.instances[0];
        assert!(i.files.contains(&"token.shadow".to_string()));
        assert!(i.missing_required.is_empty());
        assert_eq!(
            i.apply_schedule,
            r#"orca config upsert schedule pbs-config-backup-pbs '{"job":"backup.run","cron":"10 3 * * *","args":{"kind":"pbs-config","instance":"pbs","execute":true}}' --execute"#
        );
        assert_eq!(i.schedule["args"]["instance"], "pbs");
        assert_ne!(SCHEDULE_CRON, "40 2 * * *");
    }

    #[test]
    fn backup_locks_the_payload_down_and_notes_orphan_tokens() {
        let (_tmp, kind, live) = host("pbs");
        fs::write(live.join("token.shadow"), "{}").unwrap();
        let payload = tempfile::tempdir().unwrap();
        let out = kind.backup_into(payload.path(), "pbs").unwrap();
        let note = out.note.unwrap();
        assert!(
            note.contains("tokens without a secret: root@pam!orca"),
            "{note}"
        );
        assert!(!note.contains("ignored chmod"), "{note}");
        let mode = |p: &Path| fs::metadata(p).unwrap().mode() & 0o777;
        assert_eq!(mode(payload.path()), 0o700);
        assert_eq!(mode(&payload.path().join("files/acme")), 0o700);
        assert_eq!(mode(&payload.path().join(MANIFEST)), 0o600);
        assert_eq!(mode(&payload.path().join("files/user.cfg")), 0o600);
    }

    #[test]
    fn kind_backs_up_and_restores_a_rebuilt_container_over_the_wire() {
        let (tmp, kind, live) = host("pbs");
        container(tmp.path(), "pbs", false, "pbs-config");
        let payload = tempfile::tempdir().unwrap();
        fs::set_permissions(live.join("proxy.key"), fs::Permissions::from_mode(0o640)).unwrap();

        assert_eq!(
            dispatch_kind_op(&kind, OP_INSTANCES, json!({})).unwrap(),
            json!(["pbs"])
        );
        let args = json!({"payload_dir": payload.path(), "instance": "pbs"});
        let outcome = dispatch_kind_op(&kind, OP_BACKUP, args.clone()).unwrap();
        assert!(outcome["checksum"].as_str().unwrap().starts_with("sha256:"));

        // A rebuilt container: fresh identity, no datastores, no tokens.
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        fs::set_permissions(live.join("proxy.key"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(live.join("datastore.cfg")).unwrap();
        fs::write(live.join("user.cfg"), "user: root@pam\n").unwrap();
        dispatch_kind_op(&kind, OP_RESTORE, args).unwrap();

        let m = Manifest::read(payload.path()).unwrap();
        let v = verify(&live, &m);
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.datastores, ["willow-primary", "offsite"]);
        assert_eq!(v.tokens, ["root@pam!orca"]);
        assert!(verify_meta(&live, &m).is_empty());
        assert_eq!(
            fs::metadata(live.join("proxy.key")).unwrap().mode() & 0o777,
            0o640
        );
        assert!(leftovers(&live).is_empty(), "{:?}", leftovers(&live));
    }

    #[test]
    fn verify_meta_catches_a_mode_change() {
        let (_tmp, kind, live) = host("pbs");
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        fs::set_permissions(live.join("authkey.key"), fs::Permissions::from_mode(0o644)).unwrap();
        let p = verify_meta(&live, &Manifest::read(payload.path()).unwrap()).join("\n");
        assert!(p.contains("authkey.key") && p.contains("644"), "{p}");
    }

    #[test]
    fn kind_restore_refuses_while_the_container_runs() {
        let (tmp, kind, live) = host("pbs");
        container(tmp.path(), "pbs", true, "pbs-config");
        container(tmp.path(), "other", true, "other-config");
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        let err = kind.restore(payload.path(), "pbs").unwrap_err();
        assert!(err.contains("stop pbs first"), "{err}");
        assert_eq!(
            fs::read_to_string(live.join("authkey.key")).unwrap(),
            "fresh\n"
        );
    }

    #[test]
    fn kind_restore_fails_closed_without_container_state() {
        let (tmp, kind, _) = host("pbs");
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        fs::remove_dir(tmp.path().join("containers")).unwrap();
        let err = kind.restore(payload.path(), "pbs").unwrap_err();
        assert!(err.contains("cannot confirm"), "{err}");
    }

    #[test]
    fn kind_restore_refuses_a_corrupt_backup_and_leaves_live_alone() {
        let (_tmp, kind, live) = host("pbs");
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        fs::write(payload.path().join("files/user.cfg"), "user: evil@pam\n").unwrap();
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        let err = kind.restore(payload.path(), "pbs").unwrap_err();
        assert!(err.contains("nothing restored"), "{err}");
        assert_eq!(
            fs::read_to_string(live.join("authkey.key")).unwrap(),
            "fresh\n"
        );
    }

    /// A captured payload and a live dir whose files all differ from it.
    fn drifted() -> (tempfile::TempDir, tempfile::TempDir, Manifest) {
        let src = tempfile::tempdir().unwrap();
        let payload = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), payload.path(), "pbs").unwrap();
        for f in &m.files {
            fs::write(src.path().join(&f.path), "live\n").unwrap();
        }
        (src, payload, m)
    }

    #[test]
    fn a_failed_swap_rolls_every_file_back() {
        let (live, payload, m) = drifted();
        let calls = std::cell::Cell::new(0);
        let flaky = |a: &Path, b: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                return Err(io::Error::other("disk full"));
            }
            fs::rename(a, b)
        };
        let err =
            materialize_with(payload.path(), live.path(), &m, false, "T", &flaky).unwrap_err();
        assert!(format!("{err:#}").contains("rolled back"), "{err:#}");
        for f in &m.files {
            assert_eq!(
                fs::read_to_string(live.path().join(&f.path)).unwrap(),
                "live\n",
                "{}",
                f.path
            );
        }
        assert!(
            leftovers(live.path()).is_empty(),
            "{:?}",
            leftovers(live.path())
        );
    }

    #[test]
    fn restore_refuses_a_symlink_planted_at_the_temp_name() {
        let (live, payload, m) = drifted();
        let outside = tempfile::tempdir().unwrap();
        let bait = outside.path().join("bait");
        fs::write(&bait, "untouched\n").unwrap();
        std::os::unix::fs::symlink(&bait, live.path().join(".user.cfg.orca-restore-T")).unwrap();
        let rename = |a: &Path, b: &Path| fs::rename(a, b);
        assert!(materialize_with(payload.path(), live.path(), &m, false, "T", &rename).is_err());
        assert_eq!(fs::read_to_string(&bait).unwrap(), "untouched\n");
        assert_eq!(
            fs::read_to_string(live.path().join("acl.cfg")).unwrap(),
            "live\n"
        );
    }

    #[test]
    fn restore_refuses_a_symlinked_subdir_or_target() {
        let (live, payload, m) = drifted();
        let outside = tempfile::tempdir().unwrap();
        fs::remove_dir_all(live.path().join("acme")).unwrap();
        std::os::unix::fs::symlink(outside.path(), live.path().join("acme")).unwrap();
        let err = materialize(payload.path(), live.path(), &m, false).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);

        let (live, payload, m) = drifted();
        let bait = outside.path().join("bait");
        fs::write(&bait, "untouched\n").unwrap();
        fs::remove_file(live.path().join("user.cfg")).unwrap();
        std::os::unix::fs::symlink(&bait, live.path().join("user.cfg")).unwrap();
        let err = materialize(payload.path(), live.path(), &m, false).unwrap_err();
        assert!(format!("{err:#}").contains("symlink"), "{err:#}");
        assert_eq!(fs::read_to_string(&bait).unwrap(), "untouched\n");
        assert!(
            leftovers(live.path()).is_empty(),
            "{:?}",
            leftovers(live.path())
        );
    }

    /// A captured backup laid out as the store writes it.
    fn stored() -> (tempfile::TempDir, PathBuf) {
        let store = tempfile::tempdir().unwrap();
        fs::write(store.path().join(STAGE_LOCK_FILE), "").unwrap();
        let slot = store.path().join("pbs-config/pbs/20261004-031000");
        let payload = slot.join("payload");
        fs::create_dir_all(&payload).unwrap();
        fs::write(slot.join(SLOT_MANIFEST), "{}").unwrap();
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        capture(src.path(), &payload, "pbs").unwrap();
        (store, payload)
    }

    fn restore_args(payload: &Path, dest: &Path, execute: bool) -> ConfigRestoreArgs {
        ConfigRestoreArgs {
            payload: payload.display().to_string(),
            dest: dest.display().to_string(),
            execute,
        }
    }

    #[test]
    fn restore_dry_run_verifies_and_plans_without_writing() {
        let (_store, payload) = stored();
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("drill");
        let out = config_restore(&restore_args(&payload, &dest, false), None).unwrap();
        assert!(out.dry_run);
        assert!(out.verification.ok());
        assert!(out.blockers.is_empty(), "{:?}", out.blockers);
        assert_eq!(out.verification.datastores, ["willow-primary", "offsite"]);
        let plan = out.plan.unwrap();
        assert!(plan.changes.iter().any(|c| c.target == "token.shadow"));
        assert!(!dest.exists(), "a dry run wrote the destination");
    }

    #[test]
    fn restore_dry_run_reports_an_existing_dest() {
        let (_store, payload) = stored();
        let scratch = tempfile::tempdir().unwrap();
        let out = config_restore(&restore_args(&payload, scratch.path(), false), None).unwrap();
        assert!(
            out.blockers[0].contains("already exists"),
            "{:?}",
            out.blockers
        );
    }

    #[test]
    fn restore_only_reads_payloads_inside_a_backup_store() {
        let loose = tempfile::tempdir().unwrap();
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let payload = loose.path().join("payload");
        fs::create_dir(&payload).unwrap();
        capture(src.path(), &payload, "pbs").unwrap();
        let dest = loose.path().join("drill");
        let err = config_restore(&restore_args(&payload, &dest, false), None).unwrap_err();
        assert!(err.to_string().contains("inside a backup store"), "{err}");
    }

    #[test]
    fn restore_execute_needs_an_admin_caller() {
        let (_store, payload) = stored();
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("drill");
        let err = config_restore(&restore_args(&payload, &dest, true), None).unwrap_err();
        assert!(err.to_string().contains("no caller identity"), "{err}");
        assert!(!dest.exists());
    }

    #[test]
    fn restore_execute_writes_scratch_and_verifies_it() {
        let (_store, payload) = stored();
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("drill");
        let out =
            config_restore(&restore_args(&payload, &dest, true), Some(&plan::admin())).unwrap();
        assert!(!out.dry_run);
        assert!(out.verification.ok());
        assert_eq!(out.verification.tokens, ["root@pam!orca"]);
        assert_eq!(
            fs::read_to_string(dest.join("datastore.cfg")).unwrap(),
            DATASTORE_CFG
        );
        assert_eq!(fs::metadata(&dest).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn restore_execute_refuses_an_existing_destination() {
        let (_store, payload) = stored();
        let scratch = tempfile::tempdir().unwrap();
        let err = config_restore(
            &restore_args(&payload, scratch.path(), true),
            Some(&plan::admin()),
        )
        .unwrap_err();
        assert!(err.to_string().contains("already exists"), "{err}");
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
