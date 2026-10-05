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
//! directory the container can write, so every path below that directory is
//! resolved from a directory fd one component at a time without following
//! symlinks ([`Dir`]).
//!
//! `pbs.config_backup.detail` shows the file set and the schedule row;
//! `pbs.config_restore` restores a capture into a scratch directory and
//! verifies it; `pbs.config_recover` finishes or rolls back a restore that
//! was interrupted. Mutating verbs are dry runs by default.

use std::collections::{BTreeMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

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

const TEMP_MARK: &str = ".orca-restore-";
const PREV_MARK: &str = ".orca-prev-";
const SWAP_MARK: &str = ".orca-swap-";

const LOCK_ATTEMPTS: u32 = 100;
const LOCK_RETRY: Duration = Duration::from_millis(100);

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

// ═══════════════════════════════════════════════════════════════════════════
// fd-relative filesystem access
// ═══════════════════════════════════════════════════════════════════════════

/// A directory opened without following symlinks. Every path below it is
/// opened one component at a time from this fd with `O_NOFOLLOW`, so a
/// symlink the container swaps in mid-walk fails the open rather than
/// redirecting it. Portable across Linux and macOS, unlike `openat2`.
struct Dir(File);

enum Entry {
    Missing,
    Symlink,
    Dir(Dir),
    File(File),
    Other,
}

fn c_name(name: &str) -> io::Result<CString> {
    CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

impl Dir {
    fn open(path: &Path) -> Result<Self> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(path)
            .map(Dir)
            .with_context(|| format!("open directory {}", path.display()))
    }

    fn fd(&self) -> libc::c_int {
        self.0.as_raw_fd()
    }

    fn try_clone(&self) -> io::Result<Self> {
        self.0.try_clone().map(Dir)
    }

    fn openat(&self, name: &str, flags: libc::c_int) -> io::Result<File> {
        let c = c_name(name)?;
        let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: `c` is a valid C string and `self` owns an open fd.
        let fd = cvt(unsafe { libc::openat(self.fd(), c.as_ptr(), flags, 0o600 as libc::c_uint) })?;
        // SAFETY: `fd` was just returned by openat and nothing else owns it.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn sub(&self, name: &str) -> io::Result<Dir> {
        self.openat(name, libc::O_RDONLY | libc::O_DIRECTORY)
            .map(Dir)
    }

    /// `O_NONBLOCK` so a FIFO planted here cannot hang the open.
    fn file(&self, name: &str) -> io::Result<File> {
        self.openat(name, libc::O_RDONLY | libc::O_NONBLOCK)
    }

    /// Created exclusively and `0600` until the caller sets its final mode.
    fn create(&self, name: &str) -> io::Result<File> {
        self.openat(name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
    }

    fn entry(&self, name: &str) -> io::Result<Entry> {
        match self.file(name) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Entry::Missing),
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Ok(Entry::Symlink),
            Err(e) => Err(e),
            Ok(f) => {
                let m = f.metadata()?;
                Ok(if m.is_dir() {
                    Entry::Dir(Dir(f))
                } else if m.is_file() {
                    Entry::File(f)
                } else {
                    Entry::Other
                })
            }
        }
    }

    fn mkdir(&self, name: &str) -> io::Result<()> {
        let c = c_name(name)?;
        // SAFETY: valid C string, open fd.
        cvt(unsafe { libc::mkdirat(self.fd(), c.as_ptr(), 0o700) }).map(drop)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let (f, t) = (c_name(from)?, c_name(to)?);
        // SAFETY: valid C strings, open fd.
        cvt(unsafe { libc::renameat(self.fd(), f.as_ptr(), self.fd(), t.as_ptr()) }).map(drop)
    }

    /// Hard link; `linkat` without `AT_SYMLINK_FOLLOW` never follows `from`.
    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        let (f, t) = (c_name(from)?, c_name(to)?);
        // SAFETY: valid C strings, open fd.
        cvt(unsafe { libc::linkat(self.fd(), f.as_ptr(), self.fd(), t.as_ptr(), 0) }).map(drop)
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        let c = c_name(name)?;
        // SAFETY: valid C string, open fd.
        cvt(unsafe { libc::unlinkat(self.fd(), c.as_ptr(), 0) }).map(drop)
    }

    fn rmdir(&self, name: &str) -> io::Result<()> {
        let c = c_name(name)?;
        // SAFETY: valid C string, open fd.
        cvt(unsafe { libc::unlinkat(self.fd(), c.as_ptr(), libc::AT_REMOVEDIR) }).map(drop)
    }

    fn names(&self) -> io::Result<Vec<String>> {
        // SAFETY: dup of an fd this value owns.
        let fd = cvt(unsafe { libc::dup(self.fd()) })?;
        // SAFETY: on success fdopendir owns `fd` and closedir releases it.
        let dirp = unsafe { libc::fdopendir(fd) };
        if dirp.is_null() {
            let e = io::Error::last_os_error();
            // SAFETY: fdopendir failed, so `fd` is still ours to close.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // The dup shares this fd's offset, which an earlier listing left at
        // the end.
        // SAFETY: `dirp` is a valid DIR stream until closedir below.
        unsafe { libc::rewinddir(dirp) };
        let mut out = Vec::new();
        loop {
            // SAFETY: `dirp` is valid; the entry is read before the next call.
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                break;
            }
            // SAFETY: readdir returned a valid entry with a NUL-terminated name.
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            if name != "." && name != ".." {
                out.push(name);
            }
        }
        // SAFETY: `dirp` came from fdopendir and is closed once.
        unsafe { libc::closedir(dirp) };
        out.sort();
        Ok(out)
    }
}

/// The directory `rel_dir` under `root`; `""` is `root` itself.
fn open_dir(root: &Dir, rel_dir: &str) -> Result<Dir> {
    let mut d = root.try_clone()?;
    if rel_dir.is_empty() {
        return Ok(d);
    }
    check_rel(rel_dir)?;
    for seg in rel_dir.split('/') {
        d = d
            .sub(seg)
            .with_context(|| format!("open {rel_dir} at {seg}"))?;
    }
    Ok(d)
}

fn split_rel(rel: &str) -> (&str, &str) {
    rel.rsplit_once('/').unwrap_or(("", rel))
}

/// The directory holding `rel`, and `rel`'s last component.
fn parent_of<'a>(root: &Dir, rel: &'a str) -> Result<(Dir, &'a str)> {
    check_rel(rel)?;
    let (dir, name) = split_rel(rel);
    Ok((open_dir(root, dir)?, name))
}

fn open_rel(root: &Dir, rel: &str) -> Result<File> {
    let (dir, name) = parent_of(root, rel)?;
    dir.file(name).with_context(|| format!("open {rel}"))
}

fn read_rel(root: &Dir, rel: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    open_rel(root, rel)?.read_to_end(&mut buf)?;
    Ok(buf)
}

fn apply_meta(f: &File, mode: u32, owner: Option<(u32, u32)>) -> Result<()> {
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    if let Some((uid, gid)) = owner {
        std::os::unix::fs::fchown(f, Some(uid), Some(gid))
            .with_context(|| format!("chown to {uid}:{gid}"))?;
    }
    Ok(())
}

/// Remove `name`, tolerating its absence.
fn discard(dir: &Dir, name: &str) -> io::Result<()> {
    match dir.unlink(name) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Manifest
// ═══════════════════════════════════════════════════════════════════════════

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
pub struct DirEntry {
    pub path: String,
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
    /// Subdirectories, parents before children.
    #[serde(default)]
    pub dirs: Vec<DirEntry>,
    pub files: Vec<FileEntry>,
}

impl Manifest {
    /// Read and validate: a manifest names the paths a restore writes as
    /// root, so every path must be a plain relative path, listed once, under
    /// a listed directory, and no mode may carry setuid, setgid or sticky bits.
    pub fn read(payload: &Path) -> Result<Self> {
        let raw = read_rel(&Dir::open(payload)?, MANIFEST)?;
        let m: Manifest = serde_json::from_slice(&raw)
            .with_context(|| format!("parse {}", payload.join(MANIFEST).display()))?;
        if m.version != MANIFEST_VERSION {
            bail!(
                "{}: manifest version {} is not {MANIFEST_VERSION}",
                payload.join(MANIFEST).display(),
                m.version
            );
        }
        let entries: Vec<(&str, u32)> = m
            .dirs
            .iter()
            .map(|d| (d.path.as_str(), d.mode))
            .chain(m.files.iter().map(|f| (f.path.as_str(), f.mode)))
            .collect();
        let mut seen = HashSet::new();
        for (path, mode) in &entries {
            check_rel(path)?;
            if !seen.insert(*path) {
                bail!("manifest lists {path:?} twice");
            }
            if mode & !PERMISSION_BITS != 0 {
                bail!("manifest gives {path:?} mode {mode:o}; only permission bits are restored");
            }
        }
        let dirs: HashSet<&str> = m.dirs.iter().map(|d| d.path.as_str()).collect();
        for (path, _) in &entries {
            let (parent, _) = split_rel(path);
            if !parent.is_empty() && !dirs.contains(parent) {
                bail!("manifest lists {path:?} but not its directory {parent:?}");
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
        bail!("unsafe path {p:?}");
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Capture
// ═══════════════════════════════════════════════════════════════════════════

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
    Ok(scan(&Dir::open(dir)?)?.1)
}

/// `(directories, files)` under `root`, each sorted.
fn scan(root: &Dir) -> Result<(Vec<String>, Vec<String>)> {
    let (mut dirs, mut files) = (Vec::new(), Vec::new());
    scan_at(root, "", &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();
    Ok((dirs, files))
}

fn scan_at(dir: &Dir, prefix: &str, dirs: &mut Vec<String>, files: &mut Vec<String>) -> Result<()> {
    for name in dir.names()? {
        if transient(&name) {
            continue;
        }
        let rel = format!("{prefix}{name}");
        match dir.entry(&name)? {
            Entry::Dir(sub) => {
                dirs.push(rel.clone());
                scan_at(&sub, &format!("{rel}/"), dirs, files)?;
            }
            Entry::File(_) => files.push(rel),
            Entry::Missing | Entry::Symlink | Entry::Other => {}
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

/// Changes whenever a file is rewritten or replaced.
type Stamp = (u64, i64, i64, i64, i64, u64);

fn stamp(m: &fs::Metadata) -> Stamp {
    (
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
        m.ino(),
    )
}

fn stamps(src: &Dir) -> Result<BTreeMap<String, Stamp>> {
    let mut out = BTreeMap::new();
    for rel in scan(src)?.1 {
        out.insert(rel.clone(), stamp(&open_rel(src, &rel)?.metadata()?));
    }
    Ok(out)
}

/// Copy `source` into `payload/files` and write the manifest.
pub fn capture(source: &Path, payload: &Path, instance: &str) -> Result<Manifest> {
    capture_with(source, payload, instance, &|| {})
}

/// Each file is hashed from the bytes read off the source, and every
/// source file is re-stamped after the whole copy: a capture that raced a
/// change is retried once, then refused.
fn capture_with(
    source: &Path,
    payload: &Path,
    instance: &str,
    after_copy: &dyn Fn(),
) -> Result<Manifest> {
    let src = Dir::open(source)?;
    let out = Dir::open(payload)?;
    let _locks = hold_locks(&src)?;
    for _ in 0..2 {
        let (dirs, files, before) = capture_once(&src, &out)?;
        after_copy();
        if stamps(&src)? == before {
            let manifest = Manifest {
                version: MANIFEST_VERSION,
                instance: instance.to_string(),
                source: source.display().to_string(),
                dirs,
                files,
            };
            let mut f = out.create(MANIFEST)?;
            f.write_all(&serde_json::to_vec_pretty(&manifest)?)?;
            f.sync_all()?;
            return Ok(manifest);
        }
        fs::remove_dir_all(payload.join(FILES_DIR))?;
    }
    bail!(
        "{} kept changing while it was copied; try again",
        source.display()
    )
}

type Captured = (Vec<DirEntry>, Vec<FileEntry>, BTreeMap<String, Stamp>);

fn capture_once(src: &Dir, out: &Dir) -> Result<Captured> {
    let (dir_names, file_names) = scan(src)?;
    let missing = missing_required(&file_names);
    if !missing.is_empty() {
        bail!(
            "not a complete PBS config directory; missing {}",
            missing.join(", ")
        );
    }
    out.mkdir(FILES_DIR)?;
    let root = out.sub(FILES_DIR)?;
    let mut dirs = Vec::with_capacity(dir_names.len());
    for rel in dir_names {
        let meta = open_dir(src, &rel)?.0.metadata()?;
        let (parent, name) = parent_of(&root, &rel)?;
        parent.mkdir(name)?;
        dirs.push(DirEntry {
            mode: meta.mode() & PERMISSION_BITS,
            uid: meta.uid(),
            gid: meta.gid(),
            path: rel,
        });
    }
    let mut files = Vec::with_capacity(file_names.len());
    let mut before = BTreeMap::new();
    for rel in file_names {
        let mut from = open_rel(src, &rel)?;
        let meta = from.metadata()?;
        if !meta.is_file() {
            bail!("{rel} is no longer a regular file");
        }
        let mut buf = Vec::new();
        from.read_to_end(&mut buf)?;
        let (parent, name) = parent_of(&root, &rel)?;
        let mut to = parent.create(name)?;
        to.write_all(&buf)
            .and_then(|()| to.sync_all())
            .with_context(|| format!("copy {rel}"))?;
        before.insert(rel.clone(), stamp(&meta));
        files.push(FileEntry {
            sha256: sha256_hex(&buf),
            size: buf.len() as u64,
            mode: meta.mode() & PERMISSION_BITS,
            uid: meta.uid(),
            gid: meta.gid(),
            path: rel,
        });
    }
    Ok((dirs, files, before))
}

/// PBS rewrites each config file by atomic rename while holding an exclusive
/// flock on its `.lck`/`.lock` sibling. Holding all of them shared gives a
/// view consistent across files (`user.cfg` with `token.shadow`). They are
/// taken non-blocking and all-or-nothing, so this never waits while holding
/// one and cannot deadlock with PBS, whose writers wait out the few
/// milliseconds of the copy inside their own lock timeout. Missing lock
/// files are not created: a root-owned one would lock PBS out.
fn hold_locks(src: &Dir) -> Result<Vec<File>> {
    let names: Vec<String> = src
        .names()?
        .into_iter()
        .filter(|n| n.ends_with(".lck") || n.ends_with(".lock"))
        .collect();
    'attempt: for _ in 0..LOCK_ATTEMPTS {
        let mut held = Vec::with_capacity(names.len());
        for n in &names {
            let Entry::File(f) = src.entry(n)? else {
                continue;
            };
            match f.try_lock_shared() {
                Ok(()) => held.push(f),
                Err(TryLockError::WouldBlock) => {
                    drop(held);
                    std::thread::sleep(LOCK_RETRY);
                    continue 'attempt;
                }
                Err(TryLockError::Error(e)) => return Err(e).with_context(|| format!("lock {n}")),
            }
        }
        return Ok(held);
    }
    bail!("PBS kept its config locked; try again")
}

/// Make the payload root-only: it holds token hashes and the ticket signing
/// key. Modes are set through fds, never through a symlink. Returns a
/// warning when the target ignores modes (CIFS does).
pub fn lock_down(payload: &Path) -> Result<Option<String>> {
    let root = Dir::open(payload)?;
    let mut loose = Vec::new();
    chmod_checked(&root.0, 0o700, "/", &mut loose)?;
    lock_down_at(&root, "", &mut loose)?;
    Ok((!loose.is_empty()).then(|| {
        format!(
            "target ignored chmod on {} path(s) (e.g. {}); the backup may be readable beyond root",
            loose.len(),
            loose[0]
        )
    }))
}

fn lock_down_at(dir: &Dir, prefix: &str, loose: &mut Vec<String>) -> Result<()> {
    for name in dir.names()? {
        let rel = format!("{prefix}/{name}");
        match dir.entry(&name)? {
            Entry::Dir(sub) => {
                chmod_checked(&sub.0, 0o700, &rel, loose)?;
                lock_down_at(&sub, &rel, loose)?;
            }
            Entry::File(f) => chmod_checked(&f, 0o600, &rel, loose)?,
            Entry::Missing => {}
            Entry::Symlink | Entry::Other => {
                bail!("{rel} in the payload is not a regular file or directory")
            }
        }
    }
    Ok(())
}

fn chmod_checked(f: &File, mode: u32, rel: &str, loose: &mut Vec<String>) -> Result<()> {
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    if f.metadata()?.mode() & PERMISSION_BITS != mode {
        loose.push(rel.to_string());
    }
    Ok(())
}

/// Check `dir` holds exactly what `manifest` recorded, and that what it holds
/// is a server that would come back with its datastores and working tokens.
pub fn verify(dir: &Path, manifest: &Manifest) -> Verification {
    let mut v = Verification::default();
    let root = match Dir::open(dir) {
        Ok(r) => r,
        Err(e) => {
            v.problems.push(format!("{e:#}"));
            return v;
        }
    };
    for f in &manifest.files {
        match read_rel(&root, &f.path) {
            Ok(buf) if sha256_hex(&buf) == f.sha256 => v.files_checked += 1,
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
        read_rel(&root, name)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
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

/// Owner and mode of every restored directory and file against the manifest.
pub fn verify_meta(dir: &Path, manifest: &Manifest) -> Vec<String> {
    let root = match Dir::open(dir) {
        Ok(r) => r,
        Err(e) => return vec![format!("{e:#}")],
    };
    let dirs = manifest.dirs.iter().map(|d| {
        let meta = open_dir(&root, &d.path).and_then(|x| Ok(x.0.metadata()?));
        (&d.path, (d.mode, d.uid, d.gid), meta)
    });
    let files = manifest.files.iter().map(|f| {
        let meta = open_rel(&root, &f.path).and_then(|x| Ok(x.metadata()?));
        (&f.path, (f.mode, f.uid, f.gid), meta)
    });
    let mut problems = Vec::new();
    for (path, want, meta) in dirs.chain(files) {
        let Ok(meta) = meta else {
            problems.push(format!("{path}: missing"));
            continue;
        };
        let got = (meta.mode() & PERMISSION_BITS, meta.uid(), meta.gid());
        if got != want {
            problems.push(format!(
                "{path}: {}:{} {:o}, backup has {}:{} {:o}",
                got.1, got.2, got.0, want.1, want.2, want.0
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

// ═══════════════════════════════════════════════════════════════════════════
// Restore
// ═══════════════════════════════════════════════════════════════════════════

/// Written once every file is staged and every original set aside, removed
/// before the set-aside originals are. While it exists the directory may be
/// half swapped and only [`recover`] can settle it; without it the live
/// files are consistent and any leftovers are disposable.
#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct SwapMarker {
    files: Vec<MarkedFile>,
    created_dirs: Vec<String>,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct MarkedFile {
    path: String,
    had_prev: bool,
}

struct Staged {
    dir: Dir,
    rel: String,
    name: String,
    tmp: String,
    prev: Option<String>,
    /// The original is out of place, held only by `prev`.
    displaced: bool,
}

type Rename<'a> = &'a dyn Fn(&Dir, &str, &str) -> io::Result<()>;

/// Write the captured directories and files into `dest`, which must already
/// exist, with their recorded modes and, with `owners`, their uid/gid (the
/// proxy runs as `backup` and cannot read a root-owned `authkey.pub`).
///
/// Every file is staged and fsynced before any is replaced and the replaced
/// files are hard-linked aside; on any reported error the swap is rolled
/// back. A crash mid-swap leaves a marker that [`recover`] settles.
pub fn materialize(payload: &Path, dest: &Path, manifest: &Manifest, owners: bool) -> Result<()> {
    let tag = plugin_toolkit::id::new();
    materialize_with(payload, dest, manifest, owners, &tag, &|d, a, b| {
        d.rename(a, b)
    })
}

struct Work<'a> {
    root: Dir,
    tag: &'a str,
    owners: bool,
    created: Vec<String>,
    staged: Vec<Staged>,
    marker: Option<String>,
    failures: Vec<String>,
}

fn materialize_with(
    payload: &Path,
    dest: &Path,
    manifest: &Manifest,
    owners: bool,
    tag: &str,
    rename: Rename,
) -> Result<()> {
    let root = Dir::open(dest)?;
    let left = leftovers(&root)?;
    if !left.is_empty() {
        bail!(
            "an interrupted restore left {} in {}; settle it with pbs.config_recover (action rollback or finish) first",
            left.join(", "),
            dest.display()
        );
    }
    let src = Dir::open(payload)?.sub(FILES_DIR)?;
    let mut w = Work {
        root,
        tag,
        owners,
        created: Vec::new(),
        staged: Vec::new(),
        marker: None,
        failures: Vec::new(),
    };
    let result = w
        .make_dirs(manifest)
        .and_then(|()| w.stage(&src, manifest))
        .and_then(|()| w.set_aside())
        .and_then(|()| w.mark())
        .and_then(|()| w.swap(rename));
    match result {
        Ok(()) => w.finish(manifest),
        Err(e) => {
            let left = w.undo();
            if left.is_empty() {
                Err(e)
            } else {
                Err(e.context(format!("rollback incomplete: {}", left.join("; "))))
            }
        }
    }
}

impl Work<'_> {
    fn owner(&self, uid: u32, gid: u32) -> Option<(u32, u32)> {
        self.owners.then_some((uid, gid))
    }

    fn make_dirs(&mut self, manifest: &Manifest) -> Result<()> {
        let mut dirs: Vec<&DirEntry> = manifest.dirs.iter().collect();
        dirs.sort_by_key(|d| d.path.matches('/').count());
        for d in dirs {
            let (parent, name) = parent_of(&self.root, &d.path)?;
            match parent.entry(name)? {
                Entry::Dir(_) => {}
                Entry::Missing => {
                    parent.mkdir(name)?;
                    self.created.push(d.path.clone());
                    apply_meta(&parent.sub(name)?.0, d.mode, self.owner(d.uid, d.gid))?;
                }
                _ => bail!("{} is a symlink or not a directory", d.path),
            }
        }
        Ok(())
    }

    fn stage(&mut self, src: &Dir, manifest: &Manifest) -> Result<()> {
        for f in &manifest.files {
            let (dir, name) = parent_of(&self.root, &f.path)?;
            let tmp = format!(".{name}{TEMP_MARK}{}", self.tag);
            let mut out = dir
                .create(&tmp)
                .with_context(|| format!("stage {}", f.path))?;
            self.staged.push(Staged {
                dir,
                rel: f.path.clone(),
                name: name.to_string(),
                tmp,
                prev: None,
                displaced: false,
            });
            out.write_all(&read_rel(src, &f.path)?)
                .with_context(|| format!("stage {}", f.path))?;
            apply_meta(&out, f.mode, self.owner(f.uid, f.gid))
                .with_context(|| format!("stage {}", f.path))?;
            out.sync_all()?;
        }
        self.sync_dirs()
    }

    fn set_aside(&mut self) -> Result<()> {
        for s in &mut self.staged {
            match s.dir.entry(&s.name)? {
                Entry::File(_) => {
                    let prev = format!(".{}{PREV_MARK}{}", s.name, self.tag);
                    s.dir
                        .link(&s.name, &prev)
                        .with_context(|| format!("set aside {}", s.rel))?;
                    s.prev = Some(prev);
                }
                Entry::Missing => {}
                _ => bail!("{} is a symlink or not a regular file", s.rel),
            }
        }
        self.sync_dirs()
    }

    fn mark(&mut self) -> Result<()> {
        let marker = SwapMarker {
            files: self
                .staged
                .iter()
                .map(|s| MarkedFile {
                    path: s.rel.clone(),
                    had_prev: s.prev.is_some(),
                })
                .collect(),
            created_dirs: self.created.clone(),
        };
        let name = format!("{SWAP_MARK}{}", self.tag);
        let mut f = self.root.create(&name)?;
        self.marker = Some(name);
        f.write_all(&serde_json::to_vec(&marker)?)?;
        f.sync_all()?;
        self.root.0.sync_all()?;
        Ok(())
    }

    fn swap(&mut self, rename: Rename) -> Result<()> {
        for i in 0..self.staged.len() {
            let s = &self.staged[i];
            if let Err(e) = rename(&s.dir, &s.tmp, &s.name) {
                let failed = s.rel.clone();
                for s in self.staged[..i].iter_mut().rev() {
                    let back = match &s.prev {
                        Some(prev) => s.dir.rename(prev, &s.name),
                        None => s.dir.unlink(&s.name),
                    };
                    if let Err(e) = back {
                        self.failures.push(match &s.prev {
                            Some(_) => format!("could not put back {}: {e}", s.rel),
                            None => format!("could not remove new file {}: {e}", s.rel),
                        });
                    } else {
                        s.displaced = false;
                    }
                }
                return Err(e).with_context(|| format!("replace {failed}; rolled back"));
            }
            self.staged[i].displaced = true;
        }
        Ok(())
    }

    /// Drop the marker first: from then on the restored files are the
    /// consistent state and the set-aside originals are disposable.
    fn finish(&mut self, manifest: &Manifest) -> Result<()> {
        self.sync_dirs()?;
        if let Some(m) = self.marker.take() {
            self.root.unlink(&m)?;
            self.root.0.sync_all()?;
        }
        for s in &self.staged {
            if let Some(prev) = &s.prev {
                if let Err(e) = discard(&s.dir, prev) {
                    tracing::warn!(file = %s.rel, error = %e, "could not remove the set-aside original");
                }
            }
        }
        for d in &manifest.dirs {
            apply_meta(
                &open_dir(&self.root, &d.path)?.0,
                d.mode,
                self.owner(d.uid, d.gid),
            )
            .with_context(|| format!("files restored, but setting {} failed", d.path))?;
        }
        self.sync_dirs()
    }

    /// Clean up after a reported error. Returns what could not be undone.
    fn undo(&mut self) -> Vec<String> {
        let mut left = std::mem::take(&mut self.failures);
        for s in &self.staged {
            if let Err(e) = discard(&s.dir, &s.tmp) {
                left.push(format!("could not remove {}: {e}", s.tmp));
            }
            match &s.prev {
                Some(prev) if s.displaced => {
                    left.push(format!("original of {} kept as {prev}", s.rel))
                }
                Some(prev) => {
                    if let Err(e) = discard(&s.dir, prev) {
                        left.push(format!("could not remove {prev}: {e}"));
                    }
                }
                None => {}
            }
        }
        for d in self.created.iter().rev() {
            let removed = parent_of(&self.root, d).and_then(|(p, n)| Ok(p.rmdir(n)?));
            if let Err(e) = removed {
                left.push(format!("could not remove created directory {d}: {e:#}"));
            }
        }
        if left.is_empty() {
            if let Some(m) = self.marker.take() {
                if let Err(e) = discard(&self.root, &m) {
                    left.push(format!("could not remove {m}: {e}"));
                }
            }
        }
        if let Err(e) = self.sync_dirs() {
            left.push(format!("fsync after rollback: {e:#}"));
        }
        left
    }

    fn sync_dirs(&self) -> Result<()> {
        for s in &self.staged {
            s.dir.0.sync_all()?;
        }
        self.root.0.sync_all()?;
        Ok(())
    }
}

/// Paths of temp files, set-aside originals and swap markers under `root`.
fn leftovers(root: &Dir) -> Result<Vec<String>> {
    let mut out = Vec::new();
    leftovers_at(root, "", &mut out)?;
    Ok(out)
}

fn leftovers_at(dir: &Dir, prefix: &str, out: &mut Vec<String>) -> Result<()> {
    for name in dir.names()? {
        let rel = format!("{prefix}{name}");
        if name.contains(TEMP_MARK) || name.contains(PREV_MARK) || name.starts_with(SWAP_MARK) {
            out.push(rel);
        } else if let Entry::Dir(sub) = dir.entry(&name)? {
            leftovers_at(&sub, &format!("{rel}/"), out)?;
        }
    }
    Ok(())
}

/// One step of settling an interrupted restore, relative to the config dir.
#[derive(Debug, Clone, PartialEq)]
enum Op {
    Rename {
        dir: String,
        from: String,
        to: String,
    },
    Unlink {
        dir: String,
        name: String,
    },
    Rmdir {
        dir: String,
        name: String,
    },
}

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

impl Op {
    fn describe(&self) -> String {
        match self {
            Op::Rename { dir, from, to } => {
                format!("rename {} to {}", join_rel(dir, from), join_rel(dir, to))
            }
            Op::Unlink { dir, name } => format!("remove {}", join_rel(dir, name)),
            Op::Rmdir { dir, name } => format!("remove directory {}", join_rel(dir, name)),
        }
    }

    fn apply(&self, root: &Dir) -> Result<()> {
        match self {
            Op::Rename { dir, from, to } => open_dir(root, dir)?.rename(from, to)?,
            Op::Unlink { dir, name } => discard(&open_dir(root, dir)?, name)?,
            Op::Rmdir { dir, name } => open_dir(root, dir)?.rmdir(name)?,
        }
        Ok(())
    }
}

/// The steps that settle every interrupted restore in `dest`. With a swap
/// marker, `finish` moves the remaining staged files into place and
/// rollback puts the originals back; without one the live files are already
/// consistent and both just remove the leftovers.
fn recovery(dest: &Path, finish: bool) -> Result<(Dir, Vec<Op>)> {
    let root = Dir::open(dest)?;
    let left = leftovers(&root)?;
    let exists = |rel: &str| left.iter().any(|l| l == rel);
    let mut ops = Vec::new();
    let mut markers = Vec::new();
    for rel in &left {
        let (_, name) = split_rel(rel);
        if let Some(tag) = name.strip_prefix(SWAP_MARK) {
            markers.push((rel.clone(), tag.to_string()));
        }
    }
    let marked = |name: &str| markers.iter().any(|(_, t)| name.ends_with(t.as_str()));
    for (marker_rel, tag) in &markers {
        let m: SwapMarker = serde_json::from_slice(&read_rel(&root, marker_rel)?)
            .with_context(|| format!("parse {marker_rel}"))?;
        for f in &m.files {
            check_rel(&f.path)?;
            let (dir, name) = split_rel(&f.path);
            let tmp = format!(".{name}{TEMP_MARK}{tag}");
            let prev = format!(".{name}{PREV_MARK}{tag}");
            let tmp_left = exists(&join_rel(dir, &tmp));
            let prev_left = exists(&join_rel(dir, &prev));
            let dir = dir.to_string();
            if finish {
                if tmp_left {
                    ops.push(Op::Rename {
                        dir: dir.clone(),
                        from: tmp,
                        to: name.to_string(),
                    });
                }
                if prev_left {
                    ops.push(Op::Unlink { dir, name: prev });
                }
            } else if tmp_left {
                // Never swapped, so the original is still in place and
                // `prev` is a second link to it: renaming one hard link onto
                // another is a no-op, so drop both extras instead.
                ops.push(Op::Unlink {
                    dir: dir.clone(),
                    name: tmp,
                });
                if prev_left {
                    ops.push(Op::Unlink { dir, name: prev });
                }
            } else if prev_left {
                ops.push(Op::Rename {
                    dir,
                    from: prev,
                    to: name.to_string(),
                });
            } else if !f.had_prev {
                ops.push(Op::Unlink {
                    dir,
                    name: name.to_string(),
                });
            }
        }
        if !finish {
            for d in m.created_dirs.iter().rev() {
                check_rel(d)?;
                let (dir, name) = split_rel(d);
                ops.push(Op::Rmdir {
                    dir: dir.to_string(),
                    name: name.to_string(),
                });
            }
        }
        ops.push(Op::Unlink {
            dir: String::new(),
            name: marker_rel.clone(),
        });
    }
    for rel in &left {
        let (dir, name) = split_rel(rel);
        if !name.starts_with(SWAP_MARK) && !marked(name) {
            ops.push(Op::Unlink {
                dir: dir.to_string(),
                name: name.to_string(),
            });
        }
    }
    Ok((root, ops))
}

/// Apply [`recovery`] and fsync what it touched.
fn recover(dest: &Path, finish: bool) -> Result<Vec<String>> {
    let (root, ops) = recovery(dest, finish)?;
    let mut done = Vec::with_capacity(ops.len());
    for op in &ops {
        op.apply(&root)
            .with_context(|| format!("{}; already done: [{}]", op.describe(), done.join(", ")))?;
        done.push(op.describe());
    }
    let mut dirs: Vec<&str> = ops
        .iter()
        .map(|op| match op {
            Op::Rename { dir, .. } | Op::Unlink { dir, .. } | Op::Rmdir { dir, .. } => dir.as_str(),
        })
        .collect();
    dirs.sort();
    dirs.dedup();
    for d in dirs {
        if let Ok(dir) = open_dir(&root, d) {
            dir.0.sync_all()?;
        }
    }
    Ok(done)
}

// ═══════════════════════════════════════════════════════════════════════════
// Container state
// ═══════════════════════════════════════════════════════════════════════════

/// Why `volume` (whose data lives at `data_dir`) may be in use, read from
/// docker's on-disk container state. Fails closed: state that cannot be read
/// or parsed counts as in use.
fn volume_users(containers_dir: &Path, volume: &str, data_dir: &Path) -> Result<Vec<String>> {
    let entries = fs::read_dir(containers_dir).with_context(|| {
        format!(
            "cannot confirm no container uses {volume}: read {}",
            containers_dir.display()
        )
    })?;
    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let id = entry.file_name().to_string_lossy().into_owned();
        let state = fs::read(entry.path().join("config.v2.json"))
            .map_err(plugin_toolkit::anyhow::Error::from)
            .and_then(|raw| Ok(serde_json::from_slice::<Value>(&raw)?));
        let c = match state {
            Ok(c) => c,
            Err(e) => {
                out.push(format!("container {id}: state unreadable ({e:#})"));
                continue;
            }
        };
        let Some(running) = c["State"]["Running"].as_bool() else {
            out.push(format!("container {id}: state has no State.Running"));
            continue;
        };
        let uses = c["MountPoints"]
            .as_object()
            .into_iter()
            .flatten()
            .any(|(_, m)| {
                m["Name"] == volume || m["Source"].as_str().map(Path::new) == Some(data_dir)
            });
        if running && uses {
            let name = c["Name"].as_str().unwrap_or(&id).trim_start_matches('/');
            out.push(format!(
                "{name} is running (per docker's state file; if docker is down or the state is stale, start and stop the container so docker rewrites it)"
            ));
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

// ═══════════════════════════════════════════════════════════════════════════
// The kind
// ═══════════════════════════════════════════════════════════════════════════

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

    fn ensure_stopped(&self, instance: &str) -> Result<()> {
        let users = volume_users(
            &self.containers_dir(),
            &crate::config_volume(instance),
            &self.config_dir(instance),
        )?;
        if !users.is_empty() {
            bail!("stop the container first: {}", users.join("; "));
        }
        Ok(())
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
                "the written backup does not match what was read: {}",
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
        // Core verification of this slot checksum is orca#478; restore
        // re-checks every file against the manifest either way.
        Ok(BackupOutcome {
            checksum: Some(format!("sha256:{}", sha256_hex(&raw))),
            note: Some(note),
            unchanged: false,
        })
    }

    fn restore_from(&self, payload_dir: &Path, instance: &str) -> Result<Verification> {
        self.ensure_stopped(instance)?;
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
        self.ensure_stopped(instance).context(
            "a container started during the restore; stop it and start it again so PBS loads only the restored config",
        )?;
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
/// holds the store's stage lock and the slot its manifest. This catches an
/// operator pointing at the wrong directory; it is not a security boundary,
/// since the caller is already an admin.
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
    if kind_dir != Some(std::path::Component::Normal(KIND.as_ref()))
        || !slot.join(SLOT_MANIFEST).is_file()
    {
        return Err(refuse());
    }
    Ok(p)
}

/// Restore a `pbs-config` backup into a new scratch directory and verify the
/// copy: every file's checksum, the datastores it defines and its API
/// tokens. Dry-run by default.
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

// ═══════════════════════════════════════════════════════════════════════════
// pbs.config_recover
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRecoverArgs {
    /// Instance whose live config volume an interrupted restore left behind.
    #[arg(long)]
    pub instance: String,
    /// `rollback` puts the originals back; `finish` completes the restore.
    #[arg(long)]
    pub action: String,
    /// Apply the change. Without it the verb lists the steps.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigRecoverOutput {
    pub dry_run: bool,
    /// Planned on a dry run; applied on execute.
    pub steps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<ExecutionPlan>,
}

/// Settle a live-volume restore that was interrupted: roll it back to the
/// originals or finish it. Needs the container stopped. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "config_recover",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_config_recover(
    args: ConfigRecoverArgs,
    ctx: &ToolCtx,
) -> Result<ConfigRecoverOutput> {
    config_recover(&PbsConfigKind::from_env(), &args, ctx.caller().as_ref())
}

fn config_recover(
    kind: &PbsConfigKind,
    args: &ConfigRecoverArgs,
    caller: Option<&CallerIdentity>,
) -> Result<ConfigRecoverOutput> {
    const TOOL: &str = "pbs.config_recover";
    let finish = match args.action.as_str() {
        "rollback" => false,
        "finish" => true,
        other => bail!("{TOOL}: action must be rollback or finish, not {other:?}"),
    };
    let live = kind.config_dir(&args.instance);
    if !args.execute {
        let steps: Vec<String> = recovery(&live, finish)?
            .1
            .iter()
            .map(Op::describe)
            .collect();
        let changes = steps
            .iter()
            .map(|s| PlannedChange::new(s.clone(), args.action.clone()))
            .collect();
        let plan = ExecutionPlan::generic(TOOL, serde_json::to_value(args)?.into())
            .detailed(format!("{} {}", args.action, live.display()), changes);
        return Ok(ConfigRecoverOutput {
            dry_run: true,
            steps,
            plan: Some(plan),
        });
    }
    plan::authorize_execute(TOOL, caller)?;
    kind.ensure_stopped(&args.instance)?;
    Ok(ConfigRecoverOutput {
        dry_run: false,
        steps: recover(&live, finish)?,
        plan: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plugin_toolkit::contract::backup::wire::{OP_BACKUP, OP_INSTANCES, OP_RESTORE};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

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
        fs::set_permissions(dir.join("acme"), fs::Permissions::from_mode(0o750)).unwrap();
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

    fn container(tmp: &Path, id: &str, state: Value) {
        let dir = tmp.join("containers").join(id);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.v2.json"), state.to_string()).unwrap();
    }

    fn pbs_state(running: bool) -> Value {
        json!({
            "Name": "/pbs",
            "State": {"Running": running},
            "MountPoints": {"/etc/proxmox-backup": {"Name": "pbs-config", "Type": "volume"}},
        })
    }

    fn manifest_with(dirs: Value, files: Value) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let m =
            json!({"version": 1, "instance": "pbs", "source": "/x", "dirs": dirs, "files": files});
        fs::write(dir.path().join(MANIFEST), m.to_string()).unwrap();
        dir
    }

    fn entry(path: &str, mode: u32) -> Value {
        json!({"path": path, "size": 0, "sha256": "", "mode": mode, "uid": 0, "gid": 0})
    }

    fn all_leftovers(dir: &Path) -> Vec<String> {
        leftovers(&Dir::open(dir).unwrap()).unwrap()
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o777
    }

    #[test]
    fn file_set_is_every_live_file_minus_locks_rotations_and_symlinks() {
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
    fn manifest_records_files_and_dirs_and_round_trips() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), out.path(), "pbs").unwrap();
        assert_eq!(m.files.len(), collect(src.path()).unwrap().len());

        let key = m.files.iter().find(|f| f.path == "authkey.key").unwrap();
        assert_eq!(key.mode, 0o600);
        assert_eq!(key.sha256, sha256_hex(b"authkey.key\n"));
        let meta = fs::metadata(src.path().join("authkey.key")).unwrap();
        assert_eq!((key.uid, key.gid), (meta.uid(), meta.gid()));
        assert_eq!(m.dirs.len(), 1);
        assert_eq!((m.dirs[0].path.as_str(), m.dirs[0].mode), ("acme", 0o750));

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
    fn manifest_refuses_traversal_absolute_odd_and_orphan_paths() {
        for bad in ["../x", "/etc/x", "acme/../../x", "./x", "a//b", "", "a\0b"] {
            let dir = manifest_with(json!([]), json!([entry(bad, 0o600)]));
            let err = Manifest::read(dir.path()).unwrap_err();
            assert!(
                format!("{err:#}").contains("unsafe path"),
                "{bad:?}: {err:#}"
            );
        }
        let dir = manifest_with(json!([]), json!([entry("a", 0o600), entry("a", 0o600)]));
        assert!(format!("{:#}", Manifest::read(dir.path()).unwrap_err()).contains("twice"));
        let dir = manifest_with(json!([]), json!([entry("acme/x", 0o600)]));
        let err = format!("{:#}", Manifest::read(dir.path()).unwrap_err());
        assert!(err.contains("not its directory"), "{err}");
    }

    #[test]
    fn manifest_refuses_setuid_setgid_and_sticky() {
        for mode in [0o4755, 0o2755, 0o1777] {
            let dir = manifest_with(json!([]), json!([entry("user.cfg", mode)]));
            let err = Manifest::read(dir.path()).unwrap_err();
            assert!(
                format!("{err:#}").contains("only permission bits"),
                "{err:#}"
            );
            let dir = manifest_with(json!([entry("acme", mode)]), json!([]));
            assert!(Manifest::read(dir.path()).is_err());
        }
    }

    #[test]
    fn fd_walk_refuses_traversal_and_symlinked_components() {
        let tmp = tempfile::tempdir().unwrap();
        let root_path = tmp.path().join("root");
        fs::create_dir_all(root_path.join("real")).unwrap();
        fs::write(root_path.join("real/f"), "x").unwrap();
        fs::write(tmp.path().join("outside"), "secret").unwrap();
        std::os::unix::fs::symlink(root_path.join("real"), root_path.join("link")).unwrap();
        let root = Dir::open(&root_path).unwrap();
        assert!(open_rel(&root, "real/f").is_ok());
        assert!(open_rel(&root, "../outside").is_err());
        assert!(open_rel(&root, "/etc/passwd").is_err());
        assert!(open_rel(&root, "link/f").is_err());
        assert!(parent_of(&root, "link/f").is_err());
        assert!(Dir::open(&root_path.join("link")).is_err());
    }

    #[test]
    fn capture_never_follows_a_symlink_swapped_in_mid_walk() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let host_dir = tempfile::tempdir().unwrap();
        fs::write(host_dir.path().join("accounts"), "HOST SECRET").unwrap();
        let s = src.path();
        fs::rename(s.join("acme"), s.join(".acme-d")).unwrap();
        std::os::unix::fs::symlink(host_dir.path(), s.join(".acme-l")).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let flipper = {
            let (stop, s) = (stop.clone(), s.to_path_buf());
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    for hold in [".acme-d", ".acme-l"] {
                        if fs::rename(s.join(hold), s.join("acme")).is_ok() {
                            fs::rename(s.join("acme"), s.join(hold)).unwrap();
                        }
                    }
                }
            })
        };
        for _ in 0..100 {
            let out = tempfile::tempdir().unwrap();
            // A capture that hit the symlink fails; one that succeeds, or
            // left a partial copy, must never hold the host's file.
            let _attempt = capture(s, out.path(), "pbs");
            let got = fs::read_to_string(out.path().join("files/acme/accounts"));
            assert_ne!(got.ok().as_deref(), Some("HOST SECRET"));
        }
        stop.store(true, Ordering::Relaxed);
        flipper.join().unwrap();
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
    fn capture_retries_a_change_once_then_refuses() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let user = src.path().join("user.cfg");

        let changes = std::cell::Cell::new(0);
        let once = || {
            if changes.get() == 0 {
                fs::write(&user, "user: root@pam\nuser: late@pam\n").unwrap();
            }
            changes.set(changes.get() + 1);
        };
        let out = tempfile::tempdir().unwrap();
        let m = capture_with(src.path(), out.path(), "pbs", &once).unwrap();
        let entry = m.files.iter().find(|f| f.path == "user.cfg").unwrap();
        assert_eq!(
            entry.sha256,
            sha256_hex(b"user: root@pam\nuser: late@pam\n")
        );
        assert_eq!(changes.get(), 2);

        let n = std::cell::Cell::new(0);
        let always = || {
            n.set(n.get() + 1);
            fs::write(&user, format!("user: u{}@pam\n", "x".repeat(n.get()))).unwrap();
        };
        let out = tempfile::tempdir().unwrap();
        let err = capture_with(src.path(), out.path(), "pbs", &always).unwrap_err();
        assert!(format!("{err:#}").contains("kept changing"), "{err:#}");
        assert!(!out.path().join(MANIFEST).exists());
    }

    #[test]
    fn capture_waits_for_a_pbs_writer_to_release_its_lock() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let lock = File::open(src.path().join(".user.lck")).unwrap();
        lock.lock().unwrap();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(lock);
        });
        let started = std::time::Instant::now();
        let out = tempfile::tempdir().unwrap();
        capture(src.path(), out.path(), "pbs").unwrap();
        assert!(started.elapsed() >= Duration::from_millis(250));
        writer.join().unwrap();
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
    fn verify_catches_tampering_loss_and_symlinks() {
        let src = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        seed(src.path());
        let m = capture(src.path(), out.path(), "pbs").unwrap();
        let files = out.path().join(FILES_DIR);
        fs::write(files.join("acl.cfg"), "changed\n").unwrap();
        fs::remove_file(files.join("proxy.key")).unwrap();
        fs::copy(files.join("proxy.pem"), out.path().join("elsewhere")).unwrap();
        fs::remove_file(files.join("proxy.pem")).unwrap();
        std::os::unix::fs::symlink(out.path().join("elsewhere"), files.join("proxy.pem")).unwrap();
        let p = verify(&files, &m).problems.join("\n");
        assert!(p.contains("acl.cfg: checksum mismatch"), "{p}");
        assert!(p.contains("proxy.key: missing"), "{p}");
        assert!(p.contains("proxy.pem: missing or unreadable"), "{p}");
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
        assert_eq!(mode(payload.path()), 0o700);
        assert_eq!(mode(&payload.path().join("files/acme")), 0o700);
        assert_eq!(mode(&payload.path().join(MANIFEST)), 0o600);
        assert_eq!(mode(&payload.path().join("files/user.cfg")), 0o600);
    }

    #[test]
    fn lock_down_refuses_a_symlink_and_never_chmods_through_it() {
        let payload = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let bait = outside.path().join("bait");
        fs::write(&bait, "x").unwrap();
        fs::set_permissions(&bait, fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&bait, payload.path().join("link")).unwrap();
        assert!(lock_down(payload.path()).is_err());
        assert_eq!(mode(&bait), 0o644);
    }

    #[test]
    fn kind_backs_up_and_restores_a_rebuilt_container_over_the_wire() {
        let (tmp, kind, live) = host("pbs");
        container(tmp.path(), "abc", pbs_state(false));
        let payload = tempfile::tempdir().unwrap();
        fs::set_permissions(live.join("proxy.key"), fs::Permissions::from_mode(0o640)).unwrap();

        assert_eq!(
            dispatch_kind_op(&kind, OP_INSTANCES, json!({})).unwrap(),
            json!(["pbs"])
        );
        let args = json!({"payload_dir": payload.path(), "instance": "pbs"});
        let outcome = dispatch_kind_op(&kind, OP_BACKUP, args.clone()).unwrap();
        assert!(outcome["checksum"].as_str().unwrap().starts_with("sha256:"));

        // A rebuilt container: fresh identity, no datastores, no tokens, no acme.
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        fs::set_permissions(live.join("proxy.key"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(live.join("datastore.cfg")).unwrap();
        fs::remove_dir_all(live.join("acme")).unwrap();
        fs::write(live.join("user.cfg"), "user: root@pam\n").unwrap();
        dispatch_kind_op(&kind, OP_RESTORE, args).unwrap();

        let m = Manifest::read(payload.path()).unwrap();
        let v = verify(&live, &m);
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.datastores, ["willow-primary", "offsite"]);
        assert_eq!(v.tokens, ["root@pam!orca"]);
        assert!(verify_meta(&live, &m).is_empty());
        assert_eq!(mode(&live.join("proxy.key")), 0o640);
        assert_eq!(mode(&live.join("acme")), 0o750);
        assert!(all_leftovers(&live).is_empty());
    }

    #[test]
    fn verify_meta_catches_file_and_dir_mode_changes() {
        let (_tmp, kind, live) = host("pbs");
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        fs::set_permissions(live.join("authkey.key"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(live.join("acme"), fs::Permissions::from_mode(0o777)).unwrap();
        let p = verify_meta(&live, &Manifest::read(payload.path()).unwrap()).join("\n");
        assert!(p.contains("authkey.key") && p.contains("644"), "{p}");
        assert!(p.contains("acme:") && p.contains("777"), "{p}");
    }

    #[test]
    fn kind_restore_refuses_while_the_container_runs() {
        let (tmp, kind, live) = host("pbs");
        container(tmp.path(), "abc", pbs_state(true));
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        let err = kind.restore(payload.path(), "pbs").unwrap_err();
        assert!(
            err.contains("pbs is running") && err.contains("stale"),
            "{err}"
        );
        assert_eq!(
            fs::read_to_string(live.join("authkey.key")).unwrap(),
            "fresh\n"
        );
    }

    #[test]
    fn container_state_fails_closed() {
        let (tmp, kind, live) = host("pbs");
        let t = tmp.path();
        container(t, "stopped", pbs_state(false));
        container(
            t,
            "other",
            json!({"State": {"Running": true}, "MountPoints": {"/x": {"Name": "other"}}}),
        );
        assert!(kind.ensure_stopped("pbs").is_ok());

        container(t, "garbled", json!("not an object"));
        fs::write(t.join("containers/garbled/config.v2.json"), "{").unwrap();
        container(t, "norunning", json!({"State": {}}));
        fs::create_dir_all(t.join("containers/nostate")).unwrap();
        container(
            t,
            "bind",
            json!({"Name": "/pbs2", "State": {"Running": true},
                   "MountPoints": {"/etc/proxmox-backup": {"Source": live.display().to_string()}}}),
        );
        let err = format!("{:#}", kind.ensure_stopped("pbs").unwrap_err());
        assert!(err.contains("garbled: state unreadable"), "{err}");
        assert!(
            err.contains("norunning: state has no State.Running"),
            "{err}"
        );
        assert!(err.contains("nostate: state unreadable"), "{err}");
        assert!(err.contains("pbs2 is running"), "{err}");

        fs::remove_dir_all(t.join("containers")).unwrap();
        let err = format!("{:#}", kind.ensure_stopped("pbs").unwrap_err());
        assert!(err.contains("cannot confirm"), "{err}");
    }

    #[test]
    fn kind_restore_refuses_a_corrupt_backup_and_leaves_live_alone() {
        let (_tmp, kind, live) = host("pbs");
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        fs::set_permissions(
            payload.path().join("files/user.cfg"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
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

    fn assert_all(live: &Path, m: &Manifest, want: impl Fn(&FileEntry) -> String) {
        for f in &m.files {
            let got = fs::read_to_string(live.join(&f.path)).unwrap_or_default();
            assert_eq!(got, want(f), "{}", f.path);
        }
    }

    fn captured_text(payload: &Path) -> impl Fn(&FileEntry) -> String + '_ {
        move |f| fs::read_to_string(payload.join(FILES_DIR).join(&f.path)).unwrap()
    }

    #[test]
    fn a_failed_swap_rolls_back_files_and_created_dirs() {
        let (live, payload, m) = drifted();
        fs::remove_dir_all(live.path().join("acme")).unwrap();
        let calls = std::cell::Cell::new(0);
        let flaky = |d: &Dir, a: &str, b: &str| {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                return Err(io::Error::other("disk full"));
            }
            d.rename(a, b)
        };
        let err =
            materialize_with(payload.path(), live.path(), &m, false, "T", &flaky).unwrap_err();
        assert!(format!("{err:#}").contains("rolled back"), "{err:#}");
        for f in m.files.iter().filter(|f| !f.path.starts_with("acme/")) {
            assert_eq!(
                fs::read_to_string(live.path().join(&f.path)).unwrap(),
                "live\n"
            );
        }
        assert!(
            !live.path().join("acme").exists(),
            "created dir left behind"
        );
        assert!(all_leftovers(live.path()).is_empty());
    }

    #[test]
    fn restore_refuses_a_symlink_planted_at_the_temp_name() {
        let (live, payload, m) = drifted();
        let outside = tempfile::tempdir().unwrap();
        let bait = outside.path().join("bait");
        fs::write(&bait, "untouched\n").unwrap();
        let rename = |d: &Dir, a: &str, b: &str| d.rename(a, b);
        std::os::unix::fs::symlink(&bait, live.path().join(".user.cfg.orca-restore-T")).unwrap();
        // The planted name is itself a leftover, so the restore stops before
        // staging; without it the exclusive no-follow create refuses the name.
        assert!(materialize_with(payload.path(), live.path(), &m, false, "T", &rename).is_err());
        fs::remove_file(live.path().join(".user.cfg.orca-restore-T")).unwrap();
        let root = Dir::open(live.path()).unwrap();
        std::os::unix::fs::symlink(&bait, live.path().join("planted")).unwrap();
        assert!(root.create("planted").is_err());
        assert_eq!(fs::read_to_string(&bait).unwrap(), "untouched\n");
        assert_all(live.path(), &m, |_| "live\n".to_string());
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
        assert!(all_leftovers(live.path()).is_empty());
    }

    /// Simulate a crash on the third rename: unwinding skips all cleanup.
    fn crash_mid_swap(live: &Path, payload: &Path, m: &Manifest) {
        let calls = std::cell::Cell::new(0);
        let crashing = |d: &Dir, a: &str, b: &str| {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                panic!("simulated crash");
            }
            d.rename(a, b)
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            materialize_with(payload, live, m, false, "T", &crashing)
        }));
        assert!(r.is_err());
        assert!(all_leftovers(live).iter().any(|l| l.starts_with(SWAP_MARK)));
    }

    #[test]
    fn an_interrupted_restore_blocks_the_next_until_rolled_back() {
        let (live, payload, m) = drifted();
        crash_mid_swap(live.path(), payload.path(), &m);
        let err = materialize(payload.path(), live.path(), &m, false).unwrap_err();
        assert!(format!("{err:#}").contains("pbs.config_recover"), "{err:#}");

        recover(live.path(), false).unwrap();
        assert_all(live.path(), &m, |_| "live\n".to_string());
        assert!(
            all_leftovers(live.path()).is_empty(),
            "{:?}",
            all_leftovers(live.path())
        );
        materialize(payload.path(), live.path(), &m, false).unwrap();
        assert_all(live.path(), &m, captured_text(payload.path()));
    }

    #[test]
    fn an_interrupted_restore_can_be_finished() {
        let (live, payload, m) = drifted();
        crash_mid_swap(live.path(), payload.path(), &m);
        recover(live.path(), true).unwrap();
        assert_all(live.path(), &m, captured_text(payload.path()));
        assert!(all_leftovers(live.path()).is_empty());
    }

    #[test]
    fn leftovers_without_a_marker_are_just_removed() {
        let (live, _payload, m) = drifted();
        fs::write(live.path().join(".user.cfg.orca-restore-X"), "partial").unwrap();
        fs::write(live.path().join("acme/.accounts.orca-prev-X"), "old").unwrap();
        let steps = recover(live.path(), true).unwrap();
        assert_eq!(steps.len(), 2, "{steps:?}");
        assert!(all_leftovers(live.path()).is_empty());
        assert_all(live.path(), &m, |_| "live\n".to_string());
    }

    #[test]
    fn recover_verb_dry_runs_and_needs_admin_and_a_stopped_container() {
        let (tmp, kind, live) = host("pbs");
        let payload = tempfile::tempdir().unwrap();
        kind.backup_into(payload.path(), "pbs").unwrap();
        let m = Manifest::read(payload.path()).unwrap();
        crash_mid_swap(&live, payload.path(), &m);
        let args = |action: &str, execute| ConfigRecoverArgs {
            instance: "pbs".into(),
            action: action.into(),
            execute,
        };
        let before = all_leftovers(&live);
        let out = config_recover(&kind, &args("rollback", false), None).unwrap();
        assert!(out.dry_run && !out.steps.is_empty());
        assert_eq!(all_leftovers(&live), before);
        assert!(config_recover(&kind, &args("sideways", false), None).is_err());
        assert!(config_recover(&kind, &args("rollback", true), None).is_err());

        container(tmp.path(), "abc", pbs_state(true));
        let admin = plan::admin();
        assert!(config_recover(&kind, &args("rollback", true), Some(&admin)).is_err());
        container(tmp.path(), "abc", pbs_state(false));
        config_recover(&kind, &args("rollback", true), Some(&admin)).unwrap();
        assert!(all_leftovers(&live).is_empty());
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
        assert_eq!(mode(&dest), 0o700);
        assert_eq!(mode(&dest.join("acme")), 0o750);
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
