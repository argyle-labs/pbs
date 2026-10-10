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
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
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
/// A marker update in flight, renamed over the marker once fsynced.
const NEXT_SUFFIX: &str = ".next";

/// Per-file and whole-config read limits; PBS configs are a few KiB.
const FILE_CAP: u64 = 16 << 20;
const TOTAL_CAP: u64 = 256 << 20;

/// Directory nesting any walk follows; PBS's config is two levels deep.
const MAX_DEPTH: usize = 32;

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

#[derive(Debug, Clone, Copy, PartialEq)]
enum Kind {
    Symlink,
    Dir,
    File,
    Other,
}

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

fn not_regular(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{name} is not a regular file"),
    )
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
        let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY;
        // SAFETY: `c` is a valid C string and `self` owns an open fd.
        let fd = cvt(unsafe { libc::openat(self.fd(), c.as_ptr(), flags, 0o600 as libc::c_uint) })?;
        // SAFETY: `fd` was just returned by openat and nothing else owns it.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Type and inode of `name` without following or opening it, so a device
    /// node or FIFO is classified and never opened.
    fn stat(&self, name: &str) -> io::Result<Option<(Kind, u64)>> {
        let c = c_name(name)?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: valid C string, open fd; `st` is written on success.
        let r = unsafe {
            libc::fstatat(
                self.fd(),
                c.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if let Err(e) = cvt(r) {
            return if e.kind() == io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(e)
            };
        }
        // SAFETY: fstatat succeeded and filled `st`.
        let st = unsafe { st.assume_init() };
        let kind = match st.st_mode & libc::S_IFMT {
            libc::S_IFLNK => Kind::Symlink,
            libc::S_IFDIR => Kind::Dir,
            libc::S_IFREG => Kind::File,
            _ => Kind::Other,
        };
        Ok(Some((kind, st.st_ino)))
    }

    fn sub(&self, name: &str) -> io::Result<Dir> {
        self.openat(name, libc::O_RDONLY | libc::O_DIRECTORY)
            .map(Dir)
    }

    /// A regular file only. On Linux the name is resolved once with
    /// `O_PATH`, which opens nothing, its type checked on that fd, and the
    /// same inode reopened through `/proc/self/fd`; there is no window for a
    /// device node to be swapped in. Without `/proc` this fails closed.
    #[cfg(target_os = "linux")]
    fn file(&self, name: &str) -> io::Result<File> {
        reopen_regular(self.openat(name, libc::O_PATH)?, name)
    }

    /// A regular file only: checked before the open and again on the fd.
    /// `O_NONBLOCK|O_NOCTTY` limit what a device node swapped in between can
    /// do; Linux closes that window with `O_PATH`.
    #[cfg(not(target_os = "linux"))]
    fn file(&self, name: &str) -> io::Result<File> {
        match self.stat(name)? {
            Some((Kind::File, _)) => {}
            None => return Err(io::Error::from(io::ErrorKind::NotFound)),
            Some(_) => return Err(not_regular(name)),
        }
        let f = self.openat(name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        if !f.metadata()?.is_file() {
            return Err(not_regular(name));
        }
        Ok(f)
    }

    /// Created exclusively and `0600` until the caller sets its final mode.
    fn create(&self, name: &str) -> io::Result<File> {
        self.openat(name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL)
    }

    fn entry(&self, name: &str) -> io::Result<Entry> {
        Ok(match self.stat(name)? {
            None => Entry::Missing,
            Some((Kind::Symlink, _)) => Entry::Symlink,
            Some((Kind::Dir, _)) => Entry::Dir(self.sub(name)?),
            Some((Kind::File, _)) => Entry::File(self.file(name)?),
            Some((Kind::Other, _)) => Entry::Other,
        })
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
        let mut not_utf8 = None;
        loop {
            // SAFETY: `dirp` is valid; the entry is read before the next call.
            let ent = unsafe { libc::readdir(dirp) };
            if ent.is_null() {
                break;
            }
            // SAFETY: readdir returned a valid entry with a NUL-terminated name.
            let raw = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            match raw.to_str() {
                Ok("." | "..") => {}
                Ok(name) => out.push(name.to_string()),
                Err(_) => {
                    not_utf8 = Some(raw.to_string_lossy().into_owned());
                    break;
                }
            }
        }
        // SAFETY: `dirp` came from fdopendir and is closed once.
        unsafe { libc::closedir(dirp) };
        // A lossy name would name a different file, so refuse rather than
        // skip or mangle it.
        if let Some(name) = not_utf8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{name:?} is not a valid UTF-8 name; rename or remove it first"),
            ));
        }
        out.sort();
        Ok(out)
    }
}

/// Refuse to descend past [`MAX_DEPTH`], so a tree the container nests
/// without end cannot exhaust the stack or fds of a root walk.
fn descend(depth: usize, rel: &str) -> Result<usize> {
    if depth >= MAX_DEPTH {
        bail!("{rel} is nested deeper than {MAX_DEPTH} directories; refusing to walk it");
    }
    Ok(depth + 1)
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

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
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

/// Read a whole file, refusing anything over [`FILE_CAP`].
fn read_capped(mut f: File, what: &str) -> Result<Vec<u8>> {
    let len = f.metadata()?.len();
    if len > FILE_CAP {
        bail!("{what} is {len} bytes, over the {FILE_CAP}-byte limit");
    }
    let mut buf = Vec::new();
    Read::by_ref(&mut f)
        .take(FILE_CAP + 1)
        .read_to_end(&mut buf)?;
    if buf.len() as u64 > FILE_CAP {
        bail!("{what} grew past the {FILE_CAP}-byte limit while it was read");
    }
    Ok(buf)
}

fn read_rel(root: &Dir, rel: &str) -> Result<Vec<u8>> {
    read_capped(open_rel(root, rel)?, rel)
}

/// `path`, an `O_PATH` fd, reopened for reading if it is a regular file.
#[cfg(target_os = "linux")]
fn reopen_regular(path: File, name: &str) -> io::Result<File> {
    if !path.metadata()?.is_file() {
        return Err(not_regular(name));
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(format!("/proc/self/fd/{}", path.as_raw_fd()))
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("reopen {name} through /proc/self/fd (is /proc mounted?): {e}"),
            )
        })
}

/// A regular file at an absolute path, never following a final symlink and
/// never opening anything else, as [`Dir::file`] does.
#[cfg(target_os = "linux")]
fn open_regular(path: &Path) -> io::Result<File> {
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    reopen_regular(fd, &path.display().to_string())
}

#[cfg(not(target_os = "linux"))]
fn open_regular(path: &Path) -> io::Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(not_regular(&path.display().to_string()));
    }
    Ok(f)
}

/// A file outside any container-writable tree (the store's slot record,
/// docker's state).
fn read_path(path: &Path) -> Result<Vec<u8>> {
    let f = open_regular(path).with_context(|| format!("open {}", path.display()))?;
    read_capped(f, &path.display().to_string())
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
    /// Read and validate a payload's manifest without checking it against
    /// the backup record; restores use [`verified_manifest`].
    pub fn read(payload: &Path) -> Result<Self> {
        let raw = read_rel(&Dir::open(payload)?, MANIFEST)?;
        Self::parse(&raw, payload)
    }

    /// A manifest names the paths a restore writes as root, so every path
    /// must be a plain relative path, listed once, under a listed directory;
    /// no mode may carry setuid, setgid or sticky bits; and no file may
    /// exceed the read caps.
    fn parse(raw: &[u8], payload: &Path) -> Result<Self> {
        let at = payload.join(MANIFEST).display().to_string();
        let m: Manifest = serde_json::from_slice(raw).with_context(|| format!("parse {at}"))?;
        m.validate(&at)?;
        Ok(m)
    }

    fn validate(&self, at: &str) -> Result<()> {
        let m = self;
        if m.version != MANIFEST_VERSION {
            bail!(
                "{at}: manifest version {} is not {MANIFEST_VERSION}",
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
        let mut total = 0u64;
        for f in &m.files {
            if f.size > FILE_CAP {
                bail!(
                    "manifest gives {:?} {} bytes, over the limit",
                    f.path,
                    f.size
                );
            }
            total += f.size;
        }
        if total > TOTAL_CAP {
            bail!("manifest totals {total} bytes, over the {TOTAL_CAP}-byte limit");
        }
        Ok(())
    }
}

/// What the slot checksum does and does not prove, stated in restore output.
pub const CHECKSUM_SCOPE: &str = "the backup checksum is stored in the backup store beside the backup, so it detects corruption but not tampering by anyone who can write to the store; orca#478 will hold it in orca's database or key it";

/// The payload's manifest, accepted only if it hashes to the checksum the
/// backup record holds for it. The record is `manifest.json` in the slot
/// beside `payload/`; a missing checksum is refused like a wrong one. See
/// [`CHECKSUM_SCOPE`] for what that proves.
pub fn verified_manifest(payload: &Path) -> Result<Manifest> {
    Ok(verified_slot(payload)?.0)
}

/// [`verified_manifest`] and the checksum it matched.
fn verified_slot(payload: &Path) -> Result<(Manifest, String)> {
    let slot = payload
        .parent()
        .ok_or_else(|| anyhow!("{} has no backup slot", payload.display()))?;
    let record: Value = serde_json::from_slice(&read_path(&slot.join(SLOT_MANIFEST))?)
        .with_context(|| format!("parse the backup record in {}", slot.display()))?;
    let Some(want) = record["checksum"].as_str() else {
        bail!(
            "the backup record in {} has no checksum; refusing to restore a backup that cannot be verified",
            slot.display()
        );
    };
    let raw = read_rel(&Dir::open(payload)?, MANIFEST)?;
    let got = format!("sha256:{}", sha256_hex(&raw));
    if want != got {
        bail!(
            "backup checksum mismatch in {}: the record has {want}, the payload manifest hashes to {got}",
            slot.display()
        );
    }
    Ok((Manifest::parse(&raw, payload)?, got))
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
    scan_at(root, "", 0, &mut dirs, &mut files)?;
    dirs.sort();
    files.sort();
    Ok((dirs, files))
}

fn scan_at(
    dir: &Dir,
    prefix: &str,
    depth: usize,
    dirs: &mut Vec<String>,
    files: &mut Vec<String>,
) -> Result<()> {
    for name in dir.names()? {
        if transient(&name) {
            continue;
        }
        let rel = format!("{prefix}{name}");
        match dir.entry(&name)? {
            Entry::Dir(sub) => {
                let depth = descend(depth, &rel)?;
                dirs.push(rel.clone());
                scan_at(&sub, &format!("{rel}/"), depth, dirs, files)?;
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

/// The source as read: directory entries, and each file with its bytes.
struct Snapshot {
    dirs: Vec<DirEntry>,
    files: Vec<(FileEntry, Vec<u8>)>,
}

/// Copy `source` into `payload/files` and write the manifest. Returns the
/// manifest and the exact bytes written for it.
pub fn capture(source: &Path, payload: &Path, instance: &str) -> Result<(Manifest, Vec<u8>)> {
    capture_with(source, payload, instance, &|| {})
}

/// The whole source is read into memory under PBS's config locks, re-stamped
/// and the locks released before anything is written, so PBS is held up only
/// for the reads. A read that raced a change is retried once, then refused.
fn capture_with(
    source: &Path,
    payload: &Path,
    instance: &str,
    after_read: &dyn Fn(),
) -> Result<(Manifest, Vec<u8>)> {
    let src = Dir::open(source)?;
    let snapshot = {
        let _locks = hold_locks(&src)?;
        read_snapshot(&src, after_read).with_context(|| format!("read {}", source.display()))?
    };
    let manifest = Manifest {
        version: MANIFEST_VERSION,
        instance: instance.to_string(),
        source: source.display().to_string(),
        dirs: snapshot.dirs,
        files: snapshot.files.iter().map(|(f, _)| f.clone()).collect(),
    };
    let out = Dir::open(payload)?;
    out.mkdir(FILES_DIR)?;
    let root = out.sub(FILES_DIR)?;
    for d in &manifest.dirs {
        let (parent, name) = parent_of(&root, &d.path)?;
        parent.mkdir(name)?;
    }
    for (f, bytes) in &snapshot.files {
        let (parent, name) = parent_of(&root, &f.path)?;
        let mut to = parent.create(name)?;
        to.write_all(bytes)
            .and_then(|()| to.sync_all())
            .with_context(|| format!("write {}", f.path))?;
    }
    let raw = serde_json::to_vec_pretty(&manifest)?;
    let mut f = out.create(MANIFEST)?;
    f.write_all(&raw)?;
    f.sync_all()?;
    out.0.sync_all()?;
    Ok((manifest, raw))
}

fn read_snapshot(src: &Dir, after_read: &dyn Fn()) -> Result<Snapshot> {
    for _ in 0..2 {
        let (snapshot, before) = read_once(src)?;
        after_read();
        if stamps(src)? == before {
            return Ok(snapshot);
        }
    }
    bail!("it kept changing while it was read; try again")
}

fn read_once(src: &Dir) -> Result<(Snapshot, BTreeMap<String, Stamp>)> {
    let (dir_names, file_names) = scan(src)?;
    let missing = missing_required(&file_names);
    if !missing.is_empty() {
        bail!(
            "not a complete PBS config directory; missing {}",
            missing.join(", ")
        );
    }
    let mut dirs = Vec::with_capacity(dir_names.len());
    for rel in dir_names {
        let meta = open_dir(src, &rel)?.0.metadata()?;
        dirs.push(DirEntry {
            mode: meta.mode() & PERMISSION_BITS,
            uid: meta.uid(),
            gid: meta.gid(),
            path: rel,
        });
    }
    let mut files = Vec::with_capacity(file_names.len());
    let mut before = BTreeMap::new();
    let mut total = 0u64;
    for rel in file_names {
        let from = open_rel(src, &rel)?;
        let meta = from.metadata()?;
        let buf = read_capped(from, &rel)?;
        total += buf.len() as u64;
        if total > TOTAL_CAP {
            bail!("the config is over the {TOTAL_CAP}-byte limit");
        }
        before.insert(rel.clone(), stamp(&meta));
        files.push((
            FileEntry {
                sha256: sha256_hex(&buf),
                size: buf.len() as u64,
                mode: meta.mode() & PERMISSION_BITS,
                uid: meta.uid(),
                gid: meta.gid(),
                path: rel,
            },
            buf,
        ));
    }
    Ok((Snapshot { dirs, files }, before))
}

/// PBS rewrites each config file by atomic rename while holding an exclusive
/// `flock(2)` on its `.lck`/`.lock` sibling: `pbs_config::open_backup_lockfile`
/// calls `proxmox_sys::fs::open_file_locked`, whose `lock_file` uses
/// `nix::fcntl::flock`, with a 10 s default timeout. `File::try_lock_shared`
/// is the same `flock`. Holding all of them shared gives a view consistent
/// across files (`user.cfg` with `token.shadow`). They are taken
/// non-blocking and all-or-nothing, so this never waits while holding one
/// and cannot deadlock with PBS, whose writers wait out the reads inside
/// that timeout. Missing lock files are not created: a root-owned one would
/// lock PBS out.
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
    lock_down_at(&root, "", 0, &mut loose)?;
    Ok((!loose.is_empty()).then(|| {
        format!(
            "target ignored chmod on {} path(s) (e.g. {}); the backup may be readable beyond root",
            loose.len(),
            loose[0]
        )
    }))
}

fn lock_down_at(dir: &Dir, prefix: &str, depth: usize, loose: &mut Vec<String>) -> Result<()> {
    for name in dir.names()? {
        let rel = format!("{prefix}/{name}");
        match dir.entry(&name)? {
            Entry::Dir(sub) => {
                chmod_checked(&sub.0, 0o700, &rel, loose)?;
                lock_down_at(&sub, &rel, descend(depth, &rel)?, loose)?;
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

/// Owner and mode of every restored file and directory against the
/// manifest. A restore never changes the owner of a directory that already
/// existed, so a directory's owner is checked only if it is in `created`.
pub fn verify_meta(dir: &Path, manifest: &Manifest, created: &[String]) -> Vec<String> {
    let root = match Dir::open(dir) {
        Ok(r) => r,
        Err(e) => return vec![format!("{e:#}")],
    };
    let dirs = manifest.dirs.iter().map(|d| {
        let meta = open_dir(&root, &d.path).and_then(|x| Ok(x.0.metadata()?));
        let owned = created.contains(&d.path);
        (&d.path, (d.mode, d.uid, d.gid), owned, meta)
    });
    let files = manifest.files.iter().map(|f| {
        let meta = open_rel(&root, &f.path).and_then(|x| Ok(x.metadata()?));
        (&f.path, (f.mode, f.uid, f.gid), true, meta)
    });
    let mut problems = Vec::new();
    for (path, want, owned, meta) in dirs.chain(files) {
        let Ok(meta) = meta else {
            problems.push(format!("{path}: missing"));
            continue;
        };
        let got = (meta.mode() & PERMISSION_BITS, meta.uid(), meta.gid());
        let differs = if owned { got != want } else { got.0 != want.0 };
        if differs {
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

/// How far a restore got, recorded in its marker before each step it
/// cannot take back unannounced.
#[orca_struct]
#[derive(Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    /// Originals untouched; temp files and created directories may exist.
    Staging,
    /// Originals set aside; some files may already be replaced.
    Swapping,
    /// A swap failed and the originals were being put back.
    RollingBack,
}

/// `.orca-swap-<tag>` at the config root, written before anything else and
/// removed last. Updated by writing `<marker>.next` and renaming it over the
/// marker, so a crash leaves the old or the new state, never a torn one.
#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct SwapMarker {
    phase: Phase,
    files: Vec<MarkedFile>,
    created_dirs: Vec<String>,
    /// Whether recorded owners are applied, as the restore was asked.
    #[serde(default)]
    owners: bool,
    /// What the restore wrote from. Recovery re-reads the manifest from this
    /// slot rather than trusting the copy here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest: Option<Manifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slot_payload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    slot_checksum: Option<String>,
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
/// Ownership is applied to files and to directories this creates; an
/// existing directory keeps its owner. Returns the directories created.
///
/// Every file is checked against the manifest as it is staged, all are
/// fsynced before any is replaced, and the replaced files are hard-linked
/// aside; on any reported error the swap is rolled back. A crash leaves a
/// marker that [`recover`] settles.
pub fn materialize(
    payload: &Path,
    dest: &Path,
    manifest: &Manifest,
    owners: bool,
) -> Result<Vec<String>> {
    let tag = plugin_toolkit::id::new();
    materialize_with(payload, dest, manifest, owners, &tag, &|d, a, b| {
        d.rename(a, b)
    })
}

struct Work<'a> {
    root: Dir,
    tag: &'a str,
    manifest: &'a Manifest,
    slot_payload: String,
    slot_checksum: String,
    owners: bool,
    phase: Phase,
    /// The phase the marker on disk holds.
    recorded: Phase,
    created: Vec<String>,
    staged: Vec<Staged>,
    marker: Option<String>,
    failures: Vec<String>,
    /// The rollback could not be recorded, so the tree is left for
    /// [`recover`] untouched.
    stranded: bool,
}

fn materialize_with(
    payload: &Path,
    dest: &Path,
    manifest: &Manifest,
    owners: bool,
    tag: &str,
    rename: Rename,
) -> Result<Vec<String>> {
    let root = Dir::open(dest)?;
    let left = leftovers(&root)?;
    if !left.is_empty() {
        bail!(
            "an interrupted restore left {} in {}; settle it with pbs.config_recover (action rollback or finish) first",
            left.iter().map(Left::rel).collect::<Vec<_>>().join(", "),
            dest.display()
        );
    }
    let (slotted, slot_checksum) = verified_slot(payload)?;
    if slotted != *manifest {
        bail!(
            "the manifest to restore is not the one in {}",
            payload.display()
        );
    }
    let slot_payload = fs::canonicalize(payload)?
        .to_str()
        .ok_or_else(|| anyhow!("{} is not a UTF-8 path", payload.display()))?
        .to_string();
    let src = Dir::open(payload)?.sub(FILES_DIR)?;
    let mut w = Work {
        root,
        tag,
        manifest,
        slot_payload,
        slot_checksum,
        owners,
        phase: Phase::Staging,
        recorded: Phase::Staging,
        created: Vec::new(),
        staged: Vec::new(),
        marker: None,
        failures: Vec::new(),
        stranded: false,
    };
    let result = w
        .write_marker()
        .and_then(|()| w.make_dirs(manifest))
        .and_then(|()| w.stage(&src, manifest))
        .and_then(|()| w.set_aside())
        .and_then(|()| {
            w.phase = Phase::Swapping;
            w.write_marker()
        })
        .and_then(|()| w.swap(rename));
    match result {
        Ok(()) => {
            w.finish()?;
            Ok(w.created)
        }
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

    fn write_marker(&mut self) -> Result<()> {
        let marker = SwapMarker {
            phase: self.phase,
            files: self
                .staged
                .iter()
                .map(|s| MarkedFile {
                    path: s.rel.clone(),
                    had_prev: s.prev.is_some(),
                })
                .collect(),
            created_dirs: self.created.clone(),
            owners: self.owners,
            manifest: Some(self.manifest.clone()),
            slot_payload: Some(self.slot_payload.clone()),
            slot_checksum: Some(self.slot_checksum.clone()),
        };
        let raw = serde_json::to_vec(&marker)?;
        let name = format!("{SWAP_MARK}{}", self.tag);
        let next = format!("{name}{NEXT_SUFFIX}");
        let mut f = self.root.create(&next)?;
        let written = f
            .write_all(&raw)
            .and_then(|()| f.sync_all())
            .and_then(|()| self.root.rename(&next, &name));
        if let Err(e) = written {
            if let Err(d) = discard(&self.root, &next) {
                tracing::warn!(file = %next, error = %d, "could not remove a failed marker update");
            }
            return Err(e.into());
        }
        self.recorded = self.phase;
        self.marker = Some(name);
        self.root.0.sync_all()?;
        Ok(())
    }

    /// Each directory is recorded in the marker before it is created, so a
    /// crash never leaves one that recovery does not know to remove.
    fn make_dirs(&mut self, manifest: &Manifest) -> Result<()> {
        let mut dirs: Vec<&DirEntry> = manifest.dirs.iter().collect();
        dirs.sort_by_key(|d| d.path.matches('/').count());
        for d in dirs {
            let (parent, name) = parent_of(&self.root, &d.path)?;
            match parent.stat(name)? {
                Some((Kind::Dir, _)) => {}
                None => {
                    self.created.push(d.path.clone());
                    self.write_marker()?;
                    parent.mkdir(name)?;
                    apply_meta(&parent.sub(name)?.0, d.mode, self.owner(d.uid, d.gid))?;
                }
                Some(_) => bail!("{} is a symlink or not a directory", d.path),
            }
        }
        Ok(())
    }

    fn stage(&mut self, src: &Dir, manifest: &Manifest) -> Result<()> {
        for f in &manifest.files {
            let bytes = read_rel(src, &f.path)?;
            if bytes.len() as u64 != f.size || sha256_hex(&bytes) != f.sha256 {
                bail!(
                    "{} in the backup no longer matches its manifest; nothing replaced",
                    f.path
                );
            }
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
            out.write_all(&bytes)
                .with_context(|| format!("stage {}", f.path))?;
            apply_meta(&out, f.mode, self.owner(f.uid, f.gid))
                .with_context(|| format!("stage {}", f.path))?;
            out.sync_all()?;
        }
        self.sync_dirs()
    }

    fn set_aside(&mut self) -> Result<()> {
        for s in &mut self.staged {
            match s.dir.stat(&s.name)? {
                Some((Kind::File, _)) => {
                    let prev = format!(".{}{PREV_MARK}{}", s.name, self.tag);
                    s.dir
                        .link(&s.name, &prev)
                        .with_context(|| format!("set aside {}", s.rel))?;
                    s.prev = Some(prev);
                }
                None => {}
                Some(_) => bail!("{} is a symlink or not a regular file", s.rel),
            }
        }
        self.sync_dirs()
    }

    /// The marker turns to [`Phase::RollingBack`] before the first file is
    /// put back, so recovery after a crash here can only roll back. If that
    /// cannot be recorded nothing is put back: a `finish` over a marker
    /// still saying [`Phase::Swapping`] would leave the put-back files old.
    fn swap(&mut self, rename: Rename) -> Result<()> {
        for i in 0..self.staged.len() {
            let s = &self.staged[i];
            if let Err(e) = rename(&s.dir, &s.tmp, &s.name) {
                let failed = s.rel.clone();
                self.phase = Phase::RollingBack;
                if let Err(m) = self.write_marker() {
                    self.phase = self.recorded;
                    self.stranded = true;
                    // The rename can land before the fsync fails, and
                    // recovery goes by what the marker on disk says.
                    let actions = if self.recorded == Phase::RollingBack {
                        "action rollback; the marker already records the rollback"
                    } else {
                        "action finish or rollback"
                    };
                    return Err(e).with_context(|| {
                        format!(
                            "replace {failed}; could not record the rollback ({m:#}), so nothing was put back; settle it with pbs.config_recover ({actions})"
                        )
                    });
                }
                for s in self.staged[..i].iter_mut().rev() {
                    let back = match &s.prev {
                        Some(prev) => rename(&s.dir, prev, &s.name),
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
    fn finish(&mut self) -> Result<()> {
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
        apply_dir_meta(&self.root, self.manifest, &self.created, self.owners)?;
        self.sync_dirs()
    }

    /// Clean up after a reported error. Returns what could not be undone.
    fn undo(&mut self) -> Vec<String> {
        if self.stranded {
            return Vec::new();
        }
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
            // A directory is recorded before it is made, so it may not exist.
            let removed = parent_of(&self.root, d).and_then(|(p, n)| {
                match p.rmdir(n) {
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                    r => r?,
                }
                Ok(p.0.sync_all()?)
            });
            if let Err(e) = removed {
                left.push(format!("could not remove created directory {d}: {e:#}"));
            }
        }
        // The marker goes only once the rollback is durable.
        if let Err(e) = self.sync_dirs() {
            left.push(format!("fsync after rollback: {e:#}"));
        }
        if left.is_empty() {
            if let Some(m) = self.marker.take() {
                let removed = discard(&self.root, &m).and_then(|()| self.root.0.sync_all());
                if let Err(e) = removed {
                    left.push(format!("could not remove {m}: {e}"));
                }
            }
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

/// Each directory's recorded mode, and its owner too if the restore created
/// it and applies owners.
fn apply_dir_meta(root: &Dir, manifest: &Manifest, created: &[String], owners: bool) -> Result<()> {
    for d in &manifest.dirs {
        let owner = (owners && created.contains(&d.path)).then_some((d.uid, d.gid));
        apply_meta(&open_dir(root, &d.path)?.0, d.mode, owner)
            .with_context(|| format!("files restored, but setting {} failed", d.path))?;
    }
    Ok(())
}

/// A file a restore leaves behind while it runs.
#[derive(Debug, Clone)]
struct Left {
    dir: String,
    name: String,
    kind: Kind,
}

impl Left {
    fn rel(&self) -> String {
        join_rel(&self.dir, &self.name)
    }

    /// The tag of a temp file or set-aside original, and the file it shadows.
    fn shadowing(&self) -> Option<(&str, &str)> {
        let (base, tag) = self
            .name
            .split_once(TEMP_MARK)
            .or_else(|| self.name.split_once(PREV_MARK))?;
        Some((base.strip_prefix('.').unwrap_or(base), tag))
    }

    /// A swap marker's tag; markers count only at the config root.
    fn marker_tag(&self) -> Option<&str> {
        if !self.dir.is_empty() || self.name.ends_with(NEXT_SUFFIX) {
            return None;
        }
        self.name.strip_prefix(SWAP_MARK)
    }
}

fn is_leftover(name: &str) -> bool {
    name.contains(TEMP_MARK) || name.contains(PREV_MARK) || name.starts_with(SWAP_MARK)
}

/// Temp files, set-aside originals and swap markers under `root`, found by
/// name and classified without being opened.
fn leftovers(root: &Dir) -> Result<Vec<Left>> {
    let mut out = Vec::new();
    leftovers_at(root, "", 0, &mut out)?;
    Ok(out)
}

fn leftovers_at(dir: &Dir, rel_dir: &str, depth: usize, out: &mut Vec<Left>) -> Result<()> {
    for name in dir.names()? {
        let Some((kind, _)) = dir.stat(&name)? else {
            continue;
        };
        if is_leftover(&name) {
            out.push(Left {
                dir: rel_dir.to_string(),
                name,
                kind,
            });
        } else if kind == Kind::Dir {
            let rel = join_rel(rel_dir, &name);
            leftovers_at(&dir.sub(&name)?, &rel, descend(depth, &rel)?, out)?;
        }
    }
    Ok(())
}

/// One step of settling an interrupted restore. `dir` is relative to the
/// config dir and `name` a single component, so no step acts through a path.
#[derive(Debug, Clone, PartialEq)]
enum Op {
    Rename {
        dir: String,
        from: String,
        to: String,
    },
    /// Install `file`'s verified bytes as `to`: `from` is read and hashed,
    /// and what was hashed is written to `staging`, a file this step creates
    /// exclusively, which is then renamed into place. Nothing swapped in at
    /// `from` after the check can reach `to`.
    Install {
        dir: String,
        from: String,
        staging: String,
        to: String,
        file: FileEntry,
        owners: bool,
    },
    Chmod {
        dir: String,
        name: String,
        mode: u32,
    },
    Unlink {
        dir: String,
        name: String,
    },
    Rmdir {
        dir: String,
        name: String,
    },
    /// Changes nothing; tells the operator what recovery cannot prove is
    /// safe to remove.
    Keep {
        dir: String,
        name: String,
        why: String,
    },
}

impl Op {
    fn describe(&self) -> String {
        match self {
            Op::Rename { dir, from, to } => {
                format!("rename {} to {}", join_rel(dir, from), join_rel(dir, to))
            }
            Op::Install {
                dir,
                from,
                to,
                file,
                owners,
                ..
            } => format!(
                "install {} from {} once it matches the backup, mode {:o}{}",
                join_rel(dir, to),
                join_rel(dir, from),
                file.mode,
                if *owners {
                    format!(", owner {}:{}", file.uid, file.gid)
                } else {
                    String::new()
                }
            ),
            Op::Chmod { dir, name, mode } => {
                format!("set mode of directory {} to {mode:o}", join_rel(dir, name))
            }
            Op::Unlink { dir, name } => format!("remove {}", join_rel(dir, name)),
            Op::Rmdir { dir, name } => format!("remove directory {}", join_rel(dir, name)),
            Op::Keep { dir, name, why } => format!("leave {}: {why}", join_rel(dir, name)),
        }
    }

    fn dir(&self) -> &str {
        match self {
            Op::Rename { dir, .. }
            | Op::Install { dir, .. }
            | Op::Chmod { dir, .. }
            | Op::Unlink { dir, .. }
            | Op::Rmdir { dir, .. }
            | Op::Keep { dir, .. } => dir,
        }
    }

    /// An install's source bytes, refused unless they hash to the backup.
    fn verified_bytes(&self, root: &Dir) -> Result<Option<Vec<u8>>> {
        let Op::Install {
            dir, from, file, ..
        } = self
        else {
            return Ok(None);
        };
        let bytes = read_capped(open_dir(root, dir)?.file(from)?, from)?;
        if sha256_hex(&bytes) != file.sha256 {
            bail!(
                "{} does not match the backup manifest; not installed",
                join_rel(dir, from)
            );
        }
        Ok(Some(bytes))
    }

    fn apply(&self, root: &Dir) -> Result<()> {
        let bytes = self.verified_bytes(root)?;
        let d = open_dir(root, self.dir())?;
        match self {
            Op::Rename { from, to, .. } => d.rename(from, to)?,
            Op::Install {
                from,
                staging,
                to,
                file,
                owners,
                ..
            } => {
                discard(&d, staging)?;
                let mut out = d.create(staging)?;
                let installed = (|| -> Result<()> {
                    out.write_all(bytes.as_deref().unwrap_or_default())?;
                    apply_meta(&out, file.mode, owners.then_some((file.uid, file.gid)))?;
                    out.sync_all()?;
                    Ok(d.rename(staging, to)?)
                })();
                if let Err(e) = installed {
                    if let Err(x) = discard(&d, staging) {
                        tracing::warn!(file = %staging, error = %x, "could not remove a failed install");
                    }
                    return Err(e);
                }
                discard(&d, from)?;
            }
            Op::Chmod { name, mode, .. } => {
                d.sub(name)?
                    .0
                    .set_permissions(fs::Permissions::from_mode(*mode))?;
            }
            Op::Unlink { name, .. } => discard(&d, name)?,
            Op::Rmdir { name, .. } => match d.rmdir(name) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                r => r?,
            },
            Op::Keep { .. } => {}
        }
        Ok(())
    }
}

fn unlink(dir: &str, name: impl Into<String>) -> Op {
    Op::Unlink {
        dir: dir.to_string(),
        name: name.into(),
    }
}

/// The restore a `finish` completes, for verifying the result once its
/// steps are done.
struct Finishing {
    manifest: Manifest,
    /// The canonical slot payload the marker names.
    slot: PathBuf,
    /// Directories the marker says the restore created that the backup
    /// holds; checked for owner, never chowned.
    created: Vec<String>,
    owners: bool,
}

/// The manifest a `finish` may act on. The marker sits in a volume the
/// container can write, so it is only a pointer: the manifest comes from the
/// backup slot it names, which must lie in a backup store outside
/// `untrusted` (where the container could build a self-consistent fake
/// slot), still verify, belong to `instance`, and match what the marker
/// recorded at restore time byte for byte.
fn finishing_manifest(
    marker: &SwapMarker,
    name: &str,
    instance: &str,
    untrusted: &Path,
) -> Result<(Manifest, PathBuf)> {
    let (Some(payload), Some(checksum), Some(recorded)) = (
        &marker.slot_payload,
        &marker.slot_checksum,
        &marker.manifest,
    ) else {
        bail!("{name} records no backup slot to check the staged files against; only rollback applies");
    };
    let verified = store_payload(payload).and_then(|p| {
        if p.starts_with(fs::canonicalize(untrusted)?) {
            bail!("it lies inside docker's data root, which the container can write");
        }
        Ok((verified_slot(&p)?, p))
    });
    let ((manifest, got), slot) = verified.with_context(|| {
        format!(
            "{name} names the backup at {payload}, which cannot be verified; only rollback applies"
        )
    })?;
    if got != *checksum || serde_json::to_vec(&manifest)? != serde_json::to_vec(recorded)? {
        bail!("{name} does not match the backup at {payload}; only rollback applies");
    }
    if manifest.instance != instance {
        bail!(
            "{name} names a backup of {:?}, not {instance:?}; only rollback applies",
            manifest.instance
        );
    }
    Ok((manifest, slot))
}

/// `finish` acts only on the backup the operator names, and only if it is
/// the one the marker records.
fn match_payload(slot: &Path, payload: Option<&str>) -> Result<()> {
    let Some(payload) = payload else {
        bail!(
            "finish needs --payload naming the backup it completes; the marker records {}",
            slot.display()
        );
    };
    let given = fs::canonicalize(payload).with_context(|| format!("resolve {payload}"))?;
    if given != slot {
        bail!(
            "--payload {payload} is not the backup the interrupted restore used ({}); refusing",
            slot.display()
        );
    }
    Ok(())
}

/// The steps that settle every interrupted restore of `instance` in `dest`.
/// `untrusted` is docker's data root: its volumes and overlay layers are all
/// container-writable, so a backup slot under it is never trusted.
///
/// A marker in [`Phase::Swapping`] can be finished (staged files moved into
/// place) or rolled back (originals put back). [`Phase::Staging`] and
/// [`Phase::RollingBack`] can only be rolled back. Leftovers whose tag has no
/// marker belong to no live operation and are removed either way. Created
/// directories are removed on rollback once empty. `finish` takes one marker
/// at most and installs only bytes that hash to the verified backup.
///
/// The marker is in the container-writable volume, so rollback acts only on
/// names carrying the marker's tag: it never removes a live file on the
/// marker's word alone.
fn recovery(
    dest: &Path,
    instance: &str,
    untrusted: &Path,
    finish: bool,
) -> Result<(Dir, Vec<Op>, Option<Finishing>)> {
    let root = Dir::open(dest)?;
    let left = leftovers(&root)?;
    let stuck: Vec<String> = left
        .iter()
        .filter(|l| !matches!(l.kind, Kind::File | Kind::Symlink))
        .map(Left::rel)
        .collect();
    if !stuck.is_empty() {
        bail!(
            "{} in {} named like restore leftovers but not files; a restore never creates these, so inspect and remove them by hand, then run recovery again",
            stuck.join(", "),
            dest.display()
        );
    }
    let kind_of = |dir: &str, name: &str| {
        left.iter()
            .find(|l| l.dir == dir && l.name == name)
            .map(|l| l.kind)
    };
    let mut ops = Vec::new();
    let mut tags = Vec::new();
    let mut finishing = None;
    for l in &left {
        let Some(tag) = l.marker_tag() else {
            continue;
        };
        let m: SwapMarker = serde_json::from_slice(&read_rel(&root, &l.name)?)
            .with_context(|| format!("parse {}", l.name))?;
        if finish && m.phase != Phase::Swapping {
            bail!(
                "{} records a restore that was {}; only rollback applies",
                l.name,
                match m.phase {
                    Phase::Staging => "still staging",
                    _ => "already rolling back",
                }
            );
        }
        if finish {
            if finishing.is_some() {
                bail!(
                    "{} holds more than one interrupted restore; only rollback applies",
                    dest.display()
                );
            }
            let (manifest, slot) = finishing_manifest(&m, &l.name, instance, untrusted)?;
            let created = m
                .created_dirs
                .iter()
                .filter(|d| manifest.dirs.iter().any(|e| &e.path == *d))
                .cloned()
                .collect();
            finishing = Some(Finishing {
                manifest,
                slot,
                created,
                owners: m.owners,
            });
        }
        for f in &m.files {
            check_rel(&f.path)?;
            let (dir, name) = split_rel(&f.path);
            let tmp = format!(".{name}{TEMP_MARK}{tag}");
            let prev = format!(".{name}{PREV_MARK}{tag}");
            let (tmp_left, prev_kind) = (kind_of(dir, &tmp).is_some(), kind_of(dir, &prev));
            if let Some(fin) = &finishing {
                if tmp_left {
                    let Some(file) = fin.manifest.files.iter().find(|e| e.path == f.path) else {
                        bail!("{} lists {} but the backup does not", l.name, f.path);
                    };
                    ops.push(Op::Install {
                        dir: dir.to_string(),
                        staging: format!("{tmp}.install"),
                        from: tmp,
                        to: name.to_string(),
                        file: file.clone(),
                        owners: fin.owners,
                    });
                }
                if prev_kind.is_some() {
                    ops.push(unlink(dir, prev));
                }
            } else if tmp_left {
                // Never swapped: the original is in place and `prev` is a
                // second link to it.
                ops.push(unlink(dir, tmp));
                if prev_kind.is_some() {
                    ops.push(unlink(dir, prev));
                }
            } else if let Some(kind) = prev_kind {
                if kind != Kind::File {
                    bail!(
                        "{} is a symlink; a restore only sets aside regular files, so inspect and remove it by hand",
                        join_rel(dir, &prev)
                    );
                }
                // Renaming a link onto another link to the same inode does
                // nothing, so an original already back is just unlinked.
                let d = open_dir(&root, dir)?;
                let same = match (d.stat(&prev)?, d.stat(name)?) {
                    (Some((_, a)), Some((_, b))) => a == b,
                    _ => false,
                };
                if same {
                    ops.push(unlink(dir, prev));
                } else {
                    ops.push(Op::Rename {
                        dir: dir.to_string(),
                        from: prev,
                        to: name.to_string(),
                    });
                }
            } else if !f.had_prev
                && open_dir(&root, dir).is_ok_and(|d| d.stat(name).is_ok_and(|s| s.is_some()))
            {
                ops.push(Op::Keep {
                    dir: dir.to_string(),
                    name: name.to_string(),
                    why: "the restore may have added it, but only the marker says so; remove it by hand if it should not be there".to_string(),
                });
            }
        }
        // Leftovers of this tag the file list does not cover: temp files
        // and links from a restore that was still staging.
        for o in &left {
            let listed = o.shadowing().is_some_and(|(base, t)| {
                t == tag && m.files.iter().any(|f| f.path == join_rel(&o.dir, base))
            });
            if !listed && o.shadowing().is_some_and(|(_, t)| t == tag) {
                ops.push(unlink(&o.dir, o.name.clone()));
            }
        }
        if let Some(fin) = &finishing {
            // Owners of directories were set when they were created, before
            // the swap; only modes are re-applied here.
            for d in &fin.manifest.dirs {
                let (dir, name) = split_rel(&d.path);
                let current = open_dir(&root, &d.path)
                    .and_then(|x| Ok(x.0.metadata()?.mode() & PERMISSION_BITS));
                if current.ok() != Some(d.mode) {
                    ops.push(Op::Chmod {
                        dir: dir.to_string(),
                        name: name.to_string(),
                        mode: d.mode,
                    });
                }
            }
        } else {
            for d in m.created_dirs.iter().rev() {
                check_rel(d)?;
                let (dir, name) = split_rel(d);
                ops.push(Op::Rmdir {
                    dir: dir.to_string(),
                    name: name.to_string(),
                });
            }
        }
        ops.push(unlink("", l.name.clone()));
        tags.push(tag);
    }
    for l in &left {
        let owned =
            l.marker_tag().is_some() || l.shadowing().is_some_and(|(_, t)| tags.contains(&t));
        if !owned {
            ops.push(unlink(&l.dir, l.name.clone()));
        }
    }
    Ok((root, ops, finishing))
}

#[derive(Debug)]
struct Recovered {
    steps: Vec<String>,
    /// The backup a finish completed from.
    slot: Option<String>,
    /// Of the finished restore; `None` after a rollback.
    verification: Option<Verification>,
}

/// Apply [`recovery`] and fsync what it touched. A `finish` then verifies
/// the restored config as a restore does.
/// `payload` is required for a finish and must be the marker's slot.
fn recover(
    dest: &Path,
    instance: &str,
    untrusted: &Path,
    finish: bool,
    payload: Option<&str>,
) -> Result<Recovered> {
    let (root, ops, finishing) = recovery(dest, instance, untrusted, finish)?;
    if let Some(f) = &finishing {
        match_payload(&f.slot, payload)?;
    }
    // Every staged file is checked before anything changes, so a mismatch
    // leaves the restore as it was and rollback still has every original.
    for op in &ops {
        op.verified_bytes(&root)?;
    }
    let mut done = Vec::with_capacity(ops.len());
    for op in &ops {
        op.apply(&root)
            .with_context(|| format!("{}; already done: [{}]", op.describe(), done.join(", ")))?;
        done.push(op.describe());
    }
    let mut dirs: Vec<&str> = ops.iter().map(Op::dir).collect();
    dirs.sort();
    dirs.dedup();
    for d in dirs {
        if let Ok(dir) = open_dir(&root, d) {
            dir.0.sync_all()?;
        }
    }
    let slot = finishing.as_ref().map(|f| f.slot.display().to_string());
    let verification = match finishing {
        Some(f) => {
            let mut v = verify(dest, &f.manifest);
            if f.owners {
                v.problems
                    .extend(verify_meta(dest, &f.manifest, &f.created));
            }
            if !v.ok() {
                bail!(
                    "finished ([{}]), but the restored config failed verification: {}",
                    done.join(", "),
                    v.problems.join("; ")
                );
            }
            Some(v)
        }
        None => None,
    };
    Ok(Recovered {
        steps: done,
        slot,
        verification,
    })
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
        let state = read_path(&entry.path().join("config.v2.json"))
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

    /// Refuses an instance name that is not a plain path component.
    pub fn config_dir(&self, instance: &str) -> Result<PathBuf> {
        crate::validate_instance(instance)?;
        Ok(self
            .volume_root
            .join(crate::config_volume(instance))
            .join("_data"))
    }

    /// Docker's data root, holding `volumes/`, `containers/` and the image
    /// layers; all of it is writable from some container.
    fn data_root(&self) -> &Path {
        self.volume_root.parent().unwrap_or(&self.volume_root)
    }

    fn containers_dir(&self) -> PathBuf {
        self.data_root().join("containers")
    }

    fn ensure_stopped(&self, instance: &str) -> Result<()> {
        let data_dir = self.config_dir(instance)?;
        let users = volume_users(
            &self.containers_dir(),
            &crate::config_volume(instance),
            &data_dir,
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
            let Ok(dir) = self.config_dir(instance) else {
                continue;
            };
            if dir.join("authkey.pub").is_file() && dir.join("user.cfg").is_file() {
                out.push(instance.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    fn backup_into(&self, payload_dir: &Path, instance: &str) -> Result<BackupOutcome> {
        let source = self.config_dir(instance)?;
        let (manifest, raw) = capture(&source, payload_dir, instance)?;
        let v = verify(&payload_dir.join(FILES_DIR), &manifest);
        if !v.ok() {
            bail!(
                "the written backup does not match what was read: {}",
                v.problems.join("; ")
            );
        }
        let warning = lock_down(payload_dir)?;
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
        self.ensure_stopped(instance)?;
        let manifest = verified_manifest(payload_dir)?;
        let captured = verify(&payload_dir.join(FILES_DIR), &manifest);
        if !captured.ok() {
            bail!(
                "backup failed verification, nothing restored: {}",
                captured.problems.join("; ")
            );
        }
        let live = self.config_dir(instance)?;
        if !live.is_dir() {
            bail!(
                "{} does not exist; deploy the container first so its config volume exists",
                live.display()
            );
        }
        let created = materialize(payload_dir, &live, &manifest, true)?;
        self.ensure_stopped(instance).context(
            "a container started during the restore; stop it and start it again so PBS loads only the restored config",
        )?;
        let mut restored = verify(&live, &manifest);
        restored
            .problems
            .extend(verify_meta(&live, &manifest, &created));
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
            "[pbs-config] restored {} files; start the container ({CHECKSUM_SCOPE})",
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
        let source = kind.config_dir(&i)?;
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
    /// What the backup checksum this restore checked does and does not prove.
    pub integrity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<ExecutionPlan>,
}

/// Resolve `payload` and require it to be a `pbs-config` slot inside a
/// backup store: `<root>/pbs-config/<instance>/<id>/payload`, where `<root>`
/// holds the store's stage lock and the slot its manifest, both regular
/// files. For `pbs.config_restore` this only catches an admin pointing at
/// the wrong directory. Recovery also uses it on a path read from the
/// container-writable marker; there it is one check of several, and the
/// boundary is the exclusion of docker's data root in `finishing_manifest`.
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
        .filter(|r| open_regular(&r.join(STAGE_LOCK_FILE)).is_ok())
        .ok_or_else(refuse)?;
    let kind_dir = p
        .strip_prefix(root)
        .ok()
        .and_then(|r| r.components().next());
    if kind_dir != Some(std::path::Component::Normal(KIND.as_ref()))
        || open_regular(&slot.join(SLOT_MANIFEST)).is_err()
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
    crate::plan::require_admin("pbs.config_restore", ctx.caller().as_ref())?;
    config_restore(&args, ctx.caller().as_ref())
}

fn config_restore(
    args: &ConfigRestoreArgs,
    caller: Option<&CallerIdentity>,
) -> Result<ConfigRestoreOutput> {
    const TOOL: &str = "pbs.config_restore";
    let payload = store_payload(&args.payload)?;
    let dest = Path::new(&args.dest);
    let manifest = verified_manifest(&payload)?;
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
            integrity: CHECKSUM_SCOPE.to_string(),
            plan: Some(plan),
        });
    }
    plan::require_admin(TOOL, caller)?;
    if !blockers.is_empty() {
        bail!("{TOOL}: refusing: {}", blockers.join("; "));
    }
    fs::DirBuilder::new()
        .mode(0o700)
        .create(dest)
        .with_context(|| format!("create {}", dest.display()))?;
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
        integrity: CHECKSUM_SCOPE.to_string(),
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
    /// For `finish`: the backup payload the interrupted restore used, as the
    /// dry run reports it. Must match the one its marker records.
    #[arg(long)]
    #[serde(default)]
    pub payload: Option<String>,
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
    /// For `finish`: the backup payload the marker records, which
    /// `--payload` must name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slot: Option<String>,
    /// The finished config's verification, as a restore reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
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
    crate::plan::require_admin("pbs.config_recover", ctx.caller().as_ref())?;
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
    let live = kind.config_dir(&args.instance)?;
    let payload = args.payload.as_deref();
    if !args.execute {
        let (_, ops, finishing) = recovery(&live, &args.instance, kind.data_root(), finish)?;
        let slot = finishing.map(|f| f.slot);
        if let (Some(slot), Some(_)) = (&slot, payload) {
            match_payload(slot, payload)?;
        }
        let steps: Vec<String> = ops.iter().map(Op::describe).collect();
        let changes = steps
            .iter()
            .map(|s| PlannedChange::new(s.clone(), args.action.clone()))
            .collect();
        let mut summary = format!("{} {}", args.action, live.display());
        if let Some(slot) = &slot {
            summary.push_str(&format!(" from the backup at {}", slot.display()));
        }
        let plan = ExecutionPlan::generic(TOOL, serde_json::to_value(args)?.into())
            .detailed(summary, changes);
        return Ok(ConfigRecoverOutput {
            dry_run: true,
            steps,
            slot: slot.map(|s| s.display().to_string()),
            verification: None,
            plan: Some(plan),
        });
    }
    plan::require_admin(TOOL, caller)?;
    kind.ensure_stopped(&args.instance)?;
    let done = recover(&live, &args.instance, kind.data_root(), finish, payload)?;
    Ok(ConfigRecoverOutput {
        dry_run: false,
        steps: done.steps,
        slot: done.slot,
        verification: done.verification,
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
        leftovers(&Dir::open(dir).unwrap())
            .unwrap()
            .iter()
            .map(Left::rel)
            .collect()
    }

    /// `<tmp>/slot/payload`, as the store lays a slot out.
    fn slotted() -> (tempfile::TempDir, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let payload = tmp.path().join("slot/payload");
        fs::create_dir_all(&payload).unwrap();
        (tmp, payload)
    }

    /// Write the slot record the store commits, carrying `checksum`.
    fn commit(payload: &Path, checksum: Option<&str>) {
        let record = json!({"id": "20261004-031000", "checksum": checksum});
        fs::write(
            payload.parent().unwrap().join(SLOT_MANIFEST),
            record.to_string(),
        )
        .unwrap();
    }

    /// A backup of `kind`'s `pbs` instance, committed with its checksum.
    fn backed_up(kind: &PbsConfigKind) -> (tempfile::TempDir, PathBuf) {
        let (tmp, payload) = slotted();
        let out = kind.backup_into(&payload, "pbs").unwrap();
        commit(&payload, out.checksum.as_deref());
        (tmp, payload)
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
        let (m, _) = capture(src.path(), out.path(), "pbs").unwrap();
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
        let (m, _) = capture_with(src.path(), out.path(), "pbs", &once).unwrap();
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
        let (m, _) = capture(src.path(), out.path(), "pbs").unwrap();
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
        let (m, _) = capture(src.path(), out.path(), "pbs").unwrap();
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
        let (_slot, payload) = slotted();
        fs::set_permissions(live.join("proxy.key"), fs::Permissions::from_mode(0o640)).unwrap();

        assert_eq!(
            dispatch_kind_op(&kind, OP_INSTANCES, json!({})).unwrap(),
            json!(["pbs"])
        );
        let args = json!({"payload_dir": payload, "instance": "pbs"});
        let outcome = dispatch_kind_op(&kind, OP_BACKUP, args.clone()).unwrap();
        let checksum = outcome["checksum"].as_str().unwrap();
        assert!(checksum.starts_with("sha256:"));
        commit(&payload, Some(checksum));

        // A rebuilt container: fresh identity, no datastores, no tokens, no acme.
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        fs::set_permissions(live.join("proxy.key"), fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_file(live.join("datastore.cfg")).unwrap();
        fs::remove_dir_all(live.join("acme")).unwrap();
        fs::write(live.join("user.cfg"), "user: root@pam\n").unwrap();
        dispatch_kind_op(&kind, OP_RESTORE, args).unwrap();

        let m = Manifest::read(&payload).unwrap();
        let v = verify(&live, &m);
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.datastores, ["willow-primary", "offsite"]);
        assert_eq!(v.tokens, ["root@pam!orca"]);
        assert!(verify_meta(&live, &m, &["acme".to_string()]).is_empty());
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
        let p = verify_meta(&live, &Manifest::read(payload.path()).unwrap(), &[]).join("\n");
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
        let (_slot, payload) = backed_up(&kind);
        fs::write(payload.join("files/user.cfg"), "user: evil@pam\n").unwrap();
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        let err = kind.restore(&payload, "pbs").unwrap_err();
        assert!(err.contains("nothing restored"), "{err}");
        assert_eq!(
            fs::read_to_string(live.join("authkey.key")).unwrap(),
            "fresh\n"
        );
    }

    /// A committed backup slot's payload.
    struct Payload {
        _slot: tempfile::TempDir,
        path: PathBuf,
    }

    impl Payload {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    /// A payload committed to a backup store, and a live dir whose files
    /// all differ from it.
    fn drifted() -> (tempfile::TempDir, Payload, Manifest) {
        let (store, path) = stored();
        let m = Manifest::read(&path).unwrap();
        let live = tempfile::tempdir().unwrap();
        seed(live.path());
        for f in &m.files {
            fs::write(live.path().join(&f.path), "live\n").unwrap();
        }
        (live, Payload { _slot: store, path }, m)
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
        assert!(!all_leftovers(live).iter().any(|l| l.ends_with(NEXT_SUFFIX)));
    }

    #[test]
    fn an_interrupted_restore_blocks_the_next_until_rolled_back() {
        let (live, payload, m) = drifted();
        crash_mid_swap(live.path(), payload.path(), &m);
        let err = materialize(payload.path(), live.path(), &m, false).unwrap_err();
        assert!(format!("{err:#}").contains("pbs.config_recover"), "{err:#}");

        recover(live.path(), "pbs", live.path(), false, None).unwrap();
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
        fs::set_permissions(live.path().join("acme"), fs::Permissions::from_mode(0o700)).unwrap();
        let staged = fs::metadata(live.path().join(".authkey.key.orca-restore-T"))
            .unwrap()
            .ino();
        let (_, ops, _) = recovery(live.path(), "pbs", live.path(), true).unwrap();
        let plan: Vec<String> = ops.iter().map(Op::describe).collect();
        assert!(
            plan.contains(&"set mode of directory acme to 750".to_string()),
            "{plan:?}"
        );
        let slot = payload.path().to_str();
        let v = recover(live.path(), "pbs", live.path(), true, slot)
            .unwrap()
            .verification
            .unwrap();
        assert!(v.ok(), "{:?}", v.problems);
        assert_eq!(v.files_checked, m.files.len());
        assert_all(live.path(), &m, captured_text(payload.path()));
        assert_eq!(mode(&live.path().join("acme")), 0o750);
        // Installed from a copy recovery wrote, never the staged inode.
        assert_ne!(
            fs::metadata(live.path().join("authkey.key")).unwrap().ino(),
            staged
        );
        assert!(all_leftovers(live.path()).is_empty());
    }

    #[test]
    fn finish_names_the_slot_and_needs_it_as_payload() {
        let (tmp, kind, live) = host("pbs");
        container(tmp.path(), "abc", pbs_state(false));
        let (_store, payload) = stored();
        let (_other_store, other) = stored();
        let m = Manifest::read(&payload).unwrap();
        crash_mid_swap(&live, &payload, &m);
        let slot = fs::canonicalize(&payload).unwrap().display().to_string();
        let args = |payload: Option<&Path>, execute| ConfigRecoverArgs {
            instance: "pbs".into(),
            action: "finish".into(),
            payload: payload.map(|p| p.display().to_string()),
            execute,
        };
        let admin = plan::admin();

        let out = config_recover(&kind, &args(None, false), None).unwrap();
        assert_eq!(out.slot.as_deref(), Some(slot.as_str()));
        let plan = serde_json::to_string(&out.plan).unwrap();
        assert!(
            plan.contains(&format!("from the backup at {slot}")),
            "{plan}"
        );

        let err = format!(
            "{:#}",
            config_recover(&kind, &args(None, true), Some(&admin)).unwrap_err()
        );
        assert!(err.contains("finish needs --payload"), "{err}");
        let err = format!(
            "{:#}",
            config_recover(&kind, &args(Some(&other), true), Some(&admin)).unwrap_err()
        );
        assert!(
            err.contains("is not the backup the interrupted restore used"),
            "{err}"
        );
        assert!(!all_leftovers(&live).is_empty());

        let out = config_recover(&kind, &args(Some(&payload), true), Some(&admin)).unwrap();
        assert_eq!(out.slot.as_deref(), Some(slot.as_str()));
        assert!(out.verification.unwrap().ok());
        assert!(all_leftovers(&live).is_empty());
    }

    #[test]
    fn a_failed_install_removes_its_staging_file() {
        let (live, payload, m) = drifted();
        let l = live.path();
        crash_mid_swap(l, payload.path(), &m);
        fs::remove_file(l.join("authkey.key")).unwrap();
        fs::create_dir(l.join("authkey.key")).unwrap();
        fs::write(l.join("authkey.key/x"), "").unwrap();
        let err = recover(l, "pbs", l, true, payload.path().to_str()).unwrap_err();
        assert!(
            format!("{err:#}").contains("install authkey.key"),
            "{err:#}"
        );
        assert!(!l.join(".authkey.key.orca-restore-T.install").exists());
        assert!(l.join(".authkey.key.orca-restore-T").exists());
    }

    fn rewrite_marker(live: &Path, edit: impl FnOnce(&mut SwapMarker)) {
        let path = live.join(format!("{SWAP_MARK}T"));
        let mut marker: SwapMarker = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        edit(&mut marker);
        fs::write(&path, serde_json::to_vec(&marker).unwrap()).unwrap();
    }

    #[test]
    fn finish_refuses_a_planted_marker_with_a_forged_manifest() {
        let (live, payload, m) = drifted();
        let l = live.path();
        crash_mid_swap(l, payload.path(), &m);
        let planted = "planted\n";
        fs::write(l.join(".authkey.key.orca-restore-T"), planted).unwrap();
        rewrite_marker(l, |marker| {
            let manifest = marker.manifest.as_mut().unwrap();
            let f = manifest
                .files
                .iter_mut()
                .find(|f| f.path == "authkey.key")
                .unwrap();
            f.sha256 = sha256_hex(planted.as_bytes());
            f.size = planted.len() as u64;
        });
        let err = format!("{:#}", recover(l, "pbs", l, true, None).unwrap_err());
        assert!(err.contains("does not match the backup"), "{err}");
        assert_eq!(fs::read_to_string(l.join("authkey.key")).unwrap(), "live\n");

        rewrite_marker(l, |marker| marker.slot_payload = None);
        let err = format!("{:#}", recover(l, "pbs", l, true, None).unwrap_err());
        assert!(err.contains("records no backup slot"), "{err}");

        rewrite_marker(l, |marker| {
            marker.slot_payload = Some(l.join("nowhere").display().to_string())
        });
        let err = format!("{:#}", recover(l, "pbs", l, true, None).unwrap_err());
        assert!(err.contains("cannot be verified"), "{err}");

        // A self-consistent slot the container built inside its own volume.
        let fake = stored_at(&l.join("acme"));
        let raw = fs::read(fake.join(MANIFEST)).unwrap();
        rewrite_marker(l, |marker| {
            marker.slot_payload = Some(fs::canonicalize(&fake).unwrap().display().to_string());
            marker.slot_checksum = Some(format!("sha256:{}", sha256_hex(&raw)));
            marker.manifest = Some(Manifest::read(&fake).unwrap());
        });
        let err = format!("{:#}", recover(l, "pbs", l, true, None).unwrap_err());
        assert!(err.contains("inside docker's data root"), "{err}");
        fs::remove_dir_all(l.join("acme/pbs-config")).unwrap();
        fs::remove_file(l.join("acme").join(STAGE_LOCK_FILE)).unwrap();

        recover(l, "pbs", l, false, None).unwrap();
        assert_all(l, &m, |_| "live\n".to_string());
    }

    #[test]
    fn finish_refuses_a_backup_of_another_instance() {
        let (live, payload, m) = drifted();
        crash_mid_swap(live.path(), payload.path(), &m);
        let err = format!(
            "{:#}",
            recover(live.path(), "other", live.path(), true, None).unwrap_err()
        );
        assert!(err.contains("not \"other\""), "{err}");
    }

    #[test]
    fn rollback_never_removes_a_live_file_on_the_marker_alone() {
        let (live, _payload, _m) = drifted();
        let l = live.path();
        let marker = json!({"phase": "swapping",
            "files": [{"path": "authkey.key", "hadPrev": false}], "createdDirs": []});
        fs::write(l.join(".orca-swap-P"), marker.to_string()).unwrap();
        let (_, ops, _) = recovery(l, "pbs", l, false).unwrap();
        assert!(!ops.contains(&unlink("", "authkey.key")), "{ops:?}");
        recover(l, "pbs", l, false, None).unwrap();
        assert_eq!(fs::read_to_string(l.join("authkey.key")).unwrap(), "live\n");
        assert!(all_leftovers(l).is_empty());
    }

    #[test]
    fn rollback_refuses_a_symlinked_set_aside_original() {
        let (live, _payload, _m) = drifted();
        let l = live.path();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("bait"), "bait\n").unwrap();
        let marker = json!({"phase": "swapping",
            "files": [{"path": "user.cfg", "hadPrev": true}], "createdDirs": []});
        fs::write(l.join(".orca-swap-S"), marker.to_string()).unwrap();
        std::os::unix::fs::symlink(outside.path().join("bait"), l.join(".user.cfg.orca-prev-S"))
            .unwrap();
        let err = format!("{:#}", recover(l, "pbs", l, false, None).unwrap_err());
        assert!(err.contains("is a symlink"), "{err}");
        assert_eq!(fs::read_to_string(l.join("user.cfg")).unwrap(), "live\n");
    }

    #[test]
    fn undo_tolerates_a_recorded_directory_never_created() {
        let (live, _payload, m) = drifted();
        let mut w = Work {
            root: Dir::open(live.path()).unwrap(),
            tag: "T",
            manifest: &m,
            slot_payload: String::new(),
            slot_checksum: String::new(),
            owners: false,
            phase: Phase::Staging,
            recorded: Phase::Staging,
            created: vec!["ghost".to_string()],
            staged: Vec::new(),
            marker: None,
            failures: Vec::new(),
            stranded: false,
        };
        assert!(w.undo().is_empty());
    }

    #[test]
    fn walks_refuse_trees_nested_past_the_limit() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let deep = (0..=MAX_DEPTH).fold(src.path().to_path_buf(), |p, i| p.join(format!("d{i}")));
        fs::create_dir_all(&deep).unwrap();
        let out = tempfile::tempdir().unwrap();
        let err = format!("{:#}", capture(src.path(), out.path(), "pbs").unwrap_err());
        assert!(err.contains("nested deeper"), "{err}");
        let err = format!(
            "{:#}",
            leftovers(&Dir::open(src.path()).unwrap()).unwrap_err()
        );
        assert!(err.contains("nested deeper"), "{err}");
        let err = format!("{:#}", lock_down(src.path()).unwrap_err());
        assert!(err.contains("nested deeper"), "{err}");
    }

    #[test]
    fn instance_names_that_could_escape_are_refused() {
        let (tmp, kind, _live) = host("pbs");
        container(tmp.path(), "abc", pbs_state(false));
        for bad in ["../pbs", "..", "a/b", "", ".pbs", "-pbs", "pbs\0", "p b"] {
            assert!(kind.config_dir(bad).is_err(), "{bad:?}");
            assert!(config_backup_detail(&kind, Some(bad)).is_err(), "{bad:?}");
            let payload = tempfile::tempdir().unwrap();
            assert!(kind.backup(payload.path(), bad).is_err(), "{bad:?}");
            assert!(kind.restore(payload.path(), bad).is_err(), "{bad:?}");
            let args = ConfigRecoverArgs {
                instance: bad.into(),
                action: "rollback".into(),
                payload: None,
                execute: false,
            };
            assert!(config_recover(&kind, &args, None).is_err(), "{bad:?}");
        }
        assert!(kind.config_dir("pbs_2-a").is_ok());
    }

    #[test]
    fn finish_refuses_a_staged_file_that_no_longer_matches_the_manifest() {
        let (live, payload, m) = drifted();
        crash_mid_swap(live.path(), payload.path(), &m);
        let staged = live.path().join(".authkey.key.orca-restore-T");
        fs::write(&staged, "planted\n").unwrap();
        let slot = payload.path().to_str();
        let err = format!(
            "{:#}",
            recover(live.path(), "pbs", live.path(), true, slot).unwrap_err()
        );
        assert!(err.contains("does not match the backup manifest"), "{err}");
        assert_eq!(
            fs::read_to_string(live.path().join("authkey.key")).unwrap(),
            "live\n"
        );
        recover(live.path(), "pbs", live.path(), false, None).unwrap();
        assert_all(live.path(), &m, |_| "live\n".to_string());
        assert!(all_leftovers(live.path()).is_empty());
    }

    #[test]
    fn an_unrecorded_rollback_puts_nothing_back_and_can_still_finish() {
        let (live, payload, m) = drifted();
        let l = live.path();
        let calls = std::cell::Cell::new(0);
        // The third rename fails, and a stray `.next` makes the rollback's
        // marker write fail too.
        let flaky = |d: &Dir, a: &str, b: &str| {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                fs::write(l.join(format!("{SWAP_MARK}T{NEXT_SUFFIX}")), "").unwrap();
                return Err(io::Error::other("disk full"));
            }
            d.rename(a, b)
        };
        let err = materialize_with(payload.path(), l, &m, true, "T", &flaky).unwrap_err();
        assert!(
            format!("{err:#}").contains("nothing was put back"),
            "{err:#}"
        );
        let want = captured_text(payload.path());
        for (i, f) in m.files.iter().enumerate() {
            let got = fs::read_to_string(l.join(&f.path)).unwrap();
            if i < 2 {
                assert_eq!(got, want(f), "{}", f.path);
            } else {
                assert_eq!(got, "live\n", "{}", f.path);
            }
        }
        let marker: SwapMarker =
            serde_json::from_slice(&fs::read(l.join(format!("{SWAP_MARK}T"))).unwrap()).unwrap();
        assert_eq!(marker.phase, Phase::Swapping);

        let slot = payload.path().to_str();
        let v = recover(l, "pbs", l, true, slot)
            .unwrap()
            .verification
            .unwrap();
        assert!(v.ok(), "{:?}", v.problems);
        assert_all(l, &m, want);
        assert!(verify_meta(l, &m, &[]).is_empty());
        assert!(all_leftovers(l).is_empty(), "{:?}", all_leftovers(l));
    }

    #[test]
    fn a_failed_marker_write_removes_its_next_file() {
        let (live, _payload, m) = drifted();
        let l = live.path();
        let target = l.join(format!("{SWAP_MARK}T"));
        fs::create_dir(&target).unwrap();
        fs::write(target.join("x"), "").unwrap();
        let mut w = Work {
            root: Dir::open(l).unwrap(),
            tag: "T",
            manifest: &m,
            slot_payload: String::new(),
            slot_checksum: String::new(),
            owners: false,
            phase: Phase::Staging,
            recorded: Phase::Staging,
            created: Vec::new(),
            staged: Vec::new(),
            marker: None,
            failures: Vec::new(),
            stranded: false,
        };
        assert!(w.write_marker().is_err());
        assert!(!l.join(format!("{SWAP_MARK}T{NEXT_SUFFIX}")).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn names_that_are_not_utf8_are_refused() {
        use std::os::unix::ffi::OsStrExt;
        let (live, _payload, _m) = drifted();
        let odd = std::ffi::OsStr::from_bytes(b"bad\xffname");
        fs::write(live.path().join(odd), "x").unwrap();
        let out = tempfile::tempdir().unwrap();
        let err = format!("{:#}", capture(live.path(), out.path(), "pbs").unwrap_err());
        assert!(err.contains("not a valid UTF-8 name"), "{err}");
        let err = format!(
            "{:#}",
            leftovers(&Dir::open(live.path()).unwrap()).unwrap_err()
        );
        assert!(err.contains("not a valid UTF-8 name"), "{err}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn device_nodes_and_fifos_are_refused_without_being_opened() {
        let src = tempfile::tempdir().unwrap();
        let pipe = CString::new(src.path().join("pipe").to_str().unwrap()).unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        let root = Dir::open(src.path()).unwrap();
        // A FIFO opened for reading would block; the O_PATH lookup never opens it.
        let err = root.file("pipe").unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
        fs::write(src.path().join("f"), "x").unwrap();
        let mut buf = String::new();
        root.file("f").unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "x");
    }

    #[test]
    fn leftovers_without_a_marker_are_just_removed() {
        let (live, _payload, m) = drifted();
        fs::write(live.path().join(".user.cfg.orca-restore-X"), "partial").unwrap();
        fs::write(live.path().join("acme/.accounts.orca-prev-X"), "old").unwrap();
        let steps = recover(live.path(), "pbs", live.path(), true, None)
            .unwrap()
            .steps;
        assert_eq!(steps.len(), 2, "{steps:?}");
        assert!(all_leftovers(live.path()).is_empty());
        assert_all(live.path(), &m, |_| "live\n".to_string());
    }

    #[test]
    fn recover_verb_dry_runs_and_needs_admin_and_a_stopped_container() {
        let (tmp, kind, live) = host("pbs");
        let (_slot, payload) = backed_up(&kind);
        let m = Manifest::read(&payload).unwrap();
        crash_mid_swap(&live, &payload, &m);
        let args = |action: &str, execute| ConfigRecoverArgs {
            instance: "pbs".into(),
            action: action.into(),
            payload: None,
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

    #[test]
    fn a_crash_during_rollback_can_only_be_rolled_back() {
        let (live, payload, m) = drifted();
        let calls = std::cell::Cell::new(0);
        let crashing = |d: &Dir, a: &str, b: &str| {
            calls.set(calls.get() + 1);
            match calls.get() {
                3 => Err(io::Error::other("disk full")),
                4 => panic!("simulated crash while putting originals back"),
                _ => d.rename(a, b),
            }
        };
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            materialize_with(payload.path(), live.path(), &m, false, "T", &crashing)
        }));
        assert!(r.is_err());
        let err = format!(
            "{:#}",
            recover(live.path(), "pbs", live.path(), true, None).unwrap_err()
        );
        assert!(err.contains("only rollback"), "{err}");
        recover(live.path(), "pbs", live.path(), false, None).unwrap();
        assert_all(live.path(), &m, |_| "live\n".to_string());
        assert!(all_leftovers(live.path()).is_empty());
    }

    #[test]
    fn a_crash_while_staging_removes_the_directories_it_created() {
        let (live, _payload, _m) = drifted();
        let l = live.path();
        fs::remove_dir_all(l.join("acme")).unwrap();
        let marker = json!({"phase": "staging", "files": [], "createdDirs": ["acme"]});
        fs::write(l.join(".orca-swap-S"), marker.to_string()).unwrap();
        fs::create_dir(l.join("acme")).unwrap();
        fs::write(l.join("acme/.accounts.orca-restore-S"), "partial").unwrap();
        fs::write(l.join(".user.cfg.orca-restore-S"), "partial").unwrap();

        let err = format!("{:#}", recover(l, "pbs", l, true, None).unwrap_err());
        assert!(err.contains("still staging"), "{err}");
        recover(l, "pbs", l, false, None).unwrap();
        assert!(!l.join("acme").exists());
        assert!(all_leftovers(l).is_empty());
        assert_eq!(fs::read_to_string(l.join("user.cfg")).unwrap(), "live\n");
    }

    #[test]
    fn rollback_unlinks_a_set_aside_link_to_the_same_inode() {
        let (live, _payload, _m) = drifted();
        let l = live.path();
        let marker = json!({"phase": "swapping",
            "files": [{"path": "user.cfg", "hadPrev": true}], "createdDirs": []});
        fs::write(l.join(".orca-swap-I"), marker.to_string()).unwrap();
        fs::hard_link(l.join("user.cfg"), l.join(".user.cfg.orca-prev-I")).unwrap();
        let (_, ops, _) = recovery(l, "pbs", l, false).unwrap();
        assert!(
            ops.contains(&unlink("", ".user.cfg.orca-prev-I")),
            "{ops:?}"
        );
        assert!(
            !ops.iter().any(|o| matches!(o, Op::Rename { .. })),
            "{ops:?}"
        );
        recover(l, "pbs", l, false, None).unwrap();
        assert_eq!(fs::read_to_string(l.join("user.cfg")).unwrap(), "live\n");
        assert!(all_leftovers(l).is_empty());
    }

    #[test]
    fn markers_count_only_at_the_config_root() {
        let (live, _payload, _m) = drifted();
        fs::write(live.path().join("acme/.orca-swap-X"), "not a marker").unwrap();
        let (_, ops, _) = recovery(live.path(), "pbs", live.path(), true).unwrap();
        assert_eq!(ops, [unlink("acme", ".orca-swap-X")]);
        recover(live.path(), "pbs", live.path(), true, None).unwrap();
        assert!(all_leftovers(live.path()).is_empty());
    }

    #[test]
    fn a_planted_leftover_directory_is_refused_with_instructions() {
        let (live, payload, m) = drifted();
        fs::create_dir(live.path().join(".user.cfg.orca-prev-Z")).unwrap();
        assert!(materialize(payload.path(), live.path(), &m, false).is_err());
        let err = format!(
            "{:#}",
            recover(live.path(), "pbs", live.path(), false, None).unwrap_err()
        );
        assert!(err.contains("remove them by hand"), "{err}");
    }

    #[test]
    fn staging_refuses_payload_bytes_that_differ_from_the_manifest() {
        let (live, payload, m) = drifted();
        fs::write(payload.path().join("files/user.cfg"), "user: evil@pam\n").unwrap();
        let err = format!(
            "{:#}",
            materialize(payload.path(), live.path(), &m, false).unwrap_err()
        );
        assert!(err.contains("no longer matches"), "{err}");
        assert_all(live.path(), &m, |_| "live\n".to_string());
        assert!(all_leftovers(live.path()).is_empty());
    }

    #[test]
    fn restores_refuse_a_missing_or_wrong_record_checksum() {
        let (_store, payload) = stored();
        let scratch = tempfile::tempdir().unwrap();
        let dest = scratch.path().join("drill");
        commit(&payload, None);
        let err = config_restore(&restore_args(&payload, &dest, false), None).unwrap_err();
        assert!(format!("{err:#}").contains("no checksum"), "{err:#}");
        commit(&payload, Some("sha256:00"));
        let err = config_restore(&restore_args(&payload, &dest, false), None).unwrap_err();
        assert!(format!("{err:#}").contains("checksum mismatch"), "{err:#}");

        let (_tmp, kind, live) = host("pbs");
        let (_slot, payload) = backed_up(&kind);
        commit(&payload, Some("sha256:00"));
        fs::write(live.join("authkey.key"), "fresh\n").unwrap();
        let err = kind.restore(&payload, "pbs").unwrap_err();
        assert!(err.contains("checksum mismatch"), "{err}");
        assert_eq!(
            fs::read_to_string(live.join("authkey.key")).unwrap(),
            "fresh\n"
        );
    }

    #[test]
    fn reads_over_the_cap_are_refused() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        File::create(src.path().join("remote.cfg"))
            .unwrap()
            .set_len(FILE_CAP + 1)
            .unwrap();
        let out = tempfile::tempdir().unwrap();
        let err = format!("{:#}", capture(src.path(), out.path(), "pbs").unwrap_err());
        assert!(err.contains("limit"), "{err}");

        let mut big = entry("user.cfg", 0o600);
        big["size"] = json!(FILE_CAP + 1);
        let dir = manifest_with(json!([]), json!([big]));
        let err = format!("{:#}", Manifest::read(dir.path()).unwrap_err());
        assert!(err.contains("over the limit"), "{err}");
    }

    #[test]
    fn fifos_are_classified_and_never_opened() {
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let pipe = CString::new(src.path().join("pipe").to_str().unwrap()).unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { libc::mkfifo(pipe.as_ptr(), 0o600) }, 0);
        let root = Dir::open(src.path()).unwrap();
        assert_eq!(
            root.stat("pipe").unwrap().map(|(k, _)| k),
            Some(Kind::Other)
        );
        assert!(root.file("pipe").is_err());
        let out = tempfile::tempdir().unwrap();
        let (m, _) = capture(src.path(), out.path(), "pbs").unwrap();
        assert!(!m.files.iter().any(|f| f.path == "pipe"));
    }

    /// A captured backup laid out as the store writes it.
    fn stored() -> (tempfile::TempDir, PathBuf) {
        let store = tempfile::tempdir().unwrap();
        let payload = stored_at(store.path());
        (store, payload)
    }

    fn stored_at(store: &Path) -> PathBuf {
        fs::write(store.join(STAGE_LOCK_FILE), "").unwrap();
        let slot = store.join("pbs-config/pbs/20261004-031000");
        let payload = slot.join("payload");
        fs::create_dir_all(&payload).unwrap();
        let src = tempfile::tempdir().unwrap();
        seed(src.path());
        let (_, raw) = capture(src.path(), &payload, "pbs").unwrap();
        commit(&payload, Some(&format!("sha256:{}", sha256_hex(&raw))));
        payload
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
        assert!(out.integrity.contains("not tampering"), "{}", out.integrity);
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
