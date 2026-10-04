//! Typed PBS API calls. Field names follow the PBS 4.x API schema
//! (kebab-case on the wire); unknown fields are ignored so a newer server
//! does not break decoding.

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::client::{encode, PbsClient};

/// The local node. PBS accepts `localhost` for its own node name.
const NODE: &str = "localhost";

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Datastore {
    pub store: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TypeCounts {
    #[serde(default)]
    pub groups: u64,
    #[serde(default)]
    pub snapshots: u64,
}

#[orca_struct]
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Counts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct: Option<TypeCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<TypeCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<TypeCounts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other: Option<TypeCounts>,
}

/// Garbage-collection result and schedule. `pending_*` are chunks GC found
/// unreferenced but kept because their atime is inside the safety window
/// (24h 5min); they are freed by a later run, not this one.
#[orca_struct]
#[derive(Debug, Clone, Default, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct GcStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_endtime: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upid: Option<String>,
    #[serde(default)]
    pub disk_bytes: u64,
    #[serde(default)]
    pub disk_chunks: u64,
    #[serde(default)]
    pub index_data_bytes: u64,
    #[serde(default)]
    pub index_file_count: u64,
    #[serde(default)]
    pub pending_bytes: u64,
    #[serde(default)]
    pub pending_chunks: u64,
    #[serde(default)]
    pub removed_bytes: u64,
    #[serde(default)]
    pub removed_chunks: u64,
    #[serde(default)]
    pub removed_bad: u64,
    #[serde(default)]
    pub still_bad: u64,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct DatastoreStatus {
    pub total: u64,
    pub used: u64,
    pub avail: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<Counts>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc_status: Option<GcStatus>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct Namespace {
    /// Full path, `""` for the datastore root.
    pub ns: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct Task {
    pub upid: String,
    #[serde(default)]
    pub node: String,
    #[serde(default)]
    pub starttime: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endtime: Option<i64>,
    /// Exit status once finished (`OK`, `WARNINGS: n`, an error); absent while
    /// running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub user: String,
    pub worker_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_id: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct TaskStatus {
    pub upid: String,
    /// `running` or `stopped`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exitstatus: Option<String>,
    #[serde(rename = "type")]
    pub task_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub user: String,
    #[serde(default)]
    pub starttime: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endtime: Option<i64>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct LogLine {
    pub n: u64,
    pub t: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TaskLog {
    pub lines: Vec<LogLine>,
    pub total: u64,
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct TaskFilter {
    pub store: Option<String>,
    pub typefilter: Option<String>,
    pub running: bool,
    pub errors: bool,
    pub since: Option<i64>,
    pub limit: u64,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct UserToken {
    /// Full auth id, `user@realm!name`.
    pub tokenid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    /// UNIX epoch; `0` or absent means never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub userid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expire: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(default)]
    pub tokens: Vec<UserToken>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct AclEntry {
    pub path: String,
    /// User, token (`user@realm!name`) or group id.
    pub ugid: String,
    /// `user` (users and tokens) or `group`.
    pub ugid_type: String,
    pub roleid: String,
    #[serde(default = "yes")]
    pub propagate: bool,
}

fn yes() -> bool {
    true
}

/// Active for `enable`/`expire` as PBS reports them: enabled unless `false`,
/// never expiring when `expire` is 0 or absent.
pub fn is_active(enable: Option<bool>, expire: Option<i64>, now: i64) -> bool {
    enable != Some(false) && expire.is_none_or(|e| e == 0 || e > now)
}

pub async fn users(c: &PbsClient) -> Result<Vec<User>> {
    c.get("/access/users", &[("include_tokens", "true".into())])
        .await
}

pub async fn acls(c: &PbsClient) -> Result<Vec<AclEntry>> {
    c.get("/access/acl", &[]).await
}

fn store_path(store: &str, rest: &str) -> String {
    format!("/admin/datastore/{}{rest}", encode(store))
}

pub async fn datastores(c: &PbsClient) -> Result<Vec<Datastore>> {
    c.get("/admin/datastore", &[]).await
}

pub async fn datastore_status(c: &PbsClient, store: &str) -> Result<DatastoreStatus> {
    c.get(&store_path(store, "/status"), &[("verbose", "true".into())])
        .await
}

pub async fn gc_status(c: &PbsClient, store: &str) -> Result<GcStatus> {
    c.get(&store_path(store, "/gc"), &[]).await
}

pub async fn namespaces(c: &PbsClient, store: &str) -> Result<Vec<Namespace>> {
    c.get(&store_path(store, "/namespace"), &[]).await
}

/// Create `name` under `parent` (`""` = root). Returns nothing useful.
pub async fn create_namespace(c: &PbsClient, store: &str, parent: &str, name: &str) -> Result<()> {
    let mut body = json!({ "name": name });
    if !parent.is_empty() {
        body["parent"] = json!(parent);
    }
    let _: Value = c.post(&store_path(store, "/namespace"), body).await?;
    Ok(())
}

/// Delete `ns`. With `delete_groups` every backup group beneath it goes too;
/// without it PBS refuses a non-empty namespace.
pub async fn delete_namespace(
    c: &PbsClient,
    store: &str,
    ns: &str,
    delete_groups: bool,
) -> Result<()> {
    let _: Value = c
        .delete(
            &store_path(store, "/namespace"),
            &[
                ("ns", ns.to_string()),
                ("delete-groups", delete_groups.to_string()),
            ],
        )
        .await?;
    Ok(())
}

pub async fn tasks(c: &PbsClient, f: &TaskFilter) -> Result<Vec<Task>> {
    let mut q: Vec<(&str, String)> = vec![("limit", f.limit.to_string())];
    if let Some(s) = &f.store {
        q.push(("store", s.clone()));
    }
    if let Some(t) = &f.typefilter {
        q.push(("typefilter", t.clone()));
    }
    if f.running {
        q.push(("running", "true".into()));
    }
    if f.errors {
        q.push(("errors", "true".into()));
    }
    if let Some(s) = f.since {
        q.push(("since", s.to_string()));
    }
    c.get(&format!("/nodes/{NODE}/tasks"), &q).await
}

pub async fn task_status(c: &PbsClient, upid: &str) -> Result<TaskStatus> {
    c.get(&format!("/nodes/{NODE}/tasks/{}/status", encode(upid)), &[])
        .await
}

/// Read the task log through the API. The CLI equivalent
/// (`proxmox-backup-manager task log`) follows a running task and never
/// returns, so it is unusable from a verb.
pub async fn task_log(c: &PbsClient, upid: &str, start: u64, limit: u64) -> Result<TaskLog> {
    let env = c
        .get_envelope(
            &format!("/nodes/{NODE}/tasks/{}/log", encode(upid)),
            &[("start", start.to_string()), ("limit", limit.to_string())],
        )
        .await?;
    let lines: Vec<LogLine> =
        plugin_toolkit::serde_json::from_value(env.data).context("decode PBS task log")?;
    let total = env
        .extra
        .get("total")
        .and_then(Value::as_u64)
        .unwrap_or(lines.len() as u64);
    let active = env.extra.get("active").and_then(Value::as_bool);
    Ok(TaskLog {
        lines,
        total,
        active,
    })
}

/// Namespace paths that must be created, parent first, for `ns` to exist.
pub fn missing_namespace_chain(existing: &[Namespace], ns: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut parent = String::new();
    for part in ns.split('/').filter(|p| !p.is_empty()) {
        let full = if parent.is_empty() {
            part.to_string()
        } else {
            format!("{parent}/{part}")
        };
        if !existing.iter().any(|n| n.ns == full) {
            out.push((parent.clone(), part.to_string()));
        }
        parent = full;
    }
    out
}

/// PBS namespace components: `[A-Za-z0-9_][A-Za-z0-9._-]*`, at most 7 deep.
pub fn validate_ns(ns: &str) -> Result<()> {
    let parts: Vec<&str> = ns.split('/').collect();
    if ns.is_empty() || parts.len() > 7 {
        bail!("namespace '{ns}' must be 1 to 7 '/'-separated components");
    }
    for p in parts {
        let mut chars = p.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
            bail!("namespace component '{p}' in '{ns}' is not a valid PBS name");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod fixtures {
    use plugin_toolkit::serde_json::{self, Value};

    /// The `data` member of a recorded fixture.
    pub fn data(raw: &str) -> Value {
        let v: Value = serde_json::from_str(raw).unwrap();
        v["data"].clone()
    }

    pub const DATASTORE_LIST: &str = include_str!("../tests/fixtures/datastore_list.json");
    pub const DATASTORE_STATUS: &str = include_str!("../tests/fixtures/datastore_status.json");
    pub const GC_STATUS: &str = include_str!("../tests/fixtures/gc_status.json");
    pub const NAMESPACE_LIST: &str = include_str!("../tests/fixtures/namespace_list.json");
    pub const TASK_LIST: &str = include_str!("../tests/fixtures/task_list.json");
    pub const TASK_STATUS: &str = include_str!("../tests/fixtures/task_status.json");
    pub const TASK_LOG: &str = include_str!("../tests/fixtures/task_log.json");
    pub const USERS_LIST: &str = include_str!("../tests/fixtures/users_list.json");
    pub const ACL_LIST: &str = include_str!("../tests/fixtures/acl_list.json");
    pub const TOKEN_CREATE: &str = include_str!("../tests/fixtures/token_create.json");
    pub const TOKEN_REGENERATE: &str = include_str!("../tests/fixtures/token_regenerate.json");
    pub const SYNC_LIST: &str = include_str!("../tests/fixtures/sync_list.json");
    pub const VERIFY_LIST: &str = include_str!("../tests/fixtures/verify_list.json");
    pub const GROUPS_LIST: &str = include_str!("../tests/fixtures/groups_list.json");
    pub const SNAPSHOTS_LIST: &str = include_str!("../tests/fixtures/snapshots_list.json");
    pub const PRUNE_DRY_RUN: &str = include_str!("../tests/fixtures/prune_dry_run.json");
    pub const GROUP_DELETE: &str = include_str!("../tests/fixtures/group_delete.json");
    pub const NODE_TIME: &str = include_str!("../tests/fixtures/node_time.json");
}

#[cfg(test)]
mod tests {
    use super::fixtures::*;
    use super::*;
    use crate::client::mock::MockTransport;
    use crate::client::Method;

    #[tokio::test]
    async fn decodes_datastore_list_and_status() {
        let m = MockTransport::new();
        m.on(Method::Get, "/admin/datastore", 200, DATASTORE_LIST);
        m.on(
            Method::Get,
            "/admin/datastore/main/status",
            200,
            DATASTORE_STATUS,
        );
        let c = m.client();
        let stores = datastores(&c).await.unwrap();
        assert_eq!(stores[0].store, "main");
        assert_eq!(stores[1].comment, None);
        let st = datastore_status(&c, "main").await.unwrap();
        assert_eq!(st.counts.unwrap().vm.unwrap().groups, 3);
        assert_eq!(st.gc_status.unwrap().pending_chunks, 3);
        assert_eq!(m.log()[1], "GET /admin/datastore/main/status?verbose=true");
    }

    #[tokio::test]
    async fn decodes_gc_and_namespaces() {
        let m = MockTransport::new();
        m.on(Method::Get, "/admin/datastore/main/gc", 200, GC_STATUS);
        m.on(
            Method::Get,
            "/admin/datastore/main/namespace",
            200,
            NAMESPACE_LIST,
        );
        let c = m.client();
        let gc = gc_status(&c, "main").await.unwrap();
        assert_eq!(gc.schedule.as_deref(), Some("daily"));
        assert_eq!(gc.pending_bytes, 7_340_032);
        let ns = namespaces(&c, "main").await.unwrap();
        assert_eq!(ns.len(), 4);
    }

    #[tokio::test]
    async fn decodes_tasks_status_and_log_with_encoded_upid() {
        let m = MockTransport::new();
        m.on(Method::Get, "/nodes/localhost/tasks", 200, TASK_LIST);
        let upid = "UPID:pbs:000001AB:00002F10:00000004:66FF0000:garbage_collection:main:root@pam:";
        let enc = encode(upid);
        m.on(
            Method::Get,
            &format!("/nodes/localhost/tasks/{enc}/status"),
            200,
            TASK_STATUS,
        );
        m.on(
            Method::Get,
            &format!("/nodes/localhost/tasks/{enc}/log"),
            200,
            TASK_LOG,
        );
        let c = m.client();
        let ts = tasks(
            &c,
            &TaskFilter {
                limit: 10,
                store: Some("main".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(ts.len(), 2);
        assert_eq!(ts[1].status, None);
        assert!(m.log()[0].contains("limit=10") && m.log()[0].contains("store=main"));
        assert_eq!(
            task_status(&c, upid).await.unwrap().exitstatus.as_deref(),
            Some("OK")
        );
        let log = task_log(&c, upid, 0, 50).await.unwrap();
        assert_eq!(log.total, 3);
        assert_eq!(log.lines[2].t, "TASK OK");
        assert_eq!(log.active, Some(false));
    }

    #[test]
    fn namespace_chain_creates_only_missing_parents_first() {
        let existing: Vec<Namespace> =
            plugin_toolkit::serde_json::from_value(data(NAMESPACE_LIST)).unwrap();
        assert_eq!(
            missing_namespace_chain(&existing, "hosts/willow"),
            vec![("hosts".to_string(), "willow".to_string())]
        );
        assert_eq!(
            missing_namespace_chain(&[], "a/b"),
            vec![(String::new(), "a".into()), ("a".into(), "b".into())]
        );
        assert!(missing_namespace_chain(&existing, "hosts/freyr").is_empty());
    }

    #[tokio::test]
    async fn decodes_users_with_tokens_and_acls() {
        let m = MockTransport::new();
        m.on(Method::Get, "/access/users", 200, USERS_LIST);
        m.on(Method::Get, "/access/acl", 200, ACL_LIST);
        let c = m.client();
        let us = users(&c).await.unwrap();
        assert_eq!(us[1].tokens[0].tokenid, "freyr@pbs!backup");
        assert!(us[2].tokens.is_empty());
        assert_eq!(m.log()[0], "GET /access/users?include_tokens=true");
        let a = acls(&c).await.unwrap();
        assert_eq!(a.len(), 7);
        assert!(a.iter().all(|e| e.propagate));
    }

    #[test]
    fn activity_follows_enable_and_expiry() {
        assert!(is_active(None, None, 100));
        assert!(is_active(Some(true), Some(0), 100));
        assert!(is_active(Some(true), Some(200), 100));
        assert!(!is_active(Some(true), Some(50), 100));
        assert!(!is_active(Some(false), None, 100));
    }

    #[test]
    fn namespace_names_are_validated() {
        assert!(validate_ns("hosts/freyr").is_ok());
        assert!(validate_ns("").is_err());
        assert!(validate_ns("hosts/../x").is_err());
        assert!(validate_ns("a/b/c/d/e/f/g/h").is_err());
        assert!(validate_ns("-bad").is_err());
    }
}
