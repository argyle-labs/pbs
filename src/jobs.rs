//! `pbs.sync_job.*` and `pbs.verify_job.*`: list, create, update, run.
//!
//! Both job types share one shape — a config section under `/config/<kind>`
//! and a status view plus `run` under `/admin/<kind>` — so one implementation
//! serves both, parameterised by [`Kind`].

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value};

use crate::client::{encode, PbsClient};
use crate::endpoint;
use crate::plan::{self, ApiCall, Change, Step};
use crate::times::{self, When, Zones};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Sync,
    Verify,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Sync => "sync",
            Self::Verify => "verify",
        }
    }

    fn config_path(self) -> String {
        format!("/config/{}", self.name())
    }

    fn admin_path(self) -> String {
        format!("/admin/{}", self.name())
    }

    fn list_query(self, store: Option<&str>) -> Vec<(&'static str, String)> {
        let mut q = Vec::new();
        if self == Self::Sync {
            // The API lists only pull jobs unless asked for both directions.
            q.push(("sync-direction", "all".to_string()));
        }
        if let Some(s) = store {
            q.push(("store", s.to_string()));
        }
        q
    }
}

/// Status keys `/admin/<kind>` adds next to the job config.
const STATUS_KEYS: [&str; 4] = [
    "next-run",
    "last-run-endtime",
    "last-run-state",
    "last-run-upid",
];

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct JobView {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
    /// Calendar event, evaluated in `scheduleZone`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    pub schedule_zone: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run: Option<When>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<When>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_upid: Option<String>,
    /// The job's configuration as PBS reports it (kebab-case keys).
    pub config: Map<String, Value>,
}

pub fn view(raw: &Value, zone: &str, zones: Zones) -> Option<JobView> {
    let obj = raw.as_object()?;
    let s = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_string);
    let t = |k: &str| {
        obj.get(k)
            .and_then(Value::as_i64)
            .map(|e| When::new(e, zones))
    };
    let config = obj
        .iter()
        .filter(|(k, _)| !STATUS_KEYS.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Some(JobView {
        id: s("id")?,
        store: s("store"),
        schedule: s("schedule"),
        schedule_zone: zone.to_string(),
        next_run: t("next-run"),
        last_run: t("last-run-endtime"),
        last_run_state: s("last-run-state"),
        last_run_upid: s("last-run-upid"),
        config,
    })
}

pub async fn raw_jobs(c: &PbsClient, kind: Kind, store: Option<&str>) -> Result<Vec<Value>> {
    c.get(&kind.admin_path(), &kind.list_query(store)).await
}

async fn find_job(c: &PbsClient, kind: Kind, id: &str) -> Result<Option<Value>> {
    Ok(raw_jobs(c, kind, None)
        .await?
        .into_iter()
        .find(|j| j.get("id").and_then(Value::as_str) == Some(id)))
}

/// The section's config digest, echoed on update so PBS refuses the write if
/// the job changed since it was read.
async fn config_digest(c: &PbsClient, kind: Kind, id: &str) -> Result<Option<String>> {
    let env = c
        .get_envelope(&format!("{}/{}", kind.config_path(), encode(id)), &[])
        .await?;
    Ok(env
        .extra
        .get("digest")
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// Field changes `desired` makes over `current`, as `(key, old, new)`.
pub fn diff_fields(
    current: &Map<String, Value>,
    desired: &Map<String, Value>,
) -> Vec<(String, Option<Value>, Value)> {
    desired
        .iter()
        .filter(|(k, v)| current.get(*k) != Some(*v))
        .map(|(k, v)| (k.clone(), current.get(k).cloned(), v.clone()))
        .collect()
}

pub fn create_steps(
    kind: Kind,
    existing: Option<&Value>,
    id: &str,
    fields: Map<String, Value>,
) -> Result<Vec<Step>> {
    if existing.is_some() {
        bail!(
            "{} job '{id}' already exists; use pbs.{}_job.update",
            kind.name(),
            kind.name()
        );
    }
    let mut body = fields;
    body.insert("id".into(), json!(id));
    let detail: Vec<String> = body.iter().map(|(k, v)| format!("{k}={v}")).collect();
    Ok(vec![Step::new(
        format!("{} job {id}", kind.name()),
        "create-job",
        ApiCall::Post {
            path: kind.config_path(),
            body: Value::Object(body),
        },
    )
    .detail(detail.join(", "))])
}

pub fn update_steps(
    kind: Kind,
    existing: Option<&Value>,
    id: &str,
    fields: Map<String, Value>,
    clear: &[String],
    digest: Option<&str>,
) -> Result<Vec<Step>> {
    let current = existing
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("no {} job '{id}'", kind.name()))?;
    let changes = diff_fields(current, &fields);
    let clear: Vec<&String> = clear.iter().filter(|k| current.contains_key(*k)).collect();
    if changes.is_empty() && clear.is_empty() {
        return Ok(Vec::new());
    }
    let mut body = Map::new();
    let mut detail = Vec::new();
    for (k, old, new) in changes {
        detail.push(format!(
            "{k}: {} -> {new}",
            old.map_or("unset".to_string(), |o| o.to_string())
        ));
        body.insert(k, new);
    }
    if !clear.is_empty() {
        detail.push(format!(
            "clear {}",
            clear
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        body.insert("delete".into(), json!(clear));
    }
    if let Some(d) = digest {
        body.insert("digest".into(), json!(d));
    }
    Ok(vec![Step::new(
        format!("{} job {id}", kind.name()),
        "update-job",
        ApiCall::Put {
            path: format!("{}/{}", kind.config_path(), encode(id)),
            body: Value::Object(body),
        },
    )
    .detail(detail.join("; "))])
}

pub fn run_steps(kind: Kind, existing: Option<&Value>, id: &str) -> Result<Vec<Step>> {
    if existing.is_none() {
        bail!("no {} job '{id}'", kind.name());
    }
    Ok(vec![Step::new(
        format!("{} job {id}", kind.name()),
        "run-job",
        ApiCall::Post {
            path: format!("{}/{}/run", kind.admin_path(), encode(id)),
            body: json!({}),
        },
    )
    .detail("starts a task; follow it with pbs.task.detail")])
}

/// Insert each `Some` value under its kebab-case PBS key.
fn put<T: Serialize>(m: &mut Map<String, Value>, key: &str, v: &Option<T>) {
    if let Some(v) = v
        .as_ref()
        .and_then(|v| plugin_toolkit::serde_json::to_value(v).ok())
    {
        m.insert(key.to_string(), v);
    }
}

fn offset(s: &Option<String>) -> Result<Option<i32>> {
    s.as_deref().map(times::parse_offset).transpose()
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct JobListOutput {
    /// Zone PBS evaluates schedules in.
    pub server_timezone: String,
    pub jobs: Vec<JobView>,
}

async fn list(
    kind: Kind,
    endpoint: Option<&str>,
    store: Option<&str>,
    utc_offset: &Option<String>,
) -> Result<JobListOutput> {
    let off = offset(utc_offset)?;
    let c = endpoint::connect(endpoint).await?;
    list_with(&c, kind, store, off).await
}

async fn list_with(
    c: &PbsClient,
    kind: Kind,
    store: Option<&str>,
    off: Option<i32>,
) -> Result<JobListOutput> {
    let (zone, server) = times::server_clock(c).await;
    let zones = Zones { server, local: off };
    let jobs = raw_jobs(c, kind, store)
        .await?
        .iter()
        .filter_map(|j| view(j, &zone, zones))
        .collect();
    Ok(JobListOutput {
        server_timezone: zone,
        jobs,
    })
}

#[allow(clippy::too_many_arguments)]
async fn mutate<A: Serialize>(
    tool: &str,
    kind: Kind,
    args: &A,
    endpoint: Option<&str>,
    id: &str,
    execute: bool,
    ctx: &ToolCtx,
    with_digest: bool,
    build: impl FnOnce(Option<&Value>, Option<&str>) -> Result<Vec<Step>>,
) -> Result<Change> {
    let c = endpoint::connect(endpoint).await?;
    let existing = find_job(&c, kind, id).await?;
    let digest = match (&existing, with_digest) {
        (Some(_), true) => config_digest(&c, kind, id).await?,
        _ => None,
    };
    let steps = build(existing.as_ref(), digest.as_deref())?;
    let summary = format!("{} job {id}", kind.name());
    plan::plan_or_apply(
        tool,
        args,
        execute,
        ctx.caller().as_ref(),
        &c,
        summary,
        steps,
        vec![],
        None,
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.sync_job.*
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct JobListArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Only jobs for this datastore.
    #[arg(long)]
    #[serde(default)]
    pub datastore: Option<String>,
    /// Render local times at this offset (`-06:00`) instead of the orca
    /// host's zone.
    #[arg(long)]
    #[serde(default)]
    pub utc_offset: Option<String>,
}

/// Sync jobs (pull and push) with next/last run in UTC and local time.
#[orca_tool(domain = "pbs", verb = "sync_job.list", role = "read")]
pub async fn pbs_sync_job_list(args: JobListArgs, _ctx: &ToolCtx) -> Result<JobListOutput> {
    list(
        Kind::Sync,
        args.endpoint.as_deref(),
        args.datastore.as_deref(),
        &args.utc_offset,
    )
    .await
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct SyncJobFields {
    /// Local datastore.
    #[arg(long)]
    #[serde(default)]
    pub store: Option<String>,
    /// Remote id; omit for a sync between local datastores.
    #[arg(long)]
    #[serde(default)]
    pub remote: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub remote_store: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub ns: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub remote_ns: Option<String>,
    /// Calendar event in the server's zone, e.g. `05:30` or `daily`.
    #[arg(long)]
    #[serde(default)]
    pub schedule: Option<String>,
    /// `pull` or `push`.
    #[arg(long)]
    #[serde(default)]
    pub sync_direction: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub remove_vanished: Option<bool>,
    #[arg(long)]
    #[serde(default)]
    pub max_depth: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub transfer_last: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub verified_only: Option<bool>,
    #[arg(long)]
    #[serde(default)]
    pub owner: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub comment: Option<String>,
    /// Group filter (`type:vm`, `group:vm/111`, `regex:…`). Repeatable;
    /// replaces the whole list.
    #[arg(long = "group-filter")]
    #[serde(default)]
    pub group_filter: Vec<String>,
}

impl SyncJobFields {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        put(&mut m, "store", &self.store);
        put(&mut m, "remote", &self.remote);
        put(&mut m, "remote-store", &self.remote_store);
        put(&mut m, "ns", &self.ns);
        put(&mut m, "remote-ns", &self.remote_ns);
        put(&mut m, "schedule", &self.schedule);
        put(&mut m, "sync-direction", &self.sync_direction);
        put(&mut m, "remove-vanished", &self.remove_vanished);
        put(&mut m, "max-depth", &self.max_depth);
        put(&mut m, "transfer-last", &self.transfer_last);
        put(&mut m, "verified-only", &self.verified_only);
        put(&mut m, "owner", &self.owner);
        put(&mut m, "comment", &self.comment);
        if !self.group_filter.is_empty() {
            m.insert("group-filter".into(), json!(self.group_filter));
        }
        m
    }
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct SyncJobCreateArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub id: String,
    #[command(flatten)]
    #[serde(flatten)]
    pub fields: SyncJobFields,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Create a sync job. Requires `store` and `remote_store`. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "sync_job.create",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_sync_job_create(args: SyncJobCreateArgs, ctx: &ToolCtx) -> Result<Change> {
    if args.fields.store.is_none() || args.fields.remote_store.is_none() {
        bail!("pbs.sync_job.create needs store and remote_store");
    }
    let fields = args.fields.to_map();
    mutate(
        "pbs.sync_job.create",
        Kind::Sync,
        &args,
        args.endpoint.as_deref(),
        &args.id,
        args.execute,
        ctx,
        false,
        |e, _| create_steps(Kind::Sync, e, &args.id, fields),
    )
    .await
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct SyncJobUpdateArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub id: String,
    #[command(flatten)]
    #[serde(flatten)]
    pub fields: SyncJobFields,
    /// PBS keys to unset (kebab-case, e.g. `schedule`, `transfer-last`).
    #[arg(long = "clear")]
    #[serde(default)]
    pub clear: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Change a sync job; only fields that differ are sent. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "sync_job.update",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_sync_job_update(args: SyncJobUpdateArgs, ctx: &ToolCtx) -> Result<Change> {
    let fields = args.fields.to_map();
    mutate(
        "pbs.sync_job.update",
        Kind::Sync,
        &args,
        args.endpoint.as_deref(),
        &args.id,
        args.execute,
        ctx,
        true,
        |e, d| update_steps(Kind::Sync, e, &args.id, fields, &args.clear, d),
    )
    .await
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct JobRunArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub id: String,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Start a sync job now. Returns the task UPID on execute.
#[orca_tool(
    domain = "pbs",
    verb = "sync_job.run",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_sync_job_run(args: JobRunArgs, ctx: &ToolCtx) -> Result<Change> {
    mutate(
        "pbs.sync_job.run",
        Kind::Sync,
        &args,
        args.endpoint.as_deref(),
        &args.id,
        args.execute,
        ctx,
        false,
        |e, _| run_steps(Kind::Sync, e, &args.id),
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.verify_job.*
// ═══════════════════════════════════════════════════════════════════════════

/// Verify jobs with next/last run in UTC and local time.
#[orca_tool(domain = "pbs", verb = "verify_job.list", role = "read")]
pub async fn pbs_verify_job_list(args: JobListArgs, _ctx: &ToolCtx) -> Result<JobListOutput> {
    list(
        Kind::Verify,
        args.endpoint.as_deref(),
        args.datastore.as_deref(),
        &args.utc_offset,
    )
    .await
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct VerifyJobFields {
    #[arg(long)]
    #[serde(default)]
    pub store: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub ns: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub schedule: Option<String>,
    /// Skip snapshots whose last verification passed and is not outdated.
    #[arg(long)]
    #[serde(default)]
    pub ignore_verified: Option<bool>,
    /// Days after which a passed verification counts as outdated.
    #[arg(long)]
    #[serde(default)]
    pub outdated_after: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub max_depth: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub read_threads: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub verify_threads: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub comment: Option<String>,
}

impl VerifyJobFields {
    pub fn to_map(&self) -> Map<String, Value> {
        let mut m = Map::new();
        put(&mut m, "store", &self.store);
        put(&mut m, "ns", &self.ns);
        put(&mut m, "schedule", &self.schedule);
        put(&mut m, "ignore-verified", &self.ignore_verified);
        put(&mut m, "outdated-after", &self.outdated_after);
        put(&mut m, "max-depth", &self.max_depth);
        put(&mut m, "read-threads", &self.read_threads);
        put(&mut m, "verify-threads", &self.verify_threads);
        put(&mut m, "comment", &self.comment);
        m
    }
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct VerifyJobCreateArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub id: String,
    #[command(flatten)]
    #[serde(flatten)]
    pub fields: VerifyJobFields,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Create a verify job. Requires `store`. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "verify_job.create",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_verify_job_create(args: VerifyJobCreateArgs, ctx: &ToolCtx) -> Result<Change> {
    if args.fields.store.is_none() {
        bail!("pbs.verify_job.create needs store");
    }
    let fields = args.fields.to_map();
    mutate(
        "pbs.verify_job.create",
        Kind::Verify,
        &args,
        args.endpoint.as_deref(),
        &args.id,
        args.execute,
        ctx,
        false,
        |e, _| create_steps(Kind::Verify, e, &args.id, fields),
    )
    .await
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct VerifyJobUpdateArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub id: String,
    #[command(flatten)]
    #[serde(flatten)]
    pub fields: VerifyJobFields,
    /// PBS keys to unset (kebab-case).
    #[arg(long = "clear")]
    #[serde(default)]
    pub clear: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Change a verify job; only fields that differ are sent. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "verify_job.update",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_verify_job_update(args: VerifyJobUpdateArgs, ctx: &ToolCtx) -> Result<Change> {
    let fields = args.fields.to_map();
    mutate(
        "pbs.verify_job.update",
        Kind::Verify,
        &args,
        args.endpoint.as_deref(),
        &args.id,
        args.execute,
        ctx,
        true,
        |e, d| update_steps(Kind::Verify, e, &args.id, fields, &args.clear, d),
    )
    .await
}

/// Start a verify job now. Returns the task UPID on execute.
#[orca_tool(
    domain = "pbs",
    verb = "verify_job.run",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_verify_job_run(args: JobRunArgs, ctx: &ToolCtx) -> Result<Change> {
    mutate(
        "pbs.verify_job.run",
        Kind::Verify,
        &args,
        args.endpoint.as_deref(),
        &args.id,
        args.execute,
        ctx,
        false,
        |e, _| run_steps(Kind::Verify, e, &args.id),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::fixtures::*;
    use crate::client::mock::MockTransport;
    use crate::client::Method;

    fn sync_job() -> Value {
        data(SYNC_LIST)[0].clone()
    }

    #[tokio::test]
    async fn list_shows_schedule_zone_and_both_times() {
        let m = MockTransport::new();
        m.on(Method::Get, "/admin/sync", 200, SYNC_LIST);
        m.on(Method::Get, "/nodes/localhost/time", 200, NODE_TIME);
        let out = list_with(&m.client(), Kind::Sync, Some("archive"), Some(-6 * 3600))
            .await
            .unwrap();
        assert_eq!(out.server_timezone, "UTC");
        let j = &out.jobs[0];
        assert_eq!(j.schedule.as_deref(), Some("05:30"));
        let next = j.next_run.as_ref().unwrap();
        assert_eq!(next.utc, "2026-10-04 05:30:00 +00:00");
        assert_eq!(next.local.as_deref(), Some("2026-10-03 23:30:00 -06:00"));
        assert_eq!(next.server.as_deref(), Some("2026-10-04 05:30:00 +00:00"));
        assert!(!j.config.contains_key("next-run"));
        assert!(m.log()[1].contains("sync-direction=all") && m.log()[1].contains("store=archive"));
    }

    #[test]
    fn create_refuses_an_existing_id_and_sends_kebab_keys() {
        let job = sync_job();
        assert!(create_steps(Kind::Sync, Some(&job), "willow-to-maple", Map::new()).is_err());
        let fields = SyncJobFields {
            store: Some("archive".into()),
            remote_store: Some("main".into()),
            schedule: Some("05:30".into()),
            remove_vanished: Some(false),
            group_filter: vec!["type:host".into()],
            ..Default::default()
        };
        let steps = create_steps(Kind::Sync, None, "j2", fields.to_map()).unwrap();
        assert_eq!(
            steps[0].call,
            ApiCall::Post {
                path: "/config/sync".into(),
                body: json!({
                    "id": "j2",
                    "store": "archive",
                    "remote-store": "main",
                    "schedule": "05:30",
                    "remove-vanished": false,
                    "group-filter": ["type:host"]
                }),
            }
        );
    }

    #[test]
    fn update_sends_only_changed_fields_and_is_a_noop_when_equal() {
        let job = sync_job();
        let same = SyncJobFields {
            schedule: Some("05:30".into()),
            ..Default::default()
        };
        assert!(update_steps(
            Kind::Sync,
            Some(&job),
            "willow-to-maple",
            same.to_map(),
            &[],
            Some("d1")
        )
        .unwrap()
        .is_empty());
        let changed = SyncJobFields {
            schedule: Some("04:00".into()),
            store: Some("archive".into()),
            ..Default::default()
        };
        let steps = update_steps(
            Kind::Sync,
            Some(&job),
            "willow-to-maple",
            changed.to_map(),
            &["comment".into(), "transfer-last".into()],
            Some("d1"),
        )
        .unwrap();
        assert_eq!(
            steps[0].call,
            ApiCall::Put {
                path: "/config/sync/willow-to-maple".into(),
                body: json!({"schedule": "04:00", "delete": ["comment"], "digest": "d1"}),
            }
        );
        assert!(steps[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("schedule: \"05:30\" -> \"04:00\""));
        assert!(update_steps(Kind::Sync, None, "nope", Map::new(), &[], None).is_err());
    }

    #[test]
    fn run_targets_the_admin_path() {
        let job = sync_job();
        let steps = run_steps(Kind::Sync, Some(&job), "willow-to-maple").unwrap();
        assert_eq!(
            steps[0].call,
            ApiCall::Post {
                path: "/admin/sync/willow-to-maple/run".into(),
                body: json!({}),
            }
        );
        assert!(run_steps(Kind::Verify, None, "x").is_err());
    }

    #[tokio::test]
    async fn verify_list_has_no_direction_filter() {
        let m = MockTransport::new();
        m.on(Method::Get, "/admin/verify", 200, VERIFY_LIST);
        let out = list_with(&m.client(), Kind::Verify, None, Some(0))
            .await
            .unwrap();
        assert_eq!(out.server_timezone, "unknown");
        assert_eq!(out.jobs[0].id, "v-main-weekly");
        assert_eq!(m.log()[1], "GET /admin/verify");
        let f = VerifyJobFields {
            outdated_after: Some(30),
            ignore_verified: Some(true),
            ..Default::default()
        };
        assert_eq!(
            f.to_map(),
            json!({"ignore-verified": true, "outdated-after": 30})
                .as_object()
                .unwrap()
                .clone()
        );
    }
}

#[cfg(test)]
mod cli_tests {
    use plugin_toolkit::clap::{Args, Command};

    use super::*;

    /// clap validates flattened/duplicate flags only when a command is built.
    #[test]
    fn every_args_struct_builds_a_valid_cli() {
        fn check<A: Args>() {
            A::augment_args(Command::new("t")).debug_assert();
        }
        check::<JobListArgs>();
        check::<SyncJobCreateArgs>();
        check::<SyncJobUpdateArgs>();
        check::<JobRunArgs>();
        check::<VerifyJobCreateArgs>();
        check::<VerifyJobUpdateArgs>();
        check::<crate::groups::GroupListArgs>();
        check::<crate::groups::GroupDeleteArgs>();
        check::<crate::groups::SnapshotListArgs>();
        check::<crate::groups::PruneArgs>();
        check::<crate::groups::GcDetailArgs>();
        check::<crate::groups::GcRunArgs>();
        check::<crate::enroll::HostEnrollArgs>();
        check::<crate::enroll::HostRevokeArgs>();
        check::<crate::tools::TaskListArgs>();
        check::<crate::tools::TaskDetailArgs>();
        check::<crate::tools::NamespaceDeleteArgs>();
        check::<crate::endpoint::PbsCreateArgs>();
        check::<crate::endpoint::PbsUpdateArgs>();
    }

    #[test]
    fn flattened_fields_parse_from_kebab_flags() {
        let cmd = SyncJobUpdateArgs::augment_args(Command::new("t"));
        let m = cmd
            .try_get_matches_from([
                "t",
                "--id",
                "j",
                "--schedule",
                "04:00",
                "--clear",
                "comment",
            ])
            .unwrap();
        let a = <SyncJobUpdateArgs as plugin_toolkit::clap::FromArgMatches>::from_arg_matches(&m)
            .unwrap();
        assert_eq!(a.fields.schedule.as_deref(), Some("04:00"));
        assert_eq!(a.clear, vec!["comment"]);
        let j: SyncJobUpdateArgs = plugin_toolkit::serde_json::from_value(
            json!({"id": "j", "schedule": "04:00", "removeVanished": true}),
        )
        .unwrap();
        assert_eq!(j.fields.remove_vanished, Some(true));
    }
}
