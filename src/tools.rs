//! `pbs.*` read and admin verbs over the PBS REST API.
//!
//! Every verb takes an optional `endpoint` (a `pbs.create`d registration);
//! omitted, the sole registered endpoint is used. Mutating verbs are dry-run
//! unless `execute` is set — see [`crate::plan`].

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::api::{
    self, Datastore, DatastoreStatus, GcStatus, LogLine, Namespace, Task, TaskFilter, TaskStatus,
};
use crate::client::PbsClient;
use crate::endpoint;
use crate::plan::{self, ApiCall, Change, Step};

fn default_task_limit() -> u64 {
    50
}
fn default_log_limit() -> u64 {
    500
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.datastore.{list,detail}
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DatastoreListArgs {
    /// Registered PBS endpoint. Default: the only one.
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct DatastoreListOutput {
    pub datastores: Vec<Datastore>,
}

/// List the datastores on a PBS server.
#[orca_tool(domain = "pbs", verb = "datastore.list", role = "read")]
pub async fn pbs_datastore_list(
    args: DatastoreListArgs,
    _ctx: &ToolCtx,
) -> Result<DatastoreListOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    Ok(DatastoreListOutput {
        datastores: api::datastores(&c).await?,
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DatastoreDetailArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct DatastoreDetailOutput {
    pub datastore: String,
    pub status: DatastoreStatus,
    /// Last GC result plus its schedule and next run.
    pub gc: GcStatus,
}

/// Usage, per-type group/snapshot counts and GC state of one datastore.
#[orca_tool(domain = "pbs", verb = "datastore.detail", role = "read")]
pub async fn pbs_datastore_detail(
    args: DatastoreDetailArgs,
    _ctx: &ToolCtx,
) -> Result<DatastoreDetailOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    datastore_detail(&c, &args.datastore).await
}

async fn datastore_detail(c: &PbsClient, store: &str) -> Result<DatastoreDetailOutput> {
    Ok(DatastoreDetailOutput {
        datastore: store.to_string(),
        status: api::datastore_status(c, store).await?,
        gc: api::gc_status(c, store).await?,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.datastore.health
// ═══════════════════════════════════════════════════════════════════════════

fn default_min_free_pct() -> u8 {
    10
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct DatastoreHealthArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Free space below this percent of total is a problem.
    #[arg(long, default_value_t = 10)]
    #[serde(default = "default_min_free_pct")]
    pub min_free_pct: u8,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DatastoreHealth {
    pub datastore: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maintenance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avail: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc_last_run_state: Option<String>,
    pub ok: bool,
    pub problems: Vec<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct DatastoreHealthOutput {
    pub ok: bool,
    pub datastores: Vec<DatastoreHealth>,
}

/// Health of every datastore: whether its chunk store is reachable (a store
/// whose backing mount vanished fails its status read), mount and maintenance
/// state, free space, the last GC result, and whether a scheduled verify job
/// covers it and last passed. Read-only.
#[orca_tool(domain = "pbs", verb = "datastore.health", role = "read")]
pub async fn pbs_datastore_health(
    args: DatastoreHealthArgs,
    _ctx: &ToolCtx,
) -> Result<DatastoreHealthOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    datastore_health(&c, args.min_free_pct).await
}

async fn datastore_health(c: &PbsClient, min_free_pct: u8) -> Result<DatastoreHealthOutput> {
    let mut datastores = Vec::new();
    let verify = crate::jobs::raw_jobs(c, crate::jobs::Kind::Verify, None)
        .await
        .map_err(|e| format!("verify jobs unreadable: {e:#}"));
    for ds in api::datastores(c).await? {
        let status = api::datastore_status(c, &ds.store).await;
        let gc = match status {
            Ok(_) => Some(api::gc_status(c, &ds.store).await),
            Err(_) => None,
        };
        let mut h = assess_datastore(ds, status, gc, min_free_pct);
        match &verify {
            Ok(jobs) => h.problems.extend(verify_problems(&h.datastore, jobs)),
            Err(e) => h.problems.push(e.clone()),
        }
        h.ok = h.problems.is_empty();
        datastores.push(h);
    }
    Ok(DatastoreHealthOutput {
        ok: datastores.iter().all(|d| d.ok),
        datastores,
    })
}

fn verify_problems(store: &str, jobs: &[Value]) -> Vec<String> {
    let str_of = |j: &Value, k: &str| j.get(k).and_then(Value::as_str).map(str::to_string);
    let mine: Vec<&Value> = jobs
        .iter()
        .filter(|j| str_of(j, "store").as_deref() == Some(store))
        .collect();
    if mine.is_empty() {
        return vec!["no verify job: corrupt chunks surface only at restore".to_string()];
    }
    let mut problems = Vec::new();
    if !mine.iter().any(|j| str_of(j, "schedule").is_some()) {
        problems.push("verify jobs exist but none is scheduled".to_string());
    }
    for j in &mine {
        if let Some(state) = str_of(j, "last-run-state").filter(|s| s != "ok") {
            problems.push(format!(
                "verify job {} last run: {state}",
                str_of(j, "id").unwrap_or_default()
            ));
        }
    }
    problems
}

fn assess_datastore(
    ds: Datastore,
    status: Result<DatastoreStatus>,
    gc: Option<Result<GcStatus>>,
    min_free_pct: u8,
) -> DatastoreHealth {
    let mut problems = Vec::new();
    if ds.mount_status.as_deref() == Some("notmounted") {
        problems.push("removable datastore is not mounted".to_string());
    }
    if let Some(m) = &ds.maintenance {
        problems.push(format!("in maintenance mode: {m}"));
    }
    let (total, avail) = match &status {
        Ok(st) => {
            if st.total == 0 {
                problems.push("reports 0 bytes total: backing path empty or unmounted".into());
            } else if (st.avail as u128) * 100 < (st.total as u128) * min_free_pct as u128 {
                problems.push(format!(
                    "{} of {} bytes free, under {min_free_pct}%",
                    st.avail, st.total
                ));
            }
            (Some(st.total), Some(st.avail))
        }
        Err(e) => {
            problems.push(format!(
                "status unreadable (chunk store missing or stale mount): {e:#}"
            ));
            (None, None)
        }
    };
    let gc_last_run_state = match gc {
        Some(Ok(gc)) => {
            if let Some(state) = gc.last_run_state.as_deref().filter(|s| *s != "ok") {
                problems.push(format!("last GC: {state}"));
            }
            if gc.still_bad > 0 {
                problems.push(format!("GC found {} chunks still bad", gc.still_bad));
            }
            gc.last_run_state
        }
        Some(Err(e)) => {
            problems.push(format!("GC status unreadable: {e:#}"));
            None
        }
        None => None,
    };
    DatastoreHealth {
        datastore: ds.store,
        mount_status: ds.mount_status,
        maintenance: ds.maintenance,
        total,
        avail,
        gc_last_run_state,
        ok: problems.is_empty(),
        problems,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.namespace.{list,create,delete}
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceListArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct NamespaceListOutput {
    pub datastore: String,
    pub namespaces: Vec<Namespace>,
}

/// List every namespace in a datastore (the root is `""`).
#[orca_tool(domain = "pbs", verb = "namespace.list", role = "read")]
pub async fn pbs_namespace_list(
    args: NamespaceListArgs,
    _ctx: &ToolCtx,
) -> Result<NamespaceListOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    Ok(NamespaceListOutput {
        namespaces: api::namespaces(&c, &args.datastore).await?,
        datastore: args.datastore,
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceCreateArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
    /// Full namespace path, e.g. `hosts/freyr`. Missing parents are created.
    #[arg(long)]
    pub ns: String,
    /// Apply the change. Without it the verb returns its plan.
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Steps that create `ns` and any missing parent, parent first.
pub fn namespace_create_steps(store: &str, existing: &[Namespace], ns: &str) -> Vec<Step> {
    let path = format!(
        "/admin/datastore/{}/namespace",
        crate::client::encode(store)
    );
    api::missing_namespace_chain(existing, ns)
        .into_iter()
        .map(|(parent, name)| {
            let full = if parent.is_empty() {
                name.clone()
            } else {
                format!("{parent}/{name}")
            };
            let mut body = json!({ "name": name });
            if !parent.is_empty() {
                body["parent"] = json!(parent);
            }
            Step::new(
                format!("{store}:{full}"),
                "create-namespace",
                ApiCall::Post {
                    path: path.clone(),
                    body,
                },
            )
        })
        .collect()
}

/// Create a namespace (and its missing parents). Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "namespace.create",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_namespace_create(args: NamespaceCreateArgs, ctx: &ToolCtx) -> Result<Change> {
    crate::plan::require_admin("pbs.namespace.create", ctx.caller().as_ref())?;
    const TOOL: &str = "pbs.namespace.create";
    api::validate_ns(&args.ns)?;
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    let existing = api::namespaces(&c, &args.datastore).await?;
    let steps = namespace_create_steps(&args.datastore, &existing, &args.ns);
    let summary = format!("namespace {} on datastore {}", args.ns, args.datastore);
    plan::plan_or_apply(
        TOOL,
        &args,
        args.execute,
        ctx.caller().as_ref(),
        &c,
        summary,
        steps,
        vec![],
        None,
    )
    .await
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceDeleteArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
    #[arg(long)]
    pub ns: String,
    /// Also destroy every backup group in and below the namespace. Without it
    /// PBS refuses to delete a namespace that still holds backups.
    #[arg(long)]
    #[serde(default)]
    pub delete_groups: bool,
    /// The dry run's change targets to apply (execute only). Comma-separated
    /// on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Delete a namespace. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "namespace.delete",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_namespace_delete(args: NamespaceDeleteArgs, ctx: &ToolCtx) -> Result<Change> {
    crate::plan::require_admin("pbs.namespace.delete", ctx.caller().as_ref())?;
    api::validate_ns(&args.ns)?;
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    namespace_delete(&c, &args, ctx.caller().as_ref()).await
}

async fn namespace_delete(
    c: &PbsClient,
    args: &NamespaceDeleteArgs,
    caller: Option<&plugin_toolkit::contract::CallerIdentity>,
) -> Result<Change> {
    const TOOL: &str = "pbs.namespace.delete";
    let existing = api::namespaces(c, &args.datastore).await?;
    let contents = if args.delete_groups {
        Some(api::ns_contents(c, &args.datastore, &existing, &args.ns).await?)
    } else {
        None
    };
    let (steps, notes) =
        namespace_delete_steps(&args.datastore, &existing, &args.ns, contents.as_ref());
    if args.execute {
        plan::require_admin(TOOL, caller)?;
        plan::refuse_drifted(TOOL, &steps, &args.items)?;
    }
    let summary = format!(
        "delete namespace {} on datastore {}",
        args.ns, args.datastore
    );
    plan::plan_or_apply(
        TOOL,
        args,
        args.execute,
        caller,
        c,
        summary,
        steps,
        notes,
        Some(&args.items),
    )
    .await
}

/// `contents` is set when the delete takes the backups with it. Its
/// fingerprint goes into the plan item, so a namespace that gained or lost
/// backups after the dry run is no longer confirmed.
pub fn namespace_delete_steps(
    store: &str,
    existing: &[Namespace],
    ns: &str,
    contents: Option<&api::NsContents>,
) -> (Vec<Step>, Vec<String>) {
    if !existing.iter().any(|n| n.ns == ns) {
        return (Vec::new(), vec![format!("namespace {ns} does not exist")]);
    }
    let delete_groups = contents.is_some();
    let target = match contents {
        Some(c) => format!("{store}:{ns}#{}", c.fingerprint()),
        None => format!("{store}:{ns}"),
    };
    let step = Step::new(
        target,
        "delete-namespace",
        ApiCall::Delete {
            path: format!(
                "/admin/datastore/{}/namespace",
                crate::client::encode(store)
            ),
            query: vec![
                ("ns".into(), ns.to_string()),
                ("delete-groups".into(), delete_groups.to_string()),
            ],
        },
    )
    .detail(match contents {
        Some(c) => format!(
            "removes {} groups ({} snapshots) in and below it",
            c.groups, c.snapshots
        ),
        None => "fails if any backup group remains".to_string(),
    });
    (vec![step], Vec::new())
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.task.{list,detail}
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct TaskListArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Only tasks touching this datastore.
    #[arg(long)]
    #[serde(default)]
    pub datastore: Option<String>,
    /// Only task types containing this (e.g. `backup`, `garbage_collection`,
    /// `syncjob`, `verificationjob`, `prune`).
    #[arg(long = "type")]
    #[serde(default, rename = "type")]
    pub task_type: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub running: bool,
    /// Only failed tasks.
    #[arg(long)]
    #[serde(default)]
    pub errors: bool,
    /// Only tasks since this UNIX epoch.
    #[arg(long)]
    #[serde(default)]
    pub since: Option<i64>,
    #[arg(long, default_value_t = default_task_limit())]
    #[serde(default = "default_task_limit")]
    pub limit: u64,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct TaskListOutput {
    pub tasks: Vec<Task>,
}

/// List recent PBS tasks, newest first.
#[orca_tool(domain = "pbs", verb = "task.list", role = "read")]
pub async fn pbs_task_list(args: TaskListArgs, _ctx: &ToolCtx) -> Result<TaskListOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    let f = TaskFilter {
        store: args.datastore,
        typefilter: args.task_type,
        running: args.running,
        errors: args.errors,
        since: args.since,
        limit: args.limit,
    };
    Ok(TaskListOutput {
        tasks: api::tasks(&c, &f).await?,
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct TaskDetailArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Task id (`UPID:…`).
    #[arg(long)]
    pub upid: String,
    /// First log line to return (0-based).
    #[arg(long, default_value_t = 0)]
    #[serde(default)]
    pub log_start: u64,
    /// Log lines to return; 0 returns the whole log.
    #[arg(long, default_value_t = default_log_limit())]
    #[serde(default = "default_log_limit")]
    pub log_limit: u64,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct TaskDetailOutput {
    pub status: TaskStatus,
    pub log: Vec<LogLine>,
    /// Total log lines on the server, so a caller can page.
    pub log_total: u64,
}

/// One task's status and log, read through the API.
#[orca_tool(domain = "pbs", verb = "task.detail", role = "read")]
pub async fn pbs_task_detail(args: TaskDetailArgs, _ctx: &ToolCtx) -> Result<TaskDetailOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    task_detail(&c, &args.upid, args.log_start, args.log_limit).await
}

async fn task_detail(
    c: &PbsClient,
    upid: &str,
    start: u64,
    limit: u64,
) -> Result<TaskDetailOutput> {
    let status = api::task_status(c, upid).await?;
    let log = api::task_log(c, upid, start, limit).await?;
    Ok(TaskDetailOutput {
        status,
        log: log.lines,
        log_total: log.total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::fixtures::*;
    use crate::client::mock::MockTransport;
    use crate::client::Method;
    use crate::plan::admin;
    use plugin_toolkit::serde_json::{json, Value};

    fn existing() -> Vec<Namespace> {
        plugin_toolkit::serde_json::from_value(data(NAMESPACE_LIST)).unwrap()
    }

    #[test]
    fn namespace_create_plans_missing_parent_first() {
        let steps = namespace_create_steps("main", &[], "hosts/maple");
        assert_eq!(steps.len(), 2);
        assert_eq!(steps[0].target, "main:hosts");
        assert_eq!(
            steps[1].call,
            ApiCall::Post {
                path: "/admin/datastore/main/namespace".into(),
                body: json!({"name": "maple", "parent": "hosts"}),
            }
        );
        assert!(namespace_create_steps("main", &existing(), "hosts/freyr").is_empty());
    }

    #[test]
    fn namespace_delete_is_a_noop_when_absent() {
        let (steps, notes) = namespace_delete_steps("main", &existing(), "hosts/gone", None);
        assert!(steps.is_empty());
        assert!(notes[0].contains("does not exist"));
        let contents = api::NsContents {
            groups: 1,
            snapshots: 14,
            last_backup: 1_791_000_000,
        };
        let (steps, _) =
            namespace_delete_steps("main", &existing(), "hosts/freyr", Some(&contents));
        assert_eq!(steps[0].target, "main:hosts/freyr#g1.s14@1791000000");
        let grown = api::NsContents {
            snapshots: 15,
            ..contents
        };
        let (now, _) = namespace_delete_steps("main", &existing(), "hosts/freyr", Some(&grown));
        let (kept, _) = plan::confirm("t", now, &[steps[0].item()]).unwrap();
        assert!(kept.is_empty(), "new backups must void the confirmation");
        assert_eq!(
            steps[0].call,
            ApiCall::Delete {
                path: "/admin/datastore/main/namespace".into(),
                query: vec![
                    ("ns".into(), "hosts/freyr".into()),
                    ("delete-groups".into(), "true".into())
                ],
            }
        );
    }

    #[tokio::test]
    async fn namespace_create_applies_in_order() {
        let m = MockTransport::new();
        m.ok(Method::Post, "/admin/datastore/main/namespace", json!(null));
        let c = m.client();
        let steps = namespace_create_steps("main", &[], "hosts/maple");
        let out = plan::plan_or_apply(
            "pbs.namespace.create",
            &json!({}),
            true,
            Some(&admin()),
            &c,
            "s".into(),
            steps,
            vec![],
            None,
        )
        .await
        .unwrap();
        assert!(matches!(out, Change::Applied(_)));
        assert_eq!(m.mutations().len(), 2);
        assert_eq!(m.body_of(0), json!({"name": "hosts"}));
        assert_eq!(m.body_of(1), json!({"name": "maple", "parent": "hosts"}));
    }

    #[tokio::test]
    async fn datastore_detail_combines_status_and_gc() {
        let m = MockTransport::new();
        m.on(
            Method::Get,
            "/admin/datastore/main/status",
            200,
            DATASTORE_STATUS,
        );
        m.on(Method::Get, "/admin/datastore/main/gc", 200, GC_STATUS);
        let d = datastore_detail(&m.client(), "main").await.unwrap();
        assert_eq!(d.status.used, 1_099_511_627_776);
        assert_eq!(d.gc.next_run, Some(1_759_636_800));
    }

    #[tokio::test]
    async fn datastore_health_flags_an_unreadable_store_and_passes_a_healthy_one() {
        let m = MockTransport::new();
        m.on(Method::Get, "/admin/datastore", 200, DATASTORE_LIST);
        m.on(
            Method::Get,
            "/admin/datastore/main/status",
            200,
            DATASTORE_STATUS,
        );
        m.on(Method::Get, "/admin/datastore/main/gc", 200, GC_STATUS);
        m.on(Method::Get, "/admin/verify", 200, VERIFY_LIST);
        m.on(
            Method::Get,
            "/admin/datastore/archive/status",
            400,
            r#"{"data":null,"message":"unable to open chunk store at \"/mnt/pbs/.chunks\""}"#,
        );
        let h = datastore_health(&m.client(), 10).await.unwrap();
        assert!(!h.ok);
        assert!(h.datastores[0].ok, "{:?}", h.datastores[0].problems);
        assert_eq!(h.datastores[0].gc_last_run_state.as_deref(), Some("ok"));
        let archive = &h.datastores[1];
        assert!(!archive.ok);
        assert!(
            archive.problems[0].starts_with("status unreadable"),
            "{:?}",
            archive.problems
        );
        assert!(archive
            .problems
            .iter()
            .any(|p| p.starts_with("no verify job")));
        assert!(!m.log().iter().any(|l| l.contains("archive/gc")));
    }

    #[test]
    fn verify_job_coverage_problems() {
        let jobs = vec![
            json!({"id": "a", "store": "main", "schedule": "sat 03:00", "last-run-state": "ok"}),
            json!({"id": "b", "store": "main", "last-run-state": "TASK ERROR: 3 snapshots failed"}),
            json!({"id": "c", "store": "cold"}),
        ];
        assert_eq!(
            verify_problems("main", &jobs),
            vec!["verify job b last run: TASK ERROR: 3 snapshots failed".to_string()]
        );
        assert_eq!(
            verify_problems("cold", &jobs),
            vec!["verify jobs exist but none is scheduled".to_string()]
        );
        assert!(verify_problems("none", &jobs)[0].starts_with("no verify job"));
    }

    fn ds(mount: Option<&str>, maintenance: Option<&str>) -> Datastore {
        Datastore {
            store: "main".into(),
            comment: None,
            backend_type: None,
            mount_status: mount.map(str::to_string),
            maintenance: maintenance.map(str::to_string),
        }
    }

    fn st(total: u64, avail: u64) -> Result<DatastoreStatus> {
        Ok(DatastoreStatus {
            total,
            used: total - avail,
            avail,
            backend_type: None,
            counts: None,
            gc_status: None,
        })
    }

    #[test]
    fn datastore_health_problems() {
        let h = assess_datastore(
            ds(Some("notmounted"), Some("read-only")),
            st(0, 0),
            None,
            10,
        );
        assert_eq!(h.problems.len(), 3, "{:?}", h.problems);
        let low = assess_datastore(ds(None, None), st(1000, 99), None, 10);
        assert!(low.problems[0].contains("under 10%"));
        assert!(assess_datastore(ds(None, None), st(1000, 100), None, 10).ok);
        let gc = GcStatus {
            last_run_state: Some("TASK ERROR: EIO".into()),
            still_bad: 2,
            ..GcStatus::default()
        };
        let h = assess_datastore(ds(None, None), st(1000, 500), Some(Ok(gc)), 10);
        assert_eq!(
            h.problems,
            vec!["last GC: TASK ERROR: EIO", "GC found 2 chunks still bad"]
        );
    }

    #[tokio::test]
    async fn task_detail_reads_status_and_log() {
        let m = MockTransport::new();
        let upid = "UPID:pbs:000001AB:00002F10:00000004:66FF0000:garbage_collection:main:root@pam:";
        let enc = crate::client::encode(upid);
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
        let d = task_detail(&m.client(), upid, 0, 0).await.unwrap();
        assert_eq!(d.status.status, "stopped");
        assert_eq!(d.log_total, 3);
    }

    #[tokio::test]
    async fn namespace_delete_refuses_when_its_backups_changed() {
        let m = MockTransport::new();
        m.on(
            Method::Get,
            "/admin/datastore/main/namespace",
            200,
            NAMESPACE_LIST,
        );
        m.on(
            Method::Get,
            "/admin/datastore/main/groups",
            200,
            GROUPS_LIST,
        );
        m.ok(
            Method::Delete,
            "/admin/datastore/main/namespace",
            Value::Null,
        );
        let mut args = NamespaceDeleteArgs {
            datastore: "main".into(),
            ns: "hosts/freyr".into(),
            delete_groups: true,
            ..Default::default()
        };
        let Change::Plan(p) = namespace_delete(&m.client(), &args, Some(&crate::plan::admin()))
            .await
            .unwrap()
        else {
            panic!()
        };
        args.items = p.changes.iter().map(|c| c.target.clone()).collect();
        assert_eq!(
            args.items,
            vec!["delete-namespace main:hosts/freyr#g3.s36@1791000000"]
        );
        let mut grown: Value = plugin_toolkit::serde_json::from_str(GROUPS_LIST).unwrap();
        grown["data"][0]["backup-count"] = json!(13);
        m.on(
            Method::Get,
            "/admin/datastore/main/groups",
            200,
            &grown.to_string(),
        );
        args.execute = true;
        let err = namespace_delete(&m.client(), &args, Some(&admin()))
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("changed or vanished since the dry run"),
            "{err}"
        );
        assert!(m.mutations().is_empty(), "{:?}", m.mutations());
    }
}
