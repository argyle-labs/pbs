//! Backup groups, snapshots, prune and garbage collection:
//! `pbs.group.{list,delete}`, `pbs.snapshot.list`, `pbs.prune`,
//! `pbs.gc.{detail,run}`.

use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::{Map, Value};

use crate::api::{self, GcStatus};
use crate::client::{encode, PbsClient};
use crate::endpoint;
use crate::plan::{self, ApiCall, Change, Step};
use crate::times::{self, When, Zones};

/// Fleet retention policy: keep the last 10 snapshots per group.
pub const DEFAULT_KEEP_LAST: u64 = 10;

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Group {
    pub backup_type: String,
    pub backup_id: String,
    #[serde(default)]
    pub backup_count: u64,
    #[serde(default)]
    pub last_backup: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct Verification {
    /// `ok` or `failed`.
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upid: Option<String>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Snapshot {
    pub backup_type: String,
    pub backup_id: String,
    pub backup_time: i64,
    #[serde(default)]
    pub protected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification: Option<Verification>,
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct PruneEntry {
    pub backup_type: String,
    pub backup_id: String,
    pub backup_time: i64,
    pub keep: bool,
    #[serde(default)]
    pub protected: bool,
}

fn store_path(store: &str, rest: &str) -> String {
    format!("/admin/datastore/{}{rest}", encode(store))
}

fn ns_query(ns: &Option<String>) -> Vec<(&'static str, String)> {
    ns.iter()
        .filter(|n| !n.is_empty())
        .map(|n| ("ns", n.clone()))
        .collect()
}

pub async fn groups(c: &PbsClient, store: &str, ns: &Option<String>) -> Result<Vec<Group>> {
    c.get(&store_path(store, "/groups"), &ns_query(ns)).await
}

pub async fn snapshots(
    c: &PbsClient,
    store: &str,
    ns: &Option<String>,
    backup_type: &Option<String>,
    backup_id: &Option<String>,
) -> Result<Vec<Snapshot>> {
    let mut q = ns_query(ns);
    if let Some(t) = backup_type {
        q.push(("backup-type", t.clone()));
    }
    if let Some(i) = backup_id {
        q.push(("backup-id", i.clone()));
    }
    c.get(&store_path(store, "/snapshots"), &q).await
}

/// Resolve the datastore set: the named ones, or every datastore when `all`.
async fn datastores(c: &PbsClient, named: &[String], all: bool) -> Result<Vec<String>> {
    match (named.is_empty(), all) {
        (false, false) => Ok(named.to_vec()),
        (true, true) => Ok(api::datastores(c)
            .await?
            .into_iter()
            .map(|d| d.store)
            .collect()),
        (false, true) => bail!("pass either datastores or all_datastores, not both"),
        (true, false) => bail!("name at least one datastore, or set all_datastores"),
    }
}

/// `<store>:ns=<ns|root>:<type>/<id>`, the plan item naming one group.
pub fn group_target(
    store: &str,
    ns: &Option<String>,
    backup_type: &str,
    backup_id: &str,
) -> String {
    let ns = ns.as_deref().filter(|n| !n.is_empty()).unwrap_or("root");
    format!("{store}:ns={ns}:{backup_type}/{backup_id}")
}

fn offset(s: &Option<String>) -> Result<Option<i32>> {
    s.as_deref().map(times::parse_offset).transpose()
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.group.{list,delete}
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct GroupListArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Datastores to list. Repeatable; omit for every datastore.
    #[arg(long = "datastore")]
    #[serde(default)]
    pub datastores: Vec<String>,
    /// Namespace; omit for the root.
    #[arg(long)]
    #[serde(default)]
    pub ns: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct DatastoreGroups {
    pub datastore: String,
    pub groups: Vec<Group>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct GroupListOutput {
    pub datastores: Vec<DatastoreGroups>,
}

/// Backup groups in one namespace, across one or more datastores.
#[orca_tool(domain = "pbs", verb = "group.list", role = "read")]
pub async fn pbs_group_list(args: GroupListArgs, _ctx: &ToolCtx) -> Result<GroupListOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    let stores = datastores(&c, &args.datastores, args.datastores.is_empty()).await?;
    let mut out = Vec::new();
    for s in stores {
        out.push(DatastoreGroups {
            groups: groups(&c, &s, &args.ns).await?,
            datastore: s,
        });
    }
    Ok(GroupListOutput { datastores: out })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct GroupDeleteArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Datastores to delete from. Repeatable.
    #[arg(long = "datastore")]
    #[serde(default)]
    pub datastores: Vec<String>,
    /// Delete from every datastore that holds the group, including sync
    /// targets that keep a replica of it.
    #[arg(long)]
    #[serde(default)]
    pub all_datastores: bool,
    #[arg(long)]
    #[serde(default)]
    pub ns: Option<String>,
    /// `vm`, `ct` or `host`.
    #[arg(long)]
    pub backup_type: String,
    #[arg(long)]
    pub backup_id: String,
    /// The dry run's change targets to apply (execute only). Comma-separated
    /// on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// One delete step per datastore that holds the group. Each target ends in
/// `#<snapshots>@<last backup>`, so a group that gained or lost snapshots
/// after the dry run no longer matches the confirmed item.
pub fn group_delete_steps(
    found: &[(String, Vec<Group>)],
    ns: &Option<String>,
    backup_type: &str,
    backup_id: &str,
    all_datastores: bool,
) -> (Vec<Step>, Vec<String>) {
    let mut steps = Vec::new();
    let mut notes = Vec::new();
    for (store, gs) in found {
        let Some(g) = gs
            .iter()
            .find(|g| g.backup_type == backup_type && g.backup_id == backup_id)
        else {
            notes.push(format!("{store}: no group {backup_type}/{backup_id}"));
            continue;
        };
        let mut query = vec![
            ("backup-type".to_string(), backup_type.to_string()),
            ("backup-id".to_string(), backup_id.to_string()),
        ];
        query.extend(ns_query(ns).into_iter().map(|(k, v)| (k.to_string(), v)));
        let mut detail = format!(
            "{} snapshots, last {}; protected snapshots make PBS refuse",
            g.backup_count,
            times::utc(g.last_backup)
        );
        if all_datastores {
            detail.push_str("; all_datastores also deletes the replica on sync targets");
        }
        steps.push(
            Step::new(
                format!(
                    "{}#{}@{}",
                    group_target(store, ns, backup_type, backup_id),
                    g.backup_count,
                    g.last_backup
                ),
                "delete-group",
                ApiCall::Delete {
                    path: store_path(store, "/groups"),
                    query,
                },
            )
            .detail(detail),
        );
    }
    (steps, notes)
}

/// Delete a backup group (all its snapshots) from one or more datastores.
/// Chunks are freed by the next GC. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "group.delete",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_group_delete(args: GroupDeleteArgs, ctx: &ToolCtx) -> Result<Change> {
    crate::plan::require_admin("pbs.group.delete", ctx.caller().as_ref())?;
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    group_delete(&c, &args, ctx.caller().as_ref()).await
}

async fn group_delete(
    c: &PbsClient,
    args: &GroupDeleteArgs,
    caller: Option<&plugin_toolkit::contract::CallerIdentity>,
) -> Result<Change> {
    const TOOL: &str = "pbs.group.delete";
    let stores = datastores(c, &args.datastores, args.all_datastores).await?;
    let mut found = Vec::new();
    for s in stores {
        found.push((s.clone(), groups(c, &s, &args.ns).await?));
    }
    let (steps, notes) = group_delete_steps(
        &found,
        &args.ns,
        &args.backup_type,
        &args.backup_id,
        args.all_datastores,
    );
    if args.execute {
        plan::require_admin(TOOL, caller)?;
        plan::refuse_drifted(TOOL, &steps, &args.items)?;
    }
    let summary = format!("delete group {}/{}", args.backup_type, args.backup_id);
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

// ═══════════════════════════════════════════════════════════════════════════
// pbs.snapshot.list
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotListArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
    #[arg(long)]
    #[serde(default)]
    pub ns: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub backup_type: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub backup_id: Option<String>,
    /// Only snapshots whose last verification failed.
    #[arg(long)]
    #[serde(default)]
    pub failed_only: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct VerifySummary {
    pub ok: u64,
    pub failed: u64,
    pub unverified: u64,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct SnapshotListOutput {
    pub datastore: String,
    pub verify: VerifySummary,
    pub snapshots: Vec<Snapshot>,
    pub note: String,
}

pub fn summarize(snaps: &[Snapshot]) -> VerifySummary {
    fn state(s: &Snapshot) -> Option<&str> {
        s.verification.as_ref().map(|v| v.state.as_str())
    }
    VerifySummary {
        ok: snaps.iter().filter(|s| state(s) == Some("ok")).count() as u64,
        failed: snaps.iter().filter(|s| state(s) == Some("failed")).count() as u64,
        unverified: snaps.iter().filter(|s| state(s).is_none()).count() as u64,
    }
}

/// Snapshots with their verify state.
#[orca_tool(domain = "pbs", verb = "snapshot.list", role = "read")]
pub async fn pbs_snapshot_list(
    args: SnapshotListArgs,
    _ctx: &ToolCtx,
) -> Result<SnapshotListOutput> {
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    let mut snaps = snapshots(
        &c,
        &args.datastore,
        &args.ns,
        &args.backup_type,
        &args.backup_id,
    )
    .await?;
    let verify = summarize(&snaps);
    if args.failed_only {
        snaps.retain(|s| s.verification.as_ref().is_some_and(|v| v.state == "failed"));
    }
    Ok(SnapshotListOutput {
        datastore: args.datastore,
        verify,
        snapshots: snaps,
        note: "a snapshot whose verification failed is never used as an incremental base; \
               the next backup of that group re-uploads its chunks"
            .into(),
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.prune
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct PruneArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
    #[arg(long)]
    #[serde(default)]
    pub ns: Option<String>,
    /// Limit to one backup type (`vm`, `ct`, `host`). Required unless
    /// `all_groups`.
    #[arg(long)]
    #[serde(default)]
    pub backup_type: Option<String>,
    /// Prune every group in the namespace.
    #[arg(long)]
    #[serde(default)]
    pub all_groups: bool,
    /// Limit to one backup id (requires `backup_type`).
    #[arg(long)]
    #[serde(default)]
    pub backup_id: Option<String>,
    /// Snapshots to keep per group. Defaults to 10 when no keep option is
    /// given.
    #[arg(long)]
    #[serde(default)]
    pub keep_last: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub keep_hourly: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub keep_daily: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub keep_weekly: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub keep_monthly: Option<u64>,
    #[arg(long)]
    #[serde(default)]
    pub keep_yearly: Option<u64>,
    /// The dry run's change targets to apply (execute only). Comma-separated
    /// on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

impl PruneArgs {
    /// The `keep-*` options sent to PBS, with the fleet default applied.
    pub fn keep(&self) -> Map<String, Value> {
        let mut m = Map::new();
        let opts = [
            ("keep-last", self.keep_last),
            ("keep-hourly", self.keep_hourly),
            ("keep-daily", self.keep_daily),
            ("keep-weekly", self.keep_weekly),
            ("keep-monthly", self.keep_monthly),
            ("keep-yearly", self.keep_yearly),
        ];
        for (k, v) in opts {
            if let Some(v) = v {
                m.insert(k.into(), json!(v));
            }
        }
        if m.is_empty() {
            m.insert("keep-last".into(), json!(DEFAULT_KEEP_LAST));
        }
        m
    }
}

fn prune_body(
    keep: &Map<String, Value>,
    ns: &Option<String>,
    g: (&str, &str),
    dry_run: bool,
) -> Value {
    let mut body = keep.clone();
    body.insert("backup-type".into(), json!(g.0));
    body.insert("backup-id".into(), json!(g.1));
    body.insert("dry-run".into(), json!(dry_run));
    if let Some(ns) = ns.as_ref().filter(|n| !n.is_empty()) {
        body.insert("ns".into(), json!(ns));
    }
    Value::Object(body)
}

/// One step per group that would lose snapshots, from PBS's own dry run.
pub fn prune_steps(
    store: &str,
    keep: &Map<String, Value>,
    ns: &Option<String>,
    previews: &[((String, String), Vec<PruneEntry>)],
) -> Vec<Step> {
    previews
        .iter()
        .filter_map(|((t, id), entries)| {
            let doomed: Vec<&PruneEntry> =
                entries.iter().filter(|e| !e.keep && !e.protected).collect();
            if doomed.is_empty() {
                return None;
            }
            let kept = entries.iter().filter(|e| e.keep).count();
            let protected = entries.iter().filter(|e| !e.keep && e.protected).count();
            let oldest = doomed
                .iter()
                .map(|e| e.backup_time)
                .min()
                .unwrap_or_default();
            let newest = doomed
                .iter()
                .map(|e| e.backup_time)
                .max()
                .unwrap_or_default();
            let mut detail = format!(
                "removes {} snapshots ({} .. {}), keeps {kept}; PBS re-applies the keep \
                 rules at execute, so a snapshot taken after this dry run can shift which \
                 ones go",
                doomed.len(),
                times::utc(oldest),
                times::utc(newest)
            );
            if protected > 0 {
                detail.push_str(&format!("; {protected} protected snapshots stay"));
            }
            Some(
                Step::new(
                    group_target(store, ns, t, id),
                    "prune",
                    ApiCall::Post {
                        path: store_path(store, "/prune"),
                        body: prune_body(keep, ns, (t, id), false),
                    },
                )
                .detail(detail),
            )
        })
        .collect()
}

/// Prune snapshots per group. Keeps the last 10 by default (the fleet
/// policy). The plan comes from PBS's own prune dry run. Freed chunks are
/// reclaimed by the next GC. Dry-run by default.
#[orca_tool(domain = "pbs", verb = "prune", role = "admin", execute_gated = false)]
pub async fn pbs_prune(args: PruneArgs, ctx: &ToolCtx) -> Result<Change> {
    crate::plan::require_admin("pbs.prune", ctx.caller().as_ref())?;
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    prune(&c, &args, ctx.caller().as_ref()).await
}

async fn prune(
    c: &PbsClient,
    args: &PruneArgs,
    caller: Option<&plugin_toolkit::contract::CallerIdentity>,
) -> Result<Change> {
    const TOOL: &str = "pbs.prune";
    if args.backup_id.is_some() && args.backup_type.is_none() {
        bail!("backup_id needs backup_type");
    }
    match (args.backup_type.is_some(), args.all_groups) {
        (false, false) => bail!("name a backup_type, or set all_groups to prune every group"),
        (true, true) => bail!("pass either backup_type or all_groups, not both"),
        _ => {}
    }
    let keep = args.keep();
    let targets: Vec<(String, String)> = groups(c, &args.datastore, &args.ns)
        .await?
        .into_iter()
        .filter(|g| {
            args.backup_type
                .as_ref()
                .is_none_or(|t| *t == g.backup_type)
        })
        .filter(|g| args.backup_id.as_ref().is_none_or(|i| *i == g.backup_id))
        .map(|g| (g.backup_type, g.backup_id))
        .collect();
    let mut previews = Vec::new();
    for (t, id) in targets {
        let entries: Vec<PruneEntry> = c
            .post(
                &store_path(&args.datastore, "/prune"),
                prune_body(&keep, &args.ns, (&t, &id), true),
            )
            .await?;
        previews.push(((t, id), entries));
    }
    let steps = prune_steps(&args.datastore, &keep, &args.ns, &previews);
    let policy: Vec<String> = keep.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let summary = format!(
        "prune {} group(s) on {} with {}",
        previews.len(),
        args.datastore,
        policy.join(" ")
    );
    plan::plan_or_apply(
        TOOL,
        args,
        args.execute,
        caller,
        c,
        summary,
        steps,
        vec![],
        Some(&args.items),
    )
    .await
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.gc.{detail,run}
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct GcDetailArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
    /// Also render times at this offset (`-06:00`), e.g. the caller's zone.
    #[arg(long)]
    #[serde(default)]
    pub utc_offset: Option<String>,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct PendingRemovals {
    pub chunks: u64,
    pub bytes: u64,
    pub why: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct GcDetailOutput {
    pub datastore: String,
    /// Zone PBS evaluates the GC schedule in.
    pub server_timezone: String,
    pub status: GcStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<When>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run: Option<When>,
    pub pending_removals: PendingRemovals,
}

pub fn gc_detail(store: &str, status: GcStatus, zone: String, zones: Zones) -> GcDetailOutput {
    GcDetailOutput {
        datastore: store.to_string(),
        server_timezone: zone,
        last_run: status.last_run_endtime.map(|e| When::new(e, zones)),
        next_run: status.next_run.map(|e| When::new(e, zones)),
        pending_removals: PendingRemovals {
            chunks: status.pending_chunks,
            bytes: status.pending_bytes,
            why: "unreferenced chunks GC kept because they were touched within 24h 5min of its \
                  start; a later GC frees them"
                .into(),
        },
        status,
    }
}

/// Last GC result, schedule, and the pending removals the last run kept.
#[orca_tool(domain = "pbs", verb = "gc.detail", role = "read")]
pub async fn pbs_gc_detail(args: GcDetailArgs, _ctx: &ToolCtx) -> Result<GcDetailOutput> {
    let off = offset(&args.utc_offset)?;
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    let status = api::gc_status(&c, &args.datastore).await?;
    let (zone, server) = times::server_clock(&c).await;
    Ok(gc_detail(
        &args.datastore,
        status,
        zone,
        Zones { server, local: off },
    ))
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct GcRunArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub datastore: String,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// Start garbage collection on a datastore. Returns the task UPID on execute.
#[orca_tool(domain = "pbs", verb = "gc.run", role = "admin", execute_gated = false)]
pub async fn pbs_gc_run(args: GcRunArgs, ctx: &ToolCtx) -> Result<Change> {
    crate::plan::require_admin("pbs.gc.run", ctx.caller().as_ref())?;
    const TOOL: &str = "pbs.gc.run";
    let c = endpoint::connect(args.endpoint.as_deref()).await?;
    let status = api::gc_status(&c, &args.datastore).await?;
    let steps = vec![Step::new(
        &args.datastore,
        "start-gc",
        ApiCall::Post {
            path: store_path(&args.datastore, "/gc"),
            body: json!({}),
        },
    )
    .detail("starts a task; follow it with pbs.task.detail")];
    let notes = vec![format!(
        "last run kept {} chunks ({} bytes) pending removal",
        status.pending_chunks, status.pending_bytes
    )];
    let summary = format!("garbage-collect {}", args.datastore);
    plan::plan_or_apply(
        TOOL,
        &args,
        args.execute,
        ctx.caller().as_ref(),
        &c,
        summary,
        steps,
        notes,
        None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use plugin_toolkit::serde_json;

    use super::*;
    use crate::api::fixtures::*;
    use crate::client::mock::MockTransport;
    use crate::client::Method;
    use crate::plan::{admin, items};

    fn fixture_groups() -> Vec<Group> {
        serde_json::from_value(data(GROUPS_LIST)).unwrap()
    }

    #[test]
    fn group_target_names_store_namespace_and_group() {
        assert_eq!(
            group_target("main", &None, "vm", "111"),
            "main:ns=root:vm/111"
        );
        assert_eq!(
            group_target("main", &Some(String::new()), "vm", "111"),
            "main:ns=root:vm/111"
        );
        assert_eq!(
            group_target("main", &Some("hosts/freyr".into()), "host", "freyr"),
            "main:ns=hosts/freyr:host/freyr"
        );
    }

    #[test]
    fn group_delete_plans_per_datastore_and_notes_absence() {
        let found = vec![
            ("main".to_string(), fixture_groups()),
            ("archive".to_string(), fixture_groups()[2..].to_vec()),
        ];
        let (steps, notes) = group_delete_steps(&found, &None, "vm", "111", false);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].target, "main:ns=root:vm/111#12@1790985600");
        assert_eq!(
            steps[0].call,
            ApiCall::Delete {
                path: "/admin/datastore/main/groups".into(),
                query: vec![
                    ("backup-type".into(), "vm".into()),
                    ("backup-id".into(), "111".into())
                ],
            }
        );
        let d = steps[0].detail.as_deref().unwrap();
        assert!(d.starts_with("12 snapshots"), "{d}");
        assert!(!d.contains("sync targets"));
        assert_eq!(notes, vec!["archive: no group vm/111"]);
        let (all, _) = group_delete_steps(&found, &None, "vm", "111", true);
        assert!(all[0]
            .detail
            .as_deref()
            .unwrap()
            .contains("replica on sync targets"));
    }

    #[tokio::test]
    async fn namespaced_group_delete_sends_the_namespace() {
        let m = MockTransport::new();
        m.on(
            Method::Delete,
            "/admin/datastore/main/groups",
            200,
            GROUP_DELETE,
        );
        let ns = Some("hosts/freyr".to_string());
        let found = vec![("main".to_string(), fixture_groups())];
        let (steps, notes) = group_delete_steps(&found, &ns, "host", "freyr", false);
        assert_eq!(
            steps[0].target,
            "main:ns=hosts/freyr:host/freyr#14@1791000000"
        );
        let confirmed = items(&steps);
        let out = plan::plan_or_apply(
            "pbs.group.delete",
            &json!({}),
            true,
            Some(&admin()),
            &m.client(),
            "s".into(),
            steps,
            notes,
            Some(&confirmed),
        )
        .await
        .unwrap();
        let Change::Applied(a) = out else {
            panic!("expected applied")
        };
        assert_eq!(a.steps[0].result["removed-snapshots"], json!(12));
        assert_eq!(
            m.log(),
            vec!["DELETE /admin/datastore/main/groups?backup-type=host&backup-id=freyr&ns=hosts%2Ffreyr"]
        );
    }

    #[test]
    fn group_delete_refuses_a_group_that_changed_since_the_plan() {
        let found = vec![("main".to_string(), fixture_groups())];
        let (planned, _) = group_delete_steps(&found, &None, "vm", "111", false);
        let confirmed = items(&planned);
        let mut grown = fixture_groups();
        grown[0].backup_count += 1;
        let (now, _) =
            group_delete_steps(&[("main".to_string(), grown)], &None, "vm", "111", false);
        let err = plan::refuse_drifted("pbs.group.delete", &now, &confirmed).unwrap_err();
        assert!(err.to_string().contains("changed or vanished"), "{err}");
        assert!(plan::refuse_drifted("pbs.group.delete", &planned, &confirmed).is_ok());
    }

    #[test]
    fn keep_defaults_to_last_ten_only_without_other_options() {
        let a = PruneArgs::default();
        assert_eq!(Value::Object(a.keep()), json!({"keep-last": 10}));
        let b = PruneArgs {
            keep_daily: Some(7),
            ..Default::default()
        };
        assert_eq!(Value::Object(b.keep()), json!({"keep-daily": 7}));
    }

    #[test]
    fn prune_steps_skip_protected_and_untouched_groups() {
        let entries: Vec<PruneEntry> = serde_json::from_value(data(PRUNE_DRY_RUN)).unwrap();
        let keep = PruneArgs::default().keep();
        let previews = vec![
            (("vm".to_string(), "111".to_string()), entries.clone()),
            (
                ("ct".to_string(), "114".to_string()),
                entries.iter().filter(|e| e.keep).cloned().collect(),
            ),
        ];
        let steps = prune_steps("main", &keep, &Some("hosts/freyr".into()), &previews);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].target, "main:ns=hosts/freyr:vm/111");
        let d = steps[0].detail.as_deref().unwrap();
        assert!(d.starts_with("removes 1 snapshots"), "{d}");
        assert!(d.contains("1 protected snapshots stay"), "{d}");
        assert_eq!(
            steps[0].call,
            ApiCall::Post {
                path: "/admin/datastore/main/prune".into(),
                body: json!({
                    "keep-last": 10,
                    "backup-type": "vm",
                    "backup-id": "111",
                    "dry-run": false,
                    "ns": "hosts/freyr"
                }),
            }
        );
    }

    fn prune_mock() -> MockTransport {
        let m = MockTransport::new();
        m.on(
            Method::Get,
            "/admin/datastore/main/groups",
            200,
            GROUPS_LIST,
        );
        m.on(
            Method::Post,
            "/admin/datastore/main/prune",
            200,
            PRUNE_DRY_RUN,
        );
        m
    }

    #[tokio::test]
    async fn prune_needs_a_type_or_all_groups() {
        let m = prune_mock();
        let base = PruneArgs {
            datastore: "main".into(),
            ..Default::default()
        };
        let err = prune(&m.client(), &base, Some(&crate::plan::admin()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("all_groups"), "{err}");
        let both = PruneArgs {
            backup_type: Some("vm".into()),
            all_groups: true,
            datastore: "main".into(),
            ..Default::default()
        };
        assert!(prune(&m.client(), &both, Some(&crate::plan::admin()))
            .await
            .is_err());
        assert!(m.log().is_empty());
        let all = PruneArgs {
            all_groups: true,
            ..base
        };
        let Change::Plan(p) = prune(&m.client(), &all, Some(&crate::plan::admin()))
            .await
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(p.changes.len(), 3, "every group previewed as prunable");
    }

    #[tokio::test]
    async fn prune_dry_run_asks_pbs_with_dry_run_true_and_never_prunes() {
        let m = prune_mock();
        let args = PruneArgs {
            datastore: "main".into(),
            backup_type: Some("vm".into()),
            ..Default::default()
        };
        let out = prune(&m.client(), &args, Some(&crate::plan::admin()))
            .await
            .unwrap();
        let Change::Plan(p) = out else {
            panic!("expected plan")
        };
        assert_eq!(p.changes.len(), 1);
        assert_eq!(m.mutations().len(), 1, "only the PBS-side dry run");
        assert_eq!(m.body_of(1)["dry-run"], json!(true));
        let mut exec = args;
        exec.execute = true;
        assert!(
            prune(&m.client(), &exec, Some(&admin())).await.is_err(),
            "no items"
        );
        exec.items = p.changes.iter().map(|c| c.target.clone()).collect();
        prune(&m.client(), &exec, Some(&admin())).await.unwrap();
        let last = m.calls.lock().unwrap().len() - 1;
        assert_eq!(m.body_of(last)["dry-run"], json!(false));
    }

    #[test]
    fn snapshot_summary_counts_verify_states() {
        let snaps: Vec<Snapshot> = serde_json::from_value(data(SNAPSHOTS_LIST)).unwrap();
        let s = summarize(&snaps);
        assert_eq!((s.ok, s.failed, s.unverified), (1, 1, 1));
    }

    #[test]
    fn gc_detail_surfaces_pending_removals() {
        let st: GcStatus = serde_json::from_value(data(GC_STATUS)).unwrap();
        let d = gc_detail(
            "main",
            st,
            "UTC".into(),
            Zones {
                server: Some(0),
                local: None,
            },
        );
        assert_eq!(d.pending_removals.chunks, 3);
        assert_eq!(d.pending_removals.bytes, 7_340_032);
        assert!(d.pending_removals.why.contains("24h 5min"));
        let next = d.next_run.unwrap();
        assert_eq!(next.epoch, 1_759_636_800);
        assert!(next.server.is_some() && next.local.is_none());
    }

    #[test]
    fn group_delete_requires_an_explicit_datastore_choice() {
        let rt = crate::endpoint::test_store::rt();
        let m = MockTransport::new();
        let c = m.client();
        assert!(rt.block_on(datastores(&c, &[], false)).is_err());
        assert!(rt.block_on(datastores(&c, &["a".into()], true)).is_err());
        assert_eq!(
            rt.block_on(datastores(&c, &["a".into()], false)).unwrap(),
            vec!["a"]
        );
    }

    #[tokio::test]
    async fn group_delete_refuses_at_execute_when_the_group_changed() {
        let m = MockTransport::new();
        m.on(
            Method::Get,
            "/admin/datastore/main/groups",
            200,
            GROUPS_LIST,
        );
        m.on(
            Method::Delete,
            "/admin/datastore/main/groups",
            200,
            GROUP_DELETE,
        );
        let mut args = GroupDeleteArgs {
            datastores: vec!["main".into()],
            backup_type: "vm".into(),
            backup_id: "111".into(),
            ..Default::default()
        };
        let Change::Plan(p) = group_delete(&m.client(), &args, Some(&crate::plan::admin()))
            .await
            .unwrap()
        else {
            panic!("expected plan")
        };
        let mut grown: Value = serde_json::from_str(GROUPS_LIST).unwrap();
        grown["data"][0]["backup-count"] = json!(13);
        m.on(
            Method::Get,
            "/admin/datastore/main/groups",
            200,
            &grown.to_string(),
        );
        args.execute = true;
        args.items = p.changes.iter().map(|c| c.target.clone()).collect();
        let err = group_delete(&m.client(), &args, Some(&admin()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("changed or vanished"), "{err}");
        assert!(m.mutations().is_empty(), "{:?}", m.mutations());
    }
}
