//! `pbs.host.enroll|revoke`: one namespace, user, API token and ACL set per
//! backup client host, so a host can write and prune only its own backups.
//!
//! Enrolment is level-triggered: it reads the live state, reports every
//! deviation from the desired set as a [`Finding`], and plans only the calls
//! that close the gap. Re-running on an enrolled host is a no-op.

use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets;
use plugin_toolkit::serde_json::Value;

use crate::api::{self, AclEntry, Namespace, User};
use crate::client::{encode, ApiToken, PbsClient};
use crate::endpoint;
use crate::plan::{self, ApiCall, Change, Step};

/// `DatastorePowerUser` is what lets the host prune its own group; with
/// `DatastoreBackup` alone a client-side `prune` is refused.
pub const ROLES: [&str; 2] = ["DatastoreBackup", "DatastorePowerUser"];
const REALM: &str = "pbs";
const TOKEN_NAME: &str = "backup";

/// Everything enrolment derives from `(host, datastore)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Identity {
    pub host: String,
    pub datastore: String,
    pub userid: String,
    pub tokenid: String,
    pub ns: String,
    pub acl_path: String,
}

impl Identity {
    pub fn new(host: &str, datastore: &str) -> Result<Self> {
        validate_host(host)?;
        validate_datastore(datastore)?;
        let userid = format!("{host}@{REALM}");
        Ok(Self {
            host: host.to_string(),
            datastore: datastore.to_string(),
            tokenid: format!("{userid}!{TOKEN_NAME}"),
            ns: format!("hosts/{host}"),
            acl_path: format!("/datastore/{datastore}/hosts/{host}"),
            userid,
        })
    }

    /// PBS intersects a token's ACLs with its owning user's, so both carry
    /// the roles.
    fn auth_ids(&self) -> [&str; 2] {
        [&self.userid, &self.tokenid]
    }

    fn owns(&self, e: &AclEntry) -> bool {
        e.ugid_type == "user" && self.auth_ids().contains(&e.ugid.as_str())
    }

    fn token_path(&self) -> String {
        format!("/access/users/{}/token/{TOKEN_NAME}", encode(&self.userid))
    }

    fn user_path(&self) -> String {
        format!("/access/users/{}", encode(&self.userid))
    }
}

/// Host names become a PBS user name and a namespace component, so they must
/// satisfy both.
pub fn validate_host(host: &str) -> Result<()> {
    let mut chars = host.chars();
    let ok = (1..=32).contains(&host.len())
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !ok {
        bail!("invalid host '{host}': must match ^[A-Za-z0-9][A-Za-z0-9_-]{{0,31}}$");
    }
    Ok(())
}

pub fn validate_datastore(store: &str) -> Result<()> {
    if store.contains('/') {
        bail!("invalid datastore '{store}'");
    }
    api::validate_ns(store).map_err(|_| anyhow!("invalid datastore '{store}'"))
}

/// Name of the orca secret holding a host's token secret.
pub fn secret_name(endpoint: &str, host: &str) -> String {
    endpoint::secret_name(endpoint, &format!("host_{host}_token"))
}

#[orca_struct]
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: String,
    pub detail: String,
}

fn finding(kind: &str, detail: impl Into<String>) -> Finding {
    Finding {
        kind: kind.to_string(),
        detail: detail.into(),
    }
}

/// Whether the token secret orca holds still authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretState {
    /// orca holds no secret for this token.
    Missing,
    Valid,
    /// PBS rejected it: the token was regenerated or recreated elsewhere.
    Rejected,
    /// The check itself failed; nothing is concluded.
    Unknown,
}

#[derive(Debug, Clone)]
pub struct State {
    pub namespaces: Vec<Namespace>,
    pub users: Vec<User>,
    pub acls: Vec<AclEntry>,
    pub secret: SecretState,
    pub now: i64,
}

fn reactivate() -> Value {
    json!({ "enable": true, "expire": 0 })
}

/// Drift and the steps that remove it.
pub fn diff_enroll(id: &Identity, st: &State) -> (Vec<Finding>, Vec<Step>) {
    let mut findings = Vec::new();
    let mut steps = Vec::new();

    let ns_steps: Vec<Step> =
        crate::tools::namespace_create_steps(&id.datastore, &st.namespaces, &id.ns);
    if !ns_steps.is_empty() {
        findings.push(finding(
            "namespace-missing",
            format!("{}:{}", id.datastore, id.ns),
        ));
        steps.extend(ns_steps);
    }

    let user = st.users.iter().find(|u| u.userid == id.userid);
    match user {
        None => {
            findings.push(finding("user-missing", &id.userid));
            steps.push(Step::new(
                &id.userid,
                "create-user",
                ApiCall::Post {
                    path: "/access/users".into(),
                    body: json!({
                        "userid": id.userid,
                        "comment": format!("orca: backup client for {}", id.host),
                    }),
                },
            ));
        }
        Some(u) if !api::is_active(u.enable, u.expire, st.now) => {
            findings.push(finding(
                "user-inactive",
                format!("{} is disabled or expired", id.userid),
            ));
            steps.push(Step::new(
                &id.userid,
                "enable-user",
                ApiCall::Put {
                    path: id.user_path(),
                    body: reactivate(),
                },
            ));
        }
        Some(_) => {}
    }

    let token = user.and_then(|u| u.tokens.iter().find(|t| t.tokenid == id.tokenid));
    match token {
        None => {
            findings.push(finding("token-missing", &id.tokenid));
            steps.push(
                Step::new(
                    &id.tokenid,
                    "create-token",
                    ApiCall::Post {
                        path: id.token_path(),
                        body: json!({ "comment": format!("orca: {} backups", id.host) }),
                    },
                )
                .detail("secret is stored in orca, never printed")
                .sensitive(),
            );
        }
        Some(t) => {
            let inactive = !api::is_active(t.enable, t.expire, st.now);
            if inactive {
                findings.push(finding(
                    "token-inactive",
                    format!("{} is disabled or expired", id.tokenid),
                ));
            }
            let rotate = match st.secret {
                SecretState::Missing => {
                    findings.push(finding(
                        "secret-missing",
                        format!("orca holds no secret for {}", id.tokenid),
                    ));
                    true
                }
                SecretState::Rejected => {
                    findings.push(finding(
                        "token-rotated",
                        format!("PBS rejects the secret orca holds for {}", id.tokenid),
                    ));
                    true
                }
                SecretState::Unknown => {
                    findings.push(finding(
                        "secret-unverified",
                        format!("could not check the stored secret for {}", id.tokenid),
                    ));
                    false
                }
                SecretState::Valid => false,
            };
            if rotate {
                let mut body = json!({ "regenerate": true });
                if inactive {
                    body["enable"] = json!(true);
                    body["expire"] = json!(0);
                }
                steps.push(
                    Step::new(
                        &id.tokenid,
                        "regenerate-token",
                        ApiCall::Put {
                            path: id.token_path(),
                            body,
                        },
                    )
                    .detail("keeps its ACLs; the new secret is stored in orca, never printed")
                    .sensitive(),
                );
            } else if inactive {
                steps.push(Step::new(
                    &id.tokenid,
                    "enable-token",
                    ApiCall::Put {
                        path: id.token_path(),
                        body: reactivate(),
                    },
                ));
            }
        }
    }

    for auth in id.auth_ids() {
        for role in ROLES {
            let have = st.acls.iter().find(|e| {
                e.path == id.acl_path && e.ugid == auth && e.roleid == role && e.ugid_type == "user"
            });
            if have.is_some_and(|e| e.propagate) {
                continue;
            }
            findings.push(finding(
                if have.is_some() {
                    "acl-not-propagated"
                } else {
                    "acl-missing"
                },
                format!("{role} for {auth} on {}", id.acl_path),
            ));
            steps.push(Step::new(
                format!("{auth} {}", id.acl_path),
                format!("grant-{role}"),
                ApiCall::Put {
                    path: "/access/acl".into(),
                    body: json!({ "path": id.acl_path, "role": role, "auth-id": auth, "propagate": true }),
                },
            ));
        }
    }

    for e in st.acls.iter().filter(|e| id.owns(e)) {
        if e.path == id.acl_path && ROLES.contains(&e.roleid.as_str()) {
            continue;
        }
        findings.push(finding(
            "acl-out-of-scope",
            format!("{} for {} on {}", e.roleid, e.ugid, e.path),
        ));
        steps.push(revoke_acl(e));
    }

    (findings, steps)
}

fn revoke_acl(e: &AclEntry) -> Step {
    Step::new(
        format!("{} {}", e.ugid, e.path),
        format!("revoke-{}", e.roleid),
        ApiCall::Put {
            path: "/access/acl".into(),
            body: json!({ "path": e.path, "role": e.roleid, "auth-id": e.ugid, "delete": true }),
        },
    )
}

/// Steps that remove the host's access, and its data only if asked.
pub fn diff_revoke(id: &Identity, st: &State, delete_data: bool) -> (Vec<Step>, Vec<String>) {
    let mut steps: Vec<Step> = st
        .acls
        .iter()
        .filter(|e| id.owns(e))
        .map(revoke_acl)
        .collect();
    let mut notes = Vec::new();
    let user = st.users.iter().find(|u| u.userid == id.userid);
    if user.is_some_and(|u| u.tokens.iter().any(|t| t.tokenid == id.tokenid)) {
        steps.push(Step::new(
            &id.tokenid,
            "delete-token",
            ApiCall::Delete {
                path: id.token_path(),
                query: Vec::new(),
            },
        ));
    }
    if user.is_some() {
        steps.push(Step::new(
            &id.userid,
            "delete-user",
            ApiCall::Delete {
                path: id.user_path(),
                query: Vec::new(),
            },
        ));
    }
    let ns_exists = st.namespaces.iter().any(|n| n.ns == id.ns);
    match (ns_exists, delete_data) {
        (true, true) => {
            let (ns_steps, _) =
                crate::tools::namespace_delete_steps(&id.datastore, &st.namespaces, &id.ns, true);
            steps.extend(ns_steps);
        }
        (true, false) => notes.push(format!(
            "namespace {}:{} and its backups are kept; pass delete_data to remove them",
            id.datastore, id.ns
        )),
        (false, _) => {}
    }
    (steps, notes)
}

async fn check_secret(c: &PbsClient, tokenid: &str, stored: Option<String>) -> SecretState {
    let Some(secret) = stored else {
        return SecretState::Missing;
    };
    let Ok(token) = ApiToken::new(tokenid, secret) else {
        return SecretState::Rejected;
    };
    match c.with_token(token).status_of("/version").await {
        Ok(401) => SecretState::Rejected,
        Ok(s) if (200..300).contains(&s) || s == 403 => SecretState::Valid,
        _ => SecretState::Unknown,
    }
}

async fn read_state(c: &PbsClient, id: &Identity, stored: Option<String>) -> Result<State> {
    Ok(State {
        namespaces: api::namespaces(c, &id.datastore).await?,
        users: api::users(c).await?,
        acls: api::acls(c).await?,
        secret: check_secret(c, &id.tokenid, stored).await,
        now: plugin_toolkit::time::now().unix_seconds(),
    })
}

/// The minted secret from a create (`value`) or regenerate (`secret`) reply.
fn minted_secret(steps: &[Step], results: &[Value]) -> Option<String> {
    steps
        .iter()
        .zip(results)
        .filter(|(s, _)| s.sensitive_result)
        .find_map(|(_, r)| {
            r.get("value")
                .or_else(|| r.get("secret"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.host.enroll
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct HostEnrollArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Backup client host name (e.g. `freyr`).
    #[arg(long)]
    pub host: String,
    /// Datastore the host backs up into.
    #[arg(long)]
    pub datastore: String,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

/// A secret returned because orca could not store it. Shown once.
#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SensitiveSecret {
    pub sensitive: bool,
    pub token_id: String,
    pub value: String,
    pub note: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct HostEnrollOutput {
    pub host: String,
    pub datastore: String,
    pub namespace: String,
    pub user_id: String,
    pub token_id: String,
    pub acl_path: String,
    /// Deviations from the desired set, found before any change.
    pub findings: Vec<Finding>,
    pub change: Change,
    /// orca secret holding the token secret, once one has been stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_secret: Option<SensitiveSecret>,
}

/// Enrol a backup client host: namespace `hosts/<host>`, user `<host>@pbs`,
/// token `<host>@pbs!backup`, and DatastoreBackup + DatastorePowerUser on
/// `/datastore/<ds>/hosts/<host>` only. Reports drift; dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "host.enroll",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_host_enroll(args: HostEnrollArgs, ctx: &ToolCtx) -> Result<HostEnrollOutput> {
    let id = Identity::new(&args.host, &args.datastore)?;
    let (ep, c) = endpoint::connect_named(args.endpoint.as_deref()).await?;
    enroll(&ep, &c, &id, &args, ctx.caller().as_ref()).await
}

async fn enroll(
    ep: &str,
    c: &PbsClient,
    id: &Identity,
    args: &HostEnrollArgs,
    caller: Option<&plugin_toolkit::contract::CallerIdentity>,
) -> Result<HostEnrollOutput> {
    const TOOL: &str = "pbs.host.enroll";
    let sname = secret_name(ep, &id.host);
    let stored = secrets::get(&sname)?.filter(|s| !s.is_empty());
    let held = stored.is_some();
    let st = read_state(c, id, stored).await?;
    let (findings, steps) = diff_enroll(id, &st);
    let summary = format!("enrol {} on {}:{}", id.host, id.datastore, id.ns);
    let mut out = HostEnrollOutput {
        host: id.host.clone(),
        datastore: id.datastore.clone(),
        namespace: id.ns.clone(),
        user_id: id.userid.clone(),
        token_id: id.tokenid.clone(),
        acl_path: id.acl_path.clone(),
        findings,
        change: Change::Plan(plan::plan(TOOL, args, summary.clone(), &steps, &[])?),
        secret_ref: held.then(|| sname.clone()),
        token_secret: None,
    };
    if !args.execute {
        return Ok(out);
    }
    plan::authorize_execute(TOOL, caller)?;
    let results = plan::run(TOOL, c, &steps).await?;
    let mut notes = Vec::new();
    if let Some(secret) = minted_secret(&steps, &results) {
        let desc = format!("PBS token {} (pbs endpoint '{ep}')", id.tokenid);
        match secrets::set(&sname, &secret, Some(&desc)) {
            Ok(_) => out.secret_ref = Some(sname),
            Err(e) => {
                notes.push(format!("could not store the token secret in orca: {e:#}"));
                out.secret_ref = None;
                out.token_secret = Some(SensitiveSecret {
                    sensitive: true,
                    token_id: id.tokenid.clone(),
                    value: secret,
                    note: "orca could not store this secret and PBS will not show it again; \
                           save it now or re-run enroll to regenerate"
                        .into(),
                });
            }
        }
    }
    out.change = Change::Applied(plan::applied(TOOL, summary, &steps, &results, notes));
    Ok(out)
}

// ═══════════════════════════════════════════════════════════════════════════
// pbs.host.revoke
// ═══════════════════════════════════════════════════════════════════════════

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct HostRevokeArgs {
    #[arg(long)]
    #[serde(default)]
    pub endpoint: Option<String>,
    #[arg(long)]
    pub host: String,
    #[arg(long)]
    pub datastore: String,
    /// Also delete namespace `hosts/<host>` and every backup in it.
    #[arg(long)]
    #[serde(default)]
    pub delete_data: bool,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct HostRevokeOutput {
    pub host: String,
    pub change: Change,
    /// Whether orca's copy of the token secret was removed.
    pub secret_removed: bool,
}

/// Revoke a host: its ACLs (on any path), token and user. Backups are kept
/// unless `delete_data`. Dry-run by default.
#[orca_tool(
    domain = "pbs",
    verb = "host.revoke",
    role = "admin",
    execute_gated = false
)]
pub async fn pbs_host_revoke(args: HostRevokeArgs, ctx: &ToolCtx) -> Result<HostRevokeOutput> {
    let id = Identity::new(&args.host, &args.datastore)?;
    let (ep, c) = endpoint::connect_named(args.endpoint.as_deref()).await?;
    revoke(&ep, &c, &id, &args, ctx.caller().as_ref()).await
}

async fn revoke(
    ep: &str,
    c: &PbsClient,
    id: &Identity,
    args: &HostRevokeArgs,
    caller: Option<&plugin_toolkit::contract::CallerIdentity>,
) -> Result<HostRevokeOutput> {
    const TOOL: &str = "pbs.host.revoke";
    let st = State {
        namespaces: api::namespaces(c, &id.datastore).await?,
        users: api::users(c).await?,
        acls: api::acls(c).await?,
        secret: SecretState::Unknown,
        now: 0,
    };
    let (steps, mut notes) = diff_revoke(id, &st, args.delete_data);
    let sname = secret_name(ep, &id.host);
    let summary = format!("revoke {} on {}", id.host, id.datastore);
    if !args.execute {
        if secrets::exists(&sname)? {
            notes.push(format!("orca secret {sname} would be removed"));
        }
        return Ok(HostRevokeOutput {
            host: id.host.clone(),
            change: Change::Plan(plan::plan(TOOL, args, summary, &steps, &notes)?),
            secret_removed: false,
        });
    }
    plan::authorize_execute(TOOL, caller)?;
    let results = plan::run(TOOL, c, &steps).await?;
    let secret_removed = secrets::delete(&sname)?;
    Ok(HostRevokeOutput {
        host: id.host.clone(),
        change: Change::Applied(plan::applied(TOOL, summary, &steps, &results, notes)),
        secret_removed,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use plugin_toolkit::serde_json;

    use super::*;
    use crate::api::fixtures::*;
    use crate::client::mock::MockTransport;
    use crate::client::Method;
    use crate::endpoint::test_store::{with_store, Store};
    use crate::plan::admin;

    fn state(secret: SecretState) -> State {
        State {
            namespaces: serde_json::from_value(data(NAMESPACE_LIST)).unwrap(),
            users: serde_json::from_value(data(USERS_LIST)).unwrap(),
            acls: serde_json::from_value(data(ACL_LIST)).unwrap(),
            secret,
            now: 1_759_600_000,
        }
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind.as_str()).collect()
    }

    #[test]
    fn identity_is_derived_from_host_and_datastore() {
        let id = Identity::new("freyr", "main").unwrap();
        assert_eq!(id.userid, "freyr@pbs");
        assert_eq!(id.tokenid, "freyr@pbs!backup");
        assert_eq!(id.ns, "hosts/freyr");
        assert_eq!(id.acl_path, "/datastore/main/hosts/freyr");
        assert!(Identity::new("bad host", "main").is_err());
        assert!(Identity::new("ok", "a/b").is_err());
        assert!(Identity::new("-x", "main").is_err());
    }

    #[test]
    fn fresh_host_gets_everything_in_dependency_order() {
        let id = Identity::new("willow", "main").unwrap();
        let (f, steps) = diff_enroll(&id, &state(SecretState::Missing));
        assert_eq!(
            kinds(&f),
            vec![
                "namespace-missing",
                "user-missing",
                "token-missing",
                "acl-missing",
                "acl-missing",
                "acl-missing",
                "acl-missing"
            ]
        );
        let actions: Vec<&str> = steps.iter().map(|s| s.action.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "create-namespace",
                "create-user",
                "create-token",
                "grant-DatastoreBackup",
                "grant-DatastorePowerUser",
                "grant-DatastoreBackup",
                "grant-DatastorePowerUser"
            ]
        );
        assert!(steps[2].sensitive_result);
        assert_eq!(
            steps[6].call,
            ApiCall::Put {
                path: "/access/acl".into(),
                body: json!({
                    "path": "/datastore/main/hosts/willow",
                    "role": "DatastorePowerUser",
                    "auth-id": "willow@pbs!backup",
                    "propagate": true
                }),
            }
        );
    }

    #[test]
    fn enrolled_host_reports_only_out_of_scope_acl() {
        let id = Identity::new("freyr", "main").unwrap();
        let (f, steps) = diff_enroll(&id, &state(SecretState::Valid));
        assert_eq!(kinds(&f), vec!["acl-out-of-scope"]);
        assert_eq!(steps.len(), 1);
        assert_eq!(
            steps[0].call,
            ApiCall::Put {
                path: "/access/acl".into(),
                body: json!({
                    "path": "/datastore/main",
                    "role": "DatastoreAdmin",
                    "auth-id": "freyr@pbs!backup",
                    "delete": true
                }),
            }
        );
    }

    #[test]
    fn rejected_secret_regenerates_the_token() {
        let id = Identity::new("freyr", "main").unwrap();
        let (f, steps) = diff_enroll(&id, &state(SecretState::Rejected));
        assert!(kinds(&f).contains(&"token-rotated"));
        let regen = steps
            .iter()
            .find(|s| s.action == "regenerate-token")
            .unwrap();
        assert!(regen.sensitive_result);
        assert_eq!(
            regen.call,
            ApiCall::Put {
                path: "/access/users/freyr%40pbs/token/backup".into(),
                body: json!({"regenerate": true}),
            }
        );
        let (f, steps) = diff_enroll(&id, &state(SecretState::Unknown));
        assert!(kinds(&f).contains(&"secret-unverified"));
        assert!(!steps.iter().any(|s| s.action == "regenerate-token"));
    }

    #[test]
    fn partial_host_gets_missing_token_and_acls_only() {
        let id = Identity::new("baldur", "main").unwrap();
        let (f, steps) = diff_enroll(&id, &state(SecretState::Missing));
        assert_eq!(
            kinds(&f),
            vec!["token-missing", "acl-missing", "acl-missing", "acl-missing"]
        );
        assert_eq!(steps[0].action, "create-token");
        assert!(!steps
            .iter()
            .any(|s| s.target.contains("baldur@pbs /") && s.action == "grant-DatastoreBackup"));
    }

    #[test]
    fn expired_token_is_reactivated() {
        let id = Identity::new("freyr", "main").unwrap();
        let mut st = state(SecretState::Valid);
        st.users[1].tokens[0].expire = Some(1);
        let (f, steps) = diff_enroll(&id, &st);
        assert!(kinds(&f).contains(&"token-inactive"));
        let s = steps.iter().find(|s| s.action == "enable-token").unwrap();
        assert_eq!(
            s.call,
            ApiCall::Put {
                path: "/access/users/freyr%40pbs/token/backup".into(),
                body: json!({"enable": true, "expire": 0}),
            }
        );
    }

    #[test]
    fn revoke_keeps_data_unless_asked() {
        let id = Identity::new("freyr", "main").unwrap();
        let (steps, notes) = diff_revoke(&id, &state(SecretState::Unknown), false);
        let actions: Vec<&str> = steps.iter().map(|s| s.action.as_str()).collect();
        assert_eq!(
            actions,
            vec![
                "revoke-DatastoreBackup",
                "revoke-DatastorePowerUser",
                "revoke-DatastoreBackup",
                "revoke-DatastorePowerUser",
                "revoke-DatastoreAdmin",
                "delete-token",
                "delete-user"
            ]
        );
        assert!(notes[0].contains("are kept"));
        let (steps, notes) = diff_revoke(&id, &state(SecretState::Unknown), true);
        assert_eq!(steps.last().unwrap().action, "delete-namespace");
        assert!(notes.is_empty());
    }

    fn enroll_mock() -> MockTransport {
        let m = MockTransport::new();
        m.on(
            Method::Get,
            "/admin/datastore/main/namespace",
            200,
            NAMESPACE_LIST,
        );
        m.on(Method::Get, "/access/users", 200, USERS_LIST);
        m.on(Method::Get, "/access/acl", 200, ACL_LIST);
        m.ok(Method::Post, "/admin/datastore/main/namespace", Value::Null);
        m.ok(Method::Post, "/access/users", Value::Null);
        m.on(
            Method::Post,
            "/access/users/willow%40pbs/token/backup",
            200,
            TOKEN_CREATE,
        );
        m.on(
            Method::Put,
            "/access/users/freyr%40pbs/token/backup",
            200,
            TOKEN_REGENERATE,
        );
        m.ok(Method::Put, "/access/acl", Value::Null);
        m
    }

    fn enroll_args(host: &str, execute: bool) -> HostEnrollArgs {
        HostEnrollArgs {
            endpoint: None,
            host: host.into(),
            datastore: "main".into(),
            execute,
        }
    }

    fn run_enroll(
        store: &Rc<RefCell<Store>>,
        m: &MockTransport,
        host: &str,
        execute: bool,
    ) -> Result<HostEnrollOutput> {
        let id = Identity::new(host, "main").unwrap();
        let c = m.client();
        let args = enroll_args(host, execute);
        let admin = admin();
        with_store(store, || {
            crate::endpoint::test_store::rt().block_on(enroll(
                "willow-pbs",
                &c,
                &id,
                &args,
                Some(&admin),
            ))
        })
    }

    #[test]
    fn dry_run_reads_but_never_writes() {
        let store = Rc::new(RefCell::new(Store::default()));
        let m = enroll_mock();
        let out = run_enroll(&store, &m, "willow", false).unwrap();
        assert!(matches!(out.change, Change::Plan(_)));
        assert!(m.mutations().is_empty(), "{:?}", m.mutations());
        assert!(store.borrow().secrets.is_empty());
        assert!(out.secret_ref.is_none());
    }

    #[test]
    fn execute_stores_the_minted_secret_and_never_returns_it() {
        let store = Rc::new(RefCell::new(Store::default()));
        let m = enroll_mock();
        let out = run_enroll(&store, &m, "willow", true).unwrap();
        let minted = "0f6e2c1a-5d1b-4e7a-9c3e-2b8d7a6f1e00";
        assert_eq!(
            store
                .borrow()
                .secrets
                .get("pbs.willow-pbs.host_willow_token")
                .map(String::as_str),
            Some(minted)
        );
        assert_eq!(
            out.secret_ref.as_deref(),
            Some("pbs.willow-pbs.host_willow_token")
        );
        assert!(out.token_secret.is_none());
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains(minted), "secret leaked into output");
        assert_eq!(m.mutations().len(), 7);
    }

    #[test]
    fn execute_returns_secret_once_when_orca_cannot_store_it() {
        let store = Rc::new(RefCell::new(Store {
            fail_secret_set: true,
            ..Default::default()
        }));
        let m = enroll_mock();
        let out = run_enroll(&store, &m, "willow", true).unwrap();
        let s = out.token_secret.expect("secret handed back");
        assert!(s.sensitive);
        assert_eq!(s.value, "0f6e2c1a-5d1b-4e7a-9c3e-2b8d7a6f1e00");
        assert!(out.secret_ref.is_none());
    }

    #[test]
    fn stored_secret_rejected_by_pbs_is_rotated_on_execute() {
        let store = Rc::new(RefCell::new(Store::default()));
        store.borrow_mut().secrets.insert(
            "pbs.willow-pbs.host_freyr_token".into(),
            "stale-secret".into(),
        );
        let m = enroll_mock();
        m.on(
            Method::Get,
            "/version",
            401,
            r#"{"data":null,"message":"authentication failed"}"#,
        );
        let out = run_enroll(&store, &m, "freyr", true).unwrap();
        assert!(out.findings.iter().any(|f| f.kind == "token-rotated"));
        assert_eq!(
            store.borrow().secrets["pbs.willow-pbs.host_freyr_token"],
            "7a1c9e4b-2f3d-4c6a-8b5e-1d0f9e8c7b6a"
        );
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains("7a1c9e4b") && !json.contains("stale-secret"));
    }

    #[test]
    fn stored_secret_accepted_by_pbs_is_left_alone() {
        let store = Rc::new(RefCell::new(Store::default()));
        store.borrow_mut().secrets.insert(
            "pbs.willow-pbs.host_freyr_token".into(),
            "good-secret".into(),
        );
        let m = enroll_mock();
        m.ok(Method::Get, "/version", json!({"version": "4.2"}));
        let out = run_enroll(&store, &m, "freyr", false).unwrap();
        assert_eq!(kinds(&out.findings), vec!["acl-out-of-scope"]);
        let probe = m
            .calls
            .lock()
            .unwrap()
            .iter()
            .find(|c| c.url.ends_with("/version"))
            .cloned()
            .unwrap();
        let auth = &probe
            .headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1;
        assert_eq!(auth, "PBSAPIToken=freyr@pbs!backup:good-secret");
    }

    #[test]
    fn revoke_execute_removes_access_and_orca_secret() {
        let store = Rc::new(RefCell::new(Store::default()));
        store
            .borrow_mut()
            .secrets
            .insert("pbs.willow-pbs.host_freyr_token".into(), "s".into());
        let m = enroll_mock();
        m.ok(
            Method::Delete,
            "/access/users/freyr%40pbs/token/backup",
            Value::Null,
        );
        m.ok(Method::Delete, "/access/users/freyr%40pbs", Value::Null);
        let id = Identity::new("freyr", "main").unwrap();
        let c = m.client();
        let args = HostRevokeArgs {
            endpoint: None,
            host: "freyr".into(),
            datastore: "main".into(),
            delete_data: false,
            execute: true,
        };
        let admin = admin();
        let out = with_store(&store, || {
            crate::endpoint::test_store::rt().block_on(revoke(
                "willow-pbs",
                &c,
                &id,
                &args,
                Some(&admin),
            ))
        })
        .unwrap();
        assert!(out.secret_removed);
        assert!(!m.mutations().iter().any(|l| l.contains("namespace")));
        assert_eq!(m.mutations().len(), 7);
    }
}
