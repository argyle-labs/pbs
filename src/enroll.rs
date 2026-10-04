//! `pbs.host.enroll|revoke`: one namespace, user, API token and ACL set per
//! backup client host, so a host can write and prune only its own backups.
//!
//! Enrolment is level-triggered: it reads the live state, reports every
//! deviation from the desired set as a [`Finding`], and plans only the calls
//! that close the gap. Re-running on an enrolled host is a no-op.
//!
//! Execute acts only on the plan items the caller echoes back (`items`), and
//! the token secret is never returned: it is written to orca's secrets domain
//! right after PBS mints it, before any later call runs.

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
/// Host names that would collide with an operator or service account.
const RESERVED: [&str; 3] = ["admin", "root", "orca"];
/// Prefix of the comment orca puts on users it creates. A user without it was
/// made by hand and is only taken over with `adopt`.
pub const MARKER: &str = "orca: backup client for";

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

    /// An enrol role on `/datastore/<any>/hosts/<host>`: a host enrolled into
    /// several datastores keeps each grant.
    fn in_scope(&self, e: &AclEntry) -> bool {
        let tail = format!("/hosts/{}", self.host);
        let store_ok = e
            .path
            .strip_prefix("/datastore/")
            .and_then(|rest| rest.strip_suffix(&tail))
            .is_some_and(|store| !store.is_empty() && !store.contains('/'));
        store_ok && ROLES.contains(&e.roleid.as_str())
    }

    fn token_path(&self) -> String {
        format!("/access/users/{}/token/{TOKEN_NAME}", encode(&self.userid))
    }

    fn user_path(&self) -> String {
        format!("/access/users/{}", encode(&self.userid))
    }

    /// Refuse to act on the account behind the endpoint's own token: enrolling
    /// or revoking it would rewrite or delete the credential orca manages
    /// PBS with.
    fn check_not_self(&self, c: &PbsClient) -> Result<()> {
        let own_user = c.token_id().split('!').next().unwrap_or_default();
        if own_user == self.userid {
            bail!(
                "host '{}' maps to {}, the user behind this endpoint's own token; refusing",
                self.host,
                self.userid
            );
        }
        Ok(())
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
    if RESERVED.iter().any(|r| r.eq_ignore_ascii_case(host)) {
        bail!("host name '{host}' is reserved");
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

fn is_marked(u: &User) -> bool {
    u.comment.as_deref().is_some_and(|c| c.starts_with(MARKER))
}

fn require_managed(id: &Identity, user: Option<&User>, adopt: bool) -> Result<()> {
    match user {
        Some(u) if !is_marked(u) && !adopt => bail!(
            "user {} exists but was not created by orca (its comment lacks '{MARKER}'); \
             pass adopt: true to take it over",
            id.userid
        ),
        _ => Ok(()),
    }
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
    pub acl_digest: Option<String>,
    pub secret: SecretState,
    pub now: i64,
}

fn user_target(id: &Identity) -> String {
    format!("user:{}", id.userid)
}

fn token_target(id: &Identity) -> String {
    format!("token:{}", id.tokenid)
}

fn acl_target(auth: &str, path: &str, role: &str) -> String {
    format!("acl:{auth}:{path}:{role}")
}

fn acl_put(path: &str, role: &str, auth: &str, delete: bool) -> Value {
    if delete {
        json!({ "path": path, "role": role, "auth-id": auth, "delete": true })
    } else {
        json!({ "path": path, "role": role, "auth-id": auth, "propagate": true })
    }
}

/// Echo the `acl.cfg` digest on the first ACL write only: that write changes
/// the digest, so later writes would be refused if they carried it too.
fn stamp_acl_digest(steps: &mut [Step], digest: Option<&str>) {
    let Some(d) = digest else { return };
    let first = steps.iter_mut().find_map(|s| match &mut s.call {
        ApiCall::Put { path, body } if path == "/access/acl" => Some(body),
        _ => None,
    });
    if let Some(body) = first {
        body["digest"] = json!(d);
    }
}

/// Drift and the steps that remove it. Errors if the user exists but is not
/// orca-managed and `adopt` is not set.
pub fn diff_enroll(id: &Identity, st: &State, adopt: bool) -> Result<(Vec<Finding>, Vec<Step>)> {
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
    require_managed(id, user, adopt)?;
    let marker = format!("{MARKER} {}", id.host);
    match user {
        None => {
            findings.push(finding("user-missing", &id.userid));
            steps.push(Step::new(
                user_target(id),
                "create-user",
                ApiCall::Post {
                    path: "/access/users".into(),
                    body: json!({ "userid": id.userid, "comment": marker }),
                },
            ));
        }
        Some(u) => {
            let mut body = json!({});
            if !is_marked(u) {
                findings.push(finding(
                    "user-unmanaged",
                    format!("{} was created by hand; adopting it", id.userid),
                ));
                body["comment"] = json!(marker);
            }
            if !api::is_active(u.enable, u.expire, st.now) {
                findings.push(finding(
                    "user-inactive",
                    format!("{} is disabled or expired", id.userid),
                ));
                body["enable"] = json!(true);
                body["expire"] = json!(0);
            }
            if body.as_object().is_some_and(|o| !o.is_empty()) {
                steps.push(Step::new(
                    user_target(id),
                    "update-user",
                    ApiCall::Put {
                        path: id.user_path(),
                        body,
                    },
                ));
            }
        }
    }

    let token = user.and_then(|u| u.tokens.iter().find(|t| t.tokenid == id.tokenid));
    match token {
        None => {
            findings.push(finding("token-missing", &id.tokenid));
            steps.push(
                Step::new(
                    token_target(id),
                    "create-token",
                    ApiCall::Post {
                        path: id.token_path(),
                        body: json!({ "comment": format!("orca: {} backups", id.host) }),
                    },
                )
                .detail("secret is stored in orca as soon as PBS returns it, never printed")
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
            let mut body = json!({});
            if rotate {
                body["regenerate"] = json!(true);
            }
            if inactive {
                body["enable"] = json!(true);
                body["expire"] = json!(0);
            }
            if rotate {
                steps.push(
                    Step::new(
                        token_target(id),
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
                    token_target(id),
                    "enable-token",
                    ApiCall::Put {
                        path: id.token_path(),
                        body,
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
                acl_target(auth, &id.acl_path, role),
                format!("grant-{role}"),
                ApiCall::Put {
                    path: "/access/acl".into(),
                    body: acl_put(&id.acl_path, role, auth, false),
                },
            ));
        }
    }

    for e in st.acls.iter().filter(|e| id.owns(e) && !id.in_scope(e)) {
        findings.push(finding(
            "acl-out-of-scope",
            format!("{} for {} on {}", e.roleid, e.ugid, e.path),
        ));
        steps.push(revoke_acl(e));
    }

    stamp_acl_digest(&mut steps, st.acl_digest.as_deref());
    Ok((findings, steps))
}

fn revoke_acl(e: &AclEntry) -> Step {
    Step::new(
        acl_target(&e.ugid, &e.path, &e.roleid),
        format!("revoke-{}", e.roleid),
        ApiCall::Put {
            path: "/access/acl".into(),
            body: acl_put(&e.path, &e.roleid, &e.ugid, true),
        },
    )
}

/// Steps that remove the host's access, and its data only if asked. Errors if
/// the user exists but is not orca-managed and `adopt` is not set.
pub fn diff_revoke(
    id: &Identity,
    st: &State,
    delete_data: bool,
    adopt: bool,
) -> Result<(Vec<Step>, Vec<String>)> {
    let user = st.users.iter().find(|u| u.userid == id.userid);
    require_managed(id, user, adopt)?;
    let mut steps: Vec<Step> = st
        .acls
        .iter()
        .filter(|e| id.owns(e))
        .map(revoke_acl)
        .collect();
    stamp_acl_digest(&mut steps, st.acl_digest.as_deref());
    let mut notes = Vec::new();
    if user.is_some_and(|u| u.tokens.iter().any(|t| t.tokenid == id.tokenid)) {
        steps.push(Step::new(
            token_target(id),
            "delete-token",
            ApiCall::Delete {
                path: id.token_path(),
                query: Vec::new(),
            },
        ));
    }
    if user.is_some() {
        steps.push(Step::new(
            user_target(id),
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
    Ok((steps, notes))
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
    let (acls, acl_digest) = api::acls_with_digest(c).await?;
    Ok(State {
        namespaces: api::namespaces(c, &id.datastore).await?,
        users: api::users(c).await?,
        acls,
        acl_digest,
        secret: check_secret(c, &id.tokenid, stored).await,
        now: plugin_toolkit::time::now().unix_seconds(),
    })
}

/// The minted secret from a create (`value`) or regenerate (`secret`) reply.
fn minted_secret(reply: &Value) -> Option<&str> {
    reply
        .get("value")
        .or_else(|| reply.get("secret"))
        .and_then(Value::as_str)
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
    /// Backup client host name (e.g. `freyr`). `admin`, `root` and `orca` are
    /// reserved.
    #[arg(long)]
    pub host: String,
    /// Datastore the host backs up into.
    #[arg(long)]
    pub datastore: String,
    /// Take over an existing `<host>@pbs` user orca did not create.
    #[arg(long)]
    #[serde(default)]
    pub adopt: bool,
    /// The dry run's change targets to apply (execute only). Comma-separated
    /// on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
    #[arg(long)]
    #[serde(default)]
    pub execute: bool,
}

#[orca_struct]
#[derive(Debug)]
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
}

/// Enrol a backup client host: namespace `hosts/<host>`, user `<host>@pbs`,
/// token `<host>@pbs!backup`, and DatastoreBackup + DatastorePowerUser on
/// `/datastore/<ds>/hosts/<host>` only. Reports drift; dry-run by default.
/// Execute applies only the `items` echoed from the dry run.
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
    id.check_not_self(c)?;
    let sname = secret_name(ep, &id.host);
    let stored = secrets::get(&sname)?.filter(|s| !s.is_empty());
    let held = stored.is_some();
    let st = read_state(c, id, stored).await?;
    let (findings, steps) = diff_enroll(id, &st, args.adopt)?;
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
    };
    if !args.execute {
        return Ok(out);
    }
    plan::authorize_execute(TOOL, caller)?;
    let (steps, notes) = plan::confirm(TOOL, steps, &args.items)?;
    let desc = format!("PBS token {} (pbs endpoint '{ep}')", id.tokenid);
    let mut stored_now = false;
    let results = plan::run_with(TOOL, c, &steps, |step, reply| {
        if !step.sensitive_result {
            return Ok(());
        }
        let secret = minted_secret(reply)
            .ok_or_else(|| anyhow!("PBS returned no secret for {}", id.tokenid))?;
        secrets::set(&sname, secret, Some(&desc)).map_err(|e| {
            anyhow!(
                "token secret for {} was minted but not stored ({e:#}); fix the secret backend \
                 and re-run, which regenerates it",
                id.tokenid
            )
        })?;
        stored_now = true;
        Ok(())
    })
    .await?;
    if stored_now {
        out.secret_ref = Some(sname);
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
    /// Revoke a `<host>@pbs` user orca did not create.
    #[arg(long)]
    #[serde(default)]
    pub adopt: bool,
    /// The dry run's change targets to apply (execute only). Comma-separated
    /// on the CLI.
    #[arg(long, value_delimiter = ',')]
    #[serde(default)]
    pub items: Vec<String>,
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
/// unless `delete_data`. Dry-run by default; execute applies only the `items`
/// echoed from the dry run.
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
    id.check_not_self(c)?;
    let (acls, acl_digest) = api::acls_with_digest(c).await?;
    let st = State {
        namespaces: api::namespaces(c, &id.datastore).await?,
        users: api::users(c).await?,
        acls,
        acl_digest,
        secret: SecretState::Unknown,
        now: 0,
    };
    let token_exists = st
        .users
        .iter()
        .any(|u| u.tokens.iter().any(|t| t.tokenid == id.tokenid));
    let (steps, mut notes) = diff_revoke(id, &st, args.delete_data, args.adopt)?;
    let sname = secret_name(ep, &id.host);
    let summary = format!("revoke {} on {}", id.host, id.datastore);
    if !args.execute {
        if secrets::exists(&sname)? {
            notes.push(format!(
                "orca secret {sname} is removed once the token is gone"
            ));
        }
        return Ok(HostRevokeOutput {
            host: id.host.clone(),
            change: Change::Plan(plan::plan(TOOL, args, summary, &steps, &notes)?),
            secret_removed: false,
        });
    }
    plan::authorize_execute(TOOL, caller)?;
    let (steps, dropped) = plan::confirm(TOOL, steps, &args.items)?;
    notes.extend(dropped);
    let results = plan::run(TOOL, c, &steps).await?;
    let token_gone = !token_exists || steps.iter().any(|s| s.action == "delete-token");
    let secret_removed = token_gone && secrets::delete(&sname)?;
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
    use crate::plan::{admin, items};

    const DIGEST: &str = "3f1a9c0b7e2d4a5f6b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c";

    fn state(secret: SecretState) -> State {
        State {
            namespaces: serde_json::from_value(data(NAMESPACE_LIST)).unwrap(),
            users: serde_json::from_value(data(USERS_LIST)).unwrap(),
            acls: serde_json::from_value(data(ACL_LIST)).unwrap(),
            acl_digest: Some(DIGEST.into()),
            secret,
            now: 1_759_600_000,
        }
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind.as_str()).collect()
    }

    fn actions(steps: &[Step]) -> Vec<&str> {
        steps.iter().map(|s| s.action.as_str()).collect()
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
    fn reserved_names_are_refused() {
        for h in ["admin", "root", "orca", "Root"] {
            let err = Identity::new(h, "main").unwrap_err().to_string();
            assert!(err.contains("reserved"), "{h}: {err}");
        }
    }

    #[test]
    fn the_endpoints_own_user_is_refused() {
        let m = MockTransport::new();
        let own = PbsClient::new(
            "https://pbs.test:8007",
            ApiToken::new("freyr@pbs!admin", "x").unwrap(),
            Box::new(m.clone()),
        );
        let err = Identity::new("freyr", "main")
            .unwrap()
            .check_not_self(&own)
            .unwrap_err();
        assert!(err.to_string().contains("own token"), "{err}");
        assert!(Identity::new("freyr", "main")
            .unwrap()
            .check_not_self(&m.client())
            .is_ok());
    }

    #[test]
    fn fresh_host_gets_everything_in_dependency_order() {
        let id = Identity::new("willow", "main").unwrap();
        let (f, steps) = diff_enroll(&id, &state(SecretState::Missing), false).unwrap();
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
        assert_eq!(
            actions(&steps),
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
            steps[1].call,
            ApiCall::Post {
                path: "/access/users".into(),
                body: json!({"userid": "willow@pbs", "comment": "orca: backup client for willow"}),
            }
        );
        let ApiCall::Put { body, .. } = &steps[3].call else {
            panic!()
        };
        assert_eq!(body["digest"], DIGEST, "first ACL write carries the digest");
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
        let targets = items(&steps);
        let mut unique = targets.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), targets.len(), "plan items must be unique");
    }

    #[test]
    fn enrolled_host_reports_only_out_of_scope_acl() {
        let id = Identity::new("freyr", "main").unwrap();
        let (f, steps) = diff_enroll(&id, &state(SecretState::Valid), false).unwrap();
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
                    "delete": true,
                    "digest": DIGEST
                }),
            }
        );
    }

    #[test]
    fn enrol_roles_on_another_datastore_stay_in_scope() {
        let id = Identity::new("freyr", "main").unwrap();
        let mut st = state(SecretState::Valid);
        for (path, role) in [
            ("/datastore/archive/hosts/freyr", "DatastoreBackup"),
            ("/datastore/archive/hosts/freyr", "DatastorePowerUser"),
            ("/datastore/archive/hosts/freyr", "DatastoreAdmin"),
            ("/datastore/a/b/hosts/freyr", "DatastoreBackup"),
        ] {
            st.acls.push(AclEntry {
                path: path.into(),
                ugid: "freyr@pbs".into(),
                ugid_type: "user".into(),
                roleid: role.into(),
                propagate: true,
            });
        }
        let (f, _) = diff_enroll(&id, &st, false).unwrap();
        let strays: Vec<&str> = f
            .iter()
            .filter(|f| f.kind == "acl-out-of-scope")
            .map(|f| f.detail.as_str())
            .collect();
        assert_eq!(
            strays,
            vec![
                "DatastoreAdmin for freyr@pbs!backup on /datastore/main",
                "DatastoreAdmin for freyr@pbs on /datastore/archive/hosts/freyr",
                "DatastoreBackup for freyr@pbs on /datastore/a/b/hosts/freyr"
            ]
        );
    }

    #[test]
    fn hand_made_user_needs_adopt_and_is_then_marked() {
        let id = Identity::new("baldur", "main").unwrap();
        let err = diff_enroll(&id, &state(SecretState::Missing), false).unwrap_err();
        assert!(err.to_string().contains("adopt"), "{err}");
        let (f, steps) = diff_enroll(&id, &state(SecretState::Missing), true).unwrap();
        assert_eq!(
            kinds(&f),
            vec![
                "user-unmanaged",
                "token-missing",
                "acl-missing",
                "acl-missing",
                "acl-missing"
            ]
        );
        assert_eq!(
            steps[0].call,
            ApiCall::Put {
                path: "/access/users/baldur%40pbs".into(),
                body: json!({"comment": "orca: backup client for baldur"}),
            }
        );
        assert!(diff_revoke(&id, &state(SecretState::Unknown), false, false).is_err());
        assert!(diff_revoke(&id, &state(SecretState::Unknown), false, true).is_ok());
    }

    #[test]
    fn rejected_secret_regenerates_the_token() {
        let id = Identity::new("freyr", "main").unwrap();
        let (f, steps) = diff_enroll(&id, &state(SecretState::Rejected), false).unwrap();
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
        let (f, steps) = diff_enroll(&id, &state(SecretState::Unknown), false).unwrap();
        assert!(kinds(&f).contains(&"secret-unverified"));
        assert!(!steps.iter().any(|s| s.action == "regenerate-token"));
    }

    #[test]
    fn expired_token_is_reactivated() {
        let id = Identity::new("freyr", "main").unwrap();
        let mut st = state(SecretState::Valid);
        st.users[1].tokens[0].expire = Some(1);
        let (f, steps) = diff_enroll(&id, &st, false).unwrap();
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
        let (steps, notes) = diff_revoke(&id, &state(SecretState::Unknown), false, false).unwrap();
        assert_eq!(
            actions(&steps),
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
        let (steps, notes) = diff_revoke(&id, &state(SecretState::Unknown), true, false).unwrap();
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

    fn enroll_args(host: &str, execute: bool, items: Vec<String>) -> HostEnrollArgs {
        HostEnrollArgs {
            endpoint: None,
            host: host.into(),
            datastore: "main".into(),
            adopt: false,
            items,
            execute,
        }
    }

    fn run_enroll(
        store: &Rc<RefCell<Store>>,
        m: &MockTransport,
        args: HostEnrollArgs,
    ) -> Result<HostEnrollOutput> {
        let id = Identity::new(&args.host, "main").unwrap();
        let c = m.client();
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

    /// Dry run, then execute echoing every planned item.
    fn plan_then_execute(
        store: &Rc<RefCell<Store>>,
        m: &MockTransport,
        host: &str,
    ) -> Result<HostEnrollOutput> {
        let dry = run_enroll(store, m, enroll_args(host, false, vec![]))?;
        let Change::Plan(p) = dry.change else {
            panic!("expected plan")
        };
        let items = p.changes.iter().map(|c| c.target.clone()).collect();
        run_enroll(store, m, enroll_args(host, true, items))
    }

    #[test]
    fn dry_run_reads_but_never_writes() {
        let store = Rc::new(RefCell::new(Store::default()));
        let m = enroll_mock();
        let out = run_enroll(&store, &m, enroll_args("willow", false, vec![])).unwrap();
        assert!(matches!(out.change, Change::Plan(_)));
        assert!(m.mutations().is_empty(), "{:?}", m.mutations());
        assert!(store.borrow().secrets.is_empty());
        assert!(out.secret_ref.is_none());
    }

    #[test]
    fn execute_without_items_changes_nothing() {
        let store = Rc::new(RefCell::new(Store::default()));
        let m = enroll_mock();
        let err = run_enroll(&store, &m, enroll_args("willow", true, vec![])).unwrap_err();
        assert!(err.to_string().contains("needs the items"), "{err}");
        assert!(m.mutations().is_empty());
    }

    #[test]
    fn execute_applies_only_confirmed_items() {
        let store = Rc::new(RefCell::new(Store::default()));
        let m = enroll_mock();
        let items = vec!["main:hosts/willow".to_string(), "acl:gone".to_string()];
        let out = run_enroll(&store, &m, enroll_args("willow", true, items)).unwrap();
        assert_eq!(m.mutations(), vec!["POST /admin/datastore/main/namespace"]);
        let Change::Applied(a) = out.change else {
            panic!()
        };
        assert_eq!(a.notes, vec!["skipped acl:gone: no longer planned"]);
    }

    #[test]
    fn execute_stores_the_minted_secret_and_never_returns_it() {
        let store = Rc::new(RefCell::new(Store::default()));
        let m = enroll_mock();
        let out = plan_then_execute(&store, &m, "willow").unwrap();
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
        let json = serde_json::to_string(&out).unwrap();
        assert!(!json.contains(minted), "secret leaked into output");
        assert_eq!(m.mutations().len(), 7);
    }

    #[test]
    fn unstorable_secret_stops_before_the_acls_and_is_never_returned() {
        let store = Rc::new(RefCell::new(Store {
            fail_secret_set: true,
            ..Default::default()
        }));
        let m = enroll_mock();
        let err = plan_then_execute(&store, &m, "willow")
            .unwrap_err()
            .to_string();
        assert!(err.contains("minted but not stored"), "{err}");
        assert!(err.contains("re-run"), "{err}");
        assert!(!err.contains("0f6e2c1a"), "secret leaked into error: {err}");
        assert!(
            !m.mutations().iter().any(|l| l.contains("/access/acl")),
            "no step may run after the secret failed to persist"
        );
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
        let out = plan_then_execute(&store, &m, "freyr").unwrap();
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
        let out = run_enroll(&store, &m, enroll_args("freyr", false, vec![])).unwrap();
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

    fn run_revoke(
        store: &Rc<RefCell<Store>>,
        m: &MockTransport,
        items: Vec<String>,
        execute: bool,
    ) -> Result<HostRevokeOutput> {
        let id = Identity::new("freyr", "main").unwrap();
        let c = m.client();
        let args = HostRevokeArgs {
            endpoint: None,
            host: "freyr".into(),
            datastore: "main".into(),
            delete_data: false,
            adopt: false,
            items,
            execute,
        };
        let admin = admin();
        with_store(store, || {
            crate::endpoint::test_store::rt().block_on(revoke(
                "willow-pbs",
                &c,
                &id,
                &args,
                Some(&admin),
            ))
        })
    }

    fn revoke_mock() -> MockTransport {
        let m = enroll_mock();
        m.ok(
            Method::Delete,
            "/access/users/freyr%40pbs/token/backup",
            Value::Null,
        );
        m.ok(Method::Delete, "/access/users/freyr%40pbs", Value::Null);
        m
    }

    #[test]
    fn revoke_execute_removes_confirmed_access_and_orca_secret() {
        let store = Rc::new(RefCell::new(Store::default()));
        store
            .borrow_mut()
            .secrets
            .insert("pbs.willow-pbs.host_freyr_token".into(), "s".into());
        let m = revoke_mock();
        let Change::Plan(p) = run_revoke(&store, &m, vec![], false).unwrap().change else {
            panic!()
        };
        let items = p.changes.iter().map(|c| c.target.clone()).collect();
        let out = run_revoke(&store, &m, items, true).unwrap();
        assert!(out.secret_removed);
        assert!(!m.mutations().iter().any(|l| l.contains("namespace")));
        assert_eq!(m.mutations().len(), 7);
    }

    #[test]
    fn revoke_keeps_the_secret_when_the_token_was_not_confirmed() {
        let store = Rc::new(RefCell::new(Store::default()));
        store
            .borrow_mut()
            .secrets
            .insert("pbs.willow-pbs.host_freyr_token".into(), "s".into());
        let m = revoke_mock();
        let items = vec!["acl:freyr@pbs!backup:/datastore/main:DatastoreAdmin".to_string()];
        let out = run_revoke(&store, &m, items, true).unwrap();
        assert!(!out.secret_removed);
        assert_eq!(m.mutations(), vec!["PUT /access/acl"]);
        assert!(store
            .borrow()
            .secrets
            .contains_key("pbs.willow-pbs.host_freyr_token"));
    }
}
