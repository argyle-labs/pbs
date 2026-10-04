//! PBS endpoint registry — `pbs.{list,detail,create,update,delete}`.
//!
//! The shared `endpoints` table persists `routes`, `enabled`, `insecure` and
//! `token_id`; anything else declared on the row would be dropped on write.
//! So the token secret and the TLS fingerprint pin live in the secrets domain
//! under `pbs.<endpoint>.token_secret` and `pbs.<endpoint>.fingerprint`. The
//! fingerprint is not sensitive; it is stored there only because the row has
//! no column for it.

use plugin_toolkit::prelude::*;
use plugin_toolkit::secrets;

use crate::client::{validate_token_id, ApiToken, PbsClient, ReqwestTransport};
use crate::tls::{Fingerprint, TlsPolicy};
use crate::PROVIDER;

#[endpoint_resource(plugin = "pbs", skip = "create, update, delete")]
pub struct PbsEndpoint {
    /// API token id, `user@realm!tokenid`.
    pub token_id: String,
    /// Skip TLS verification. Prefer a fingerprint pin.
    pub insecure: bool,
}

const SECRET_FIELD: &str = "token_secret";
const FINGERPRINT_FIELD: &str = "fingerprint";

pub(crate) fn secret_name(endpoint: &str, field: &str) -> String {
    secrets::scoped_name(PROVIDER, endpoint, field)
}

/// Endpoint names become the middle segment of `pbs.<name>.<field>`; a `.`
/// would split into a different secret scope.
pub fn validate_name(name: &str) -> Result<()> {
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        bail!("invalid endpoint name '{name}': must match ^[A-Za-z0-9_-]{{1,64}}$");
    }
    Ok(())
}

fn entry(row: &EndpointRow) -> EndpointEntry {
    EndpointEntry {
        name: row.name.clone(),
        token_id: row.token_id.clone(),
        insecure: row.insecure,
        routes: row.routes.clone(),
        enabled: row.enabled,
    }
}

fn fingerprint(endpoint: &str) -> Result<Option<Fingerprint>> {
    secrets::get(&secret_name(endpoint, FINGERPRINT_FIELD))?
        .filter(|s| !s.trim().is_empty())
        .map(|s| Fingerprint::parse(&s))
        .transpose()
}

fn token(row: &EndpointRow) -> Result<ApiToken> {
    let secret = secrets::get(&secret_name(&row.name, SECRET_FIELD))?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "no token secret stored for pbs endpoint '{}'; set one with \
                 `pbs.update --name {} --token-secret <secret>`",
                row.name,
                row.name
            )
        })?;
    ApiToken::new(&row.token_id, secret)
}

/// Pick the named endpoint, or the only one registered.
pub fn select(endpoint: Option<&str>) -> Result<EndpointRow> {
    match endpoint {
        Some(name) => endpoint_db::get(name)?
            .ok_or_else(|| anyhow!("no pbs endpoint named `{name}` — see `pbs.list`")),
        None => {
            let mut all = endpoint_db::list()?;
            match all.len() {
                1 => Ok(all.remove(0)),
                0 => bail!("no pbs endpoints registered — add one with `pbs.create`"),
                n => bail!("{n} pbs endpoints registered — pass `endpoint` to pick one"),
            }
        }
    }
}

/// Resolve an endpoint into a ready client over its first reachable route.
pub async fn connect(endpoint: Option<&str>) -> Result<PbsClient> {
    Ok(connect_named(endpoint).await?.1)
}

/// [`connect`], also returning the resolved endpoint name.
pub async fn connect_named(endpoint: Option<&str>) -> Result<(String, PbsClient)> {
    let row = select(endpoint)?;
    if !row.enabled {
        bail!("pbs endpoint '{}' is disabled", row.name);
    }
    let token = token(&row)?;
    let policy = TlsPolicy::from_config(fingerprint(&row.name)?, row.insecure);
    let base = route::resolve_reachable(&row.name, &row.routes, policy.probe_insecure()).await?;
    let client = PbsClient::new(&base, token, Box::new(ReqwestTransport::new(&policy)?));
    Ok((row.name, client))
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct PbsCreateArgs {
    #[arg(long)]
    pub name: String,
    /// API token id, `user@realm!tokenid` (e.g. `root@pam!orca`).
    #[arg(long)]
    #[serde(alias = "token_id")]
    pub token_id: String,
    /// Name of an orca secret holding the API token secret, written first
    /// with `orca secrets upsert --name <ref> --value-stdin` so the value
    /// never appears on a command line. It is copied to
    /// `pbs.<name>.token_secret`.
    #[arg(long)]
    #[serde(alias = "token_secret_ref")]
    pub token_secret_ref: String,
    /// SHA-256 fingerprint of the PBS certificate (`AA:BB:…`). Pins TLS to
    /// that certificate; the usual choice for PBS's self-signed cert.
    #[arg(long)]
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Skip TLS verification entirely. Ignored when `fingerprint` is set.
    #[arg(long)]
    #[serde(default)]
    pub insecure: bool,
    /// Reachable path(s), tried in order. Repeatable: `--route kind=url`,
    /// e.g. `--route lan_v4=https://10.0.0.5:8007`.
    #[arg(long = "route", value_parser = route::parse_route, action = clap::ArgAction::Append)]
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[orca_struct]
#[derive(Debug)]
#[serde(rename_all = "camelCase")]
pub struct PbsCreateOutput {
    pub endpoint: EndpointEntry,
    pub fingerprint_pinned: bool,
}

/// The value behind a caller-supplied secret reference.
fn resolve_ref(reference: &str) -> Result<String> {
    if reference.trim().is_empty() {
        bail!("token_secret_ref must name an orca secret");
    }
    secrets::get(reference)?
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "no orca secret named '{reference}'; write it first with \
                 `orca secrets upsert --name {reference} --value-stdin`"
            )
        })
}

fn store_secrets(name: &str, token_secret: Option<&str>, fp: Option<&Fingerprint>) -> Result<()> {
    if let Some(s) = token_secret {
        secrets::set(
            &secret_name(name, SECRET_FIELD),
            s,
            Some(&format!("PBS API token secret for endpoint '{name}'")),
        )?;
    }
    if let Some(fp) = fp {
        secrets::set(
            &secret_name(name, FINGERPRINT_FIELD),
            &fp.to_string(),
            Some(&format!(
                "PBS TLS certificate pin for endpoint '{name}' (not sensitive)"
            )),
        )?;
    }
    Ok(())
}

/// Register a PBS endpoint. The token secret is read from an orca secret
/// reference and kept in the secrets domain, never on the row.
#[orca_tool(domain = "pbs", verb = "create")]
async fn pbs_create(args: PbsCreateArgs, _ctx: &ToolCtx) -> Result<PbsCreateOutput> {
    validate_name(&args.name)?;
    validate_token_id(&args.token_id)?;
    let token_secret = resolve_ref(&args.token_secret_ref)?;
    let fp = args
        .fingerprint
        .as_deref()
        .map(Fingerprint::parse)
        .transpose()?;
    let row = EndpointRow {
        name: args.name,
        token_id: args.token_id,
        insecure: args.insecure,
        routes: Routes::from(args.routes),
        enabled: true,
    };
    endpoint_db::insert(&row).map_err(|e| runtime::map_insert_conflict(e, PROVIDER, &row.name))?;
    if let Err(e) = store_secrets(&row.name, Some(&token_secret), fp.as_ref()) {
        if let Err(rollback) = endpoint_db::remove(&row.name) {
            tracing::warn!(endpoint = %row.name, error = %rollback, "rollback of endpoint row failed");
        }
        return Err(e);
    }
    Ok(PbsCreateOutput {
        endpoint: entry(&row),
        fingerprint_pinned: fp.is_some(),
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct PbsUpdateArgs {
    #[arg(long)]
    pub name: String,
    #[arg(long)]
    #[serde(default, alias = "token_id")]
    pub token_id: Option<String>,
    /// Replace the stored token secret with the value of this orca secret
    /// (see `pbs.create`).
    #[arg(long)]
    #[serde(default, alias = "token_secret_ref")]
    pub token_secret_ref: Option<String>,
    /// Replace the TLS pin. An empty string removes it.
    #[arg(long)]
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[arg(long)]
    #[serde(default)]
    pub insecure: Option<bool>,
    /// Replace the reachable-path set. Omit to leave routes unchanged.
    #[arg(long = "route", value_parser = route::parse_route, action = clap::ArgAction::Append)]
    #[serde(default)]
    pub routes: Vec<Route>,
    #[arg(long)]
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[orca_struct]
#[derive(Debug)]
#[serde(rename_all = "camelCase")]
pub struct PbsUpdateOutput {
    pub endpoint: EndpointEntry,
    pub applied: Vec<String>,
}

/// Patch a PBS endpoint. Secrets are written to the secrets domain only after
/// the row update succeeds.
#[orca_tool(domain = "pbs", verb = "update")]
async fn pbs_update(args: PbsUpdateArgs, _ctx: &ToolCtx) -> Result<PbsUpdateOutput> {
    validate_name(&args.name)?;
    let token_secret = args
        .token_secret_ref
        .as_deref()
        .map(resolve_ref)
        .transpose()?;
    let fp_change = match args.fingerprint.as_deref().map(str::trim) {
        Some("") => Some(None),
        Some(s) => Some(Some(Fingerprint::parse(s)?)),
        None => None,
    };
    let mut row = endpoint_db::get(&args.name)?
        .ok_or_else(|| runtime::missing_row_error(PROVIDER, &args.name))?;
    let mut applied = Vec::new();
    if let Some(id) = args.token_id {
        validate_token_id(&id)?;
        row.token_id = id;
        applied.push("token_id".to_string());
    }
    if let Some(v) = args.insecure {
        row.insecure = v;
        applied.push("insecure".to_string());
    }
    if !args.routes.is_empty() {
        row.routes = Routes::from(args.routes);
        applied.push("routes".to_string());
    }
    if let Some(v) = args.enabled {
        row.enabled = v;
        applied.push("enabled".to_string());
    }
    if applied.is_empty() && token_secret.is_none() && fp_change.is_none() {
        bail!("no fields to update; pass at least one flag");
    }
    if !applied.is_empty() && !endpoint_db::update(&row)? {
        bail!("update reported no row change for `{}`", row.name);
    }
    if let Some(fp) = &fp_change {
        match fp {
            Some(fp) => store_secrets(&row.name, None, Some(fp))?,
            None => {
                secrets::delete(&secret_name(&row.name, FINGERPRINT_FIELD))?;
            }
        }
        applied.push("fingerprint".to_string());
    }
    if let Some(s) = &token_secret {
        store_secrets(&row.name, Some(s), None)?;
        applied.push("token_secret".to_string());
    }
    Ok(PbsUpdateOutput {
        endpoint: entry(&row),
        applied,
    })
}

#[orca_struct(args)]
#[serde(rename_all = "camelCase")]
pub struct PbsDeleteArgs {
    #[arg(long)]
    pub name: String,
}

#[orca_struct]
#[serde(rename_all = "camelCase")]
pub struct PbsDeleteOutput {
    pub name: String,
    pub changed: bool,
    pub secrets_removed: Vec<String>,
}

/// Remove a PBS endpoint and its stored secrets. The token itself stays on
/// the PBS server.
#[orca_tool(domain = "pbs", verb = "delete")]
async fn pbs_delete(args: PbsDeleteArgs, _ctx: &ToolCtx) -> Result<PbsDeleteOutput> {
    validate_name(&args.name)?;
    let changed = endpoint_db::remove(&args.name)?;
    let mut secrets_removed = Vec::new();
    for field in [SECRET_FIELD, FINGERPRINT_FIELD] {
        if secrets::delete(&secret_name(&args.name, field))? {
            secrets_removed.push(field.to_string());
        }
    }
    Ok(PbsDeleteOutput {
        name: args.name,
        changed,
        secrets_removed,
    })
}

#[cfg(test)]
pub(crate) mod test_store {
    //! In-memory stand-in for core's `db.op` + `secret.op` capabilities.

    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::sync::Arc;

    use plugin_toolkit::abi::{DbOp, DbReply, DbRow, DbValue, SecretOp, SecretReply};
    use plugin_toolkit::capsink::with_cap_sink;
    use plugin_toolkit::contract::config::{Config as OrcaConfig, Model};
    use plugin_toolkit::serde_json;

    use super::*;

    #[derive(Default)]
    pub struct Store {
        pub rows: Vec<DbRow>,
        pub secrets: HashMap<String, String>,
        pub fail_secret_set: bool,
    }

    fn handle(store: &mut Store, cap: &str, json: &str) -> std::result::Result<String, String> {
        match cap {
            "db.op" => {
                let op: DbOp = serde_json::from_str(json).map_err(|e| e.to_string())?;
                let mut reply = DbReply::default();
                match op {
                    DbOp::List { .. } => reply.rows = store.rows.clone(),
                    DbOp::Insert { row, .. } => {
                        store.rows.push(row);
                        reply.affected = 1;
                    }
                    DbOp::Update { key_col, row, .. } => {
                        if let Some(r) = store
                            .rows
                            .iter_mut()
                            .find(|r| r.get(&key_col) == row.get(&key_col))
                        {
                            *r = row;
                            reply.affected = 1;
                        }
                    }
                    DbOp::Delete { key_col, key, .. } => {
                        let before = store.rows.len();
                        store
                            .rows
                            .retain(|r| r.get(&key_col) != Some(&DbValue::Text(key.clone())));
                        reply.affected = (before - store.rows.len()) as u64;
                    }
                    other => return Err(format!("unexpected db op {}", other.kind())),
                }
                serde_json::to_string(&reply).map_err(|e| e.to_string())
            }
            "secret.op" => {
                let op: SecretOp = serde_json::from_str(json).map_err(|e| e.to_string())?;
                let mut reply = SecretReply::default();
                match op {
                    SecretOp::Get { name } => reply.value = store.secrets.get(&name).cloned(),
                    SecretOp::Set { .. } if store.fail_secret_set => {
                        return Err("secret backend unavailable".into());
                    }
                    SecretOp::Set { name, value, .. } => {
                        store.secrets.insert(name, value);
                    }
                    SecretOp::Exists { name } => reply.found = store.secrets.contains_key(&name),
                    SecretOp::Delete { name } => {
                        reply.found = store.secrets.remove(&name).is_some()
                    }
                }
                serde_json::to_string(&reply).map_err(|e| e.to_string())
            }
            other => Err(format!("unexpected capability {other}")),
        }
    }

    pub fn with_store<R>(store: &Rc<RefCell<Store>>, body: impl FnOnce() -> R) -> R {
        let s = store.clone();
        with_cap_sink(
            Box::new(move |cap: &str, json: &str| handle(&mut s.borrow_mut(), cap, json)),
            body,
        )
    }

    pub fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    pub fn ctx() -> ToolCtx {
        ToolCtx::new(Arc::new(OrcaConfig {
            anthropic_api_key: None,
            lmstudio_url: String::new(),
            ollama_url: String::new(),
            default_model: Model::LMStudio {
                id: String::new(),
                url: String::new(),
            },
            app_dir: std::path::PathBuf::from("/tmp"),
            memory_root: std::path::PathBuf::from("/tmp"),
            db_path: std::path::PathBuf::from("/tmp/orca-pbs-endpoint-test.db"),
            ports: Default::default(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;

    use plugin_toolkit::abi::DbValue;

    use super::test_store::*;
    use super::*;

    const FP: &str = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";

    /// A store with the staged secrets the create/update args reference.
    fn staged(mut store: Store) -> Rc<RefCell<Store>> {
        store
            .secrets
            .insert("staged.pbs".into(), "tok-secret-1".into());
        store
            .secrets
            .insert("staged.pbs.2".into(), "tok-secret-2".into());
        Rc::new(RefCell::new(store))
    }

    fn create_args(name: &str) -> PbsCreateArgs {
        PbsCreateArgs {
            name: name.into(),
            token_id: "root@pam!orca".into(),
            token_secret_ref: "staged.pbs".into(),
            fingerprint: Some(FP.to_lowercase()),
            insecure: false,
            routes: vec![route::parse_route("lan_v4=https://10.0.0.5:8007").unwrap()],
        }
    }

    #[test]
    fn create_keeps_secret_and_pin_off_the_row() {
        let store = staged(Store::default());
        let out = with_store(&store, || {
            rt().block_on(pbs_create(create_args("willow"), &ctx()))
                .unwrap()
        });
        assert!(out.fingerprint_pinned);
        let s = store.borrow();
        assert_eq!(s.secrets["pbs.willow.token_secret"], "tok-secret-1");
        assert_eq!(s.secrets["pbs.willow.fingerprint"], FP);
        assert!(
            s.rows.iter().all(|r| !r
                .values()
                .any(|v| *v == DbValue::Text("tok-secret-1".into()))),
            "token secret must never land on the endpoint row"
        );
        drop(s);
        let row = with_store(&store, || select(Some("willow")).unwrap());
        assert_eq!(row.token_id, "root@pam!orca");
        let tok = with_store(&store, || token(&row).unwrap());
        assert_eq!(tok.secret(), "tok-secret-1");
        assert_eq!(
            with_store(&store, || fingerprint("willow").unwrap()),
            Some(Fingerprint::parse(FP).unwrap())
        );
    }

    #[test]
    fn create_rolls_back_row_when_secret_store_fails() {
        let store = staged(Store {
            fail_secret_set: true,
            ..Default::default()
        });
        let err = with_store(&store, || {
            rt().block_on(pbs_create(create_args("willow"), &ctx()))
                .unwrap_err()
        });
        assert!(!err.to_string().contains("tok-secret-1"));
        assert!(store.borrow().rows.is_empty());
    }

    #[test]
    fn create_rejects_bad_inputs() {
        let store = staged(Store::default());
        with_store(&store, || {
            let rt = rt();
            let mut a = create_args("bad.name");
            assert!(rt.block_on(pbs_create(a, &ctx())).is_err());
            a = create_args("ok");
            a.token_id = "root@pam".into();
            assert!(rt.block_on(pbs_create(a, &ctx())).is_err());
            a = create_args("ok");
            a.fingerprint = Some("nope".into());
            assert!(rt.block_on(pbs_create(a, &ctx())).is_err());
        });
        assert!(store.borrow().rows.is_empty());
    }

    #[test]
    fn update_can_clear_pin_and_rotate_secret() {
        let store = staged(Store::default());
        let out = with_store(&store, || {
            let rt = rt();
            rt.block_on(pbs_create(create_args("willow"), &ctx()))
                .unwrap();
            rt.block_on(pbs_update(
                PbsUpdateArgs {
                    name: "willow".into(),
                    token_secret_ref: Some("staged.pbs.2".into()),
                    fingerprint: Some(String::new()),
                    ..Default::default()
                },
                &ctx(),
            ))
            .unwrap()
        });
        assert_eq!(out.applied, vec!["fingerprint", "token_secret"]);
        let s = store.borrow();
        assert_eq!(s.secrets["pbs.willow.token_secret"], "tok-secret-2");
        assert!(!s.secrets.contains_key("pbs.willow.fingerprint"));
    }

    #[test]
    fn delete_removes_row_and_secrets() {
        let store = staged(Store::default());
        let out = with_store(&store, || {
            let rt = rt();
            rt.block_on(pbs_create(create_args("willow"), &ctx()))
                .unwrap();
            rt.block_on(pbs_delete(
                PbsDeleteArgs {
                    name: "willow".into(),
                },
                &ctx(),
            ))
            .unwrap()
        });
        assert!(out.changed);
        assert_eq!(out.secrets_removed, vec!["token_secret", "fingerprint"]);
        assert!(!store
            .borrow()
            .secrets
            .keys()
            .any(|k| k.starts_with("pbs.willow.")));
    }

    #[test]
    fn a_missing_secret_reference_is_refused_before_any_write() {
        let store = staged(Store::default());
        let mut a = create_args("willow");
        a.token_secret_ref = "never.written".into();
        let err = with_store(&store, || rt().block_on(pbs_create(a, &ctx())).unwrap_err());
        assert!(err.to_string().contains("--value-stdin"), "{err}");
        assert!(store.borrow().rows.is_empty());
    }

    #[test]
    fn update_with_a_bad_pin_changes_nothing() {
        let store = staged(Store::default());
        let err = with_store(&store, || {
            let rt = rt();
            rt.block_on(pbs_create(create_args("willow"), &ctx()))
                .unwrap();
            rt.block_on(pbs_update(
                PbsUpdateArgs {
                    name: "willow".into(),
                    insecure: Some(true),
                    fingerprint: Some("nope".into()),
                    ..Default::default()
                },
                &ctx(),
            ))
            .unwrap_err()
        });
        assert!(err.to_string().contains("fingerprint"), "{err}");
        let row = with_store(&store, || select(Some("willow")).unwrap());
        assert!(!row.insecure);
    }

    #[test]
    fn select_needs_a_name_when_several_exist() {
        let store = staged(Store::default());
        with_store(&store, || {
            let rt = rt();
            rt.block_on(pbs_create(create_args("a"), &ctx())).unwrap();
            assert_eq!(select(None).unwrap().name, "a");
            rt.block_on(pbs_create(create_args("b"), &ctx())).unwrap();
            assert!(select(None)
                .unwrap_err()
                .to_string()
                .contains("pass `endpoint`"));
        });
    }
}
