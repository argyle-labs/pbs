//! Dry-run plans and their application.
//!
//! A mutating verb reads current state, derives the API calls that would close
//! the gap, and either returns them as an [`ExecutionPlan`] or runs them in
//! order. Mutating verbs set `execute_gated = false` and own `execute`, because
//! the central gate can only return a generic plan while these verbs can name
//! each API call. Opting out of the central gate also opts out of the role
//! check it runs, so [`authorize_execute`] replaces it.

use plugin_toolkit::contract::plan::{ExecutionPlan, PlannedChange};
use plugin_toolkit::contract::CallerIdentity;
use plugin_toolkit::prelude::*;
use plugin_toolkit::serde_json::Value;

use crate::client::PbsClient;

#[derive(Debug, Clone, PartialEq)]
pub enum ApiCall {
    Post {
        path: String,
        body: Value,
    },
    Put {
        path: String,
        body: Value,
    },
    Delete {
        path: String,
        query: Vec<(String, String)>,
    },
}

impl ApiCall {
    fn describe(&self) -> String {
        match self {
            Self::Post { path, .. } => format!("POST {path}"),
            Self::Put { path, .. } => format!("PUT {path}"),
            Self::Delete { path, query } if query.is_empty() => format!("DELETE {path}"),
            Self::Delete { path, query } => {
                let q: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
                format!("DELETE {path}?{}", q.join("&"))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub target: String,
    pub action: String,
    pub detail: Option<String>,
    pub call: ApiCall,
    /// The response carries a secret (a minted token) and is withheld from
    /// the applied report.
    pub sensitive_result: bool,
}

impl Step {
    pub fn new(target: impl Into<String>, action: impl Into<String>, call: ApiCall) -> Self {
        Self {
            target: target.into(),
            action: action.into(),
            detail: None,
            call,
            sensitive_result: false,
        }
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = Some(d.into());
        self
    }

    pub fn sensitive(mut self) -> Self {
        self.sensitive_result = true;
        self
    }

    /// The plan item a caller echoes to confirm this step: `<action> <target>`.
    /// The action is part of it, so a step whose action changed between the
    /// dry run and execute (enable became regenerate) is not confirmed.
    pub fn item(&self) -> String {
        format!("{} {}", self.action, self.target)
    }

    fn to_change(&self) -> PlannedChange {
        let call = self.call.describe();
        PlannedChange::new(self.item(), self.action.clone()).with_detail(match &self.detail {
            Some(d) => format!("{d} ({call})"),
            None => call,
        })
    }
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StepOutcome {
    pub target: String,
    pub action: String,
    /// The PBS response, or `"<withheld>"` when it carried a secret.
    pub result: Value,
}

#[orca_struct]
#[derive(Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Applied {
    /// Always `false`: changes were applied.
    pub dry_run: bool,
    pub tool: String,
    pub summary: String,
    pub steps: Vec<StepOutcome>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// A dry-run plan, or the record of what was applied.
#[orca_struct]
#[derive(Debug, Clone)]
#[serde(untagged)]
pub enum Change {
    Plan(ExecutionPlan),
    Applied(Applied),
}

/// Fail closed: applying changes needs an identified admin caller.
pub fn authorize_execute(tool: &str, caller: Option<&CallerIdentity>) -> Result<()> {
    match caller {
        Some(c) if c.role == "admin" => Ok(()),
        Some(c) => bail!(
            "{tool}: execute requires role 'admin'; caller '{}' has '{}'",
            c.username,
            c.role
        ),
        None => bail!(
            "{tool}: execute refused: the call carries no caller identity, so admin cannot be verified"
        ),
    }
}

pub fn plan<A: Serialize>(
    tool: &str,
    args: &A,
    summary: String,
    steps: &[Step],
    notes: &[String],
) -> Result<ExecutionPlan> {
    let inputs = plugin_toolkit::serde_json::to_value(args)?;
    let mut summary = summary;
    for n in notes {
        summary.push_str("; ");
        summary.push_str(n);
    }
    if steps.is_empty() {
        summary.push_str("; nothing to change");
    }
    let changes = steps.iter().map(Step::to_change).collect();
    Ok(ExecutionPlan::generic(tool, inputs.into()).detailed(summary, changes))
}

/// Run `steps` in order and return each raw PBS response. A failure names the
/// step and what already ran: a partial apply must never read as success.
pub async fn run(tool: &str, c: &PbsClient, steps: &[Step]) -> Result<Vec<Value>> {
    run_with(tool, c, steps, |_, _| Ok(())).await
}

/// [`run`], calling `after` on each step's response before the next step
/// starts, so a result that must be persisted (a minted secret) is never held
/// across later calls that could fail.
pub async fn run_with(
    tool: &str,
    c: &PbsClient,
    steps: &[Step],
    mut after: impl FnMut(&Step, &Value) -> Result<()>,
) -> Result<Vec<Value>> {
    let mut out = Vec::with_capacity(steps.len());
    for (i, s) in steps.iter().enumerate() {
        let res: Result<Value> = match &s.call {
            ApiCall::Post { path, body } => c.post(path, body.clone()).await,
            ApiCall::Put { path, body } => c.put(path, body.clone()).await,
            ApiCall::Delete { path, query } => {
                let q: Vec<(&str, String)> =
                    query.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
                c.delete(path, &q).await
            }
        };
        let done = |upto: usize| -> String {
            steps[..upto]
                .iter()
                .map(|s| format!("{} {}", s.action, s.target))
                .collect::<Vec<_>>()
                .join(", ")
        };
        match res.and_then(|v| {
            after(s, &v)
                .map(|()| v)
                .map_err(|e| e.context("after the call succeeded"))
        }) {
            Ok(v) => out.push(v),
            Err(e) => bail!(
                "{tool}: step {} of {} ({} {}) failed: {e:#}; already applied: [{}]",
                i + 1,
                steps.len(),
                s.action,
                s.target,
                done(i)
            ),
        }
    }
    Ok(out)
}

/// Keep only the steps the caller confirmed by echoing their items
/// ([`Step::item`], the dry run's change targets), in plan order. Returns the kept steps and a note for
/// each confirmed item that is no longer planned; those are never acted on.
pub fn confirm(tool: &str, steps: Vec<Step>, items: &[String]) -> Result<(Vec<Step>, Vec<String>)> {
    if items.is_empty() && !steps.is_empty() {
        bail!(
            "{tool}: execute needs the items from the dry run; re-run without execute and pass its change targets as items"
        );
    }
    let dropped = items
        .iter()
        .filter(|i| !steps.iter().any(|s| s.item() == **i))
        .map(|i| format!("skipped {i}: no longer planned"))
        .collect();
    let kept = steps
        .into_iter()
        .filter(|s| items.contains(&s.item()))
        .collect();
    Ok((kept, dropped))
}

/// A confirmed item bound to contents (its target carries `#`) that is no
/// longer planned is a refusal, not a skip: the backups it named have changed
/// since the dry run. Called before any write, so nothing else in the plan
/// runs either.
pub fn refuse_drifted(tool: &str, steps: &[Step], items: &[String]) -> Result<()> {
    let drifted: Vec<&str> = items
        .iter()
        .filter(|i| i.contains('#') && !steps.iter().any(|s| s.item() == **i))
        .map(String::as_str)
        .collect();
    if !drifted.is_empty() {
        bail!(
            "{tool}: refusing: {} changed since the dry run; re-run it and confirm the new items",
            drifted.join(", ")
        );
    }
    Ok(())
}

pub fn applied(
    tool: &str,
    summary: String,
    steps: &[Step],
    results: &[Value],
    notes: Vec<String>,
) -> Applied {
    Applied {
        dry_run: false,
        tool: tool.to_string(),
        summary,
        steps: steps
            .iter()
            .zip(results)
            .map(|(s, r)| StepOutcome {
                target: s.target.clone(),
                action: s.action.clone(),
                result: if s.sensitive_result {
                    Value::String("<withheld>".into())
                } else {
                    r.clone()
                },
            })
            .collect(),
        notes,
    }
}

/// The common shape: plan unless `execute`, else authorize, run, report.
/// With `confirmed`, execute acts only on the plan items the caller echoed
/// back (see [`confirm`]).
#[allow(clippy::too_many_arguments)]
pub async fn plan_or_apply<A: Serialize>(
    tool: &str,
    args: &A,
    execute: bool,
    caller: Option<&CallerIdentity>,
    c: &PbsClient,
    summary: String,
    steps: Vec<Step>,
    mut notes: Vec<String>,
    confirmed: Option<&[String]>,
) -> Result<Change> {
    if !execute {
        return Ok(Change::Plan(plan(tool, args, summary, &steps, &notes)?));
    }
    authorize_execute(tool, caller)?;
    let steps = match confirmed {
        Some(items) => {
            let (kept, dropped) = confirm(tool, steps, items)?;
            notes.extend(dropped);
            kept
        }
        None => steps,
    };
    let results = run(tool, c, &steps).await?;
    Ok(Change::Applied(applied(
        tool, summary, &steps, &results, notes,
    )))
}

/// A plan item for each step, for a caller to confirm on execute.
#[cfg(test)]
pub(crate) fn items(steps: &[Step]) -> Vec<String> {
    steps.iter().map(Step::item).collect()
}

#[cfg(test)]
pub(crate) fn admin() -> CallerIdentity {
    CallerIdentity {
        user_id: "1".into(),
        username: "skey".into(),
        role: "admin".into(),
        can_mutate: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::mock::MockTransport;
    use crate::client::Method;

    fn steps() -> Vec<Step> {
        vec![
            Step::new(
                "a",
                "create",
                ApiCall::Post {
                    path: "/one".into(),
                    body: json!({"x": 1}),
                },
            ),
            Step::new(
                "b",
                "mint",
                ApiCall::Post {
                    path: "/two".into(),
                    body: json!({}),
                },
            )
            .sensitive(),
        ]
    }

    #[test]
    fn execute_needs_an_admin_identity() {
        assert!(authorize_execute("t", None).is_err());
        let mut c = admin();
        c.role = "read".into();
        assert!(authorize_execute("t", Some(&c))
            .unwrap_err()
            .to_string()
            .contains("role 'admin'"));
        assert!(authorize_execute("t", Some(&admin())).is_ok());
    }

    #[tokio::test]
    async fn dry_run_lists_calls_and_touches_nothing() {
        let m = MockTransport::new();
        let out = plan_or_apply(
            "pbs.t",
            &json!({}),
            false,
            None,
            &m.client(),
            "s".into(),
            steps(),
            vec![],
            None,
        )
        .await
        .unwrap();
        let Change::Plan(p) = out else {
            panic!("expected a plan")
        };
        assert!(p.dry_run);
        assert_eq!(p.changes.len(), 2);
        assert_eq!(p.changes[0].detail.as_deref(), Some("POST /one"));
        assert!(m.log().is_empty());
    }

    #[tokio::test]
    async fn apply_withholds_sensitive_results() {
        let m = MockTransport::new();
        m.ok(Method::Post, "/one", json!("ok"));
        m.ok(Method::Post, "/two", json!({"value": "minted-secret"}));
        let out = plan_or_apply(
            "pbs.t",
            &json!({}),
            true,
            Some(&admin()),
            &m.client(),
            "s".into(),
            steps(),
            vec![],
            None,
        )
        .await
        .unwrap();
        let Change::Applied(a) = out else {
            panic!("expected applied")
        };
        assert_eq!(a.steps[0].result, json!("ok"));
        assert_eq!(a.steps[1].result, json!("<withheld>"));
        assert!(!plugin_toolkit::serde_json::to_string(&a)
            .unwrap()
            .contains("minted-secret"));
    }

    #[tokio::test]
    async fn partial_failure_names_the_step_and_what_ran() {
        let m = MockTransport::new();
        m.ok(Method::Post, "/one", json!(null));
        let err = run("pbs.t", &m.client(), &steps())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("step 2 of 2 (mint b)"), "{err}");
        assert!(err.contains("already applied: [create a]"), "{err}");
    }

    #[tokio::test]
    async fn after_hook_failure_stops_before_the_next_step() {
        let m = MockTransport::new();
        m.ok(Method::Post, "/one", json!(null));
        m.ok(Method::Post, "/two", json!(null));
        let err = run_with("pbs.t", &m.client(), &steps(), |s, _| {
            if s.target == "a" {
                bail!("store failed")
            }
            Ok(())
        })
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("step 1 of 2") && err.contains("store failed"),
            "{err}"
        );
        assert_eq!(m.mutations(), vec!["POST /one"]);
    }

    #[test]
    fn confirm_keeps_only_echoed_targets_and_reports_stale_ones() {
        assert!(confirm("t", steps(), &[]).is_err());
        assert!(confirm("t", Vec::new(), &[]).unwrap().0.is_empty());
        let (kept, dropped) = confirm("t", steps(), &["mint b".into(), "gone".into()]).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].target, "b");
        assert_eq!(dropped, vec!["skipped gone: no longer planned"]);
    }

    #[test]
    fn an_item_confirms_only_the_action_it_named() {
        let planned = Step::new(
            "token:h@pbs!backup",
            "enable-token",
            ApiCall::Put {
                path: "/t".into(),
                body: json!({}),
            },
        );
        let confirmed = vec![planned.item()];
        let now = Step::new(
            "token:h@pbs!backup",
            "regenerate-token",
            ApiCall::Put {
                path: "/t".into(),
                body: json!({"regenerate": true}),
            },
        );
        let (kept, dropped) = confirm("t", vec![now], &confirmed).unwrap();
        assert!(kept.is_empty(), "enable must not authorize regenerate");
        assert_eq!(
            dropped,
            vec!["skipped enable-token token:h@pbs!backup: no longer planned"]
        );
    }

    #[tokio::test]
    async fn execute_without_items_is_refused_when_confirmation_is_required() {
        let m = MockTransport::new();
        let err = plan_or_apply(
            "pbs.t",
            &json!({}),
            true,
            Some(&admin()),
            &m.client(),
            "s".into(),
            steps(),
            vec![],
            Some(&[]),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("needs the items"), "{err}");
        assert!(m.log().is_empty());
    }
}
