//! Label-based access rules. Default deny.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Rule {
    pub name: String,
    /// OIDC groups this rule applies to; "*" = any authenticated user.
    pub groups: Vec<String>,
    /// Every label must match; value "*" = label present with any value.
    #[serde(default)]
    pub node_labels: BTreeMap<String, String>,
    #[serde(default = "default_services")]
    pub services: Vec<String>,
    /// Local logins allowed; "{{user.username}}" expands to the Orbital username.
    #[serde(default)]
    pub logins: Vec<String>,
    #[serde(default)]
    pub require_approval: bool,
    /// Break-glass: requester may self-approve with a reason; flagged + high-severity webhook.
    #[serde(default)]
    pub emergency: bool,
    #[serde(default = "default_ttl")]
    pub max_ttl_secs: i32,
}

fn default_services() -> Vec<String> {
    vec!["ssh".into()]
}
fn default_ttl() -> i32 {
    3600
}

#[derive(Debug, PartialEq)]
pub enum Decision {
    Allow { rule: String, ttl: i32 },
    NeedsApproval { rule: String, ttl: i32 },
    Emergency { rule: String, ttl: i32 },
    Deny(String),
}

pub struct Request<'a> {
    pub username: &'a str,
    pub groups: &'a [String],
    pub node_labels: &'a BTreeMap<String, String>,
    pub service: &'a str,
    pub login: &'a str,
    pub emergency: bool,
}

pub fn login_allowed(rule: &Rule, username: &str, login: &str) -> bool {
    rule.logins.iter().any(|l| {
        if l == "{{user.username}}" {
            // root is only reachable through an explicit "root" entry
            login == username && login != "root"
        } else {
            l == login
        }
    })
}

pub fn matches(rule: &Rule, r: &Request) -> bool {
    let group_ok = rule.groups.iter().any(|g| g == "*" || r.groups.contains(g));
    let labels_ok = rule.node_labels.iter().all(|(k, v)| match r.node_labels.get(k) {
        Some(have) => v == "*" || v == have,
        None => false,
    });
    let svc_ok = rule.services.iter().any(|s| s == "*" || s == r.service);
    let login_ok = r.service != "ssh" || login_allowed(rule, r.username, r.login);
    group_ok && labels_ok && svc_ok && login_ok
}

pub fn evaluate(rules: &[Rule], r: &Request) -> Decision {
    let hits: Vec<&Rule> = rules.iter().filter(|rule| matches(rule, r)).collect();
    if let Some(rule) = hits.iter().find(|x| !x.require_approval) {
        return Decision::Allow { rule: rule.name.clone(), ttl: rule.max_ttl_secs };
    }
    if r.emergency {
        if let Some(rule) = hits.iter().find(|x| x.emergency) {
            return Decision::Emergency { rule: rule.name.clone(), ttl: rule.max_ttl_secs };
        }
    }
    match hits.first() {
        Some(rule) => Decision::NeedsApproval { rule: rule.name.clone(), ttl: rule.max_ttl_secs },
        None => Decision::Deny(format!(
            "no rule allows {}@{} ({}) for {}",
            r.login, r.service, labels_str(r.node_labels), r.username
        )),
    }
}

fn labels_str(l: &BTreeMap<String, String>) -> String {
    l.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Vec<Rule> {
        serde_json::from_value(serde_json::json!([
            {"name": "dev-self", "groups": ["devs"], "node_labels": {"env": "dev"},
             "logins": ["{{user.username}}"]},
            {"name": "dev-deploy", "groups": ["devs"], "node_labels": {"env": "dev"},
             "logins": ["deploy"], "require_approval": true, "emergency": true, "max_ttl_secs": 600},
            {"name": "ops-root", "groups": ["ops"], "node_labels": {"env": "*"}, "logins": ["root"]}
        ]))
        .unwrap()
    }

    fn req<'a>(user: &'a str, groups: &'a [String], labels: &'a BTreeMap<String, String>, login: &'a str) -> Request<'a> {
        Request { username: user, groups, node_labels: labels, service: "ssh", login, emergency: false }
    }

    #[test]
    fn evaluation() {
        let rules = rules();
        let dev: BTreeMap<_, _> = [("env".to_string(), "dev".to_string())].into();
        let prod: BTreeMap<_, _> = [("env".to_string(), "prod".to_string())].into();
        let devs = vec!["devs".to_string()];
        let none: Vec<String> = vec![];

        assert!(matches!(evaluate(&rules, &req("alice", &devs, &dev, "alice")), Decision::Allow { .. }));
        // default deny: no group / wrong label / unknown login
        assert!(matches!(evaluate(&rules, &req("bob", &none, &dev, "bob")), Decision::Deny(_)));
        assert!(matches!(evaluate(&rules, &req("alice", &devs, &prod, "alice")), Decision::Deny(_)));
        assert!(matches!(evaluate(&rules, &req("alice", &devs, &dev, "bob")), Decision::Deny(_)));
        // approval required
        assert_eq!(
            evaluate(&rules, &req("alice", &devs, &dev, "deploy")),
            Decision::NeedsApproval { rule: "dev-deploy".into(), ttl: 600 }
        );
        // break-glass
        let mut r = req("alice", &devs, &dev, "deploy");
        r.emergency = true;
        assert!(matches!(evaluate(&rules, &r), Decision::Emergency { .. }));
        // root only when explicit: a user literally named root gets nothing from the template
        let devs_root = vec!["devs".to_string()];
        assert!(matches!(evaluate(&rules, &req("root", &devs_root, &dev, "root")), Decision::Deny(_)));
        let ops = vec!["ops".to_string()];
        assert!(matches!(evaluate(&rules, &req("carol", &ops, &prod, "root")), Decision::Allow { .. }));
        // wildcard label requires presence
        assert!(matches!(evaluate(&rules, &req("carol", &ops, &BTreeMap::new(), "root")), Decision::Deny(_)));
    }
}
