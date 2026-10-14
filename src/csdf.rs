// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:FDX
// SPDX-License-Identifier: Apache-2.0

//! Story — CSDF minimization engine.
//! Story — OAuth scope to data cluster mapping.
//! CSDF (Consensus Standard Data Format) filters JSON responses based on
//! consent scopes, product rules, and requested fields, removing any data
//! outside the authorised scope before serialisation.

use serde::{Deserialize, Serialize};

// ── Story — Data clusters ───────────────────────────────────────

/// FDX data clusters — coarse-grained groupings of financial data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataCluster {
    Accounts,
    Payments,
    Statements,
    Customers,
    Transactions,
    Transfers,
    Tax,
}

impl DataCluster {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accounts => "ACCOUNTS",
            Self::Payments => "PAYMENTS",
            Self::Statements => "STATEMENTS",
            Self::Customers => "CUSTOMERS",
            Self::Transactions => "TRANSACTIONS",
            Self::Transfers => "TRANSFERS",
            Self::Tax => "TAX",
        }
    }
}

/// Map an OAuth scope string to one or more data clusters.
/// Returns an empty vec for unknown scopes.
pub fn scope_to_clusters(scope: &str) -> Vec<DataCluster> {
    match scope {
        "bank8:fdx:accountbasic:read" | "bank8:fdx:accountdetailed:read" => vec![DataCluster::Accounts],
        "bank8:fdx:balances:read" => vec![DataCluster::Accounts],
        "bank8:fdx:transactions:read" => vec![DataCluster::Transactions],
        "bank8:fdx:statements:read" => vec![DataCluster::Statements],
        "bank8:fdx:customercontact:read" | "bank8:fdx:customerpersonal:read" => vec![DataCluster::Customers],
        "bank8:fdx:transfers:read" | "bank8:fdx:transfers:write" => vec![DataCluster::Transfers, DataCluster::Payments],
        "bank8:fdx:payments:write" => vec![DataCluster::Payments],
        "bank8:fdx:tax:read" => vec![DataCluster::Tax],
        _ => vec![],
    }
}

// ── Story — CSDF filter ──────────────────────────────────────────

/// Filter parameters driving CSDF minimisation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsdfFilter {
    /// Consent scopes granted to the recipient (OAuth scopes).
    pub consent_scopes: Vec<String>,
    /// Product category — restricts fields valid for the product type.
    pub product_id: Option<String>,
    /// Explicitly requested fields (whitelist). When set, only these fields
    /// are returned.
    pub fields: Option<Vec<String>>,
}

impl CsdfFilter {
    pub fn new(scopes: Vec<String>) -> Self {
        Self { consent_scopes: scopes, product_id: None, fields: None }
    }

    /// Compute the set of data clusters allowed by the consent scopes.
    pub fn allowed_clusters(&self) -> Vec<DataCluster> {
        let mut out = vec![];
        for s in &self.consent_scopes {
            for c in scope_to_clusters(s) {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
        }
        out
    }

    /// Check whether a given data cluster is within the consent scope.
    pub fn has_cluster(&self, cluster: DataCluster) -> bool {
        self.allowed_clusters().contains(&cluster)
    }
}

/// Minimise a JSON payload against the CSDF filter.
/// - Removes top-level keys whose data cluster is not in scope.
/// - Applies field whitelisting when `filter.fields` is set.
pub fn minimize_csdf(data: &serde_json::Value, filter: &CsdfFilter) -> serde_json::Value {
    let clusters = filter.allowed_clusters();
    // Map top-level key → data cluster.
    let key_cluster = |key: &str| -> Option<DataCluster> {
        match key {
            "accounts" | "account" | "balances" => Some(DataCluster::Accounts),
            "transactions" => Some(DataCluster::Transactions),
            "statements" => Some(DataCluster::Statements),
            "customer" | "customers" | "contact" => Some(DataCluster::Customers),
            "transfers" => Some(DataCluster::Transfers),
            "payments" | "payment" => Some(DataCluster::Payments),
            "tax" | "taxForms" => Some(DataCluster::Tax),
            _ => None,
        }
    };
    match data {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                // Skip fields not in consent scope (when we can identify the cluster).
                if let Some(c) = key_cluster(k) {
                    if !clusters.contains(&c) {
                        continue;
                    }
                }
                let filtered = if let Some(allowed) = &filter.fields {
                    apply_field_filter(v, allowed)
                } else {
                    v.clone()
                };
                out.insert(k.clone(), filtered);
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| minimize_csdf(v, filter)).collect())
        }
        other => other.clone(),
    }
}

/// Whitelist specific fields from a JSON object (or each object in an array).
pub fn apply_field_filter(data: &serde_json::Value, allowed_fields: &[String]) -> serde_json::Value {
    match data {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for f in allowed_fields {
                if let Some(v) = map.get(f) {
                    out.insert(f.clone(), v.clone());
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| apply_field_filter(v, allowed_fields)).collect())
        }
        other => other.clone(),
    }
}

/// Check whether a consent scope grants access to a requested data item.
/// `requested_data` is a human-readable label like "accounts", "transactions",
/// "statements", "payments", "transfers", "customers", "tax".
pub fn check_consent_scope(scope: &str, requested_data: &str) -> bool {
    let clusters = scope_to_clusters(scope);
    let target = match requested_data.to_lowercase().as_str() {
        "accounts" | "account" | "balances" => DataCluster::Accounts,
        "transactions" | "transaction" => DataCluster::Transactions,
        "statements" | "statement" => DataCluster::Statements,
        "customers" | "customer" | "contact" => DataCluster::Customers,
        "transfers" | "transfer" => DataCluster::Transfers,
        "payments" | "payment" => DataCluster::Payments,
        "tax" | "taxforms" => DataCluster::Tax,
        _ => return false,
    };
    clusters.contains(&target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_to_clusters_known() {
        assert_eq!(scope_to_clusters("bank8:fdx:transactions:read"), vec![DataCluster::Transactions]);
        assert_eq!(scope_to_clusters("bank8:fdx:statements:read"), vec![DataCluster::Statements]);
    }

    #[test]
    fn test_scope_to_clusters_transfers_includes_payments() {
        let c = scope_to_clusters("bank8:fdx:transfers:write");
        assert!(c.contains(&DataCluster::Transfers));
        assert!(c.contains(&DataCluster::Payments));
    }

    #[test]
    fn test_scope_to_clusters_unknown() {
        assert!(scope_to_clusters("bank8:fdx:unknown:read").is_empty());
    }

    #[test]
    fn test_csdf_filter_allowed_clusters() {
        let f = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into(), "bank8:fdx:transactions:read".into()]);
        let c = f.allowed_clusters();
        assert!(c.contains(&DataCluster::Accounts));
        assert!(c.contains(&DataCluster::Transactions));
        assert!(!c.contains(&DataCluster::Statements));
    }

    #[test]
    fn test_minimize_removes_out_of_scope_keys() {
        let data = serde_json::json!({
            "accounts": [{"id": "a1"}],
            "transactions": [{"id": "t1"}],
            "statements": [{"id": "s1"}]
        });
        let filter = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
        let out = minimize_csdf(&data, &filter);
        assert!(out.get("accounts").is_some());
        assert!(out.get("transactions").is_none());
        assert!(out.get("statements").is_none());
    }

    #[test]
    fn test_minimize_keeps_unknown_keys() {
        let data = serde_json::json!({"meta": {"version": "1"}, "accounts": []});
        let filter = CsdfFilter::new(vec!["bank8:fdx:accountbasic:read".into()]);
        let out = minimize_csdf(&data, &filter);
        assert!(out.get("meta").is_some());
        assert!(out.get("accounts").is_some());
    }

    #[test]
    fn test_apply_field_filter_whitelist() {
        let data = serde_json::json!({"a": 1, "b": 2, "c": 3});
        let out = apply_field_filter(&data, &["a".into(), "c".into()]);
        assert_eq!(out["a"], 1);
        assert_eq!(out["c"], 3);
        assert!(out.get("b").is_none());
    }

    #[test]
    fn test_apply_field_filter_array() {
        let data = serde_json::json!([{"a": 1, "b": 2}, {"a": 3, "b": 4}]);
        let out = apply_field_filter(&data, &["a".into()]);
        assert_eq!(out[0]["a"], 1);
        assert!(out[0].get("b").is_none());
        assert_eq!(out[1]["a"], 3);
    }

    #[test]
    fn test_minimize_with_field_filter() {
        let data = serde_json::json!({"accounts": [{"id": "a1", "balance": "100", "secret": "x"}]});
        let filter = CsdfFilter {
            consent_scopes: vec!["bank8:fdx:accountbasic:read".into()],
            product_id: None,
            fields: Some(vec!["id".into()]),
        };
        let out = minimize_csdf(&data, &filter);
        assert_eq!(out["accounts"][0]["id"], "a1");
        assert!(out["accounts"][0].get("balance").is_none());
    }

    #[test]
    fn test_check_consent_scope_allowed() {
        assert!(check_consent_scope("bank8:fdx:transactions:read", "transactions"));
        assert!(check_consent_scope("bank8:fdx:accountbasic:read", "accounts"));
    }

    #[test]
    fn test_check_consent_scope_denied() {
        assert!(!check_consent_scope("bank8:fdx:accountbasic:read", "transactions"));
        assert!(!check_consent_scope("bank8:fdx:unknown:read", "accounts"));
    }

    #[test]
    fn test_data_cluster_as_str() {
        assert_eq!(DataCluster::Accounts.as_str(), "ACCOUNTS");
        assert_eq!(DataCluster::Tax.as_str(), "TAX");
    }
}