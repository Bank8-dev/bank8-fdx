// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Contributors to the bank8 bank8-fdx
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI drift guard (OAPEC design §3) - floor variant.
//!
//! The router requires a live state (`routes(router, state)` - AppState
//! carries the pooled DB), so the full router introspection guard
//! (`sentin8::shell::drift_guard`, used by lib-stateless services like
//! auth/bus) cannot run stateless. The dumped spec shape is pinned here:
//! `docs/openapi.json` must exist and stay at or above the documented
//! operation floor. Adding a served route without an annotation drops the
//! count only when a companion annotation is removed - OAPEC-8 tracks the
//! stateless harness for state-bound services.

#[test]
fn openapi_dump_exists_and_exceeds_floor() {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/openapi.json"))
        .expect("docs/openapi.json - regenerate via --print-registration --section=openapi");
    let spec: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    let paths = spec
        .get("paths")
        .and_then(|p| p.as_object())
        .expect("paths object");
    let ops: usize = paths
        .values()
        .map(|v| {
            v.as_object()
                .map(|o| o.keys().filter(|k| *k != "parameters").count())
                .unwrap_or(0)
        })
        .sum();
    assert!(
        ops >= 87,
        "spec floor: expected >= 87 ops, got {ops} - an annotation was removed or stale"
    );
}
