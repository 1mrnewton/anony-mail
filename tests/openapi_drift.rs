//! Spec drift guards (U4). The OpenAPI document is hand-maintained, so these
//! tests fail loudly when it stops matching reality:
//! - `info.version` must equal the crate version, and
//! - the router's path set and the spec's path set must be identical (axum
//!   0.8 and OpenAPI share the `{param}` syntax, so paths compare verbatim).

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;

fn manifest_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn spec() -> serde_json::Value {
    let raw = std::fs::read_to_string(manifest_path("openapi.json")).expect("read openapi.json");
    serde_json::from_str(&raw).expect("openapi.json is valid JSON")
}

#[test]
fn spec_version_matches_crate_version() {
    assert_eq!(
        spec()["info"]["version"].as_str().expect("info.version"),
        env!("CARGO_PKG_VERSION"),
        "openapi.json info.version must match Cargo.toml"
    );
}

#[test]
fn every_router_path_is_documented_and_vice_versa() {
    // All routes are registered in src/api/mod.rs via `.route("...", ...)`;
    // scrape them from the source so new endpoints can't dodge the spec.
    let source =
        std::fs::read_to_string(manifest_path("src/api/mod.rs")).expect("read src/api/mod.rs");
    let route_re = Regex::new(r#"\.route\(\s*"([^"]+)""#).unwrap();
    let router_paths: BTreeSet<String> = route_re
        .captures_iter(&source)
        .map(|c| c[1].to_string())
        .collect();
    assert!(
        router_paths.len() >= 10,
        "route scrape looks broken: only found {router_paths:?}"
    );

    let spec = spec();
    let spec_paths: BTreeSet<String> = spec["paths"]
        .as_object()
        .expect("paths object")
        .keys()
        .cloned()
        .collect();

    let undocumented: Vec<_> = router_paths.difference(&spec_paths).collect();
    let phantom: Vec<_> = spec_paths.difference(&router_paths).collect();
    assert!(
        undocumented.is_empty() && phantom.is_empty(),
        "openapi.json drifted from the router.\n  routes missing from spec: \
         {undocumented:?}\n  spec paths with no route: {phantom:?}"
    );
}
