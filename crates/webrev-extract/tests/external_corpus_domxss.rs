//! Runs the static DOM XSS detector over the external corpus fetched by
//! `scripts/external_corpus.py` and writes per-case results. It never fails on a
//! detection mismatch: the corpus measures the detector, and the labels must not
//! be bent to it. Run explicitly (the cache is not committed):
//!
//! ```sh
//! python3 scripts/external_corpus.py fetch
//! cargo test --release -p webrev-extract --test external_corpus_domxss -- --ignored --nocapture
//! python3 scripts/external_corpus.py report
//! ```

use std::collections::BTreeSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use serde_json::{json, Value};
use webrev_core::SessionId;
use webrev_extract::{ContentKind, ExtractInput, ExtractorRegistry};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/external-corpus/v1")
}

fn cache_dir() -> PathBuf {
    std::env::var_os("WEBREV_EXTERNAL_CORPUS")
        .map(PathBuf::from)
        .unwrap_or_else(|| corpus_dir().join("cache"))
}

fn kind_for(path: &Path) -> Option<ContentKind> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "html" | "htm" => Some(ContentKind::Html),
        "js" | "mjs" | "cjs" | "jsx" => Some(ContentKind::JavaScript),
        _ => None,
    }
}

fn git_commit() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

#[test]
#[ignore = "needs the corpus cache from scripts/external_corpus.py fetch"]
fn external_corpus_dom_xss_diagnostic() {
    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(corpus_dir().join("manifest.json")).expect("read manifest"),
    )
    .expect("parse manifest");
    let cache = cache_dir();
    let registry = ExtractorRegistry::with_defaults();
    let mut cases = Vec::new();
    let mut ids = BTreeSet::new();

    for case in manifest["cases"].as_array().expect("cases array") {
        let id = case["id"].as_str().expect("case id");
        assert!(ids.insert(id.to_owned()), "duplicate case {id}");
        let mut findings: Vec<String> = Vec::new();
        let mut confidences: Vec<String> = Vec::new();
        let mut file_reports = Vec::new();
        let mut evaluable = false;
        let mut error: Option<String> = None;

        for file in case["files"].as_array().expect("files array") {
            let relative = file["path"].as_str().expect("file path");
            let path = Path::new(relative);
            assert!(
                path.components()
                    .all(|part| matches!(part, Component::Normal(_))),
                "unsafe corpus path {relative}"
            );
            let Some(kind) = kind_for(path) else {
                file_reports.push(json!({"path": relative, "skipped": "unsupported extension"}));
                continue;
            };
            let body = match std::fs::read(cache.join(path)) {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(err) => {
                    error = Some(format!("read {relative}: {err}"));
                    continue;
                }
            };
            evaluable = true;
            let input = ExtractInput::new(
                SessionId::new(),
                Some(format!("fixture://external-corpus/{relative}")),
                kind,
                &body,
            );
            let started = Instant::now();
            let outcome = catch_unwind(AssertUnwindSafe(|| registry.run(&input)));
            let elapsed_ms = started.elapsed().as_millis() as u64;
            match outcome {
                Ok(all) => {
                    let flows: Vec<_> = all
                        .into_iter()
                        .filter(|finding| finding.value.starts_with("DOM XSS:"))
                        .collect();
                    file_reports.push(json!({
                        "path": relative, "bytes": body.len(), "elapsed_ms": elapsed_ms,
                        "flows": flows.len(),
                        "findings": flows.iter().map(|f| f.value.clone()).collect::<Vec<_>>(),
                    }));
                    for finding in flows {
                        confidences.push(format!("{:?}", finding.confidence));
                        findings.push(finding.value);
                    }
                }
                Err(_) => {
                    error = Some(format!("extractor panicked on {relative}"));
                }
            }
        }
        cases.push(json!({
            "id": id,
            "evaluable": evaluable && error.is_none(),
            "detected": !findings.is_empty(),
            "findings": findings,
            "confidences": confidences,
            "files": file_reports,
            "error": error,
        }));
    }

    let results = json!({
        "corpus": manifest["version"],
        "commit": git_commit(),
        "mode": "static registry (ExtractorRegistry::with_defaults), per file, release build",
        "cases": cases,
    });
    let out = std::env::var_os("WEBREV_EXTERNAL_RESULTS")
        .map(PathBuf::from)
        .unwrap_or_else(|| corpus_dir().join("results.json"));
    std::fs::write(&out, serde_json::to_string_pretty(&results).unwrap() + "\n")
        .expect("write results");
    eprintln!("wrote {} ({} cases)", out.display(), ids.len());
}
