use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use serde_json::Value;
use webrev_core::SessionId;
use webrev_extract::{ContentKind, ExtractInput, ExtractorRegistry};

#[derive(Default)]
struct Counts {
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
    inconclusive: usize,
}

#[test]
fn pinned_swipe_dom_xss_diagnostic() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/external-candidates/swipe-v1");
    let manifest =
        std::fs::read_to_string(root.join("cases.jsonl")).expect("read SWIPE fixture manifest");
    let inventory: Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("inventory.json")).expect("read SWIPE inventory"),
    )
    .expect("parse SWIPE inventory");
    let inventory_files: BTreeMap<_, _> = inventory["files"]
        .as_array()
        .expect("inventory files array")
        .iter()
        .map(|file| {
            (
                file["path"].as_str().expect("inventory path").to_owned(),
                file["bytes"].as_u64().expect("inventory byte count"),
            )
        })
        .collect();
    assert_eq!(
        inventory["files"].as_array().unwrap().len(),
        inventory_files.len(),
        "duplicate inventoried source path"
    );
    assert_eq!(
        inventory_files.len(),
        32,
        "update pinned inventory deliberately"
    );
    // Improvements on these positives are allowed. Every other adjudicated
    // case must retain its own result; aggregate counts could hide a swap.
    let known_misses = BTreeSet::from(["swipe-simpleDOMXSS1-index", "swipe-testFields3-index"]);
    let registry = ExtractorRegistry::with_defaults();
    let mut ids = BTreeSet::new();
    let mut used_files = BTreeSet::new();
    let mut regressions = Vec::new();
    let mut counts = Counts::default();
    let mut total = 0;

    for (line_no, line) in manifest.lines().enumerate() {
        let case: Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("invalid JSON at line {}: {error}", line_no + 1));
        let field = |name: &str| {
            case.get(name)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("missing {name} at line {}", line_no + 1))
        };
        let id = field("id");
        let label = field("label");
        assert!(ids.insert(id.to_owned()), "duplicate SWIPE fixture {id}");
        assert_eq!(
            field("detector"),
            "dom_xss_flow",
            "unexpected detector at {id}"
        );
        assert_eq!(
            field("split"),
            "external-diagnostic",
            "unexpected split at {id}"
        );
        assert!(
            !field("provenance").is_empty(),
            "missing provenance at {id}"
        );
        assert!(!field("rationale").is_empty(), "missing rationale at {id}");

        let files = case
            .get("files")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing files array at {id}"));
        assert!(!files.is_empty(), "empty file list at {id}");
        let mut flow_findings = Vec::new();
        for file in files {
            let relative = file
                .as_str()
                .unwrap_or_else(|| panic!("non-string file path at {id}"));
            let path = Path::new(relative);
            assert!(
                path.components()
                    .all(|part| matches!(part, Component::Normal(_))),
                "unsafe corpus path at {id}: {relative}"
            );
            used_files.insert(relative.to_owned());
            let expected_bytes = inventory_files
                .get(relative)
                .unwrap_or_else(|| panic!("file missing from inventory at {id}: {relative}"));
            let body = std::fs::read_to_string(root.join("files").join(path))
                .unwrap_or_else(|error| panic!("read {relative} for {id}: {error}"));
            assert_eq!(
                body.len() as u64,
                *expected_bytes,
                "pinned source byte length changed at {relative}"
            );
            let kind = match path.extension().and_then(|ext| ext.to_str()) {
                Some("html") => ContentKind::Html,
                Some("js") => ContentKind::JavaScript,
                other => panic!("unsupported file extension {other:?} in {id}"),
            };
            let input = ExtractInput::new(
                SessionId::new(),
                Some(format!("fixture://swipe-v1/{relative}")),
                kind,
                &body,
            );
            flow_findings.extend(
                registry
                    .run(&input)
                    .into_iter()
                    .filter(|finding| finding.value.starts_with("DOM XSS:"))
                    .map(|finding| finding.value),
            );
        }
        let detected = !flow_findings.is_empty();
        if (label == "positive" && !detected) || (label == "negative" && detected) {
            eprintln!("SWIPE mismatch {id}: label={label}, findings={flow_findings:?}");
        }

        if (label == "positive" && !detected && !known_misses.contains(id))
            || (label == "negative" && detected)
        {
            regressions.push(format!("{id}: label={label}, findings={flow_findings:?}"));
        }
        if known_misses.contains(id) {
            assert_eq!(label, "positive", "known miss must remain a positive: {id}");
        }

        match (label, detected) {
            ("positive", true) => counts.tp += 1,
            ("positive", false) => counts.fn_ += 1,
            ("negative", true) => counts.fp += 1,
            ("negative", false) => counts.tn += 1,
            ("inconclusive", _) => counts.inconclusive += 1,
            _ => panic!("unknown label {label} at {id}"),
        }
        total += 1;
    }

    assert_eq!(total, 30, "update SWIPE candidate README when cases change");
    assert_eq!(counts.tp + counts.fn_, 16, "positive label count changed");
    assert_eq!(counts.fp + counts.tn, 13, "negative label count changed");
    assert_eq!(counts.inconclusive, 1, "inconclusive label count changed");
    assert!(known_misses.iter().all(|id| ids.contains(*id)));
    assert_eq!(
        used_files,
        inventory_files.keys().cloned().collect(),
        "manifest must exercise every inventoried source file"
    );
    let mut by_label = BTreeMap::new();
    by_label.insert("positive", (counts.tp, counts.fn_));
    by_label.insert("negative", (counts.fp, counts.tn));
    eprintln!(
        "SWIPE DOM-XSS candidate: cases={total}, TP={} FP={} FN={} TN={} inconclusive={}, positive={:?}, negative={:?}",
        counts.tp,
        counts.fp,
        counts.fn_,
        counts.tn,
        counts.inconclusive,
        by_label["positive"],
        by_label["negative"]
    );
    assert!(
        regressions.is_empty(),
        "SWIPE per-case regressions (known gaps are tolerated):\n{}",
        regressions.join("\n")
    );
}
