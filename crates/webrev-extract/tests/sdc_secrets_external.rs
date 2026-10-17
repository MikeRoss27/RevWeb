//! External, controlled JS/TS fixture diagnostic, not independent accuracy evidence.
use std::collections::BTreeSet;
use std::path::{Component, Path};

use serde_json::{json, Value};
use webrev_core::{FindingKind, SessionId};
use webrev_extract::{extractors::SecretExtractor, ContentKind, ExtractInput, Extractor};

#[test]
fn pinned_external_hardcoded_secret_presence() {
    let root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../benchmarks/external-secrets/sdc-v1");
    let manifest = std::fs::read_to_string(root.join("cases.jsonl")).expect("read case manifest");
    let extractor = SecretExtractor::with_random_key();
    let mut ids = BTreeSet::new();
    let mut families = BTreeSet::new();
    let mut results = Vec::new();
    let (mut tp, mut fp, mut fn_, mut tn) = (0, 0, 0, 0);
    for line in manifest.lines() {
        let case: Value = serde_json::from_str(line).expect("valid case JSON");
        let field = |name: &str| case[name].as_str().expect(name);
        let id = field("id");
        assert!(ids.insert(id.to_owned()), "duplicate case {id}");
        families.insert(field("family").to_owned());
        assert_eq!(field("detector"), "secrets");
        assert_eq!(case["independent_label_review"], false);
        assert!(!field("provenance").is_empty());
        assert!(!field("rationale").is_empty());
        assert_eq!(field("sha256").len(), 64);
        let path = Path::new(field("path"));
        assert!(path
            .components()
            .all(|part| matches!(part, Component::Normal(_))));
        let body = std::fs::read_to_string(root.join(path)).expect("read upstream source");
        assert_eq!(body.len() as u64, case["bytes"].as_u64().unwrap());
        let input = ExtractInput::new(
            SessionId::new(),
            Some(format!("fixture://sdc-secrets-v1/{id}")),
            ContentKind::JavaScript,
            &body,
        );
        // This extractor scans text and does not parse JS/TS or model reachability.
        let findings = extractor.extract(&input);
        let secret_findings: Vec<_> = findings
            .iter()
            .filter(|finding| finding.kind == FindingKind::Secret)
            .collect();
        let detected = !secret_findings.is_empty();
        let positive = match field("label") {
            "positive" => true,
            "negative" => false,
            other => panic!("unexpected label {other}"),
        };
        match (positive, detected) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (true, false) => fn_ += 1,
            (false, false) => tn += 1,
        }
        eprintln!(
            "SDC secrets {id}: label={} detected={detected}",
            field("label")
        );
        // Preserve every negative and the existing true positive. Known misses
        // remain allowed so generic future improvements do not require relabeling.
        if !positive || id == "TS-SECRET-001-reachable" {
            assert_eq!(detected, positive, "case-level regression at {id}");
        }
        results.push(json!({
            "id": id, "family": field("family"), "label": field("label"),
            "detected": detected, "secret_findings": secret_findings.len(),
            "source_sha256": field("sha256"),
        }));
    }
    assert_eq!(ids.len(), 8);
    assert_eq!(families.len(), 3);
    assert_eq!(tp + fn_, 5);
    assert_eq!(fp + tn, 3);
    let ratio = |n: usize, d: usize| {
        (d != 0)
            .then(|| f64::from(u32::try_from(n).unwrap()) / f64::from(u32::try_from(d).unwrap()))
    };
    let report = json!({
        "corpus": "security-defect-corpus-static-secrets-v1",
        "cases": results, "families": families.len(),
        "tp": tp, "fp": fp, "fn": fn_, "tn": tn,
        "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn_),
        "fpr": ratio(fp, fp + tn), "fnr": ratio(fn_, fn_ + tp),
        "independent_label_review": false,
        "limitations": ["controlled toy fixtures", "three correlated families", "static credential presence only", "no active credential validation", "labels remapped by Webrev maintainers", "not representative of browser applications"],
    });
    eprintln!("SDC secrets TP={tp} FP={fp} FN={fn_} TN={tn}");
    if let Some(path) = std::env::var_os("WEBREV_SDC_SECRETS_REPORT") {
        std::fs::write(path, serde_json::to_string_pretty(&report).unwrap() + "\n")
            .expect("write diagnostic report");
    }
}
