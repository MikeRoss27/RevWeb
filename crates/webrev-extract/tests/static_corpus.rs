use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use webrev_core::{Finding, FindingKind, SessionId};
use webrev_extract::{
    extractors::{
        DomSinkExtractor, JsAstExtractor, JsRegexExtractor, ParamExtractor, SecretExtractor,
    },
    ContentKind, ExtractInput, Extractor,
};

#[derive(Default, Clone, Copy)]
struct Counts {
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
    ambiguous: usize,
}

impl Counts {
    fn observe(&mut self, label: &str, detected: bool) {
        match (label, detected) {
            ("positive", true) => self.tp += 1,
            ("positive", false) => self.fn_ += 1,
            ("negative", true) => self.fp += 1,
            ("negative", false) => self.tn += 1,
            ("ambiguous", _) => self.ambiguous += 1,
            _ => panic!("unknown corpus label: {label}"),
        }
    }

    fn metrics(self) -> String {
        format!(
            "TP={} FP={} FN={} TN={} ambiguous={} precision={} recall={} FPR={} FNR={}",
            self.tp,
            self.fp,
            self.fn_,
            self.tn,
            self.ambiguous,
            ratio(self.tp, self.tp + self.fp),
            ratio(self.tp, self.tp + self.fn_),
            ratio(self.fp, self.fp + self.tn),
            ratio(self.fn_, self.fn_ + self.tp),
        )
    }
}

fn ratio(numerator: usize, denominator: usize) -> String {
    if denominator == 0 {
        "n/a".to_owned()
    } else {
        format!("{:.3}", numerator as f64 / denominator as f64)
    }
}

fn has_signal(detector: &str, findings: &[Finding]) -> bool {
    findings.iter().any(|finding| match detector {
        "js_ast_endpoint" | "js_regex_endpoint" => finding.kind == FindingKind::Endpoint,
        "http_parameters" => finding.kind == FindingKind::Parameter,
        "secrets" => finding.kind == FindingKind::Secret,
        "dom_xss_flow" => finding.value.starts_with("DOM XSS:"),
        _ => panic!("unknown detector: {detector}"),
    })
}

fn extractor(detector: &str) -> Box<dyn Extractor> {
    match detector {
        "js_ast_endpoint" => Box::new(JsAstExtractor::new()),
        "js_regex_endpoint" => Box::new(JsRegexExtractor::new()),
        "http_parameters" => Box::new(ParamExtractor::new()),
        "secrets" => Box::new(SecretExtractor::with_random_key()),
        "dom_xss_flow" => Box::new(DomSinkExtractor::new()),
        _ => panic!("unknown detector: {detector}"),
    }
}

#[test]
fn labeled_static_corpus_metrics() {
    let manifest = format!(
        "{}/../../benchmarks/static-corpus/v1/cases.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let source = std::fs::read_to_string(manifest).expect("read static corpus cases");
    let mut ids = BTreeSet::new();
    let mut families: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut metrics: BTreeMap<(String, String), Counts> = BTreeMap::new();
    let mut total = 0usize;

    for (line_no, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let case: Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("invalid JSON at corpus line {}: {error}", line_no + 1));
        let field = |name: &str| {
            case.get(name)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("missing string field {name} at line {}", line_no + 1))
        };
        let id = field("id").to_owned();
        let detector = field("detector").to_owned();
        let split = field("split").to_owned();
        let family = field("project_family").to_owned();
        let label = field("label");
        let body = field("source");
        let kind = match field("kind") {
            "html" => ContentKind::Html,
            "javascript" => ContentKind::JavaScript,
            other => panic!("unsupported content kind {other} at {id}"),
        };
        assert!(ids.insert(id.clone()), "duplicate corpus id {id}");
        assert!(
            matches!(split.as_str(), "dev" | "validation"),
            "invalid split at {id}"
        );
        assert!(!field("provenance").is_empty(), "empty provenance at {id}");
        assert!(!field("rationale").is_empty(), "empty rationale at {id}");
        assert!(
            !field("expected_signal").is_empty(),
            "empty expected signal at {id}"
        );
        assert!(!body.is_empty(), "empty source at {id}");
        match (detector.as_str(), kind) {
            ("http_parameters" | "secrets", ContentKind::Html | ContentKind::JavaScript)
            | ("js_ast_endpoint" | "js_regex_endpoint" | "dom_xss_flow", ContentKind::JavaScript) =>
                {}
            _ => panic!("invalid detector/content-kind combination at {id}"),
        }

        // A family is assigned to only one split for a given detector.
        let family_key = (detector.clone(), family.clone());
        if let Some(previous) = families.insert(family_key, split.clone()) {
            assert_eq!(
                previous, split,
                "family {family} leaks across splits for {detector}"
            );
        }

        let input = ExtractInput::new(
            SessionId::new(),
            Some(format!("fixture://webrev-static-v1/{family}/{id}")),
            kind,
            body,
        );
        let found = extractor(&detector).extract(&input);
        let detected = has_signal(&detector, &found);
        if (label == "positive" && !detected) || (label == "negative" && detected) {
            let kinds: Vec<_> = found
                .iter()
                .map(|finding| format!("{:?}", finding.kind))
                .collect();
            eprintln!("corpus mismatch {id}: label={label}, finding kinds={kinds:?}");
        }
        metrics
            .entry((detector.clone(), split.clone()))
            .or_default()
            .observe(label, detected);
        total += 1;
    }

    assert_eq!(
        total, 50,
        "update the corpus README when case count changes"
    );
    eprintln!("static corpus v1: {total} cases; ambiguous labels excluded from binary metrics");
    for ((detector, split), counts) in metrics {
        eprintln!("{detector} [{split}]: {}", counts.metrics());
    }
}
