use std::collections::BTreeMap;

use serde_json::Value;
use webrev_core::{Finding, FindingKind, SessionId};
use webrev_extract::{
    extractors::{DomSinkExtractor, JsAstExtractor, JsRegexExtractor, ParamExtractor},
    ContentKind, ExtractInput, Extractor,
};

#[derive(Default, Clone, Copy)]
struct Counts {
    tp: usize,
    fp: usize,
    fn_: usize,
    tn: usize,
}

impl Counts {
    fn observe(&mut self, positive: bool, detected: bool) {
        match (positive, detected) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
    }

    fn print(self, detector: &str) {
        eprintln!(
            "juice-shop {detector}: TP={} FP={} FN={} TN={} precision={} recall={} FPR={}",
            self.tp,
            self.fp,
            self.fn_,
            self.tn,
            ratio(self.tp, self.tp + self.fp),
            ratio(self.tp, self.tp + self.fn_),
            ratio(self.fp, self.fp + self.tn),
        );
    }
}

fn ratio(n: usize, d: usize) -> String {
    if d == 0 {
        "n/a".to_owned()
    } else {
        format!("{:.3}", n as f64 / d as f64)
    }
}

fn extractor(name: &str) -> Box<dyn Extractor> {
    match name {
        "js_ast_endpoint" => Box::new(JsAstExtractor::new()),
        "js_regex_endpoint" => Box::new(JsRegexExtractor::new()),
        "http_parameters" => Box::new(ParamExtractor::new()),
        "dom_xss_flow" => Box::new(DomSinkExtractor::new()),
        _ => panic!("unknown detector {name}"),
    }
}

fn has_signal(detector: &str, findings: &[Finding]) -> bool {
    findings.iter().any(|finding| match detector {
        "js_ast_endpoint" | "js_regex_endpoint" => finding.kind == FindingKind::Endpoint,
        "http_parameters" => finding.kind == FindingKind::Parameter,
        "dom_xss_flow" => finding.value.starts_with("DOM XSS:"),
        _ => panic!("unknown detector {detector}"),
    })
}

fn eval_source(detector: &str, kind: ContentKind, source: &str, path: &str) -> Vec<Finding> {
    // The pinned corpus stores line-level JavaScript excerpts to keep the
    // evidence reviewable. A method-body `return` is not valid at module scope,
    // so provide the smallest syntactic context needed by the AST parser.
    let body = if kind == ContentKind::JavaScript && source.trim_start().starts_with("return ") {
        format!("function __probe__() {{ {source} }}")
    } else {
        source.to_owned()
    };
    let input = ExtractInput::new(
        SessionId::new(),
        Some(format!("https://juice-shop.invalid/{path}")),
        kind,
        body,
    );
    let extractor = extractor(detector);
    if extractor.applies_to(&input) {
        extractor.extract(&input)
    } else {
        Vec::new()
    }
}

#[test]
fn pinned_juice_shop_external_probe() {
    let manifest = format!(
        "{}/../../benchmarks/juice-shop/v19.0.0/cases.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let source = std::fs::read_to_string(manifest).expect("read Juice Shop cases");
    let mut metrics: BTreeMap<String, Counts> = BTreeMap::new();
    let mut cases = 0;

    for (line_no, line) in source.lines().enumerate() {
        let case: Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("invalid JSON at line {}: {error}", line_no + 1));
        let get = |key: &str| {
            case.get(key)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("missing {key} at line {}", line_no + 1))
        };
        assert_eq!(
            get("commit"),
            "36870cbbdfe7864698e1adf644c7bf772f67ebb7",
            "external corpus commit must stay pinned"
        );
        assert_eq!(
            get("label"),
            "positive",
            "this exploratory corpus has positives only"
        );
        let id = get("id");
        let detector = get("detector");
        let mut findings = Vec::new();
        if let Some(inputs) = case.get("sources").and_then(Value::as_array) {
            for input in inputs {
                let kind = match input.get("kind").and_then(Value::as_str) {
                    Some("javascript") => ContentKind::JavaScript,
                    Some("html") => ContentKind::Html,
                    other => panic!("bad source kind in {id}: {other:?}"),
                };
                let body = input
                    .get("source")
                    .and_then(Value::as_str)
                    .expect("source text");
                let path = input
                    .get("path")
                    .and_then(Value::as_str)
                    .expect("source path");
                findings.extend(eval_source(detector, kind, body, path));
            }
        } else {
            let kind = match get("kind") {
                "javascript" => ContentKind::JavaScript,
                "html" => ContentKind::Html,
                other => panic!("unsupported source kind {other} in {id}"),
            };
            findings.extend(eval_source(
                detector,
                kind,
                get("source"),
                get("provenance"),
            ));
        }

        let detected = has_signal(detector, &findings);
        if !detected {
            eprintln!(
                "external mismatch {id}: label=positive, detector={detector}, findings={:?}",
                findings
                    .iter()
                    .map(|f| (&f.kind, &f.value))
                    .collect::<Vec<_>>()
            );
        }
        metrics
            .entry(detector.to_owned())
            .or_default()
            .observe(true, detected);
        cases += 1;
    }

    assert_eq!(cases, 4, "update README when cases change");
    eprintln!(
        "Juice Shop v19.0.0: {cases} positive detector cases; no negative labels, metrics are recall-only"
    );
    for (detector, counts) in metrics {
        counts.print(&detector);
    }
}
