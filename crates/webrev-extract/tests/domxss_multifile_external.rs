use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use webrev_core::SessionId;
use webrev_extract::{extractors::DomSinkExtractor, ContentKind, ExtractInput, Extractor};

const MODELED_SOURCE_IDS: &[&str] = &[
    "01", "02", "03", "04", "05", "10", "11", "12", "13", "14", "15", "19",
];
const MODELED_SINK_IDS: &[&str] = &["09", "10", "12", "15", "18"];

fn modeled_source_name(id: &str) -> Option<&'static str> {
    match id {
        "01" => Some("document.baseURI"),
        "02" => Some("document.cookie"),
        "03" => Some("document.documentURI"),
        "04" => Some("document.referrer"),
        "05" => Some("document.URL"),
        "10" => Some("location"),
        "11" => Some("location.hash"),
        "12" => Some("location.href"),
        "13" => Some("location.pathname"),
        "14" => Some("location.search"),
        "15" => Some("event.data"),
        "19" => Some("window.name"),
        _ => None,
    }
}

fn modeled_flow_matches(value: &str, source_id: &str, sink_id: &str) -> bool {
    let Some(expected_source) = modeled_source_name(source_id) else {
        return false;
    };
    let Some(flow) = value.strip_prefix("DOM XSS: ") else {
        return false;
    };
    let Some((origin, sink)) = flow.rsplit_once(" -> ") else {
        return false;
    };
    let source_matches = origin == expected_source
        || origin
            .strip_prefix(expected_source)
            .is_some_and(|tail| tail.starts_with(" -> "));
    let sink_matches = match sink_id {
        "09" => sink == "document.write",
        "10" => sink == "document.writeln",
        "12" => sink == "eval",
        "15" => sink == "new Function",
        "18" => sink.ends_with(".innerHTML"),
        _ => false,
    };
    source_matches && sink_matches
}

#[test]
fn external_flow_matcher_requires_the_annotated_sink() {
    assert!(modeled_flow_matches(
        "DOM XSS: location.hash -> div.innerHTML",
        "11",
        "18"
    ));
    assert!(modeled_flow_matches(
        "DOM XSS: location.hash -> substr -> div.innerHTML",
        "11",
        "18"
    ));
    assert!(!modeled_flow_matches(
        "DOM XSS: location.hash -> div.outerHTML",
        "11",
        "18"
    ));
}

#[derive(Default)]
struct CoverageCounts {
    cases: usize,
    hits: usize,
}

#[test]
fn pinned_external_multifile_dom_xss_diagnostic() {
    let manifest = format!(
        "{}/../../benchmarks/external-domxss/multifile-v1/cases.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let input = std::fs::read_to_string(manifest).expect("read pinned external corpus");
    let extractor = DomSinkExtractor::new();
    let mut ids = BTreeSet::new();
    let mut unique_pairs = BTreeSet::new();
    let mut per_method: BTreeMap<String, usize> = BTreeMap::new();
    let mut method_coverage: BTreeMap<String, CoverageCounts> = BTreeMap::new();
    let mut modeled_pairs = BTreeSet::new();
    let mut detected_modeled_pairs = BTreeSet::new();
    let mut raw_signal_cases = 0usize;
    let mut modeled = CoverageCounts::default();

    for (line_no, line) in input.lines().enumerate() {
        let case: Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("invalid JSON at line {}: {error}", line_no + 1));
        let field = |name: &str| {
            case.get(name)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("missing {name} at line {}", line_no + 1))
        };
        let id = field("id");
        let method = field("split_method");
        let source_id = field("source_id");
        let sink_id = field("sink_id");
        assert_eq!(field("label"), "positive", "unexpected label in {id}");
        assert!(ids.insert(id.to_owned()), "duplicate case id {id}");
        unique_pairs.insert((source_id.to_owned(), sink_id.to_owned()));
        *per_method.entry(method.to_owned()).or_default() += 1;

        let files = case
            .get("files")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("missing files object in {id}"));
        assert!(files.contains_key("index.html"), "missing index in {id}");
        assert!(files.contains_key("source.js"), "missing source.js in {id}");
        assert!(files.contains_key("sink.js"), "missing sink.js in {id}");

        // Keep independent ASTs and link only explicit, resolved ES imports.
        let session = SessionId::new();
        let modules: Vec<_> = files
            .iter()
            .filter_map(|(path, source)| {
                if !path.ends_with(".js") {
                    return None;
                }
                Some(ExtractInput::new(
                    session,
                    Some(format!("https://multifile-domxss.test/{id}/{path}")),
                    ContentKind::JavaScript,
                    source
                        .as_str()
                        .unwrap_or_else(|| panic!("non-string JavaScript in {id}/{path}")),
                ))
            })
            .collect();
        let mut findings: Vec<_> = modules
            .iter()
            .flat_map(|input| extractor.extract(input))
            .collect();
        let linked = DomSinkExtractor::extract_modules(&modules);
        assert!(linked
            .iter()
            .all(|finding| finding.status == webrev_core::FindingStatus::Suspicious));
        findings.extend(linked);
        let findings: Vec<_> = findings
            .into_iter()
            .filter(|finding| finding.value.starts_with("DOM XSS:"))
            .map(|finding| finding.value)
            .collect();
        raw_signal_cases += usize::from(!findings.is_empty());

        let in_model_scope =
            MODELED_SOURCE_IDS.contains(&source_id) && MODELED_SINK_IDS.contains(&sink_id);
        if in_model_scope {
            let detected = findings
                .iter()
                .any(|finding| modeled_flow_matches(finding, source_id, sink_id));
            let method_counts = method_coverage.entry(method.to_owned()).or_default();
            method_counts.cases += 1;
            method_counts.hits += usize::from(detected);
            let pair = (source_id.to_owned(), sink_id.to_owned());
            modeled_pairs.insert(pair.clone());
            if detected {
                detected_modeled_pairs.insert(pair);
            }
            modeled.cases += 1;
            modeled.hits += usize::from(detected);
        }
    }

    assert_eq!(ids.len(), 342);
    assert_eq!(unique_pairs.len(), 69);
    assert_eq!(modeled.cases, 122);
    assert_eq!(
        modeled.hits, 105,
        "pinned ES value/function-import coverage must not silently regress"
    );
    assert_eq!(
        per_method,
        BTreeMap::from([
            ("type01".to_owned(), 69),
            ("type02".to_owned(), 66),
            ("type03".to_owned(), 69),
            ("type04".to_owned(), 69),
            ("type05".to_owned(), 69),
        ])
    );
    eprintln!(
        "external multi-file DOM XSS: raw unrelated-or-matching flow signals on {raw_signal_cases}/342 cases; modeled-category exact-flow coverage across explicitly linked module ASTs: matched={} unmatched={} / {}; unique pairs with a match={}/{}; all unique pairs={} (variants are correlated)",
        modeled.hits,
        modeled.cases - modeled.hits,
        modeled.cases,
        detected_modeled_pairs.len(),
        modeled_pairs.len(),
        unique_pairs.len(),
    );
    for (method, counts) in method_coverage {
        eprintln!(
            "{method}: exact-flow multi-file coverage matched={} unmatched={} / {}",
            counts.hits,
            counts.cases - counts.hits,
            counts.cases
        );
    }
    eprintln!("detected in-scope source/sink pairs: {detected_modeled_pairs:?}");
}
