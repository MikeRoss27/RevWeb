use serde_json::Value;
use webrev_core::SessionId;
use webrev_extract::{extractors::DomSinkExtractor, ContentKind, ExtractInput, Extractor};

/// Maintainer-authored negatives: any `DOM XSS:` flow, single-file or linked
/// across modules, is a false positive.
#[test]
fn multifile_negatives_produce_no_dom_xss_flow() {
    let manifest = format!(
        "{}/../../benchmarks/external-domxss/multifile-negatives-v1/cases.jsonl",
        env!("CARGO_MANIFEST_DIR")
    );
    let input = std::fs::read_to_string(manifest).expect("read negative set");
    let extractor = DomSinkExtractor::new();
    let (mut cases, mut false_positives) = (0usize, Vec::new());
    for line in input.lines() {
        let case: Value = serde_json::from_str(line).expect("valid JSON line");
        let id = case["id"].as_str().expect("id");
        assert_eq!(case["label"], "negative", "{id}");
        let session = SessionId::new();
        let modules: Vec<_> = case["files"]
            .as_object()
            .expect("files")
            .iter()
            .filter(|(path, _)| path.ends_with(".js"))
            .map(|(path, source)| {
                ExtractInput::new(
                    session,
                    Some(format!("https://negatives.test/{id}/{path}")),
                    ContentKind::JavaScript,
                    source.as_str().expect("string source"),
                )
            })
            .collect();
        let mut flows: Vec<String> = modules
            .iter()
            .flat_map(|module| extractor.extract(module))
            .chain(DomSinkExtractor::extract_modules(&modules))
            .map(|finding| finding.value)
            .filter(|value| value.starts_with("DOM XSS:"))
            .collect();
        flows.sort();
        flows.dedup();
        cases += 1;
        if !flows.is_empty() {
            false_positives.push(format!("{id}: {flows:?}"));
        }
    }
    eprintln!(
        "multi-file DOM XSS negatives (maintainer-authored): cases={cases} flagged={}",
        false_positives.len()
    );
    assert_eq!(cases, 20);
    assert!(
        false_positives.is_empty(),
        "false positives: {false_positives:#?}"
    );
}
