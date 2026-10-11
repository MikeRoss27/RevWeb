// crates/webrev-extract/src/extractors/metadata/domsinks.rs
//! Flags dangerous DOM / script sinks and cross-document messaging in
//! JavaScript: HTML-injection sinks (`innerHTML =`, `outerHTML =`,
//! `document.write(`, `.insertAdjacentHTML(`, `dangerouslySetInnerHTML`),
//! dynamic code execution (`eval(`, `new Function(`), navigation sinks
//! (`location.href =`), `postMessage` receivers (`addEventListener('message')`
//! / `onmessage =`, flagged when no origin check is visible nearby), and
//! WebAssembly use (`WebAssembly.instantiate`, `*.wasm` references).
//!
//! These are *leads*, not proofs — reachability from attacker-controlled input
//! is not established statically — so findings are [`FindingKind::Config`] at
//! `Low`/`Medium` confidence, each carrying a short source snippet.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Generic sink patterns: `(regex, label, confidence)`.
const SINK_PATTERNS: &[(&str, &str, Confidence)] = &[
    (
        r"(?i)\.innerhtml\s*=[^=]",
        "innerHTML assignment (DOM-XSS sink)",
        Confidence::Medium,
    ),
    (
        r"(?i)\.outerhtml\s*=[^=]",
        "outerHTML assignment (DOM-XSS sink)",
        Confidence::Medium,
    ),
    (
        r"(?i)document\.write(?:ln)?\s*\(",
        "document.write() sink",
        Confidence::Medium,
    ),
    (r"\beval\s*\(", "eval() sink", Confidence::Medium),
    (
        r"(?i)\.insertadjacenthtml\s*\(",
        "insertAdjacentHTML() sink",
        Confidence::Medium,
    ),
    (
        r"\bnew\s+Function\s*\(",
        "new Function() sink",
        Confidence::Medium,
    ),
    (
        r"dangerouslySetInnerHTML",
        "React dangerouslySetInnerHTML sink",
        Confidence::Medium,
    ),
    (
        r"(?i)location\.href\s*=[^=]",
        "location.href assignment (open-redirect / navigation sink)",
        Confidence::Low,
    ),
    (
        r"(?i)WebAssembly\.(?:instantiatestreaming|instantiate|compilestreaming|compile)",
        "WebAssembly instantiation",
        Confidence::Low,
    ),
    (
        r"(?i)[\w./\-]+\.wasm\b",
        "WebAssembly module reference",
        Confidence::Low,
    ),
];

/// `postMessage` receiver patterns, analysed specially for a nearby origin
/// check.
const MESSAGE_PATTERNS: &[&str] = &[
    r#"(?i)addeventlistener\s*\(\s*['"]message['"]"#,
    r"(?i)\bonmessage\s*=[^=]",
];

/// How far past a `message` handler to look for an `origin` check.
const ORIGIN_WINDOW: usize = 240;

/// DOM-sink / postMessage / wasm extractor.
pub struct DomSinkExtractor {
    patterns: Vec<(Regex, &'static str, Confidence)>,
    message: Vec<Regex>,
}

impl DomSinkExtractor {
    /// Build the extractor.
    ///
    /// # Panics
    ///
    /// Never at runtime: all patterns are constants verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        let patterns = SINK_PATTERNS
            .iter()
            .map(|(re, label, conf)| {
                (
                    Regex::new(re).expect("sink pattern is valid"),
                    *label,
                    *conf,
                )
            })
            .collect();
        let message = MESSAGE_PATTERNS
            .iter()
            .map(|re| Regex::new(re).expect("message pattern is valid"))
            .collect();
        Self { patterns, message }
    }
}

impl Default for DomSinkExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// A whitespace-collapsed snippet of source starting at `start`, bounded to the
/// current statement (stops at the first `;` or newline, or 96 chars). Bounding
/// to the statement keeps repeated identical sinks deduplicating cleanly.
fn snippet(body: &str, start: usize) -> String {
    let window: String = body[start..]
        .chars()
        .take(96)
        .take_while(|&c| c != ';' && c != '\n')
        .collect();
    window.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Extractor for DomSinkExtractor {
    fn name(&self) -> &'static str {
        "dom-sinks"
    }

    fn priority(&self) -> u8 {
        42
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::JavaScript
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let body = &input.body;
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();

        let mut push = |value: String, confidence: Confidence| {
            if !seen.insert(value.clone()) {
                return;
            }
            findings.push(Finding::new(
                input.session_id,
                FindingKind::Config,
                None,
                value,
                confidence,
                Provenance::new(Source::JsRegex, input.url.clone()),
            ));
        };

        for (regex, label, confidence) in &self.patterns {
            for m in regex.find_iter(body) {
                push(
                    format!("{label}: {}", snippet(body, m.start())),
                    *confidence,
                );
            }
        }

        // postMessage receivers: a missing origin check in the handler window
        // is the interesting case, so it is bumped to Medium.
        for regex in &self.message {
            for m in regex.find_iter(body) {
                let end = (m.start() + ORIGIN_WINDOW).min(body.len());
                // Snap to a char boundary so slicing never panics.
                let mut end = end;
                while end < body.len() && !body.is_char_boundary(end) {
                    end += 1;
                }
                let has_origin = body[m.start()..end].to_ascii_lowercase().contains("origin");
                let (label, confidence) = if has_origin {
                    ("postMessage receiver", Confidence::Low)
                } else {
                    (
                        "postMessage receiver (no origin check nearby)",
                        Confidence::Medium,
                    )
                };
                push(format!("{label}: {}", snippet(body, m.start())), confidence);
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(js: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/app.js".into()),
            ContentKind::JavaScript,
            js,
        );
        DomSinkExtractor::new().extract(&input)
    }

    fn labels(found: &[Finding]) -> Vec<String> {
        found
            .iter()
            .map(|f| f.value.split(':').next().unwrap_or("").to_owned())
            .collect()
    }

    #[test]
    fn patterns_compile() {
        let _ = DomSinkExtractor::new();
    }

    #[test]
    fn detects_html_and_code_sinks() {
        let js = r"
            el.innerHTML = userInput;
            node.outerHTML = x;
            document.write(data);
            eval(code);
            target.insertAdjacentHTML('beforeend', frag);
            const f = new Function('a', 'return a');
            const r = <div dangerouslySetInnerHTML={{__html: x}} />;
            window.location.href = next;
        ";
        let found = run(js);
        assert!(found.iter().all(|f| f.kind == FindingKind::Config));
        let ls = labels(&found);
        assert!(ls.iter().any(|l| l.contains("innerHTML assignment")));
        assert!(ls.iter().any(|l| l.contains("outerHTML assignment")));
        assert!(ls.iter().any(|l| l.contains("document.write")));
        assert!(ls.iter().any(|l| l.contains("eval")));
        assert!(ls.iter().any(|l| l.contains("insertAdjacentHTML")));
        assert!(ls.iter().any(|l| l.contains("new Function")));
        assert!(ls.iter().any(|l| l.contains("dangerouslySetInnerHTML")));
        assert!(ls.iter().any(|l| l.contains("location.href")));
    }

    #[test]
    fn detects_wasm() {
        let js = r#"fetch("/app.wasm"); WebAssembly.instantiateStreaming(resp);"#;
        let ls = labels(&run(js));
        assert!(ls
            .iter()
            .any(|l| l.contains("WebAssembly module reference")));
        assert!(ls.iter().any(|l| l.contains("WebAssembly instantiation")));
    }

    #[test]
    fn postmessage_without_origin_is_medium() {
        let js = r"window.addEventListener('message', function (e) { run(e.data); });";
        let found = run(js);
        let f = found
            .iter()
            .find(|f| f.value.starts_with("postMessage receiver"))
            .expect("postMessage finding");
        assert_eq!(f.confidence, Confidence::Medium);
        assert!(f.value.contains("no origin check"));
    }

    #[test]
    fn postmessage_with_origin_is_low() {
        let js = r"window.addEventListener('message', function (e) { if (e.origin !== OK) return; run(e.data); });";
        let found = run(js);
        let f = found
            .iter()
            .find(|f| f.value.starts_with("postMessage receiver"))
            .expect("postMessage finding");
        assert_eq!(f.confidence, Confidence::Low);
    }

    #[test]
    fn negative_and_dedup() {
        // No sinks here.
        assert_eq!(run("const total = a + b; renderSafely(total);"), Vec::new());
        // Two identical sinks collapse to one finding.
        let js = "a.innerHTML = x;\na.innerHTML = x;";
        assert_eq!(run(js).len(), 1);
    }
}
