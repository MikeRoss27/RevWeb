// crates/webrev-extract/src/extractors/metadata/domsinks.rs
//! Flags client-side DOM-XSS exposure in JavaScript, with evidence of a
//! *dataflow path* from an attacker-controllable source into a dangerous sink
//! rather than the mere presence of a sink.
//!
//! # Two passes
//!
//! 1. **Static taint pass (swc AST, [`Source::JsAst`]).** A lightweight,
//!    *intra-procedural* taint tracker walks the module and reports flows of
//!    the form `source -> sink` (e.g. `DOM XSS: location.hash -> el.innerHTML`).
//!    A flow is reported when a sink's argument / right-hand side is:
//!    (a) directly a taint source, (b) a variable previously assigned a tainted
//!    value in an enclosing scope, or (c) a string concatenation / template
//!    literal containing a tainted value. Direct source → sink flows are
//!    `High` confidence; flows laundered through a variable or a
//!    concatenation are `Medium`.
//!    - **Sources:** `location`, `location.href`/`search`/`hash`/`pathname`,
//!      `document.URL`/`documentURI`/`referrer`/`cookie`/`baseURI`,
//!      `window.name`, and, inside a `message` event handler, the handler's
//!      first parameter and its `.data` property (`event.data` / `e.data`).
//!    - **Sinks:** assignment to `.innerHTML`/`.outerHTML`, `document.write(`
//!      / `writeln(`, `eval(`, `new Function(`, `.insertAdjacentHTML(`,
//!      assignment to `location` / `location.href`, and the React
//!      `dangerouslySetInnerHTML` `{__html: …}` property.
//!
//! 2. **Regex fallback ([`Source::JsRegex`]).** To keep recall on minified or
//!    unparseable code, every sink *pattern* is still matched textually; a sink
//!    for which the taint pass traced no source is emitted as a `Low`
//!    "unverified source" lead (unless it falls inside a traced flow, in which
//!    case the higher-confidence AST finding already covers it). `WebAssembly.*`
//!    / `*.wasm` references and `postMessage` receiver origin-check analysis are
//!    retained here unchanged.
//!
//! # Limitations (deliberately conservative — these are leads, not proofs)
//!
//! Ordinary extraction is intra-procedural and single-file. The separate
//! [`DomSinkExtractor::extract_modules`] batch pass links explicit ES-module
//! value/function imports (including `ns.name` of namespace imports and
//! `export {..} from` / `export * from` re-exports) across already collected files,
//! with bounded work and static candidates only. Export summaries require
//! straight-line initialization; module control flow is not modeled. Function
//! summaries require short, synchronous, straight-line declaration bodies; within
//! one file they also carry a tainted argument or return value through calls to
//! top-level `function` declarations. There is **no** other cross-function
//! propagation (closures, methods and nested declarations are not summarized) and
//! **no** aliasing analysis beyond simple
//! `x = <tainted>` assignments (no object-field, array-element, or destructuring
//! tracking). A tainted value's property access / method call is conservatively
//! assumed to stay tainted (`location.hash.slice(1)` is still tainted). Scope
//! lookup is lexical but generous: an inner closure can see an outer scope's
//! tainted variables. `DOMPurify.sanitize` is recognized for HTML sinks;
//! custom/framework sanitizers remain unmodelled, so a flow is a candidate.

mod ast;
mod modules;
mod sinks;
mod sources;
mod taint;

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use sinks::{FALLBACK_SINK_PATTERNS, NAVIGATION_SINK_HINT, TAINT_SINK_HINTS, WASM_PATTERNS};
use sources::{MESSAGE_PATTERNS, TAINT_SOURCE_HINTS};
use std::collections::BTreeSet;
use swc_core::common::input::StringInput;
use swc_core::common::sync::Lrc;
use swc_core::common::{BytePos, FileName, SourceMap};
use swc_core::ecma::parser::{EsSyntax, Parser, Syntax};
use swc_core::ecma::visit::VisitWith;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, SessionId, Source};

/// How far past a `message` handler to look for an `origin` check.
const ORIGIN_WINDOW: usize = 240;

/// DOM-sink taint / postMessage / wasm extractor.
pub struct DomSinkExtractor {
    sink_patterns: Vec<(Regex, &'static str)>,
    wasm_patterns: Vec<(Regex, &'static str)>,
    message: Vec<Regex>,
    navigation_sink_hint: Regex,
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
        let sink_patterns = FALLBACK_SINK_PATTERNS
            .iter()
            .map(|(re, label)| (Regex::new(re).expect("sink pattern is valid"), *label))
            .collect();
        let wasm_patterns = WASM_PATTERNS
            .iter()
            .map(|(re, label)| (Regex::new(re).expect("wasm pattern is valid"), *label))
            .collect();
        let message = MESSAGE_PATTERNS
            .iter()
            .map(|re| Regex::new(re).expect("message pattern is valid"))
            .collect();
        let navigation_sink_hint =
            Regex::new(NAVIGATION_SINK_HINT).expect("navigation sink hint is valid");
        Self {
            sink_patterns,
            wasm_patterns,
            message,
            navigation_sink_hint,
        }
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

/// ASCII case-insensitive substring search without allocating a lowercase
/// copy of the full (often minified) bundle.
fn contains_ascii_case_insensitive(body: &str, needle: &str) -> bool {
    body.as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Skip only the expensive taint AST walk when the text cannot contain both a
/// modeled source and modeled sink. This gate is recall-preserving by design:
/// false positives keep the AST parse; only absence of every broad source or
/// sink hint skips it. The regex fallback and its independent analyses always
/// run regardless of this decision.
fn should_run_taint_ast(
    body: &str,
    message_patterns: &[Regex],
    navigation_sink_hint: &Regex,
) -> bool {
    let has_source = TAINT_SOURCE_HINTS
        .iter()
        .any(|hint| contains_ascii_case_insensitive(body, hint))
        || message_patterns
            .iter()
            .any(|pattern| pattern.is_match(body));
    has_source
        && (TAINT_SINK_HINTS
            .iter()
            .any(|hint| contains_ascii_case_insensitive(body, hint))
            || navigation_sink_hint.is_match(body))
}

fn sanitizer_wraps_sink(body: &str, start: usize) -> bool {
    let (statement_start, statement_end) = statement_bounds(body, start);
    let statement = &body[statement_start..statement_end];
    statement.contains("DOMPurify.sanitize(") || entity_encoding_chain_wraps_sink(statement)
}

/// The byte range of the statement containing byte offset `pos`: back to the
/// nearest unquoted `;`/`\n` (or the start of `body`), forward to the next
/// one (or the end). Quote-aware (single, double, backtick, with `\`
/// escaping) in a single left-to-right scan, because a naive quote-blind
/// scan mistakes the literal `;` inside an HTML entity like `&amp;` for a
/// statement separator and truncates the statement mid-string.
fn statement_bounds(body: &str, pos: usize) -> (usize, usize) {
    let bytes = body.as_bytes();
    let is_boundary = |c: u8| c == b';' || c == b'\n';
    let is_quote = |c: u8| c == b'\'' || c == b'"' || c == b'`';
    let mut quote: Option<u8> = None;
    let mut start_bound = 0usize;
    let mut i = 0usize;
    while i < pos.min(bytes.len()) {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if is_boundary(c) {
                    start_bound = i + 1;
                } else if is_quote(c) {
                    quote = Some(c);
                }
            }
        }
        i += 1;
    }
    let mut end_bound = bytes.len();
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if is_boundary(c) {
                    end_bound = i;
                    break;
                } else if is_quote(c) {
                    quote = Some(c);
                }
            }
        }
        i += 1;
    }
    (start_bound, end_bound)
}

/// Textual mirror of the AST-level entity-encoding `.replace()` chain
/// recognition (`taint::REQUIRED_ESCAPED`): when the AST pass already proved
/// a statement's `<`/`>` are entity-encoded (so it recorded no trace at all),
/// this fallback must not still surface a Low "unverified source" lead for
/// the same statement -- that would contradict the AST pass's own verdict,
/// exactly like the existing `DOMPurify.sanitize(` check above.
fn entity_encoding_chain_wraps_sink(statement: &str) -> bool {
    let lower = statement.to_ascii_lowercase();
    lower.contains(".replace(") && lower.contains("&lt;") && lower.contains("&gt;")
}

/// Traced `source -> sink` flows and the byte-range spans they cover.
type TaintResult = (Vec<(String, Confidence)>, Vec<(usize, usize)>);

/// Run the AST taint pass, returning traced flows and their covering spans.
/// Returns empty (never errors) on parse failure, mirroring the other AST
/// extractors.
fn run_taint(body: &str) -> TaintResult {
    let cm: Lrc<SourceMap> = Lrc::default();
    let fm = cm.new_source_file(Lrc::new(FileName::Anon), body.to_owned());
    let len = u32::try_from(fm.src.len()).unwrap_or(u32::MAX);
    let parser_input = StringInput::new(&fm.src, BytePos(0), BytePos(len));
    // JSX is enabled so React (`dangerouslySetInnerHTML`) parses.
    let syntax = Syntax::Es(EsSyntax {
        jsx: true,
        ..EsSyntax::default()
    });
    let mut parser = Parser::new(syntax, parser_input, None);

    let Some(module) = crate::js_parse::guarded(|| parser.parse_module()) else {
        return (Vec::new(), Vec::new());
    };

    modules::analyze_standalone(module)
}

/// Push a finding iff its value has not been seen, keeping dedup on `value`.
fn push_unique(
    findings: &mut Vec<Finding>,
    seen: &mut BTreeSet<String>,
    session: SessionId,
    url: Option<&str>,
    value: String,
    confidence: Confidence,
    source: Source,
) {
    if seen.insert(value.clone()) {
        findings.push(Finding::new(
            session,
            FindingKind::Config,
            None,
            value,
            confidence,
            Provenance::new(source, url.map(str::to_owned)),
        ));
    }
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
        let session = input.session_id;
        let url = input.url.as_deref();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut findings = Vec::new();

        // Pass 1: static taint flows (AST).
        let (traces, traced_spans) =
            if should_run_taint_ast(body, &self.message, &self.navigation_sink_hint) {
                run_taint(body)
            } else {
                (Vec::new(), Vec::new())
            };
        for (value, confidence) in traces {
            push_unique(
                &mut findings,
                &mut seen,
                session,
                url,
                value,
                confidence,
                Source::JsAst,
            );
        }

        // Pass 2: regex fallback. Sink leads whose statement was already traced
        // are suppressed; everything else is a Low "unverified source" lead.
        for (regex, label) in &self.sink_patterns {
            for m in regex.find_iter(body) {
                let start = m.start();
                if traced_spans
                    .iter()
                    .any(|&(lo, hi)| lo <= start && start < hi)
                {
                    continue;
                }
                if sanitizer_wraps_sink(body, start) {
                    continue;
                }
                push_unique(
                    &mut findings,
                    &mut seen,
                    session,
                    url,
                    format!(
                        "dom sink (unverified source): {label}: {}",
                        snippet(body, start)
                    ),
                    Confidence::Low,
                    Source::JsRegex,
                );
            }
        }

        // WebAssembly references (reported as-is).
        for (regex, label) in &self.wasm_patterns {
            for m in regex.find_iter(body) {
                push_unique(
                    &mut findings,
                    &mut seen,
                    session,
                    url,
                    format!("{label}: {}", snippet(body, m.start())),
                    Confidence::Low,
                    Source::JsRegex,
                );
            }
        }

        // postMessage receivers: a missing origin check in the handler window
        // is the interesting case, so it is bumped to Medium.
        for regex in &self.message {
            for m in regex.find_iter(body) {
                let mut end = (m.start() + ORIGIN_WINDOW).min(body.len());
                // Snap to a char boundary so slicing never panics.
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
                push_unique(
                    &mut findings,
                    &mut seen,
                    session,
                    url,
                    format!("{label}: {}", snippet(body, m.start())),
                    confidence,
                    Source::JsRegex,
                );
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    include!("domsinks_tests.rs");
}
