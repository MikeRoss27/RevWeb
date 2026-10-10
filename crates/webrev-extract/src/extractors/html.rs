// crates/webrev-extract/src/extractors/html.rs
//! HTML extraction via `lol_html`: `<script src>`, `<a href>`, and `<form>`.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use lol_html::{element, rewrite_str, RewriteStrSettings};
use regex::Regex;
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::OnceLock;
use webrev_core::{Confidence, Finding, FindingKind, Method, Provenance, Source};

/// Extract the bodies of inline `<script>` elements (those without a `src`).
///
/// Used by the registry to cascade HTML into JavaScript extraction: inline
/// scripts are where endpoints and source-map comments usually live.
pub(crate) fn inline_scripts(html: &str) -> Vec<String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        // Group 1 = opening-tag attributes, group 2 = lazily captured body.
        // The `regex` crate has no look-around, so we drop `src`-bearing tags
        // in code below rather than in the pattern.
        Regex::new(r"(?is)<script([^>]*)>(.*?)</script>")
            .expect("constant inline-script pattern must compile")
    });
    re.captures_iter(html)
        .filter(|c| {
            c.get(1)
                .is_none_or(|attrs| !attrs.as_str().to_ascii_lowercase().contains("src"))
        })
        .filter_map(|c| c.get(2).map(|m| m.as_str().to_owned()))
        .filter(|body| !body.trim().is_empty())
        .collect()
}

/// Extracts structural references from HTML markup.
pub struct HtmlExtractor;

impl HtmlExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for HtmlExtractor {
    fn default() -> Self {
        Self::new()
    }
}

/// A reference discovered in markup, before it is attributed to a session.
struct Ref {
    kind: FindingKind,
    url: String,
    value: String,
    confidence: Confidence,
}

fn is_noise_href(href: &str) -> bool {
    let h = href.trim();
    h.is_empty()
        || h.starts_with('#')
        || h.starts_with("javascript:")
        || h.starts_with("mailto:")
        || h.starts_with("tel:")
}

impl Extractor for HtmlExtractor {
    fn name(&self) -> &'static str {
        "html"
    }

    fn priority(&self) -> u8 {
        80
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::Html
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let refs: Rc<RefCell<Vec<Ref>>> = Rc::new(RefCell::new(Vec::new()));

        let scripts = Rc::clone(&refs);
        let links = Rc::clone(&refs);
        let forms = Rc::clone(&refs);

        let settings = RewriteStrSettings::new()
            .append_element_content_handler(element!("script[src]", move |el| {
                if let Some(src) = el.get_attribute("src") {
                    scripts.borrow_mut().push(Ref {
                        kind: FindingKind::Script,
                        url: src.clone(),
                        value: src,
                        confidence: Confidence::High,
                    });
                }
                Ok(())
            }))
            .append_element_content_handler(element!("a[href]", move |el| {
                if let Some(href) = el.get_attribute("href") {
                    if !is_noise_href(&href) {
                        links.borrow_mut().push(Ref {
                            kind: FindingKind::Link,
                            url: href.clone(),
                            value: href,
                            confidence: Confidence::Low,
                        });
                    }
                }
                Ok(())
            }))
            .append_element_content_handler(element!("form", move |el| {
                let action = el.get_attribute("action").unwrap_or_default();
                if !action.trim().is_empty() {
                    let method = el
                        .get_attribute("method")
                        .map_or(Method::Get, |m| Method::parse(&m));
                    forms.borrow_mut().push(Ref {
                        kind: FindingKind::Form,
                        url: action.clone(),
                        value: format!("{method} {action}"),
                        confidence: Confidence::Medium,
                    });
                }
                Ok(())
            }));

        // `rewrite_str` fails only on malformed handler logic or hard memory
        // limits; neither applies here, so an error means "extract nothing".
        if rewrite_str(&input.body, settings).is_err() {
            return Vec::new();
        }

        let findings = refs
            .borrow()
            .iter()
            .map(|r| {
                Finding::new(
                    input.session_id,
                    r.kind,
                    Some(r.url.clone()),
                    r.value.clone(),
                    r.confidence,
                    Provenance::new(Source::Html, input.url.clone()),
                )
            })
            .collect();
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    fn run(html: &str) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/".into()),
            ContentKind::Html,
            html,
        );
        HtmlExtractor::new().extract(&input)
    }

    #[test]
    fn finds_scripts_links_and_forms() {
        let html = r##"
            <html><head>
              <script src="/static/app.js"></script>
            </head><body>
              <a href="/about">About</a>
              <a href="#skip">skip</a>
              <a href="javascript:void(0)">noise</a>
              <form action="/login" method="post"></form>
            </body></html>"##;
        let found = run(html);
        assert_eq!(
            found.iter().filter(|f| f.kind == FindingKind::Script).count(),
            1
        );
        // Only the real link survives noise filtering.
        assert_eq!(
            found.iter().filter(|f| f.kind == FindingKind::Link).count(),
            1
        );
        let form = found
            .iter()
            .find(|f| f.kind == FindingKind::Form)
            .expect("form finding");
        assert_eq!(form.value, "POST /login");
    }
}
