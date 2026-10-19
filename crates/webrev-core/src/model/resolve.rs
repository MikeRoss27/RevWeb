// crates/webrev-core/src/model/resolve.rs
//! Resolve relative discoveries against their document, retaining concrete URLs.
use crate::model::endpoint::Source;
use crate::model::finding::Finding;
use crate::model::session::Mission;
use url::Url;

/// Parse seed URLs once, and reuse the last source's document base while a
/// resource's findings pass through the store. The one-entry cache is bounded
/// independently of the number of resources or findings in a scan.
pub struct EndpointResolver {
    seeds: Vec<Option<Url>>,
    last_base: Option<(Option<String>, bool, Option<Url>)>,
}

impl EndpointResolver {
    #[must_use]
    pub fn new(mission: &Mission) -> Self {
        Self {
            seeds: mission
                .seeds
                .iter()
                .map(|seed| Url::parse(seed).ok())
                .collect(),
            last_base: None,
        }
    }

    pub fn resolve(&mut self, finding: &Finding) -> Option<Url> {
        let raw = finding.url.as_deref()?;
        if let Ok(url) = Url::parse(raw) {
            return Some(url);
        }
        let source = finding.provenance.location.as_deref();
        // JS fetch/XHR references are document-relative, not script-relative.
        let document_relative =
            matches!(finding.provenance.source, Source::JsAst | Source::JsRegex);
        let cached = self.last_base.as_ref().is_some_and(|(location, js, _)| {
            location.as_deref() == source && *js == document_relative
        });
        if !cached {
            let source_url = source.and_then(|source| Url::parse(source).ok());
            let base = if document_relative {
                let document = source_url.as_ref().and_then(|source| {
                    let origin = source.origin().ascii_serialization();
                    self.seeds
                        .iter()
                        .flatten()
                        .find(|seed| seed.origin().ascii_serialization() == origin)
                });
                document.cloned().or_else(|| {
                    // A supplied but invalid first seed must not silently fall
                    // back to a script URL: retain the existing resolution rule.
                    self.seeds.first().cloned().unwrap_or(source_url)
                })
            } else if source.is_some() {
                source_url
            } else {
                self.seeds.first().cloned().flatten()
            };
            self.last_base = Some((source.map(str::to_owned), document_relative, base));
        }
        self.last_base.as_ref()?.2.as_ref()?.join(raw).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::finding::{Confidence, FindingKind, Provenance};
    use crate::model::session::Scope;

    #[test]
    fn resolution_preserves_document_origin_and_source_rules() {
        let mission = Mission::new(
            "resolution",
            Scope::default(),
            vec!["https://a.test/app/".into(), "https://b.test/other/".into()],
        );
        let mut resolver = EndpointResolver::new(&mission);
        for (raw, source, location, expected) in [
            (
                "item?q=1",
                Source::JsAst,
                Some("https://b.test/assets/app.js"),
                Some("https://b.test/other/item?q=1"),
            ),
            (
                "next",
                Source::JsRegex,
                Some("https://b.test/assets/app.js"),
                Some("https://b.test/other/next"),
            ),
            (
                "item",
                Source::Html,
                Some("https://b.test/assets/page.html"),
                Some("https://b.test/assets/item"),
            ),
            (
                "item",
                Source::JsAst,
                Some("https://outside.test/app.js"),
                Some("https://a.test/app/item"),
            ),
            ("item", Source::Html, None, Some("https://a.test/app/item")),
            ("item", Source::Html, Some("invalid"), None),
            (
                "https://absolute.test/path",
                Source::Html,
                Some("invalid"),
                Some("https://absolute.test/path"),
            ),
            (
                "//b.test/absolute",
                Source::JsAst,
                None,
                Some("https://b.test/absolute"),
            ),
        ] {
            let finding = Finding::new(
                mission.id,
                FindingKind::Endpoint,
                Some(raw.into()),
                raw,
                Confidence::High,
                Provenance::new(source, location.map(str::to_owned)),
            );
            assert_eq!(
                resolver.resolve(&finding).as_ref().map(Url::as_str),
                expected
            );
        }
    }

    #[test]
    fn no_seeds_uses_source_and_invalid_first_seed_retains_failure() {
        for (seeds, expected) in [
            (vec![], Some("https://a.test/assets/item")),
            (vec!["invalid".into()], None),
        ] {
            let mission = Mission::new("resolution", Scope::default(), seeds);
            let mut resolver = EndpointResolver::new(&mission);
            let finding = Finding::new(
                mission.id,
                FindingKind::Endpoint,
                Some("item".into()),
                "item",
                Confidence::High,
                Provenance::new(Source::JsAst, Some("https://a.test/assets/app.js".into())),
            );
            assert_eq!(
                resolver.resolve(&finding).as_ref().map(Url::as_str),
                expected
            );
        }
    }
}
