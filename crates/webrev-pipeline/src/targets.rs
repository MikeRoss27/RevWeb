//! Resolve relative discoveries against their document, retaining concrete URLs.
use webrev_core::{Finding, Mission, Source};

pub(crate) fn resolve_endpoint_url(mission: &Mission, finding: &Finding) -> Option<reqwest::Url> {
    let raw = finding.url.as_deref()?;
    let source_url = finding.provenance.location.as_deref();
    let source_origin = source_url.and_then(origin);
    let document = source_origin.and_then(|source| {
        mission
            .seeds
            .iter()
            .find(|seed| origin(seed).as_deref() == Some(source.as_str()))
    });
    // JS fetch/XHR references are document-relative rather than script-relative.
    let base = if matches!(finding.provenance.source, Source::JsAst | Source::JsRegex) {
        document
            .or_else(|| mission.seeds.first())
            .map(String::as_str)
            .or(source_url)
    } else {
        source_url.or_else(|| mission.seeds.first().map(String::as_str))
    };
    reqwest::Url::parse(raw).ok().or_else(|| {
        base.and_then(|base| reqwest::Url::parse(base).ok())?
            .join(raw)
            .ok()
    })
}

fn origin(url: &str) -> Option<String> {
    let url = reqwest::Url::parse(url).ok()?;
    Some(url.origin().ascii_serialization())
}
