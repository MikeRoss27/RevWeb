//! URL/query handling and endpoint classification for active probes.

/// `scheme://host[:port]` prefix of a URL, or `None` if it has no scheme.
pub(super) fn origin_of(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

/// Decode each raw query position separately, including empty and duplicate keys.
pub(super) fn query_parameters(url: &str) -> Vec<(String, String)> {
    let url = url.split('#').next().unwrap_or(url);
    let query = url
        .split_once('?')
        .map_or("", |(_, q)| q.split('#').next().unwrap_or(q));
    query
        .split('&')
        .filter(|_| !query.is_empty())
        .map(|pair| {
            let parsed = reqwest::Url::parse(&format!("http://query.invalid/?{pair}"));
            parsed
                .ok()
                .and_then(|u| {
                    u.query_pairs()
                        .next()
                        .map(|(k, v)| (k.into_owned(), v.into_owned()))
                })
                .unwrap_or_default()
        })
        .collect()
}

/// Mutate one position; other raw pairs, signed values and percent escapes stay intact.
pub(super) fn mutate_parameter(url: &str, index: usize, value: &str) -> Option<String> {
    let url = url.split('#').next()?;
    let (base, query) = url.split_once('?')?;
    let mut pairs: Vec<String> = query.split('&').map(str::to_owned).collect();
    let pair = pairs.get_mut(index)?;
    let key = pair.split('=').next()?;
    *pair = format!("{key}={}", urlencode(value));
    Some(format!("{base}?{}", pairs.join("&")))
}

/// Minimal percent-encoding, sufficient for the ASCII probe characters this
/// module injects (quotes, angle brackets, braces).
pub(super) fn urlencode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// True when the path contains a segment that looks like a database id: an
/// all-digit segment, or a UUID.
pub(super) fn has_identifier_segment(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    path.split('/').any(|seg| {
        (!seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit())) || looks_like_uuid(seg)
    })
}

/// Heuristic for "this looks like an API/XHR endpoint, not a page" — used to
/// pick a second, more CORS-relevant target per origin beyond the root.
pub(super) fn looks_like_api_endpoint(url: &str) -> bool {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let lower = url.to_ascii_lowercase();
    lower.contains("/api/")
        || lower.contains("/rest/")
        || lower.contains("/graphql")
        || std::path::Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || url.contains('?')
}

pub(super) fn looks_like_uuid(seg: &str) -> bool {
    let parts: Vec<&str> = seg.split('-').collect();
    parts.len() == 5
        && [8usize, 4, 4, 4, 12]
            .iter()
            .zip(&parts)
            .all(|(&len, p)| p.len() == len && p.bytes().all(|b| b.is_ascii_hexdigit()))
}
