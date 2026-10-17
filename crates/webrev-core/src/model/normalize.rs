// crates/webrev-core/src/model/normalize.rs
//! URL/path normalization into route templates.
//!
//! Recon output is far more actionable as routes (`/users/{id}`) than as a
//! flood of concrete instances (`/users/1`, `/users/2`, ...). This collapses
//! volatile path segments (ids, UUIDs, hashes, long tokens) into placeholders
//! and drops the query string, without pulling in a URL-parsing dependency.

/// Normalize a URL or path into a route template.
///
/// Keeps scheme + host when present, drops `?query` and `#fragment`, and
/// replaces volatile path segments with `{id}` / `{uuid}` / `{hash}` /
/// `{token}`.
#[must_use]
pub fn normalize_url(url: &str) -> String {
    normalize_url_with_pattern(url).0
}

/// Normalize a URL and report whether a volatile path segment became a
/// placeholder. Removing query strings or trailing slashes alone does not
/// make the route inferred.
#[must_use]
pub fn normalize_url_with_pattern(url: &str) -> (String, bool) {
    // Separate an optional `scheme://host` prefix from the path.
    let (prefix, path) = match url.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
            (format!("{scheme}://{host}"), path)
        }
        None => (String::new(), url.trim_start_matches('/')),
    };

    // Drop query and fragment.
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');

    let mut out = prefix;
    let mut inferred_pattern = false;
    if path.is_empty() {
        out.push('/');
        return (out, false);
    }
    for segment in path.split('/') {
        out.push('/');
        let normalized = normalize_segment(segment);
        inferred_pattern |= normalized != segment;
        out.push_str(normalized);
    }
    (out, inferred_pattern)
}

fn normalize_segment(segment: &str) -> &str {
    if segment.is_empty() {
        return segment;
    }
    if is_uuid(segment) {
        "{uuid}"
    } else if segment.chars().all(|c| c.is_ascii_digit()) {
        // A 4-digit year (1900–2099) is far more often a date path segment
        // (`/blog/2024/post`, `/2000/svg`) than a collapsible resource id.
        if is_year_like(segment) {
            segment
        } else {
            "{id}"
        }
    } else if is_hex(segment) && segment.len() >= 16 {
        "{hash}"
    } else if segment.len() >= 24 && is_token_like(segment) {
        "{token}"
    } else {
        segment
    }
}

fn is_year_like(s: &str) -> bool {
    s.len() == 4 && s.parse::<u32>().is_ok_and(|n| (1900..=2099).contains(&n))
}

fn is_uuid(s: &str) -> bool {
    // Ordinary path segments need no allocation or UUID group collection.
    if s.len() != 36 {
        return false;
    }
    s.bytes().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    })
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_token_like(s: &str) -> bool {
    let mut has_digit = false;
    let mut has_alpha = false;
    for c in s.chars() {
        match c {
            '0'..='9' => has_digit = true,
            'a'..='z' | 'A'..='Z' => has_alpha = true,
            '_' | '-' | '.' | '~' => {}
            _ => return false,
        }
    }
    has_digit && has_alpha
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collapses_ids_uuids_and_hashes() {
        assert_eq!(
            normalize_url("https://x/api/users/123"),
            "https://x/api/users/{id}"
        );
        assert_eq!(
            normalize_url("/api/users/550e8400-e29b-41d4-a716-446655440000/posts"),
            "/api/users/{uuid}/posts"
        );
        assert_eq!(
            normalize_url("/files/deadbeefdeadbeef1234"),
            "/files/{hash}"
        );
    }

    #[test]
    fn drops_query_and_trailing_slash() {
        assert_eq!(
            normalize_url("https://x/search/?q=1&p=2"),
            "https://x/search"
        );
        assert_eq!(normalize_url("/a/b/"), "/a/b");
        assert_eq!(normalize_url("https://x/"), "https://x/");
    }

    #[test]
    fn keeps_stable_segments() {
        assert_eq!(normalize_url("/api/v1/login"), "/api/v1/login");
    }

    #[test]
    fn keeps_year_like_segments() {
        // Years are dates, not resource ids.
        assert_eq!(
            normalize_url("http://www.w3.org/2000/svg"),
            "http://www.w3.org/2000/svg"
        );
        assert_eq!(normalize_url("/blog/2024/launch"), "/blog/2024/launch");
        // Non-year numerics still collapse.
        assert_eq!(normalize_url("/users/123"), "/users/{id}");
        assert_eq!(normalize_url("/items/12345"), "/items/{id}");
    }

    #[test]
    fn reports_only_pattern_inference() {
        assert_eq!(
            normalize_url_with_pattern("/users/123?q=x"),
            ("/users/{id}".into(), true)
        );
        assert_eq!(
            normalize_url_with_pattern("/users/{id}?q=x"),
            ("/users/{id}".into(), false)
        );
        assert_eq!(
            normalize_url_with_pattern("/search/?q=x"),
            ("/search".into(), false)
        );
    }
}
