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
    // Separate an optional `scheme://host` prefix from the path.
    let (prefix, path) = match url.split_once("://") {
        Some((scheme, rest)) => {
            let (host, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
            (format!("{scheme}://{host}"), path.to_owned())
        }
        None => (String::new(), url.trim_start_matches('/').to_owned()),
    };

    // Drop query and fragment.
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('/');

    let mut out = prefix;
    if path.is_empty() {
        out.push('/');
        return out;
    }
    for segment in path.split('/') {
        out.push('/');
        out.push_str(normalize_segment(segment));
    }
    out
}

fn normalize_segment(segment: &str) -> &str {
    if segment.is_empty() {
        return segment;
    }
    if is_uuid(segment) {
        "{uuid}"
    } else if segment.chars().all(|c| c.is_ascii_digit()) {
        "{id}"
    } else if is_hex(segment) && segment.len() >= 16 {
        "{hash}"
    } else if segment.len() >= 24 && is_token_like(segment) {
        "{token}"
    } else {
        segment
    }
}

fn is_uuid(s: &str) -> bool {
    let groups = [8usize, 4, 4, 4, 12];
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip(groups)
            .all(|(p, n)| p.len() == n && p.chars().all(|c| c.is_ascii_hexdigit()))
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
        assert_eq!(normalize_url("https://x/api/users/123"), "https://x/api/users/{id}");
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
        assert_eq!(normalize_url("https://x/search/?q=1&p=2"), "https://x/search");
        assert_eq!(normalize_url("/a/b/"), "/a/b");
        assert_eq!(normalize_url("https://x/"), "https://x/");
    }

    #[test]
    fn keeps_stable_segments() {
        assert_eq!(normalize_url("/api/v1/login"), "/api/v1/login");
    }
}
