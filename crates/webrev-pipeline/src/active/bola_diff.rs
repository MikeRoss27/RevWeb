//! Readable proof for a cross-account object read: a bounded raw body per
//! observation and a field-level comparison of the two owners' objects, so the
//! report shows what one account could read without replaying the request.

use serde_json::Value;
use std::collections::BTreeMap;

/// Largest response prefix stored per observation.
pub(super) const BODY_LIMIT: usize = 4096;
const MAX_DIFF_LINES: usize = 20;
const MAX_FIELDS: usize = 2000;
const VALUE_WIDTH: usize = 80;

/// Characters that make up every secret shape `Sanitizer` recognises (see
/// `transport::is_token_char`, which this mirrors at the byte level: every
/// token character here is single-byte ASCII, so slicing on bytes is exact).
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'+' | b'/' | b'=' | b'%')
}

/// Shortest run worth protecting against a mid-token cut; below this a value
/// is too short for `Sanitizer`'s unnamed-token heuristic to flag anyway.
const MIN_PROTECTED_RUN: usize = 12;

/// Bound on how far a cut may retreat to avoid splitting a run. Well past
/// the length of every token `Sanitizer` recognises by structure alone (see
/// `transport::MAX_RETREAT`), so a real secret is always dropped whole, but
/// bounded so one huge opaque blob (base64 image data, ...) cannot collapse
/// the whole excerpt.
const MAX_RETREAT: usize = 256;

/// Drop a trailing partial token from `text` when the byte right after it in
/// the original response (`next_byte`) shows the run continues past the cut.
/// Without this, a secret that straddles [`BODY_LIMIT`] is stored as a
/// half-value: `Sanitizer`'s patterns match a whole shape (a JWT's three
/// dot-separated parts, a 16+ character high-entropy run, ...), so the
/// fragment can slip past every one of them, unlike a secret kept whole or
/// dropped whole.
fn trim_split_token(text: &str, next_byte: Option<u8>) -> String {
    let continues = next_byte.is_some_and(is_token_byte);
    let ends_in_token = text.as_bytes().last().copied().is_some_and(is_token_byte);
    if !continues || !ends_in_token {
        return text.to_owned();
    }
    let bytes = text.as_bytes();
    let mut start = bytes.len();
    while start > 0 && is_token_byte(bytes[start - 1]) {
        start -= 1;
    }
    let run_len = bytes.len() - start;
    if !(MIN_PROTECTED_RUN..=MAX_RETREAT).contains(&run_len) {
        return text.to_owned();
    }
    text[..start].to_owned()
}

/// UTF-8-safe prefix of at most [`BODY_LIMIT`] bytes, and whether the response
/// was longer. A multi-byte character cut by the limit is dropped, not
/// mangled; a secret-shaped run cut by the limit is dropped too (see
/// [`trim_split_token`]), so `--redact` always sees a whole value or none of
/// it, never an unrecognisable half that could slip past its patterns.
pub(super) fn body_excerpt(bytes: &[u8]) -> (String, bool) {
    let limit = bytes.len().min(BODY_LIMIT);
    let head = &bytes[..limit];
    let truncated = limit < bytes.len();
    let text = match std::str::from_utf8(head) {
        Ok(text) => text.to_owned(),
        Err(error) if truncated && error.error_len().is_none() => {
            String::from_utf8_lossy(&head[..error.valid_up_to()]).into_owned()
        }
        Err(_) => String::from_utf8_lossy(head).into_owned(),
    };
    let text = if truncated {
        trim_split_token(&text, bytes.get(limit).copied())
    } else {
        text
    };
    (text, truncated)
}

/// Why the signal fired, then how the two owners' own objects differ.
pub(super) fn comparison(
    own_a: &[u8],
    own_b: &[u8],
    b_reads_a: bool,
    a_reads_b: bool,
) -> Vec<String> {
    let mut lines = Vec::new();
    if b_reads_a {
        lines.push(format!(
            "B reads A's object: body byte-identical to A's own response ({} bytes)",
            own_a.len()
        ));
    }
    if a_reads_b {
        lines.push(format!(
            "A reads B's object: body byte-identical to B's own response ({} bytes)",
            own_b.len()
        ));
    }
    if let (Ok(a), Ok(b)) = (
        serde_json::from_slice::<Value>(own_a),
        serde_json::from_slice::<Value>(own_b),
    ) {
        lines.extend(field_diff(&a, &b));
    }
    lines
}

fn field_diff(a: &Value, b: &Value) -> Vec<String> {
    let (mut fields_a, mut fields_b) = (BTreeMap::new(), BTreeMap::new());
    flatten(a, "", &mut fields_a);
    flatten(b, "", &mut fields_b);
    let mut changed = Vec::new();
    let mut only_a = Vec::new();
    let mut same = 0_usize;
    for (path, value_a) in &fields_a {
        match fields_b.get(path) {
            Some(value_b) if value_a == value_b => same += 1,
            Some(value_b) => changed.push(format!(
                "{path}: {} ≠ {}",
                shorten(value_a),
                shorten(value_b)
            )),
            None => only_a.push(format!("{path}: only in A's object")),
        }
    }
    let only_b = fields_b
        .keys()
        .filter(|path| !fields_a.contains_key(*path))
        .map(|path| format!("{path}: only in B's object"));
    let details: Vec<String> = changed.into_iter().chain(only_a).chain(only_b).collect();
    let mut lines = vec![format!(
        "A's and B's own objects: {} field(s) differ, {same} identical",
        details.len()
    )];
    let hidden = details.len().saturating_sub(MAX_DIFF_LINES);
    lines.extend(details.into_iter().take(MAX_DIFF_LINES));
    if hidden > 0 {
        lines.push(format!("... {hidden} more field(s)"));
    }
    lines
}

fn flatten(value: &Value, path: &str, out: &mut BTreeMap<String, String>) {
    if out.len() >= MAX_FIELDS {
        return;
    }
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, child) in map {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                flatten(child, &child_path, out);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (index, child) in items.iter().enumerate() {
                flatten(child, &format!("{path}[{index}]"), out);
            }
        }
        scalar => {
            let key = if path.is_empty() { "$" } else { path };
            out.insert(key.to_owned(), scalar.to_string());
        }
    }
}

fn shorten(value: &str) -> String {
    if value.chars().count() <= VALUE_WIDTH {
        return value.to_owned();
    }
    let head: String = value.chars().take(VALUE_WIDTH).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_body_is_kept_whole() {
        let (text, truncated) = body_excerpt(br#"{"id":7}"#);
        assert_eq!(text, r#"{"id":7}"#);
        assert!(!truncated);
    }

    #[test]
    fn long_body_is_cut_at_the_limit_and_flagged() {
        let (text, truncated) = body_excerpt(&vec![b'x'; BODY_LIMIT + 500]);
        assert_eq!(text.len(), BODY_LIMIT);
        assert!(truncated);
    }

    /// Regression for the gap tracked in `goal.md` (Étape 4, "secret coupé
    /// par la troncature à 256 caractères d'un extrait de sonde"; the proof
    /// body here shares the same truncate-then-redact structure, just at
    /// `BODY_LIMIT` instead of the probe excerpt's 256-character limit — see
    /// `transport::a_token_straddling_the_excerpt_limit_is_dropped_whole_not_split`
    /// for the actual 256-character case). A credential-shaped run split by
    /// the limit can lose the shape `Sanitizer::scrub` (used by `--redact`)
    /// matches on, letting a fragment of it (here, a JWT's readable claims)
    /// through unmasked. The fix must drop such a run whole, for every cut
    /// point that actually lands inside it.
    #[test]
    fn a_secret_straddling_the_limit_is_dropped_whole_not_split() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0.c2lnbmF0dXJlYmxvYmJsb2JibG9iYmxvYmJsb2I";
        let sanitizer = webrev_core::Sanitizer::with_default_patterns();
        let mut covered_a_straddling_cut = false;
        for pad_len in (BODY_LIMIT - 150)..(BODY_LIMIT - 20) {
            let pad = "a".repeat(pad_len);
            // "v" is not a name any of Sanitizer's key-name patterns
            // recognise, so only the JWT's own three-part structure could
            // have caught it -- exactly what a mid-token cut breaks.
            let body =
                format!(r#"{{"pad":"{pad}","link":"https://x.test/r?v={jwt}"}}"#).into_bytes();
            if body.len() < BODY_LIMIT {
                continue;
            }
            let naive_head = String::from_utf8_lossy(&body[..BODY_LIMIT]).into_owned();
            let naive_ends_mid_jwt = (1..jwt.len()).any(|n| naive_head.ends_with(&jwt[..n]));
            if !naive_ends_mid_jwt {
                continue;
            }
            covered_a_straddling_cut = true;
            let (text, truncated) = body_excerpt(&body);
            assert!(truncated);
            let scrubbed = sanitizer.scrub(&text);
            let leaked = (MIN_PROTECTED_RUN..jwt.len()).find(|&n| scrubbed.contains(&jwt[..n]));
            assert!(
                leaked.is_none(),
                "pad_len={pad_len} leaked {:?} in {scrubbed:?}",
                leaked.map(|n| &jwt[..n])
            );
        }
        assert!(
            covered_a_straddling_cut,
            "no pad length landed the naive cut inside the JWT; test is not exercising the bug"
        );
    }

    /// A short, non-secret run of word characters straddling the limit is
    /// unaffected: nothing retreats just because the boundary falls inside a
    /// run of letters.
    #[test]
    fn a_short_ordinary_run_at_the_boundary_is_not_retreated() {
        let body = format!(r#"{}"readability""#, "x".repeat(BODY_LIMIT - 6)).into_bytes();
        let (text, truncated) = body_excerpt(&body);
        assert!(truncated);
        assert_eq!(text.len(), BODY_LIMIT);
    }

    #[test]
    fn a_character_split_by_the_limit_is_dropped_not_mangled() {
        // "é" is two bytes: the second one falls past the limit.
        let mut bytes = vec![b'x'; BODY_LIMIT - 1];
        bytes.extend("é".as_bytes());
        bytes.extend(b"tail");
        let (text, truncated) = body_excerpt(&bytes);
        assert!(truncated);
        assert_eq!(text.len(), BODY_LIMIT - 1);
        assert!(!text.contains('\u{fffd}'));
    }

    #[test]
    fn invalid_utf8_inside_the_limit_is_replaced_not_dropped() {
        let (text, truncated) = body_excerpt(&[b'o', b'k', 0xFF, b'!']);
        assert!(!truncated);
        assert_eq!(text, "ok\u{fffd}!");
    }

    #[test]
    fn comparison_names_the_differing_fields_and_the_direction() {
        let a = br#"{"id":"1","name":"alice","tier":"pro","only_a":true}"#;
        let b = br#"{"id":"2","name":"bob","tier":"pro","only_b":1}"#;
        let lines = comparison(a, b, true, false);
        assert!(lines[0].starts_with("B reads A's object"), "{lines:?}");
        assert!(lines
            .iter()
            .any(|l| l == "A's and B's own objects: 4 field(s) differ, 1 identical"));
        assert!(lines.contains(&r#"name: "alice" ≠ "bob""#.to_owned()));
        assert!(lines.contains(&"only_a: only in A's object".to_owned()));
        assert!(lines.contains(&"only_b: only in B's object".to_owned()));
        assert!(!lines.iter().any(|l| l.starts_with("A reads B")));
    }

    #[test]
    fn comparison_walks_nested_objects_and_arrays() {
        let a = br#"{"user":{"email":"a@t.test"},"orders":[{"n":1}]}"#;
        let b = br#"{"user":{"email":"b@t.test"},"orders":[{"n":2}]}"#;
        let lines = comparison(a, b, false, true);
        assert!(lines.contains(&r#"user.email: "a@t.test" ≠ "b@t.test""#.to_owned()));
        assert!(lines.contains(&"orders[0].n: 1 ≠ 2".to_owned()));
    }

    #[test]
    fn comparison_is_capped_and_long_values_are_shortened() {
        let object = |prefix: &str| {
            let fields: Vec<String> = (0..40)
                .map(|i| format!(r#""f{i:02}":"{prefix}{i}""#))
                .collect();
            format!("{{{}}}", fields.join(",")).into_bytes()
        };
        let lines = comparison(&object("a"), &object("b"), true, false);
        assert!(
            lines.iter().any(|l| l == "... 20 more field(s)"),
            "{lines:?}"
        );
        let long = format!(r#"{{"k":"{}"}}"#, "y".repeat(500)).into_bytes();
        let lines = comparison(&long, br#"{"k":"z"}"#, true, false);
        assert!(lines
            .iter()
            .any(|l| l.contains('…') && l.chars().count() < 120));
    }

    #[test]
    fn non_json_bodies_get_only_the_direction_line() {
        let lines = comparison(b"<html>", b"<body>", true, false);
        assert_eq!(lines.len(), 1);
    }
}
