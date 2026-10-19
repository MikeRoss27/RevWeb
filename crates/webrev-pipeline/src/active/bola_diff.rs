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

/// UTF-8-safe prefix of at most [`BODY_LIMIT`] bytes, and whether the response
/// was longer. A multi-byte character cut by the limit is dropped, not mangled.
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
