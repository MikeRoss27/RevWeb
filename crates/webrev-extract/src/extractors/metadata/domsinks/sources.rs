// crates/webrev-extract/src/extractors/metadata/domsinks/sources.rs
//! Taint-source catalogue: which expressions are attacker-controllable.

/// `postMessage` receiver patterns, analysed specially for a nearby origin
/// check.
pub(super) const MESSAGE_PATTERNS: &[&str] = &[
    r#"(?i)addeventlistener\s*\(\s*['"]message['"]"#,
    r"(?i)\bonmessage\s*=[^=]",
];

/// Text hints for the conservative taint-AST gate. Matching is intentionally
/// broader than the AST model: comments, strings, or unrelated identifiers may
/// trigger a parse, but a possible source or sink must never be filtered out.
pub(super) const TAINT_SOURCE_HINTS: &[&str] = &[
    "location",
    // Broad identifiers also cover whitespace around member-access dots.
    "document", "window", "self",
    // Covers the modeled `message` event parameter source even without a
    // global-object prefix (for example, `addEventListener(...)`).
    "message", ".data",
];

/// Functions that preserve taint on their (string) argument.
pub(super) const TAINT_PRESERVING_CALLS: &[&str] = &[
    "decodeURIComponent",
    "decodeURI",
    "encodeURIComponent",
    "unescape",
    "escape",
    "String",
    "atob",
];

/// `new` targets that preserve taint on their first argument: parsing a
/// tainted string into a `URL` or `URLSearchParams` keeps every property and
/// accessor (`.href`, `.search`, `.searchParams.get(...)`, ...) tainted,
/// because the member-access and method-call rules already treat a property
/// or method result of a tainted value as tainted.
pub(super) const TAINT_PRESERVING_CONSTRUCTORS: &[&str] = &["URL", "URLSearchParams"];

/// Drop a `window.`/`self.` global prefix and fold `document.location` into
/// `location`, which the DOM defines as the same object.
pub(super) fn global_tail(path: &str) -> &str {
    let tail = path
        .strip_prefix("window.")
        .or_else(|| path.strip_prefix("self."))
        .unwrap_or(path);
    match tail.strip_prefix("document.") {
        Some(rest) if rest == "location" || rest.starts_with("location.") => rest,
        _ => tail,
    }
}

/// Map a member/identifier path to a canonical taint-source label, or `None`.
pub(super) fn known_source(path: &str) -> Option<String> {
    let tail = global_tail(path);
    let had_prefix = path.starts_with("window.") || path.starts_with("self.");
    match tail {
        "location" => Some("location".to_owned()),
        "location.href" | "location.search" | "location.hash" | "location.pathname" => {
            Some(tail.to_owned())
        }
        "document.URL"
        | "document.documentURI"
        | "document.referrer"
        | "document.cookie"
        | "document.baseURI" => Some(tail.to_owned()),
        "name" if had_prefix => Some("window.name".to_owned()),
        _ => None,
    }
}
