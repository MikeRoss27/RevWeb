//! Entropy scoring, contextual confidence and false-positive filters.

/// Shannon-entropy threshold (bits/char) above which a token looks random.
pub(super) const ENTROPY_MIN: f64 = 3.8;

/// Minimum number of *distinct* characters an entropy candidate must have.
/// Real credentials draw from a wide alphabet; repetitive strings do not.
pub(super) const ENTROPY_MIN_DISTINCT: usize = 12;

/// How many bytes before a match to scan for a secret-ish keyword when
/// deciding whether an entropy-only hit deserves a confidence bump.
const CONTEXT_WINDOW: usize = 48;

/// Lowercased substrings that mark a value as a dummy/placeholder rather than a
/// live credential. Industry scanners allowlist these to cut false positives
/// (e.g. AWS's own `AKIAIOSFODNN7EXAMPLE` doc key).
const PLACEHOLDER_MARKERS: &[&str] = &[
    "example",
    "placeholder",
    "changeme",
    "dummy",
    "your_",
    "your-",
    "yourkey",
    "sample",
    "redacted",
    "insert_",
    "replace_",
    "lorem",
    "foobar",
    "xxxx",
    "notreal",
    "<secret",
    "<token",
    "000000",
    "123456",
];

/// Secret-ish keywords used for the entropy-pass context check.
const SECRET_KEYWORDS: &[&str] = &[
    "key", "secret", "token", "password", "passwd", "auth", "cred", "bearer",
];

/// Literal values that are never a secret, whatever key name they sit under
/// (`password: true`, `"token": null`). Mirrors the same exclusion in
/// `webrev_core::Sanitizer::scrub`'s `credential_values` pass.
const LITERAL_VALUES: &[&str] = &["true", "false", "null", "none", "undefined"];

/// Is `value` a boolean/null-ish literal rather than an actual credential?
pub(super) fn is_boolean_or_null_literal(value: &str) -> bool {
    LITERAL_VALUES.iter().any(|l| value.eq_ignore_ascii_case(l))
}

/// Shannon entropy in bits per character.
pub(super) fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    let mut total = 0usize;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    #[allow(clippy::cast_precision_loss)] // counts are small; f64 is exact here
    let len = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            #[allow(clippy::cast_precision_loss)]
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub(super) fn is_mixed(s: &str) -> bool {
    s.bytes().any(|b| b.is_ascii_alphabetic()) && s.bytes().any(|b| b.is_ascii_digit())
}

/// Count of distinct byte values in `s`.
pub(super) fn distinct_chars(s: &str) -> usize {
    let mut seen = [false; 256];
    let mut n = 0usize;
    for b in s.bytes() {
        if !seen[b as usize] {
            seen[b as usize] = true;
            n += 1;
        }
    }
    n
}

/// Every byte identical (`"aaaa…"`).
fn is_single_repeated(s: &str) -> bool {
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(first) => bytes.all(|b| b == first),
        None => false,
    }
}

/// Whole string ascends or descends by one byte value (`"abcdef"`, `"9876"`).
fn is_sequential(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 4 {
        return false;
    }
    let asc = b.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    let desc = b.windows(2).all(|w| w[0] == w[1].wrapping_add(1));
    asc || desc
}

/// Hex of a common digest length (md5/sha1/sha224/sha256/sha384/sha512):
/// almost always an asset, chunk, or content hash in built front-end code,
/// not a credential.
pub(super) fn is_hex_digest(s: &str) -> bool {
    matches!(s.len(), 32 | 40 | 56 | 64 | 96 | 128) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// A Subresource Integrity hash (`sha256-…` / `sha384-…` / `sha512-…`).
fn is_sri_hash(s: &str) -> bool {
    s.starts_with("sha256-") || s.starts_with("sha384-") || s.starts_with("sha512-")
}

fn looks_like_placeholder(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    PLACEHOLDER_MARKERS.iter().any(|m| lower.contains(m))
}

/// The short `sk-` prefix also occurs in CSS utility names. Require a
/// substantial random-looking suffix rather than treating the prefix alone
/// as a credential signature. Apply this to both passes so rejected names
/// cannot come back through an assignment or the entropy fallback.
fn is_weak_sk_candidate(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix("sk-") else {
        return false;
    };
    let suffix = suffix.strip_prefix("proj-").unwrap_or(suffix);
    let mixed_case = suffix.bytes().any(|b| b.is_ascii_uppercase())
        && suffix.bytes().any(|b| b.is_ascii_lowercase());
    let opaque_alphanumeric = is_mixed(suffix) && !suffix.contains('-');
    suffix.len() < 32
        || !(mixed_case || opaque_alphanumeric)
        || distinct_chars(suffix) < ENTROPY_MIN_DISTINCT
        || shannon_entropy(suffix) < ENTROPY_MIN
}

/// False positives common to *every* candidate, regardless of how it matched:
/// placeholders, trivially-structured strings, and SRI integrity hashes.
pub(super) fn is_common_false_positive(value: &str) -> bool {
    looks_like_placeholder(value)
        || is_single_repeated(value)
        || is_sequential(value)
        || is_sri_hash(value)
        || is_weak_sk_candidate(value)
}

/// Is there a secret-ish keyword in the `CONTEXT_WINDOW` bytes preceding `at`?
/// Used to promote an entropy-only hit from low to medium confidence.
pub(super) fn near_secret_keyword(body: &str, at: usize) -> bool {
    let start = at.saturating_sub(CONTEXT_WINDOW);
    let window = String::from_utf8_lossy(&body.as_bytes()[start..at]).to_ascii_lowercase();
    SECRET_KEYWORDS.iter().any(|k| window.contains(k))
}

/// A token in an HTML identity/style attribute or CSS selector is an identifier,
/// even when its bytes happen to have high entropy or a credential-like prefix.
pub(super) fn is_identifier_context(body: &str, at: usize) -> bool {
    let before = &body[..at];
    let tag_start = before.rfind('<');
    let tag_end = before.rfind('>');
    if let Some(start) = tag_start.filter(|start| tag_end.is_none_or(|end| *start > end)) {
        let attribute = before[start..]
            .trim_end_matches(['\'', '"', '`', ' ', '\t'])
            .to_ascii_lowercase();
        if ["id=", "class=", "classname=", "style=", "for="]
            .iter()
            .any(|name| attribute.ends_with(name))
        {
            return true;
        }
    }
    matches!(before.as_bytes().last(), Some(b'#' | b'.'))
}
