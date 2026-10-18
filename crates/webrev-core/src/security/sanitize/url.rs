// crates/webrev-core/src/security/sanitize/url.rs
//! URL redaction for log lines, error messages, `Debug` renderings and the
//! compact terminal summary.

use super::{contains_known_token, looks_like_secret, REDACTED};

/// Substrings of a query/fragment parameter name that mark its value as
/// credential-like for log and error output.
const SENSITIVE_PARAM_HINTS: [&str; 17] = [
    "token",
    "key",
    "secret",
    "pass",
    "pwd",
    "auth",
    "sig",
    "session",
    "sid",
    "jwt",
    "bearer",
    "credential",
    "csrf",
    "xsrf",
    "saml",
    "hmac",
    "ticket",
];

/// Short names that are too generic for a substring match but are credentials
/// when they are the whole parameter name (OAuth `code`, one-time codes).
const SENSITIVE_PARAM_NAMES: [&str; 4] = ["code", "otp", "pin", "mfa"];

fn is_sensitive_param(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    SENSITIVE_PARAM_NAMES.contains(&lower.as_str())
        || SENSITIVE_PARAM_HINTS.iter().any(|h| lower.contains(h))
}

/// True when a 16-character window of an alphanumeric run mixes letters and
/// digits with almost no repetition, as random tokens do. This catches a
/// secret glued to ordinary text inside one path segment or parameter, where
/// the whole-value entropy of [`looks_like_secret`] is diluted by the padding.
fn has_secret_window(text: &str) -> bool {
    const WINDOW: usize = 16;
    text.as_bytes()
        .split(|b| !b.is_ascii_alphanumeric())
        .filter(|run| run.len() >= WINDOW)
        .any(|run| {
            run.windows(WINDOW).any(|window| {
                let digits = window.iter().filter(|b| b.is_ascii_digit()).count();
                let mut seen = [false; 128];
                let mut distinct = 0;
                for &b in window {
                    if !seen[usize::from(b)] {
                        seen[usize::from(b)] = true;
                        distinct += 1;
                    }
                }
                digits >= 2 && WINDOW - digits >= 4 && distinct >= 12
            })
        })
}

/// A path segment or bare fragment worth hiding. Stricter than a query value:
/// a segment must also contain digits and letters, so `getUserProfileData`,
/// slugs, versions and numeric ids stay readable.
fn segment_hides_secret(segment: &str) -> bool {
    let digits = segment.bytes().filter(u8::is_ascii_digit).count();
    let letters = segment.bytes().filter(u8::is_ascii_alphabetic).count();
    contains_known_token(segment)
        || has_secret_window(segment)
        || (digits >= 2 && letters >= 2 && looks_like_secret(segment))
}

fn value_hides_secret(value: &str) -> bool {
    looks_like_secret(value) || contains_known_token(value) || has_secret_window(value)
}

fn redact_path(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            if segment_hides_secret(segment) {
                REDACTED
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn redact_pairs(part: &str) -> String {
    part.split('&')
        .map(|pair| match pair.split_once('=') {
            // A name that itself carries a secret hides the whole pair.
            Some((name, _)) if segment_hides_secret(name) => REDACTED.to_owned(),
            Some((name, value)) if is_sensitive_param(name) || value_hides_secret(value) => {
                format!("{name}={REDACTED}")
            }
            None if segment_hides_secret(pair) => REDACTED.to_owned(),
            _ => pair.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Mask credentials embedded in a URL before it enters a log line, an error
/// message, a `Debug` rendering or the compact terminal summary: `user:pass@`
/// userinfo; path segments that hold a token (`/reset/<token>`, a JWT, a known
/// key prefix); the values of credential-like query or fragment parameters
/// (`token`, `key`, `secret`, `password`, `sig`, `session`, `code`, ...) and of
/// any parameter whose value is credential-shaped whatever its name
/// (`?tok=...`). Everything else is left intact so the URL stays recognisable.
/// Exported reports and detected secret plaintext are never passed through it.
#[must_use]
pub fn redact_url(raw: &str) -> String {
    let (rest, fragment) = match raw.split_once('#') {
        Some((r, f)) => (r, Some(f)),
        None => (raw, None),
    };
    let (base, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    let mut out = String::with_capacity(raw.len());
    // Userinfo lives in the authority, i.e. before the first '/' after "://".
    if let Some((scheme, after)) = base.split_once("://") {
        let (authority, path) = match after.find('/') {
            Some(i) => after.split_at(i),
            None => (after, ""),
        };
        out.push_str(scheme);
        out.push_str("://");
        match authority.rsplit_once('@') {
            Some((_, host)) => {
                out.push_str(REDACTED);
                out.push('@');
                out.push_str(host);
            }
            None => out.push_str(authority),
        }
        out.push_str(&redact_path(path));
    } else {
        out.push_str(&redact_path(base));
    }
    if let Some(q) = query {
        out.push('?');
        out.push_str(&redact_pairs(q));
    }
    if let Some(f) = fragment {
        out.push('#');
        if f.contains('=') {
            out.push_str(&redact_pairs(f));
        } else {
            // SPA routes such as `#/reset/<token>`.
            out.push_str(&redact_path(f));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::redact_url;

    const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlkxMjM0In0.c2lnbmF0dXJlQ0FOQVJZMTIz";

    #[test]
    fn masks_userinfo_and_sensitive_params() {
        assert_eq!(
            redact_url("http://user:p%40ss@proxy.test:8080/x?a=1&access_token=abc&Api_Key=k#id_token=zzz"),
            "http://[REDACTED]@proxy.test:8080/x?a=1&access_token=[REDACTED]&Api_Key=[REDACTED]#id_token=[REDACTED]"
        );
        assert_eq!(
            redact_url("socks5://onlyuser@h:1"),
            "socks5://[REDACTED]@h:1"
        );
        // Non-sensitive URLs are unchanged, '@' in the path is not userinfo.
        for plain in [
            "https://x.test/a@b?page=2&q=hi#top",
            "/rel?x=1",
            "not a url",
        ] {
            assert_eq!(redact_url(plain), plain);
        }
    }

    #[test]
    fn masks_credential_shaped_values_under_any_name() {
        // `tok` is not a known sensitive name; the value gives it away.
        assert_eq!(
            redact_url("https://app.test/cb?tok=Zk3Jq9XvT2bLm8Rw4NpYs7Ad&page=2"),
            "https://app.test/cb?tok=[REDACTED]&page=2"
        );
        assert_eq!(
            redact_url(
                "https://app.test/?h=9f86d081884c7d659a2feaa0c55ad015#x=Zk3Jq9XvT2bLm8Rw4NpYs7Ad"
            ),
            "https://app.test/?h=[REDACTED]#x=[REDACTED]"
        );
    }

    #[test]
    fn keeps_ordinary_values_readable() {
        for plain in [
            "https://x.test/?page=2&sort=created_at_desc&lang=en-US",
            "https://x.test/?next=/dashboard/settings&q=hello+world",
            "https://x.test/?ts=1700000000000&version=2024-10-18T12:00:00",
            "https://x.test/?title=internationalization-guidelines",
            "https://x.test/?encode=utf-8&barcode=123456&postcode=75001",
        ] {
            assert_eq!(redact_url(plain), plain);
        }
    }

    #[test]
    fn masks_new_sensitive_names() {
        assert_eq!(
            redact_url("https://x.test/cb?code=4/0AY&otp=123456&csrf_token=a&state=xyz"),
            "https://x.test/cb?code=[REDACTED]&otp=[REDACTED]&csrf_token=[REDACTED]&state=xyz"
        );
        assert_eq!(
            redact_url("https://x.test/login?ticket=ST-42-abc&SAMLResponse=PHN"),
            "https://x.test/login?ticket=[REDACTED]&SAMLResponse=[REDACTED]"
        );
    }

    #[test]
    fn masks_secret_path_segments() {
        assert_eq!(
            redact_url("https://app.test/reset/Zk3Jq9XvT2bLm8Rw4NpYs7Ad/confirm"),
            "https://app.test/reset/[REDACTED]/confirm"
        );
        assert_eq!(
            redact_url(&format!("https://app.test/auth/{JWT}")),
            "https://app.test/auth/[REDACTED]"
        );
        assert_eq!(
            redact_url("/hooks/ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8/x"),
            "/hooks/[REDACTED]/x"
        );
        // SPA route in the fragment.
        assert_eq!(
            redact_url("https://app.test/#/invite/Zk3Jq9XvT2bLm8Rw4NpYs7Ad"),
            "https://app.test/#/invite/[REDACTED]"
        );
    }

    #[test]
    fn masks_a_secret_glued_to_padding() {
        // Fuzzing reproducer (fuzz.yml run 39166754778): a JWT inside a longer
        // path segment, and a token padded so the whole segment's entropy
        // drops below the value threshold.
        let glued = format!("https://host.test/ht{JWT}dWIiOiJDQU5BUlkxM0In0U.junk");
        assert!(!redact_url(&glued).contains(JWT), "{}", redact_url(&glued));
        let padded = format!(
            "https://host.test/{}Zk3Jq9XvLm2Rt7WpYb4Nc8",
            "a".repeat(200)
        );
        assert!(!redact_url(&padded).contains("Zk3Jq9XvLm2Rt7WpYb4Nc8"));
        // A secret used as a parameter name, or as a bare parameter.
        assert_eq!(
            redact_url("https://h.test/?Zk3Jq9XvLm2Rt7WpYb4Nc8=1&AKIAQ7ZXC9VB2NM4LK8P"),
            "https://h.test/?[REDACTED]&[REDACTED]"
        );
    }

    #[test]
    fn keeps_ordinary_path_segments_readable() {
        for plain in [
            "https://x.test/api/v2/users/12345/orders",
            "https://x.test/docs/getUserProfileData/README.md",
            "https://x.test/blog/2024-10-18/internationalization-guidelines",
            "https://x.test/static/app.3f2a1c.js",
            "https://x.test/en-US/products/sku-1234-blue",
            "https://x.test/#/settings/profile",
        ] {
            assert_eq!(redact_url(plain), plain);
        }
    }
}
