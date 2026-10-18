// fuzz/fuzz_targets/redaction.rs
//! Log and report redaction. Properties: `redact_url`, `Sanitizer::scrub` and
//! `scrub_header` never panic on arbitrary text, and a known secret embedded in
//! otherwise hostile text never survives into the output.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use webrev_core::security::sanitize::{redact_url, Sanitizer};

const PASSWORD: &str = "Zk3Jq9XvLm2Rt7WpYb4Nc8";
const AWS_KEY: &str = "AKIAQ7ZXC9VB2NM4LK8P";
const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJDQU5BUlkxMjM0In0.c2lnbmF0dXJlQ0FOQVJZMTIz";
const SECRETS: [&str; 3] = [PASSWORD, AWS_KEY, JWT];

fn sanitizer() -> &'static Sanitizer {
    static SANITIZER: OnceLock<Sanitizer> = OnceLock::new();
    SANITIZER.get_or_init(Sanitizer::with_default_patterns)
}

/// Keep only characters that cannot change how the surrounding URL is split.
fn url_safe(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_'))
        .take(256)
        .collect()
}

fn assert_no_secret(output: &str, context: &str) {
    for secret in SECRETS {
        assert!(
            !output.contains(secret),
            "{context} leaked {secret}: {output}"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);

    // Arbitrary text: must not panic.
    let _ = redact_url(&text);
    let _ = sanitizer().scrub(&text);
    let _ = sanitizer().scrub_header("X-Whatever", &text);

    // Known secrets inside hostile text, kept on their own lines.
    let noise = text.replace('\r', "");
    let embedded = format!(
        "{noise}\nAuthorization: Bearer {JWT}\n{AWS_KEY}\napi_key=\"{PASSWORD}\"\nsession: {PASSWORD}\n{noise}"
    );
    assert_no_secret(&sanitizer().scrub(&embedded), "scrub");

    // Known secrets in the userinfo, query and fragment of a URL whose path and
    // extra parameters come from the input.
    let safe = url_safe(&text);
    let url = format!(
        "https://user:{PASSWORD}@host.test/{safe}?tok={PASSWORD}&password={PASSWORD}&{safe}=1#id_token={PASSWORD}"
    );
    assert_no_secret(&redact_url(&url), "redact_url");
});
