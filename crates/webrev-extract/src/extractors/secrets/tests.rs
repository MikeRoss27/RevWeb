use super::*;
use webrev_core::SessionId;

fn run(js: &str) -> Vec<Finding> {
    let input = ExtractInput::new(
        SessionId::new(),
        Some("https://t/app.js".into()),
        ContentKind::JavaScript,
        js,
    );
    SecretExtractor::with_random_key().extract(&input)
}

#[test]
fn patterns_compile() {
    let _ = SecretExtractor::with_random_key();
}

#[test]
fn secrets_include_plaintext_and_fingerprint_by_default() {
    // A real-shaped AWS key id (not the `…EXAMPLE` doc key, which is now
    // filtered as a placeholder).
    let secret = "AKIAZ4XB7NMPQR2STUVW";
    let found = run(&format!("const k = '{secret}';"));
    assert_eq!(found.len(), 1);
    for f in &found {
        assert!(f.value.starts_with("fp:"), "value must be a fingerprint");
        assert_eq!(f.plaintext.as_deref(), Some(secret));
        assert_eq!(f.kind, FindingKind::Secret);
        assert!(f.url.is_none(), "secrets dedup on fingerprint, not url");
    }
}

#[test]
fn default_registry_retains_plaintext() {
    let secret = "AKIAZ4XB7NMPQR2STUVW";
    let input = ExtractInput::new(
        SessionId::new(),
        Some("https://t/app.js".into()),
        ContentKind::JavaScript,
        format!("const k = '{secret}';"),
    );
    let shown = crate::ExtractorRegistry::with_defaults().run(&input);
    let shown: Vec<_> = shown
        .iter()
        .filter(|f| f.kind == FindingKind::Secret)
        .collect();
    assert_eq!(shown.len(), 1);
    for f in &shown {
        assert!(
            f.value.starts_with("fp:"),
            "value must still be a fingerprint"
        );
        assert_eq!(f.plaintext.as_deref(), Some(secret));
    }
}

#[test]
fn detects_assignment_and_dedups_within_file() {
    let found = run(r#"apiKey="A1b2C3d4E5f6G7h8"; apiKey="A1b2C3d4E5f6G7h8";"#);
    // Same secret twice => one fingerprint.
    assert_eq!(found.len(), 1);
}

#[test]
fn drops_placeholder_and_example_values() {
    // AWS's own documentation key id, and a generic dummy assignment.
    let found = run(r#"const a = "AKIAIOSFODNN7EXAMPLE"; const t = "token=your_api_key_here";"#);
    assert!(
        found.is_empty(),
        "placeholder/example values must not be reported"
    );
}

#[test]
fn drops_sri_and_digest_hashes() {
    // A 40-char SHA-1 asset hash and an SRI integrity value: both benign.
    let sha1 = "a".repeat(10) + "b1c2d3e4f5" + "0011223344" + "aabbccddee"; // 40 hex
    let js = format!(
        r#"var h = "{sha1}"; var i = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8w";"#
    );
    let found = run(&js);
    assert!(found.is_empty(), "digest and SRI hashes must be filtered");
}

#[test]
fn keeps_high_entropy_token_and_bumps_on_context() {
    let token = "Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad"; // 32 mixed, high entropy
                                                   // Near a keyword → medium; isolated → low.
    let with_ctx = run(&format!(r#"const apiSecret = "{token}";"#));
    assert_eq!(with_ctx.len(), 1);
    assert_eq!(with_ctx[0].confidence, Confidence::Medium);

    let no_ctx = run(&format!(r#"["{token}"]"#));
    assert_eq!(no_ctx.len(), 1);
    assert_eq!(no_ctx[0].confidence, Confidence::Low);
}

#[test]
fn keeps_high_entropy_token_in_backtick_template_literal() {
    let token = "Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad";
    let found = run(&format!("const apiKey = `{token}`;"));
    assert_eq!(found.len(), 1, "backtick-quoted secrets must be caught too");
}

#[test]
fn drops_sha224_and_sha512_hex_digests() {
    let sha224 = "a1b2".repeat(14); // 56 hex chars
    let sha512 = "a1b2".repeat(32); // 128 hex chars
    let js = format!(r#"var a = "{sha224}"; var b = "{sha512}";"#);
    let found = run(&js);
    assert!(
        found.is_empty(),
        "sha224/sha512 hex digests must be filtered too"
    );
}

#[test]
fn detects_github_and_stripe_shapes() {
    let gh = format!("ghp_{}", "A1b2C3d4E5".repeat(4)); // ghp_ + 40
    let sk = format!("sk_live_{}", "A1b2C3d4E5f6".repeat(2)); // 24
    let found = run(&format!(r#"const g="{gh}"; const s="{sk}";"#));
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|f| f.confidence == Confidence::High));
}

#[test]
fn css_mask_utilities_are_not_secret_keys() {
    let found = run(
        r#"["mask-image-radial-to-color", "mask-image-radial-from-transparent",
            "sk-image-radial-to-color", "sk-image-radial-from-transparent-100"];
            token="sk-image-radial-from-transparent-100";"#,
    );
    assert!(
        found.is_empty(),
        "CSS names must not be reported as secrets"
    );
}

#[test]
fn sk_prefix_inside_an_identifier_is_not_a_key_signature() {
    let suffix = "Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad";
    let found = run(&format!("const mask-{suffix} = true;"));
    assert!(found.is_empty(), "a signature cannot begin inside a word");
}

#[test]
fn retains_full_random_looking_sk_keys() {
    let suffix = "Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad";
    for prefix in ["sk-", "sk-proj-", "sk-ant-api03-"] {
        let key = format!("{prefix}{suffix}{suffix}");
        let found = run(&format!("const token = '{key}';"));
        assert_eq!(found.len(), 1, "must retain {prefix} credential shape");
        assert_eq!(found[0].confidence, Confidence::High);
        assert_eq!(found[0].plaintext.as_deref(), Some(key.as_str()));
    }
}
