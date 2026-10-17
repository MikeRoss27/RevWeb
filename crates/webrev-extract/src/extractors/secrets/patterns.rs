//! Known credential shapes and the generic entropy-candidate pattern.
use regex::Regex;
use webrev_core::Confidence;

pub(super) fn compile() -> (Vec<(Regex, Confidence)>, Regex) {
    let compile = |p: &str| Regex::new(p).expect("constant secret pattern must compile");
    let patterns = vec![
        // JSON Web Token
        (
            compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
            Confidence::High,
        ),
        // AWS access key id
        (compile(r"(AKIA[0-9A-Z]{16})"), Confidence::High),
        // Google API key
        (compile(r"(AIza[0-9A-Za-z\-_]{35})"), Confidence::High),
        // Slack token
        (compile(r"(xox[baprs]-[0-9A-Za-z-]{10,})"), Confidence::High),
        // GitHub personal access / OAuth / app / refresh token
        (compile(r"(gh[pousr]_[A-Za-z0-9]{36,})"), Confidence::High),
        // GitLab personal access token
        (compile(r"(glpat-[0-9A-Za-z_\-]{20})"), Confidence::High),
        // Stripe live secret / restricted key
        (
            compile(r"((?:sk|rk)_live_[0-9A-Za-z]{24,})"),
            Confidence::High,
        ),
        // OpenAI / Anthropic-style project key
        (
            compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})"),
            Confidence::High,
        ),
        // SendGrid key
        (
            compile(r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})"),
            Confidence::High,
        ),
        // npm automation token
        (compile(r"(npm_[A-Za-z0-9]{36})"), Confidence::High),
        // PEM private key header
        (
            compile(r"(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)"),
            Confidence::High,
        ),
        // Generic `key = "value"` assignment or `password === "value"`
        // comparison (hardcoded credential check); the value is captured.
        (
            compile(
                r#"(?i)(?:api[_-]?key|secret|token|password|access[_-]?key)\s*(?::|=|[!=]==?)\s*["']([A-Za-z0-9\-_\.]{16,})["']"#,
            ),
            Confidence::Medium,
        ),
    ];
    // Includes backtick so template-literal secrets
    // (`` const k = `sk_live_...`; ``), common in bundled JS, aren't
    // silently missed by the entropy fallback.
    let entropy_candidate = compile(r#"["'`]([A-Za-z0-9+/=_\-]{20,100})["'`]"#);
    (patterns, entropy_candidate)
}
