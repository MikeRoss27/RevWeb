//! Known credential shapes and the generic entropy-candidate pattern.
use regex::Regex;
use webrev_core::Confidence;

/// Everything [`compile`] produces.
pub(super) struct Patterns {
    /// Structural/vendor-prefixed token shapes (JWT, AWS, Google, GitHub,
    /// GitLab, Stripe, `sk-...`, `SendGrid`, npm, PEM header). No quoting is
    /// required, so these also run against a URL's hostname, not just
    /// quoted string literals in a body.
    pub(super) shapes: Vec<(Regex, Confidence)>,
    /// Generic `key = "value"` assignment or `password === "value"`
    /// comparison (hardcoded credential check), value 16+ chars. Body-only:
    /// a hostname never carries a quoted assignment.
    pub(super) assignment: (Regex, Confidence),
    /// Same idea as `assignment`, but for values too short for entropy
    /// scoring (`password = "abc"`, `"sid": "4242"`): the explicit,
    /// unambiguous key name is the signal instead. Captures the separator in
    /// group 1 (so callers can tell a plain assignment, which is in scope,
    /// from an equality *comparison*, which is left to `assignment`'s 16-char
    /// floor to avoid flagging ordinary string-equality checks against short
    /// dictionary words) and the value in group 2.
    pub(super) short_named: Regex,
    /// Quoted high-entropy candidate tokens (base64/hex-ish, 20..=100 chars).
    /// Body-only, like `assignment`.
    pub(super) entropy_candidate: Regex,
}

pub(super) fn compile() -> Patterns {
    let compile = |p: &str| Regex::new(p).expect("constant secret pattern must compile");
    let shapes = vec![
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
    ];
    let assignment = (
        compile(
            r#"(?i)(?:api[_-]?key|secret|token|password|access[_-]?key)\s*(?::|=|[!=]==?)\s*["']([A-Za-z0-9\-_\.]{16,})["']"#,
        ),
        Confidence::Medium,
    );
    // Same keyword set as `webrev_core::security::sanitize`'s
    // `credential_values`, so detection and redaction agree on what counts as
    // an unambiguous credential name. Separator is captured (group 1) so the
    // caller can restrict matches to plain assignment (`:`/`=`), not `==`,
    // `===`, `!=`, `!==`.
    let short_named = compile(
        r#"(?i)(?:password|passwd|passphrase|pwd|secret|api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|auth[_-]?token|private[_-]?key|session[_-]?id|sessid|sid|bearer|token)["']?\s*(:|==?=?|!==?)\s*["']([^\s"']{1,15})["']"#,
    );
    // Includes backtick so template-literal secrets
    // (`` const k = `sk_live_...`; ``), common in bundled JS, aren't
    // silently missed by the entropy fallback.
    let entropy_candidate = compile(r#"["'`]([A-Za-z0-9+/=_\-]{20,100})["'`]"#);
    Patterns {
        shapes,
        assignment,
        short_named,
        entropy_candidate,
    }
}
