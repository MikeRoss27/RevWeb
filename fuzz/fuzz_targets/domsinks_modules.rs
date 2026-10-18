// fuzz/fuzz_targets/domsinks_modules.rs
//! Cross-module DOM XSS linking: namespace imports, re-exports, local and
//! exported function summaries. The input is split into up to 16 modules at
//! `//@@` lines and served at https://fuzz.test/m<i>.js so relative specifiers
//! such as `./m1.js` link them. Properties: no panic or hang, and the
//! documented invariant that a static candidate is never `Confirmed`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::Once;
use webrev_core::{FindingStatus, SessionId};
use webrev_extract::extractors::DomSinkExtractor;
use webrev_extract::{ContentKind, ExtractInput};

const MAX_FUZZ_MODULES: usize = 16;

/// libFuzzer's panic hook aborts on every panic, which would defeat the
/// extractors' deliberate containment of swc panics (`js_parse::guarded`).
/// Swap it for a silent hook: a panic that escapes the extractors still unwinds
/// out of the target, where libfuzzer-sys catches it and aborts.
fn allow_contained_panics() {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| std::panic::set_hook(Box::new(|_| {})));
}

fuzz_target!(|data: &[u8]| {
    allow_contained_panics();
    let text = String::from_utf8_lossy(data);
    let session = SessionId::new();
    let mut inputs = Vec::new();
    for (index, body) in text.split("\n//@@\n").take(MAX_FUZZ_MODULES).enumerate() {
        let input = ExtractInput::new(
            session,
            Some(format!("https://fuzz.test/m{index}.js")),
            ContentKind::JavaScript,
            body,
        );
        DomSinkExtractor::retain_module_input(&mut inputs, input);
    }
    for finding in DomSinkExtractor::extract_modules(&inputs) {
        assert_ne!(
            finding.status,
            FindingStatus::Confirmed,
            "a static module candidate must never be Confirmed"
        );
    }
});
