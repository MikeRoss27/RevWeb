// fuzz/fuzz_targets/extract_registry.rs
//! Every default extractor against one hostile input. The first byte picks the
//! content kind; the rest is the body (raw bytes for WebAssembly). Property: no
//! panic, no hang, no unbounded memory.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::{Once, OnceLock};
use webrev_core::SessionId;
use webrev_extract::{ContentKind, ExtractInput, ExtractorRegistry};

fn registry() -> &'static ExtractorRegistry {
    static REGISTRY: OnceLock<ExtractorRegistry> = OnceLock::new();
    REGISTRY.get_or_init(ExtractorRegistry::with_defaults)
}

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
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let kind = match selector % 4 {
        0 => ContentKind::Html,
        1 => ContentKind::JavaScript,
        2 => ContentKind::Json,
        _ => ContentKind::Wasm,
    };
    let url = Some("https://fuzz.test/app/main.js".to_owned());
    let input = if kind == ContentKind::Wasm {
        ExtractInput::new(SessionId::new(), url, kind, String::new()).with_bytes(rest.to_vec())
    } else {
        ExtractInput::new(
            SessionId::new(),
            url,
            kind,
            String::from_utf8_lossy(rest).into_owned(),
        )
        .with_headers(vec![
            ("Server".to_owned(), "fuzz".to_owned()),
            (
                "Content-Security-Policy".to_owned(),
                "default-src 'self'".to_owned(),
            ),
        ])
    };
    let _ = registry().run(&input);
});
