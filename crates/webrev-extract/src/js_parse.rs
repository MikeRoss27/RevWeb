// crates/webrev-extract/src/js_parse.rs
//! Panic containment for the swc parser.
//!
//! Every extractor parses attacker-controlled JavaScript. swc is a large third
//! party parser with internal assertions (fuzzing found `import"\n=\n/` tripping
//! one in the lexer), so a panic is treated like any other parse failure: the
//! input yields no AST and the callers' existing "unparseable" paths apply,
//! including the regex fallbacks. Without this a single hostile script could
//! unwind through the extractor and take the scan stage down with it.

use std::panic::{catch_unwind, AssertUnwindSafe};

/// Run a parse step, mapping both `Err` and a panic to `None`.
pub(crate) fn guarded<T, E>(parse: impl FnOnce() -> Result<T, E>) -> Option<T> {
    catch_unwind(AssertUnwindSafe(parse)).ok()?.ok()
}

#[cfg(test)]
mod tests {
    use super::guarded;

    #[test]
    fn ok_passes_through() {
        assert_eq!(guarded(|| Ok::<_, ()>(7)), Some(7));
    }

    #[test]
    fn err_is_none() {
        assert_eq!(guarded(|| Err::<u8, _>("bad")), None);
    }

    #[test]
    fn panic_is_none() {
        let parsed: Option<u8> = guarded(|| -> Result<u8, ()> { panic!("lexer assertion") });
        assert_eq!(parsed, None);
    }
}
