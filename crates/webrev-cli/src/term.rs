// crates/webrev-cli/src/term.rs
//! Terminal-width helpers shared by the progress line and the triage summary.

/// Columns of the terminal behind `fd`, or `COLUMNS` as a fallback.
pub fn width_of(fd: impl std::os::fd::AsFd) -> Option<usize> {
    terminal_size::terminal_size_of(fd)
        .map(|(w, _)| usize::from(w.0))
        .or_else(|| std::env::var("COLUMNS").ok()?.parse().ok())
        .filter(|w| *w > 0)
}

/// Shorten `s` to at most `max` chars, keeping the start and ending with `…`.
pub fn fit_end(s: &str, max: usize) -> String {
    let count = s.chars().count();
    if count <= max {
        return s.to_owned();
    }
    if max == 0 {
        return String::new();
    }
    let mut out: String = s.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// Shorten `s` to at most `max` chars with a middle ellipsis, so both the host
/// and the tail of a URL stay readable.
pub fn fit_middle(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_owned();
    }
    if max < 3 {
        return fit_end(s, max);
    }
    let keep = max - 1;
    let head = keep.div_ceil(2);
    let tail = keep - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_strings_are_untouched() {
        assert_eq!(fit_end("abc", 3), "abc");
        assert_eq!(fit_middle("abc", 3), "abc");
    }

    #[test]
    fn end_truncation_fits_exactly() {
        assert_eq!(fit_end("abcdefgh", 5), "abcd…");
        assert_eq!(fit_end("abc", 0), "");
    }

    #[test]
    fn middle_truncation_keeps_both_ends_and_width() {
        let s = fit_middle("https://example.test/a/very/long/path/file.js", 20);
        assert_eq!(s.chars().count(), 20);
        assert!(s.starts_with("https://"));
        assert!(s.ends_with("file.js"));
        assert!(s.contains('…'));
    }
}
