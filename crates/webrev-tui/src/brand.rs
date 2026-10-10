// crates/webrev-tui/src/brand.rs
//! webrev brand assets: palette and block-character art.
//!
//! One place for everything the terminal needs to look like webrev, shared by
//! the TUI and the `webrev` CLI banner (the CLI already depends on this
//! crate). Pure data and layout: no I/O, no terminal types, so each front end
//! maps [`Tone`] onto its own styling.
//!
//! The symbol is study C1 ("Shifted tool"): a 17×16 pixel raster of the SVG's
//! four rectangles, packed two pixels per cell with half blocks (`▀ ▄ █`) so a
//! pixel is square in a terminal. The wordmark is a hand-set pixel face.

/// An 8-bit RGB color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

/// Orange `#E5653F`: the one signal color (mark, active state, live status).
pub const ORANGE: Rgb = Rgb(229, 101, 63);
/// Cream `#FAF4E8`: primary text on ink.
pub const CREAM: Rgb = Rgb(250, 244, 232);
/// Ink `#211C1C`: text on orange, and the dark ground.
pub const INK: Rgb = Rgb(33, 28, 28);
/// Stone `#A39A92`: secondary text.
pub const STONE: Rgb = Rgb(163, 154, 146);
/// Sand `#E5C77E`: warnings.
pub const SAND: Rgb = Rgb(229, 199, 126);
/// Mint `#95C8B6`: success / completed.
pub const MINT: Rgb = Rgb(149, 200, 182);
/// Clay `#D76F61`: errors.
pub const CLAY: Rgb = Rgb(215, 111, 97);

/// Symbol C1 as half blocks: 17 columns × 8 rows.
pub const GLYPH: [&str; 8] = [
    "█████████████████",
    "█████████████████",
    "████             ",
    "████     ▄▄▄▄▄▄▄▄",
    "████     ████████",
    "████     ▀▀▀▀████",
    "████         ████",
    "████         ████",
];

/// The lowercase wordmark as half blocks: 45 columns × 5 rows.
pub const WORDMARK: [&str; 5] = [
    "                ██                           ",
    "▄▄    ▄▄  ▄▄▄▄  ██▄▄▄  ▄▄ ▄▄▄  ▄▄▄▄  ▄▄    ▄▄",
    "██ ▄▄ ██ ██▄▄██ ██  ██ ██▀    ██▄▄██ ▀█▄  ▄█▀",
    "██▄██▄██ ██  ▄▄ ██  ██ ██     ██  ▄▄  ▀█▄▄█▀ ",
    " ▀▀  ▀▀   ▀▀▀▀  ▀▀▀▀▀  ▀▀      ▀▀▀▀     ▀▀   ",
];

/// Glyph row the first wordmark row sits beside.
const WORDMARK_TOP: usize = 1;
/// Columns between the symbol and the text block.
const GAP: &str = "   ";

/// How a run of banner text should be colored. Each front end decides what a
/// tone looks like (ANSI escapes, ratatui styles, or nothing at all).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    /// The signal color (symbol, "authorized targets only").
    Orange,
    /// Primary text (wordmark).
    Cream,
    /// Secondary text (tagline, version).
    Dim,
}

/// One styled run of text.
pub type Run = (Tone, String);

/// The startup banner: the symbol on the left, the wordmark and a two-line
/// caption on the right. Always [`GLYPH`]`.len()` rows, each a list of runs.
#[must_use]
pub fn banner(tagline: &str, version: &str) -> Vec<Vec<Run>> {
    let blank = " ".repeat(WORDMARK[0].chars().count());
    (0..GLYPH.len())
        .map(|row| {
            let mut runs: Vec<Run> = vec![(Tone::Orange, GLYPH[row].to_owned())];
            runs.push((Tone::Dim, GAP.to_owned()));
            let word_row = row.checked_sub(WORDMARK_TOP).filter(|r| *r < WORDMARK.len());
            match (row, word_row) {
                (_, Some(r)) => runs.push((Tone::Cream, WORDMARK[r].to_owned())),
                (6, None) => {
                    runs.push((Tone::Dim, format!("{tagline} · v{version}")));
                }
                (7, None) => {
                    runs.push((Tone::Orange, "authorized targets only".to_owned()));
                }
                _ => runs.push((Tone::Dim, blank.clone())),
            }
            runs
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn width(s: &str) -> usize {
        s.chars().count()
    }

    #[test]
    fn glyph_is_a_clean_rectangle() {
        assert!(GLYPH.iter().all(|l| width(l) == 17));
    }

    #[test]
    fn wordmark_rows_have_equal_width() {
        let w = width(WORDMARK[0]);
        assert!(WORDMARK.iter().all(|l| width(l) == w));
    }

    #[test]
    fn art_only_uses_half_block_characters() {
        let ok = |c: char| matches!(c, ' ' | '█' | '▀' | '▄');
        assert!(GLYPH.iter().chain(WORDMARK.iter()).all(|l| l.chars().all(ok)));
    }

    #[test]
    fn banner_fits_a_classic_80_column_terminal() {
        let rows = banner("web reconnaissance toolkit", "0.1.0");
        assert_eq!(rows.len(), GLYPH.len());
        for row in &rows {
            let w: usize = row.iter().map(|(_, s)| width(s)).sum();
            assert!(w <= 80, "banner row is {w} columns");
        }
    }

    #[test]
    fn banner_carries_caption_and_authorization_line() {
        let text: String = banner("web reconnaissance toolkit", "9.9.9")
            .iter()
            .flatten()
            .map(|(_, s)| s.as_str())
            .collect();
        assert!(text.contains("web reconnaissance toolkit · v9.9.9"));
        assert!(text.contains("authorized targets only"));
    }
}
