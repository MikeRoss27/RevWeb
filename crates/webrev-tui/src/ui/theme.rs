//! UI colors derived from the shared brand palette.

use crate::brand::{self, Rgb};
use ratatui::style::Color;

const fn rgb(c: Rgb) -> Color {
    Color::Rgb(c.0, c.1, c.2)
}

/// Brand palette, shared across the UI (values live in [`crate::brand`]).
/// Orange is the one signal color: the mark, the active tab, live state and
/// severity; the rest is cream on ink with sand/mint/clay for log levels.
pub(super) const PRIMARY: Color = rgb(brand::ORANGE);
pub(super) const ACCENT: Color = rgb(brand::CREAM);
pub(super) const WARN: Color = rgb(brand::SAND);
pub(super) const VOID: Color = rgb(brand::INK);
pub(super) const OK: Color = rgb(brand::MINT);
pub(super) const ERR: Color = rgb(brand::CLAY);
