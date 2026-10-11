//! Terminal styling on top of the reusable plain-text triage report.
use std::io::IsTerminal;
use webrev_report::{RenderOptions, SessionReport};

pub(super) fn show(report: &SessionReport) -> anyhow::Result<()> {
    let body = report.render_text(RenderOptions::default());
    if !std::io::stdout().is_terminal() || std::env::var_os("NO_COLOR").is_some() {
        return super::report::write_stdout(&body);
    }
    let mut styled = String::new();
    for line in body.lines() {
        let color = if line.starts_with("  [CRIT]") || line.starts_with("  [HIGH]") {
            "\x1b[1;38;2;229;101;63m"
        } else if line.starts_with("  [MED]") {
            "\x1b[33m"
        } else if [
            "webrev",
            "VULNERABILITIES",
            "SECRETS",
            "TECHNOLOGIES",
            "ATTACK SURFACE",
        ]
        .iter()
        .any(|heading| line.starts_with(heading))
        {
            "\x1b[1;38;2;250;244;232m"
        } else {
            ""
        };
        styled.push_str(color);
        styled.push_str(line);
        if !color.is_empty() {
            styled.push_str("\x1b[0m");
        }
        styled.push('\n');
    }
    super::report::write_stdout(&styled)
}
