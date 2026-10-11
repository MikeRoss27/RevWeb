use super::render;
use crate::app::{App, Tab, UiEvent};
use ratatui::{backend::TestBackend, Terminal};
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Scope, SessionId, Source};
use webrev_pipeline::PipelineEvent;

fn render_text(app: &mut App) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(ratatui::buffer::Cell::symbol)
        .collect()
}

#[test]
fn finding_detail_keeps_the_detected_secret_visible() {
    let mut app = App::new("render fixture".into(), Scope::default());
    let finding = Finding::new(
        SessionId::new(),
        FindingKind::Secret,
        None,
        "fp:test",
        Confidence::High,
        Provenance::new(Source::JsRegex, Some("app.js".into())),
    )
    .with_plaintext(Some("AKIAZ4XB7NMPQR2STUVW".into()));
    app.apply(UiEvent::Pipeline(PipelineEvent::Finding(Box::new(finding))));
    app.select_tab(Tab::Findings);
    app.toggle_detail();
    let screen = render_text(&mut app);
    assert!(screen.contains("detected"));
    assert!(screen.contains("fingerprint"));
    assert!(screen.contains("AKIAZ4XB7NMPQR2STUVW"));
    assert!(screen.contains("detail"));
}

#[test]
fn help_overlay_and_empty_panel_render_after_the_split() {
    let mut app = App::new("render fixture".into(), Scope::default());
    assert!(render_text(&mut app).contains("render fixture"));
    app.toggle_help();
    let screen = render_text(&mut app);
    assert!(screen.contains("Navigate"));
    assert!(screen.contains("export the JSON report"));
}

#[test]
fn technology_name_and_vulnerability_evidence_are_visible_in_their_tabs() {
    let mut app = App::new("render fixture".into(), Scope::default());
    for (kind, value) in [
        (FindingKind::Technology, "React (framework)"),
        (
            FindingKind::Vulnerability,
            "reflected parameter: possible XSS",
        ),
    ] {
        let finding = Finding::new(
            SessionId::new(),
            kind,
            Some("https://x/search".into()),
            value,
            Confidence::Low,
            Provenance::new(Source::Active, None),
        );
        app.apply(UiEvent::Pipeline(PipelineEvent::Finding(Box::new(finding))));
    }
    app.select_tab(Tab::Technologies);
    assert!(render_text(&mut app).contains("React (framework)"));
    app.select_tab(Tab::Vulnerabilities);
    assert!(render_text(&mut app).contains("reflected parameter"));
    app.toggle_detail();
    let screen = render_text(&mut app);
    assert!(screen.contains("signal / verify manually"));
    assert!(screen.contains("severity"));
    app.show_detail = false;
    app.select_tab(Tab::Status);
    assert!(render_text(&mut app).contains("RCE:       not tested"));
}

#[test]
fn long_secret_details_can_scroll_to_the_end_and_stop_there() {
    let mut app = App::new("long evidence".into(), Scope::default());
    let finding = Finding::new(
        SessionId::new(),
        FindingKind::Secret,
        None,
        "fp:long",
        Confidence::High,
        Provenance::new(Source::Html, None),
    )
    .with_plaintext(Some(format!("{}END-OF-SECRET", "x".repeat(2000))));
    app.apply(UiEvent::Pipeline(PipelineEvent::Finding(Box::new(finding))));
    app.select_tab(Tab::Secrets);
    app.toggle_detail();
    app.detail_scroll = u16::MAX;
    let screen = render_text(&mut app);
    assert!(screen.contains("END-OF-SECRET"));
    assert!(app.detail_scroll > 0 && app.detail_scroll < u16::MAX);
    let last_scroll = app.detail_scroll;
    assert!(render_text(&mut app).contains("END-OF-SECRET"));
    assert_eq!(app.detail_scroll, last_scroll);
}

#[test]
fn status_shows_latest_incomplete_active_coverage() {
    let mut app = App::new("coverage fixture".into(), Scope::default());
    let mut finding = Finding::new(
        SessionId::new(),
        FindingKind::ScanCoverage,
        None,
        "active coverage: incomplete / no clean verdict; 7 / 7 requests",
        Confidence::High,
        Provenance::new(Source::Active, None),
    );
    finding.coverage = Some(Box::new(webrev_core::ActiveCoverage {
        requests: 7,
        request_limit: 7,
        budget_exhausted: true,
        ..webrev_core::ActiveCoverage::default()
    }));
    app.apply(UiEvent::Pipeline(PipelineEvent::Finding(Box::new(finding))));
    app.select_tab(Tab::Status);
    let screen = render_text(&mut app);
    assert!(screen.contains("incomplete / no clean verdict"));
    assert!(screen.contains("7 / 7 requests"));
}
