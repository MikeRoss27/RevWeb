// crates/webrev-tui/src/lib.rs
#![warn(clippy::all, clippy::pedantic)]
// Justification: this is an application crate (anyhow at the boundary); the
// event loop and scan launchers are inherently long and side-effecting, so a
// handful of noisy pedantic lints are allowed with intent.
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::too_many_lines
)]

//! `webrev-tui`: a `ratatui` front-end that runs the pipeline live and renders
//! endpoints, findings, logs, and status across four tabs.
//!
//! Exposed as a library so the `webrev` CLI's `tui` subcommand can launch it,
//! and as a thin binary of its own.

pub mod app;
pub mod events;
pub mod ui;

use crate::app::{App, UiEvent};
use crate::events::{map_key, Action};
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use ratatui::DefaultTerminal;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::mpsc::{self, UnboundedSender};
use tokio_util::sync::CancellationToken;
use webrev_browser::{run_dynamic, BrowserProfile};
use webrev_core::{Mission, MissionProfile, OpsecConfig};
use webrev_extract::ExtractorRegistry;
use webrev_pipeline::stages::{FetchStage, StaticExtractStage, StoreStage};
use webrev_pipeline::{PipelineBuilder, PipelineEvent, StageContext};
use webrev_report::SessionReport;
use webrev_storage::{SqliteStorage, Storage};

/// How long each dynamic page dwell lasts.
const DYNAMIC_DWELL: Duration = Duration::from_secs(8);

/// Everything the TUI needs to run.
pub struct TuiOptions {
    pub profile: MissionProfile,
    pub db_path: PathBuf,
    pub report_path: PathBuf,
}

/// Launch the TUI: set up the terminal, run the event loop, and restore the
/// terminal afterwards (even on error).
pub async fn run(options: TuiOptions) -> anyhow::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(SqliteStorage::connect(&options.db_path).await?);
    storage.create_session(&options.profile.mission).await?;

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, options, storage).await;
    ratatui::restore();
    result
}

/// Shared handles used to launch scans and export reports.
struct Controller {
    mission: Arc<Mission>,
    opsec: Arc<OpsecConfig>,
    registry: Arc<ExtractorRegistry>,
    storage: Arc<dyn Storage>,
    cancel: CancellationToken,
    report_path: PathBuf,
}

impl Controller {
    /// Launch a static pipeline, forwarding its events into `ui_tx`.
    fn start_static(&self, ui_tx: UnboundedSender<UiEvent>) {
        let builder = PipelineBuilder::new()
            .add_stage(Arc::new(FetchStage::new()))
            .add_stage(Arc::new(StaticExtractStage::new()))
            .add_stage(Arc::new(StoreStage::new()));
        let mut events = builder.subscribe();
        let ctx = StageContext::new(
            Arc::clone(&self.mission),
            Arc::clone(&self.opsec),
            Arc::clone(&self.registry),
            Arc::clone(&self.storage),
            self.cancel.clone(),
        );

        let forward_tx = ui_tx.clone();
        tokio::spawn(async move {
            loop {
                match events.recv().await {
                    Ok(event) => {
                        if forward_tx.send(UiEvent::Pipeline(event)).is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        tokio::spawn(async move {
            let message = match builder.run(ctx, Vec::new()).await {
                Ok(summary) => format!(
                    "static scan done: {} findings, {} errors",
                    summary.findings_emitted, summary.errors
                ),
                Err(e) => format!("static scan error: {e}"),
            };
            let _ = ui_tx.send(UiEvent::Status(message));
        });
    }

    /// Launch a dynamic scan of each in-scope seed, persisting and surfacing the
    /// findings as they complete.
    fn start_dynamic(&self, ui_tx: UnboundedSender<UiEvent>) {
        let mission = Arc::clone(&self.mission);
        let opsec = Arc::clone(&self.opsec);
        let storage = Arc::clone(&self.storage);
        let cancel = self.cancel.clone();

        tokio::spawn(async move {
            let profile = match BrowserProfile::from_opsec(&opsec) {
                Ok(profile) => profile,
                Err(e) => {
                    let _ = ui_tx.send(UiEvent::Status(format!("dynamic: profile error: {e}")));
                    return;
                }
            };

            let mut total = 0usize;
            for seed in &mission.seeds {
                if !mission.scope.allows(seed) {
                    let _ = ui_tx.send(UiEvent::Status(format!("dynamic: skip out-of-scope {seed}")));
                    continue;
                }
                match run_dynamic(&profile, seed, DYNAMIC_DWELL, mission.id, cancel.clone()).await {
                    Ok(findings) => {
                        for finding in &findings {
                            let _ = storage.insert_finding(finding).await;
                            let _ = ui_tx.send(UiEvent::Pipeline(PipelineEvent::Finding(Box::new(
                                finding.clone(),
                            ))));
                        }
                        total += findings.len();
                    }
                    Err(e) => {
                        let _ = ui_tx.send(UiEvent::Status(format!("dynamic error on {seed}: {e}")));
                    }
                }
            }
            let _ = ui_tx.send(UiEvent::Status(format!("dynamic scan done: {total} findings")));
        });
    }

    /// Build and write the JSON report for the current session.
    async fn export_report(&self) -> anyhow::Result<PathBuf> {
        let findings = self.storage.findings_by_session(self.mission.id).await?;
        let endpoints = self.storage.endpoints_by_session(self.mission.id).await?;
        let report = SessionReport::build((*self.mission).clone(), findings, endpoints);
        std::fs::write(&self.report_path, report.to_json()?)?;
        Ok(self.report_path.clone())
    }
}

async fn event_loop(
    terminal: &mut DefaultTerminal,
    options: TuiOptions,
    storage: Arc<dyn Storage>,
) -> anyhow::Result<()> {
    let mission = Arc::new(options.profile.mission);
    let controller = Controller {
        mission: Arc::clone(&mission),
        opsec: Arc::new(options.profile.opsec),
        registry: Arc::new(ExtractorRegistry::with_defaults()),
        storage,
        cancel: CancellationToken::new(),
        report_path: options.report_path,
    };

    let mut app = App::new(mission.name.clone(), mission.scope.clone());
    let (ui_tx, mut ui_rx) = mpsc::unbounded_channel::<UiEvent>();
    // Async terminal input — the idiomatic ratatui pattern, no blocking thread.
    let mut term_events = EventStream::new();

    // Kick off a static scan immediately so the UI is useful on open.
    controller.start_static(ui_tx.clone());
    app.apply(UiEvent::Status("auto static scan started".to_owned()));

    loop {
        terminal.draw(|frame| ui::render(frame, &mut app))?;

        tokio::select! {
            Some(event) = ui_rx.recv() => app.apply(event),
            maybe = term_events.next() => match maybe {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    if app.filtering {
                        handle_filter_key(key, &mut app);
                    } else {
                        handle_action(map_key(key), &mut app, &controller, &ui_tx).await;
                    }
                }
                // Resize and other events just trigger a redraw next iteration.
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            else => break,
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// While the filter line is open, keys edit the filter string instead of
/// triggering actions. Enter confirms (keeps the filter), Esc cancels (clears).
fn handle_filter_key(key: crossterm::event::KeyEvent, app: &mut App) {
    use crossterm::event::KeyCode;
    match key.code {
        KeyCode::Esc => app.filter_cancel(),
        KeyCode::Enter => app.filter_confirm(),
        KeyCode::Backspace => app.filter_backspace(),
        KeyCode::Char(c) => app.filter_push(c),
        _ => {}
    }
}

/// Apply a decoded key action to the app and controller.
async fn handle_action(
    action: Action,
    app: &mut App,
    controller: &Controller,
    ui_tx: &UnboundedSender<UiEvent>,
) {
    match action {
        Action::Quit => {
            // Esc/q first dismisses an open detail overlay, then quits.
            if app.show_detail {
                app.show_detail = false;
            } else {
                controller.cancel.cancel();
                app.should_quit = true;
            }
        }
        Action::ToggleDetail => app.toggle_detail(),
        Action::ToggleSort => app.toggle_sort(),
        Action::NextTab => app.select_tab(app.tab.next()),
        Action::PrevTab => app.select_tab(app.tab.prev()),
        Action::ScrollUp => app.scroll_up(),
        Action::ScrollDown => app.scroll_down(),
        Action::ScrollTop => app.scroll_to_top(),
        Action::ScrollBottom => app.scroll_to_bottom(),
        Action::StartStatic => {
            controller.start_static(ui_tx.clone());
            app.apply(UiEvent::Status("static scan started".to_owned()));
        }
        Action::StartDynamic => {
            controller.start_dynamic(ui_tx.clone());
            app.apply(UiEvent::Status("dynamic scan started".to_owned()));
        }
        Action::ExportReport => {
            let status = match controller.export_report().await {
                Ok(path) => format!("report written to {}", path.display()),
                Err(e) => format!("report failed: {e}"),
            };
            app.apply(UiEvent::Status(status));
        }
        Action::Filter => app.begin_filter(),
        Action::None => {}
    }
}
