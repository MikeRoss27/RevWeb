//! Terminal lifetime and asynchronous event loop.
mod active;
mod controller;
mod input;
#[cfg(test)]
mod tests;

use crate::{
    app::{App, UiEvent},
    events::map_key,
    ui,
};
use controller::Controller;
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use input::{handle_action, handle_confirm_key, handle_filter_key};
use ratatui::DefaultTerminal;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use webrev_core::MissionProfile;
use webrev_extract::ExtractorRegistry;
use webrev_storage::{InMemoryStorage, Storage};

/// Animation/expiry cadence. Redraws happen on this tick only when something
/// animated changed, so an idle UI stays idle.
const TICK: Duration = Duration::from_millis(100);

/// Everything the TUI needs to run.
pub struct TuiOptions {
    pub profile: MissionProfile,
    pub report_path: PathBuf,
    /// Mask credentials in the exported report (the default); detected secret
    /// plaintext is kept either way.
    pub redact_report: bool,
}

/// Launch the TUI: set up the terminal, run the event loop, and restore the
/// terminal afterwards (even on error).
pub async fn run(options: TuiOptions) -> anyhow::Result<()> {
    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
    storage.create_session(&options.profile.mission).await?;

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, options, storage).await;
    ratatui::restore();
    result
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
        redact_report: options.redact_report,
    };

    let mut app = App::new(mission.name.clone(), mission.scope.clone());
    let (ui_tx, mut ui_rx) = mpsc::unbounded_channel::<UiEvent>();
    // Async terminal input — the idiomatic ratatui pattern, no blocking thread.
    let mut term_events = EventStream::new();

    // Kick off a static scan immediately so the UI is useful on open.
    app.begin_scan();
    controller.start_static(ui_tx.clone());
    app.apply(UiEvent::Status("auto static scan started".to_owned()));

    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut redraw = true;

    loop {
        if redraw {
            terminal.draw(|frame| ui::render(frame, &mut app))?;
            redraw = false;
        }

        tokio::select! {
            Some(event) = ui_rx.recv() => {
                app.apply(event);
                redraw = true;
            }
            _ = tick.tick() => redraw |= app.tick(Instant::now()),
            maybe = term_events.next() => match maybe {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                    if app.confirm_quit {
                        handle_confirm_key(key, &mut app, &controller, &ui_tx);
                    } else if app.filtering {
                        handle_filter_key(key, &mut app);
                    } else {
                        handle_action(map_key(key), &mut app, &controller, &ui_tx);
                    }
                    redraw = true;
                }
                // The terminal was resized or regained focus: repaint at once.
                Some(Ok(Event::Resize(..) | Event::FocusGained)) => redraw = true,
                // Mouse capture is not enabled yet, key releases/repeats carry no
                // action, focus loss and bracketed paste need no repaint.
                Some(Ok(
                    Event::Mouse(_) | Event::FocusLost | Event::Paste(_) | Event::Key(_),
                )) => {}
                Some(Err(_)) | None => break,
            },
            else => break,
        }

        if app.should_quit {
            break;
        }
    }

    controller.cancel.cancel();
    Ok(())
}

/// Test hook: drive the filter-line key handler from other modules' tests.
#[cfg(test)]
pub(crate) fn handle_filter_key_for_tests(key: crossterm::event::KeyEvent, app: &mut App) {
    handle_filter_key(key, app);
}
