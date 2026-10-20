//! Cross-file `postMessage` handler linking: see [`super::handlers`].
use super::*;
use webrev_core::SessionId;

fn flows(sources: &[(&str, &str)]) -> Vec<Finding> {
    let session = SessionId::new();
    let inputs: Vec<_> = sources
        .iter()
        .map(|(path, body)| {
            ExtractInput::new(
                session,
                Some(format!("https://example.test/{path}")),
                ContentKind::JavaScript,
                *body,
            )
        })
        .collect();
    DomSinkExtractor::extract_modules(&inputs)
}

#[test]
fn imported_message_handler_links_across_files() {
    let found = flows(&[
        (
            "handler.js",
            "export function onMsg(e) { document.body.innerHTML = e.data; }",
        ),
        (
            "main.js",
            "import {onMsg} from './handler.js'; window.addEventListener('message', onMsg);",
        ),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].value,
        "DOM XSS: event.data -> document.body.innerHTML"
    );
    assert_eq!(found[0].status, webrev_core::FindingStatus::Suspicious);
    let provenance_urls: std::collections::BTreeSet<_> = found[0]
        .provenances
        .iter()
        .filter_map(|p| p.location.clone())
        .collect();
    assert!(provenance_urls.contains("https://example.test/handler.js"));
    assert!(provenance_urls.contains("https://example.test/main.js"));
}

#[test]
fn imported_default_message_handler_links_across_files() {
    let found = flows(&[
        (
            "handler.js",
            "export default function (e) { eval(e.data); }",
        ),
        (
            "main.js",
            "import onMsg from './handler.js'; addEventListener('message', onMsg);",
        ),
    ]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].value, "DOM XSS: event.data -> eval");
}

#[test]
fn non_message_imported_handlers_and_local_functions_are_not_linked() {
    // Wrong event name: never a handler.
    assert!(flows(&[
        ("handler.js", "export function onMsg(e) { eval(e.data); }"),
        (
            "main.js",
            "import {onMsg} from './handler.js'; window.addEventListener('click', onMsg);",
        ),
    ])
    .is_empty());
    // Not imported from elsewhere: ordinary same-file linking already covers
    // this and is unaffected.
    assert!(flows(&[(
        "only.js",
        "function onMsg(e) { eval(e.data); } window.addEventListener('message', onMsg);",
    )])
    .is_empty());
}

/// `addEventListener('message', table[key])`: a computed registration never
/// resolves to a concrete identifier, so it stays unlinked, matching the
/// explicitly scoped boundary documented in `domsinks/modules/handlers.rs`.
#[test]
fn computed_message_handler_registration_is_not_tracked() {
    assert!(flows(&[
        ("handler.js", "export function onMsg(e) { eval(e.data); }"),
        (
            "main.js",
            "import {onMsg} from './handler.js'; const table = {onMsg}; window.addEventListener('message', table['onMsg']);",
        ),
    ])
    .is_empty());
}

/// A namespace-imported handler (`ns.onMsg`) is also out of scope for this
/// feature: only a plain identifier is followed.
#[test]
fn namespace_member_message_handler_registration_is_not_tracked() {
    assert!(flows(&[
        ("handler.js", "export function onMsg(e) { eval(e.data); }"),
        (
            "main.js",
            "import * as ns from './handler.js'; window.addEventListener('message', ns.onMsg);",
        ),
    ])
    .is_empty());
}

/// A handler reached only through a re-export barrel is out of scope: the
/// import must resolve directly to the declaring module.
#[test]
fn reexported_message_handler_is_not_tracked() {
    assert!(flows(&[
        ("handler.js", "export function onMsg(e) { eval(e.data); }"),
        ("barrel.js", "export {onMsg} from './handler.js';"),
        (
            "main.js",
            "import {onMsg} from './barrel.js'; window.addEventListener('message', onMsg);",
        ),
    ])
    .is_empty());
}
