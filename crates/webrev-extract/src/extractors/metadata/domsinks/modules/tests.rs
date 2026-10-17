use super::*;
use webrev_core::SessionId;

fn inputs(sources: &[(&str, &str)]) -> Vec<ExtractInput> {
    let session = SessionId::new();
    sources
        .iter()
        .map(|(path, body)| {
            ExtractInput::new(
                session,
                Some(format!("https://example.test/{path}")),
                ContentKind::JavaScript,
                *body,
            )
        })
        .collect()
}
fn flows(sources: &[(&str, &str)]) -> Vec<Finding> {
    DomSinkExtractor::extract_modules(&inputs(sources))
}
#[test]
fn named_alias_and_default_imports_preserve_provenance() {
    for source in [
        "const value = location.hash; export {value as payload};",
        "export const payload = location.hash;",
    ] {
        let found = flows(&[
            ("source.js", source),
            (
                "sink.js",
                "import {payload as data} from './source.js'; document.write(data);",
            ),
        ]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].value, "DOM XSS: location.hash -> document.write");
        assert_eq!(found[0].status, webrev_core::FindingStatus::Suspicious);
        assert_eq!(found[0].confidence, Confidence::Medium);
        assert_eq!(found[0].provenances.len(), 2);
    }
    assert_eq!(
        flows(&[
            ("source.js", "export default location.hash;"),
            ("sink.js", "import data from './source.js'; eval(data);")
        ])
        .len(),
        1
    );
}
#[test]
fn relative_urls_and_chains_work_without_order_dependence() {
    let found = flows(&[
        (
            "app/sink.js",
            "import {value} from '../bridge.js'; eval(value);",
        ),
        (
            "bridge.js",
            "import {payload} from './source.js'; export const value = payload;",
        ),
        ("source.js", "export const payload = location.search;"),
    ]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].provenances.len(), 3);
}
#[test]
fn missing_wrong_bare_and_unexported_imports_never_link() {
    for import in [
        "import {missing as payload} from './source.js';",
        "import {payload} from './other.js';",
        "import {payload} from 'source.js';",
        "const payload = 'safe';",
    ] {
        assert!(flows(&[
            ("source.js", "export const payload = location.hash;"),
            ("sink.js", &format!("{import} eval(payload);"))
        ])
        .is_empty());
    }
    assert!(flows(&[
        ("source.js", "const payload = location.hash;"),
        (
            "sink.js",
            "import {payload} from './source.js'; eval(payload);"
        )
    ])
    .is_empty());
}
#[test]
fn sanitizers_overwrites_numeric_results_and_shadowing_stop_flow() {
    for body in [
        "eval(DOMPurify.sanitize(payload));",
        "let data = payload; data = 'safe'; eval(data);",
        "eval(payload.search('x'));",
        "function f(payload) {eval(payload);}",
        "const f = payload => eval(payload);",
        "function f({payload}) {eval(payload);}",
        "function f([payload]) {eval(payload);}",
        "function f() { const {payload} = safe; eval(payload); }",
        "try {doSomething();} catch(payload) {eval(payload);}",
    ] {
        assert!(
            flows(&[
                ("source.js", "export const payload = location.hash;"),
                (
                    "sink.js",
                    &format!("import {{payload}} from './source.js'; {body}")
                )
            ])
            .is_empty(),
            "{body}"
        );
    }
    assert!(flows(&[
        (
            "source.js",
            "let payload = location.hash; payload = 'safe'; export {payload};"
        ),
        (
            "sink.js",
            "import {payload} from './source.js'; eval(payload);"
        )
    ])
    .is_empty());
}
#[test]
fn sessions_cycles_parse_errors_and_caps_do_not_invent_sources() {
    let mut separate = inputs(&[
        ("source.js", "export const payload = location.hash;"),
        (
            "sink.js",
            "import {payload} from './source.js'; eval(payload);",
        ),
    ]);
    separate[1].session_id = SessionId::new();
    assert!(DomSinkExtractor::extract_modules(&separate).is_empty());
    assert!(flows(&[
        (
            "source.js",
            "import {value} from './sink.js'; export const payload=value;"
        ),
        (
            "sink.js",
            "import {payload} from './source.js'; export const value=payload; eval(value);"
        )
    ])
    .is_empty());
    assert!(flows(&[
        ("source.js", "export const payload = location.hash; ???"),
        (
            "sink.js",
            "import {payload} from './source.js'; eval(payload);"
        )
    ])
    .is_empty());
    let oversized = format!(
        "export const payload = location.hash; /*{}*/",
        "x".repeat(MAX_MODULE_BYTES)
    );
    assert!(flows(&[
        ("source.js", &oversized),
        (
            "sink.js",
            "import {payload} from './source.js'; eval(payload);"
        )
    ])
    .is_empty());
}

#[test]
fn conflicting_urls_are_excluded_in_both_orders() {
    let mut conflicting = inputs(&[
        ("source.js", "export const payload = location.hash;"),
        ("source.js", "export const payload = 'safe';"),
        (
            "sink.js",
            "import {payload} from './source.js'; eval(payload);",
        ),
    ]);
    assert!(DomSinkExtractor::extract_modules(&conflicting).is_empty());
    conflicting.reverse();
    assert!(DomSinkExtractor::extract_modules(&conflicting).is_empty());
}

#[test]
fn default_exports_are_snapshots_and_block_bindings_do_not_escape() {
    for source in [
        "let payload='safe'; export default payload; payload=location.hash;",
        "const payload='safe'; { const payload=location.hash; } export {payload as default};",
        "let payload=location.hash; {payload='safe';} export {payload as default};",
    ] {
        assert!(
            flows(&[
                ("source.js", source),
                (
                    "sink.js",
                    "import payload from './source.js'; eval(payload);"
                )
            ])
            .is_empty(),
            "{source}"
        );
    }
    assert_eq!(
        flows(&[
            (
                "source.js",
                "let payload=location.hash; export default payload; payload='safe';"
            ),
            (
                "sink.js",
                "import payload from './source.js'; eval(payload);"
            )
        ])
        .len(),
        1
    );
}

#[test]
fn exported_function_calls_link_source_returns_and_sink_parameters() {
    for declaration in [
        "function source(){const data=location.hash.substr(1); return data;} export {source};",
        "export function source(){const data=location.hash.substr(1); return data;}",
    ] {
        let found = flows(&[
            ("source.js", declaration),
            ("sink.js", "function render(data){let copy=data; document.write(copy);} export {render as sink};"),
            ("main.js", "import {source as read} from './source.js'; import {sink as write} from './sink.js'; const data=read(); write(data);"),
        ]);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].value,
            "DOM XSS: location.hash -> substr -> document.write"
        );
        assert_eq!(found[0].status, webrev_core::FindingStatus::Suspicious);
        assert_eq!(found[0].confidence, Confidence::Medium);
        assert_eq!(found[0].provenances.len(), 3);
    }
}

#[test]
fn source_functions_only_taint_explicit_calls() {
    for body in [
        "eval(source);",
        "if(false){eval(source());}",
        "if(true){}else{eval(source());}",
        "false ? eval(source()) : 0;",
        "function unused(){eval(source());}",
        "const unused=()=>eval(source());",
        "function unused(source){eval(source());}",
        "{let source=()=> 'safe'; eval(source());}",
        "source=()=> 'safe'; eval(source());",
        "({source}=safe); eval(source());",
        "source++; eval(source());",
        "{eval(source()); function source(){return 'safe';}}",
        "const value=DOMPurify.sanitize(source()); eval(value);",
        "const value=source(); let copy=value; copy='safe'; eval(copy);",
    ] {
        assert!(
            flows(&[
                (
                    "source.js",
                    "export function source(){return location.hash;}"
                ),
                (
                    "main.js",
                    &format!("import {{source}} from './source.js'; {body}")
                ),
            ])
            .is_empty(),
            "{body}"
        );
    }
    for source in [
        "export function source(){return DOMPurify.sanitize(location.hash);}",
        "export function source(){let x=location.hash; x='safe'; return x;}",
        "export function source(){if(false){return location.hash;} return 'safe';}",
        "export function source(){return location.hash;} source=()=> 'safe';",
        "export function source(){return location.hash;} ({source}=safe);",
        "export function source(){return location.hash;} source++;",
        "const location={hash:'safe'}; export function source(){return location.hash;}",
        "export async function source(){return location.hash;}",
        "export function* source(){return location.hash;}",
        "export function source(location){return location.hash;}",
        "export function source(){const location={hash:'safe'}; return location.hash;}",
    ] {
        assert!(
            flows(&[
                ("source.js", source),
                (
                    "main.js",
                    "import {source} from './source.js'; eval(source());"
                ),
            ])
            .is_empty(),
            "{source}"
        );
    }
}

#[test]
fn imported_sink_requires_called_unsanitized_unshadowed_argument() {
    for body in [
        "sink('safe');",
        "sink(DOMPurify.sanitize(location.hash));",
        "function unused(){sink(location.hash);}",
        "const unused=()=>sink(location.hash);",
        "{const sink=()=>{}; sink(location.hash);}",
        "sink=()=>{}; sink(location.hash);",
        "sink(...['safe'],location.hash);",
    ] {
        assert!(
            flows(&[
                (
                    "sink.js",
                    "export function sink(value){document.write(value);}"
                ),
                (
                    "main.js",
                    &format!("import {{sink}} from './sink.js'; {body}")
                ),
            ])
            .is_empty(),
            "{body}"
        );
    }
    for sink in [
        "export function sink(value){document.write(DOMPurify.sanitize(value));}",
        "export function sink(value){value='safe'; document.write(value);}",
        "export function sink(value){function unused(){document.write(value);}}",
        "export function sink(value){if(false){document.write(value);}}",
        "export function sink(value){document.write(value);} sink=()=>{};",
        "export function sink(value){document={write(){}}; document.write(value);}",
    ] {
        assert!(
            flows(&[
                ("sink.js", sink),
                (
                    "main.js",
                    "import {sink} from './sink.js'; sink(location.hash);"
                ),
            ])
            .is_empty(),
            "{sink}"
        );
    }
}

#[test]
fn function_import_names_urls_and_cycles_do_not_invent_flows() {
    for import in [
        "import {missing as source} from './source.js';",
        "import {source} from './missing.js';",
        "import source from './source.js';",
        "import {source} from 'source.js';",
    ] {
        assert!(
            flows(&[
                (
                    "source.js",
                    "export function source(){return location.hash;}"
                ),
                ("main.js", &format!("{import} eval(source());")),
            ])
            .is_empty(),
            "{import}"
        );
    }
    assert!(flows(&[
        (
            "source.js",
            "import {other} from './other.js'; export function source(){return other();}"
        ),
        (
            "other.js",
            "import {source} from './source.js'; export function other(){return source();}"
        ),
        (
            "main.js",
            "import {source} from './source.js'; eval(source());"
        ),
    ])
    .is_empty());
    assert!(flows(&[
        ("source.js", "export const data=location.hash;"),
        (
            "main.js",
            "import {data} from './source.js'; function unused(){eval(data);}"
        ),
    ])
    .is_empty());
}

#[test]
fn module_cap_precedes_session_filter_and_parse_failures_consume_budget() {
    let mut capped = inputs(&[("source.js", "export const payload=location.hash;")]);
    let foreign_session = SessionId::new();
    for index in 1..MAX_MODULES {
        let mut input = capped[0].clone();
        input.session_id = foreign_session;
        input.url = Some(format!("https://example.test/foreign-{index}.js"));
        capped.push(input);
    }
    let mut beyond = capped[0].clone();
    beyond.url = Some("https://example.test/sink.js".to_owned());
    beyond.body = "import {payload} from './source.js'; eval(payload);".to_owned();
    capped.push(beyond);
    assert!(DomSinkExtractor::extract_modules(&capped).is_empty());

    let mut budget = inputs(&[(
        "bad.js",
        &format!("???{}", " ".repeat(MAX_MODULE_BYTES - 3)),
    )]);
    for index in 1..(MAX_TOTAL_BYTES / MAX_MODULE_BYTES) {
        let mut input = budget[0].clone();
        input.url = Some(format!("https://example.test/bad-{index}.js"));
        budget.push(input);
    }
    let session = budget[0].session_id;
    let mut trailing = inputs(&[
        ("source.js", "export const payload=location.hash;"),
        (
            "sink.js",
            "import {payload} from './source.js'; eval(payload);",
        ),
    ]);
    for input in &mut trailing {
        input.session_id = session;
    }
    budget.extend(trailing);
    assert!(DomSinkExtractor::extract_modules(&budget).is_empty());
}

#[test]
fn mutable_captures_are_not_assumed_stable_across_exported_calls() {
    assert!(flows(&[
        ("source.js", "let value=location.hash; export function clear(){value='safe';} export function source(){return value;}"),
        ("main.js", "import {clear,source} from './source.js'; clear(); eval(source());"),
    ]).is_empty());
}

#[test]
fn literal_live_call_branches_still_link() {
    for body in [
        "if(true){eval(source());}",
        "if(false){}else{eval(source());}",
        "true ? eval(source()) : 0;",
    ] {
        assert_eq!(
            flows(&[
                (
                    "source.js",
                    "export function source(){return location.hash;}"
                ),
                (
                    "main.js",
                    &format!("import {{source}} from './source.js'; {body}")
                ),
            ])
            .len(),
            1,
            "{body}"
        );
    }
}

const SINK: &str = "import {payload} from './source.js'; document.write(payload);";

fn labels(source: &str, sink: &str) -> Vec<String> {
    flows(&[("source.js", source), ("sink.js", sink)])
        .into_iter()
        .map(|finding| finding.value)
        .collect()
}

#[test]
fn document_location_is_the_same_source_as_location() {
    assert_eq!(
        labels(
            "export var payload = document.location.search.substr(1);",
            SINK
        ),
        ["DOM XSS: location.search -> substr -> document.write"]
    );
}

#[test]
fn top_level_if_merges_arms_with_may_taint() {
    // Hoisted `var` in either arm, and a window.name guard, keep the export.
    for source in [
        "if (document.referrer == '') { location.href = 'x'; } else { var payload = document.referrer; }\nexport {payload};",
        "if (window.name == '') { window.name = 'x'; }\nvar payload = window.name;\nexport {payload};",
        "var payload = location.hash;\nif (cond) { payload = 'safe'; }\nexport {payload};",
    ] {
        assert_eq!(labels(source, SINK).len(), 1, "{source}");
    }
    // Unsupported statements and block-scoped declarations withdraw the summary.
    for source in [
        "if (c) { for (const x of y) {} }\nvar payload = location.hash;\nexport {payload};",
        "if (c) { let payload = location.hash; }\nexport {payload};",
        "if (c) { try {} catch (e) {} }\nvar payload = location.hash;\nexport {payload};",
    ] {
        assert!(labels(source, SINK).is_empty(), "{source}");
    }
}

#[test]
fn function_summaries_follow_branches_loops_and_local_helpers() {
    let sink = "import {source} from './source.js'; document.write(source());";
    for source in [
        // Early return inside a branch.
        "export function source() { if (document.referrer == '') { location.href = 'x'; } else { var p = document.referrer; return p; } }",
        // Helper declared inside the body, with a loop.
        "export function source() { function find(n) { var parts = document.cookie.split(';'); for (var i = 0; i < parts.length; i++) { if (parts[i].indexOf(n) == 0) { return parts[i].substr(n.length); } } } return find('a'); }",
        // Module-level helper called from the exported function.
        "function find(n) { var parts = document.cookie.split(';'); for (var i = 0; i < parts.length; i++) { return parts[i]; } }\nexport function source() { var v = find('a'); return v; }",
        // Property write to a global does not disable the summary.
        "export function source() { if (window.name == '') { window.name = 'x'; } return window.name; }",
    ] {
        assert_eq!(labels(source, sink).len(), 1, "{source}");
    }
    // A top-level return that is not last, or an unsupported statement, is dropped.
    for source in [
        "export function source() { return 'a'; return location.hash; }",
        "export function source() { var p = location.hash; switch (p) {} return p; }",
        "export function source() { if (c) { let p = location.hash; return p; } }",
    ] {
        assert!(labels(source, sink).is_empty(), "{source}");
    }
}
