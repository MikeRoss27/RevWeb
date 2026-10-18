//! Namespace imports and re-exports across explicit ES-module specifiers.
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

fn values(sources: &[(&str, &str)]) -> Vec<String> {
    flows(sources).into_iter().map(|f| f.value).collect()
}

const VALUE: &str = "export const payload = location.hash;";
const FUNCTION: &str = "export function source() { return location.hash; }";

#[test]
fn namespace_import_member_carries_value_and_function_flows() {
    for (source, sink) in [
        (
            VALUE,
            "import * as ns from './source.js'; document.write(ns.payload);",
        ),
        (
            VALUE,
            "import * as ns from './source.js'; const v = ns.payload; document.write(v);",
        ),
        (
            FUNCTION,
            "import * as ns from './source.js'; document.write(ns.source());",
        ),
        (
            "export default location.hash;",
            "import * as ns from './source.js'; document.write(ns.default);",
        ),
    ] {
        assert_eq!(
            values(&[("source.js", source), ("sink.js", sink)]),
            ["DOM XSS: location.hash -> document.write"],
            "{sink}"
        );
    }
    // A parameter sink summarized in the dependency is reached through `ns.fn(arg)`.
    let found = flows(&[
        ("lib.js", "export function show(x) { document.write(x); }"),
        (
            "app.js",
            "import * as lib from './lib.js'; lib.show(location.hash);",
        ),
    ]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].value, "DOM XSS: location.hash -> document.write");
    assert_eq!(found[0].provenances.len(), 2);
}

#[test]
fn namespace_import_never_invents_a_flow() {
    for sink in [
        "import * as ns from './source.js'; document.write(ns.missing);",
        "import * as ns from './source.js'; document.write(ns);",
        "import * as ns from './source.js'; document.write(ns[name]);",
        "import * as ns from 'source.js'; document.write(ns.payload);",
        "import * as ns from './other.js'; document.write(ns.payload);",
        "import * as ns from './source.js'; ns.missing(); document.write(ns.safe);",
        "import * as ns from './source.js'; { const ns = {payload: 'x'}; document.write(ns.payload); }",
        "import * as ns from './source.js'; document.write(DOMPurify.sanitize(ns.payload));",
    ] {
        assert!(
            values(&[
                (
                    "source.js",
                    "export const payload = location.hash; export const safe = 'x';"
                ),
                ("sink.js", sink)
            ])
            .is_empty(),
            "{sink}"
        );
    }
    // The dependency's own value is safe, so the namespace carries nothing.
    assert!(values(&[
        ("source.js", "export const payload = 'safe';"),
        (
            "sink.js",
            "import * as ns from './source.js'; document.write(ns.payload);"
        )
    ])
    .is_empty());
}

#[test]
fn named_reexports_forward_values_functions_and_aliases() {
    for (source, barrel, sink) in [
        (
            VALUE,
            "export {payload} from './source.js';",
            "import {payload} from './barrel.js'; document.write(payload);",
        ),
        (
            VALUE,
            "export {payload as data} from './source.js';",
            "import {data as p} from './barrel.js'; document.write(p);",
        ),
        (
            "export default location.hash;",
            "export {default as payload} from './source.js';",
            "import {payload} from './barrel.js'; document.write(payload);",
        ),
        (
            FUNCTION,
            "export {source} from './source.js';",
            "import {source} from './barrel.js'; document.write(source());",
        ),
        (
            VALUE,
            "export {payload} from './source.js';",
            "import * as ns from './barrel.js'; document.write(ns.payload);",
        ),
    ] {
        let found = flows(&[
            ("source.js", source),
            ("barrel.js", barrel),
            ("sink.js", sink),
        ]);
        assert_eq!(found.len(), 1, "{barrel} {sink}");
        assert_eq!(found[0].value, "DOM XSS: location.hash -> document.write");
        assert_eq!(
            found[0].provenances.len(),
            3,
            "barrel is part of the evidence"
        );
    }
    // Chains of barrels link without order dependence.
    assert_eq!(
        values(&[
            (
                "sink.js",
                "import {payload} from './outer.js'; eval(payload);"
            ),
            ("outer.js", "export {payload} from './inner.js';"),
            ("inner.js", "export {payload} from './source.js';"),
            ("source.js", VALUE),
        ]),
        ["DOM XSS: location.hash -> eval"]
    );
}

#[test]
fn star_reexports_forward_named_exports_only() {
    let sink = "import {payload, source} from './barrel.js'; document.write(payload); document.write(source());";
    let found = values(&[
        ("source.js", &format!("{VALUE} {FUNCTION}")),
        ("barrel.js", "export * from './source.js';"),
        ("sink.js", sink),
    ]);
    assert_eq!(found, ["DOM XSS: location.hash -> document.write"]);
    // `export *` never forwards the default export.
    assert!(values(&[
        ("source.js", "export default location.hash;"),
        ("barrel.js", "export * from './source.js';"),
        (
            "sink.js",
            "import payload from './barrel.js'; document.write(payload);"
        ),
    ])
    .is_empty());
}

#[test]
fn reexports_never_invent_a_flow() {
    let sink = "import {payload} from './barrel.js'; document.write(payload);";
    for (source, barrel) in [
        // Missing name, wrong module, bare specifier.
        (VALUE, "export {other as payload} from './source.js';"),
        (VALUE, "export {payload} from './missing.js';"),
        (VALUE, "export {payload} from 'source.js';"),
        // The dependency value is safe.
        (
            "export const payload = 'safe';",
            "export {payload} from './source.js';",
        ),
        (
            "export const payload = 'safe';",
            "export * from './source.js';",
        ),
        // A local export hides a star export of the same name.
        (
            VALUE,
            "export * from './source.js'; export const payload = 'safe';",
        ),
        // A name provided by two different star exports is ambiguous.
        (
            VALUE,
            "export * from './source.js'; export * from './other.js';",
        ),
    ] {
        assert!(
            values(&[
                ("source.js", source),
                ("other.js", "export const payload = location.search;"),
                ("barrel.js", barrel),
                ("sink.js", sink),
            ])
            .is_empty(),
            "{barrel}"
        );
    }
    // Cycles between barrels without a concrete source stay empty.
    assert!(values(&[
        ("a.js", "export * from './b.js';"),
        ("b.js", "export * from './a.js';"),
        (
            "sink.js",
            "import {payload} from './a.js'; document.write(payload);"
        ),
    ])
    .is_empty());
}
