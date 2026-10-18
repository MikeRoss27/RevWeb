// crates/webrev-extract/src/extractors/metadata/domsinks/sinks.rs
//! Sink catalogue: regex fallback patterns, AST gate hints, and sink labels.

use super::sources::global_tail;

/// Generic sink patterns for the regex fallback: `(regex, label)`. All are
/// emitted at `Low` confidence as "unverified source" leads unless the taint
/// pass already traced a source into them.
pub(super) const FALLBACK_SINK_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?i)\.innerhtml\s*=[^=]",
        "innerHTML assignment (DOM-XSS sink)",
    ),
    (
        r"(?i)\.outerhtml\s*=[^=]",
        "outerHTML assignment (DOM-XSS sink)",
    ),
    (r"(?i)document\.write(?:ln)?\s*\(", "document.write() sink"),
    (r"\beval\s*\(", "eval() sink"),
    (
        r"(?i)\.insertadjacenthtml\s*\(",
        "insertAdjacentHTML() sink",
    ),
    (r"\bnew\s+Function\s*\(", "new Function() sink"),
    (
        r"dangerouslySetInnerHTML",
        "React dangerouslySetInnerHTML sink",
    ),
    (
        r"(?i)location\.href\s*=[^=]",
        "location.href assignment (navigation sink)",
    ),
];

/// WebAssembly reference patterns, reported as-is at `Low`.
pub(super) const WASM_PATTERNS: &[(&str, &str)] = &[
    (
        r"(?i)WebAssembly\.(?:instantiatestreaming|instantiate|compilestreaming|compile)",
        "WebAssembly instantiation",
    ),
    (r"(?i)[\w./\-]+\.wasm\b", "WebAssembly module reference"),
];

pub(super) const TAINT_SINK_HINTS: &[&str] = &[
    "innerhtml",
    "outerhtml",
    "write",
    "eval",
    "new function",
    "insertadjacenthtml",
    "setattribute",
    "dangerouslysetinnerhtml",
    "__html",
];

pub(super) const NAVIGATION_SINK_HINT: &str =
    r"(?i)\b(?:(?:window|self)\s*\.\s*)?location(?:\s*\.\s*href)?\s*=";

/// String methods whose results cannot carry attacker-controlled markup or
/// code: they return only a number or boolean. Keeping these out of string
/// sinks prevents index/predicate values from being mistaken for tainted text.
pub(super) const NON_STRING_RESULT_CALLS: &[&str] = &[
    "charCodeAt",
    "codePointAt",
    "indexOf",
    "lastIndexOf",
    "localeCompare",
    "search",
    "includes",
    "startsWith",
    "endsWith",
];

/// HTML event-handler attributes execute their string value as JavaScript.
pub(super) fn is_event_handler_attribute(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "onabort"
            | "onanimationend"
            | "onanimationiteration"
            | "onanimationstart"
            | "onauxclick"
            | "onbeforeinput"
            | "onbeforeunload"
            | "onblur"
            | "onchange"
            | "onclick"
            | "oncontextmenu"
            | "oncopy"
            | "oncut"
            | "ondblclick"
            | "ondrag"
            | "ondragend"
            | "ondragenter"
            | "ondragleave"
            | "ondragover"
            | "ondragstart"
            | "ondrop"
            | "onerror"
            | "onfocus"
            | "oninput"
            | "oninvalid"
            | "onkeydown"
            | "onkeypress"
            | "onkeyup"
            | "onload"
            | "onmousedown"
            | "onmouseenter"
            | "onmouseleave"
            | "onmousemove"
            | "onmouseout"
            | "onmouseover"
            | "onmouseup"
            | "onpaste"
            | "onreset"
            | "onresize"
            | "onscroll"
            | "onselect"
            | "onsubmit"
            | "ontoggle"
            | "ontransitionend"
    )
}

/// Canonical sink label for an assignment to a navigation target, or `None`.
pub(super) fn nav_sink(path: &str) -> Option<&'static str> {
    match global_tail(path) {
        "location" => Some("location"),
        "location.href" => Some("location.href"),
        _ => None,
    }
}
