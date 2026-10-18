use super::*;
use webrev_core::SessionId;

fn run(js: &str) -> Vec<Finding> {
    let input = ExtractInput::new(
        SessionId::new(),
        Some("https://t/app.js".into()),
        ContentKind::JavaScript,
        js,
    );
    DomSinkExtractor::new().extract(&input)
}

fn find_value<'a>(found: &'a [Finding], needle: &str) -> Option<&'a Finding> {
    found.iter().find(|f| f.value.contains(needle))
}

#[test]
fn patterns_compile() {
    let _ = DomSinkExtractor::new();
}

#[test]
fn taint_ast_prefilter_requires_both_source_and_sink_hints() {
    let extractor = DomSinkExtractor::new();
    assert!(should_run_taint_ast(
        "const input = location.hash; node.innerHTML = input;",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
    assert!(should_run_taint_ast(
        "window.addEventListener('message', e => { node.innerHTML = e.data; });",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
    assert!(should_run_taint_ast(
        "addEventListener('message', e => { node.innerHTML = e.data; });",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
    assert!(should_run_taint_ast(
        "onmessage = e => { node.innerHTML = e.data; };",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
    assert!(!should_run_taint_ast(
        "const count = items.length; node.innerHTML = '<b>static</b>';",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
    assert!(!should_run_taint_ast(
        "const input = location.hash; render(input);",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
}

#[test]
fn taint_ast_prefilter_is_case_insensitive_and_does_not_change_fallback_leads() {
    let extractor = DomSinkExtractor::new();
    assert!(should_run_taint_ast(
        "const value = DOCUMENT.COOKIE; node.INNERHTML = value;",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
    assert!(should_run_taint_ast(
        "const source = document . cookie; window . location . href = source;",
        &extractor.message,
        &extractor.navigation_sink_hint
    ));
    let found = run("node.innerHTML = userInput;");
    assert!(find_value(&found, "dom sink (unverified source)").is_some());
}

#[test]
fn traces_direct_source_to_sink_as_high() {
    let found = run("el.innerHTML = location.hash;");
    let f =
        find_value(&found, "DOM XSS: location.hash -> el.innerHTML").expect("traced flow finding");
    assert_eq!(f.confidence, Confidence::High);
    assert_eq!(f.kind, FindingKind::Config);
    assert_eq!(f.provenance.source, Source::JsAst);
    // The regex lead for this sink is suppressed by the traced span.
    assert!(!found
        .iter()
        .any(|f| f.value.contains("dom sink (unverified source)")));
}

#[test]
fn traces_variable_assignment_as_medium() {
    let js = "const dirty = location.search; el.innerHTML = dirty;";
    let found = run(js);
    let f = find_value(&found, "DOM XSS: location.search -> el.innerHTML")
        .expect("traced flow via variable");
    assert_eq!(f.confidence, Confidence::Medium);
    assert_eq!(f.provenance.source, Source::JsAst);
}

#[test]
fn traces_concatenation_as_medium() {
    let found = run(r#"document.write("<h1>" + document.cookie + "</h1>");"#);
    let f = find_value(&found, "DOM XSS: document.cookie -> document.write")
        .expect("traced flow via concat");
    assert_eq!(f.confidence, Confidence::Medium);
}

#[test]
fn traces_decoder_and_method_chain() {
    let found = run("el.innerHTML = decodeURIComponent(location.hash.slice(1));");
    let f = find_value(
        &found,
        "DOM XSS: location.hash -> slice -> decodeURIComponent -> el.innerHTML",
    )
    .expect("decoder/method chain preserves taint");
    assert_eq!(f.confidence, Confidence::Medium);
}

#[test]
fn numeric_and_boolean_string_methods_break_string_taint() {
    let found = run(
        r#"const input = location.href.substring(1); const index = input.search(/f(oo*)/g); if (index >= 0) document.write("found " + index);"#,
    );
    assert!(
        !found.iter().any(|f| f.value.starts_with("DOM XSS:")),
        "numeric search result must not be treated as tainted markup: {found:?}"
    );

    let length = run("el.innerHTML = String(location.hash.length);");
    assert!(
        !length.iter().any(|f| f.value.starts_with("DOM XSS:")),
        "numeric length property must not be treated as tainted markup: {length:?}"
    );
}

#[test]
fn traces_dynamic_event_handler_attribute_sinks() {
    let found = run(
        r#"node.setAttribute("onclick", location.search.substring(1)); node.onmouseover = location.hash;"#,
    );
    assert!(find_value(
        &found,
        "DOM XSS: location.search -> substring -> setAttribute(onclick)"
    )
    .is_some(), "findings: {found:?}");
    assert!(find_value(
        &found,
        "DOM XSS: location.hash -> event handler onmouseover"
    )
    .is_some());
}

#[test]
fn ignores_non_event_setattribute_names_as_sinks() {
    let found = run(r#"node.setAttribute("class", location.search);"#);
    assert!(!found.iter().any(|f| f.value.starts_with("DOM XSS:")));
}

#[test]
fn traces_eval_and_new_function_and_insert_adjacent() {
    let js = r"
            eval(location.hash);
            const f = new Function(location.search);
            node.insertAdjacentHTML('beforeend', document.referrer);
        ";
    let found = run(js);
    assert!(find_value(&found, "DOM XSS: location.hash -> eval").is_some());
    assert!(find_value(&found, "DOM XSS: location.search -> new Function").is_some());
    assert!(
        find_value(&found, "-> node.insertAdjacentHTML").is_some(),
        "insertAdjacentHTML flow, got {:?}",
        found.iter().map(|f| &f.value).collect::<Vec<_>>()
    );
}

#[test]
fn traces_location_navigation_sink() {
    let found = run("window.location.href = location.hash;");
    let f = find_value(&found, "DOM XSS: location.hash -> location.href")
        .expect("navigation sink flow");
    assert_eq!(f.confidence, Confidence::High);
}

#[test]
fn traces_dangerously_set_inner_html() {
    let js = "const x = location.hash; const r = <div dangerouslySetInnerHTML={{__html: x}} />;";
    let found = run(js);
    let f = find_value(&found, "DOM XSS: location.hash -> dangerouslySetInnerHTML")
        .expect("React sink flow");
    assert_eq!(f.confidence, Confidence::Medium);
    assert_eq!(f.provenance.source, Source::JsAst);
}

#[test]
fn traces_postmessage_handler_param() {
    let js = "window.addEventListener('message', function (e) { el.innerHTML = e.data; });";
    let found = run(js);
    let f = find_value(&found, "DOM XSS: event.data -> el.innerHTML")
        .expect("postMessage data flows to sink");
    assert_eq!(f.confidence, Confidence::Medium);
    // The receiver itself is still flagged (no origin check).
    assert!(found
        .iter()
        .any(|f| f.value.starts_with("postMessage receiver (no origin check")));
}

#[test]
fn traces_global_message_listener_and_onmessage_with_transformations() {
    let listener =
        run("addEventListener('message', e => { node.innerHTML = decodeURIComponent(e.data); });");
    assert!(find_value(
        &listener,
        "DOM XSS: event.data -> decodeURIComponent -> node.innerHTML"
    )
    .is_some());

    let property = run("onmessage = e => { node.innerHTML = e.data; };");
    assert!(find_value(&property, "DOM XSS: event.data -> node.innerHTML").is_some());
}

#[test]
fn constant_sink_is_only_a_low_lead_never_traced() {
    let found = run(r#"el.innerHTML = "<b>constant</b>";"#);
    // No traced path.
    assert!(!found.iter().any(|f| f.value.starts_with("DOM XSS:")));
    assert!(found.iter().all(|f| f.confidence != Confidence::High));
    // A Low unverified lead keeps recall.
    let lead = find_value(&found, "dom sink (unverified source)").expect("low lead");
    assert_eq!(lead.confidence, Confidence::Low);
    assert_eq!(lead.provenance.source, Source::JsRegex);
}

#[test]
fn untraced_sink_with_unknown_variable_is_low_lead() {
    // `userInput` has no tainted origin: a lead, not a traced path.
    let found = run("el.innerHTML = userInput;");
    assert!(!found.iter().any(|f| f.value.starts_with("DOM XSS:")));
    assert!(find_value(&found, "dom sink (unverified source)").is_some());
}

#[test]
fn sanitizer_breaks_html_taint_and_transformations_are_traced() {
    let safe = run("el.innerHTML = DOMPurify.sanitize(location.hash);");
    assert!(
        safe.is_empty(),
        "sanitized flow should not create an XSS lead: {safe:?}"
    );
    let unsafe_flow = run("el.innerHTML = decodeURIComponent(location.hash);");
    assert!(unsafe_flow.iter().any(|f| f
        .value
        .contains("location.hash -> decodeURIComponent -> el.innerHTML")));
}

#[test]
fn detects_wasm() {
    let js = r#"fetch("/app.wasm"); WebAssembly.instantiateStreaming(resp);"#;
    let found = run(js);
    assert!(find_value(&found, "WebAssembly module reference").is_some());
    assert!(find_value(&found, "WebAssembly instantiation").is_some());
}

#[test]
fn postmessage_without_origin_is_medium() {
    let js = r"window.addEventListener('message', function (e) { handle(e.data); });";
    let found = run(js);
    let f = found
        .iter()
        .find(|f| f.value.starts_with("postMessage receiver"))
        .expect("postMessage finding");
    assert_eq!(f.confidence, Confidence::Medium);
    assert!(f.value.contains("no origin check"));
}

#[test]
fn postmessage_with_origin_is_low() {
    let js = r"window.addEventListener('message', function (e) { if (e.origin !== OK) return; handle(e.data); });";
    let found = run(js);
    let f = found
        .iter()
        .find(|f| f.value.starts_with("postMessage receiver"))
        .expect("postMessage finding");
    assert_eq!(f.confidence, Confidence::Low);
}

#[test]
fn negative_and_dedup() {
    // No sinks here.
    assert_eq!(run("const total = a + b; renderSafely(total);"), Vec::new());
    // Two identical traced sinks collapse to one finding.
    let js = "a.innerHTML = location.hash;\na.innerHTML = location.hash;";
    assert_eq!(run(js).len(), 1);
}

#[test]
fn unparseable_returns_empty_not_error() {
    assert_eq!(run("function (() {{{ <<< "), Vec::new());
}

fn traced(js: &str) -> Vec<String> {
    run(js)
        .into_iter()
        .map(|f| f.value)
        .filter(|value| value.starts_with("DOM XSS"))
        .collect()
}

#[test]
fn local_function_parameter_and_return_flows_are_traced() {
    let found = run("function show(x) { document.body.innerHTML = x; }\nshow(location.hash);");
    let flow = find_value(&found, "DOM XSS: location.hash -> document.body.innerHTML")
        .expect("argument flows into the local sink");
    assert_eq!(flow.confidence, Confidence::Medium);
    assert_eq!(
        traced("function get() { return location.hash; }\ndocument.write(get());"),
        ["DOM XSS: location.hash -> document.write"]
    );
    assert_eq!(
        traced("function show(a, b) { document.write(b); }\nshow('x', location.search);"),
        ["DOM XSS: location.search -> document.write"]
    );
}

#[test]
fn local_function_flows_respect_arguments_shadowing_and_sanitizers() {
    for js in [
        // Safe argument, tainted argument in the wrong position, sanitizer in the callee.
        "function show(x) { document.body.innerHTML = x; }\nshow('safe');",
        "function show(a, b) { document.body.innerHTML = b; }\nshow(location.hash, 'x');",
        "function show(x) { el.innerHTML = DOMPurify.sanitize(x); }\nshow(location.hash);",
        // The callee name is rebound, a parameter, or redeclared in a nested scope.
        "function show(x) { el.innerHTML = x; }\nshow = safeShow;\nshow(location.hash);",
        "function show(x) { el.innerHTML = x; }\nfunction run(show) { show(location.hash); }",
        "function show(x) { el.innerHTML = x; }\nfunction run() { function show(y) { log(y); } show(location.hash); }",
        // A helper that never reaches a sink or returns a tainted value.
        "function show(x) { log(x); }\nel.innerHTML = 'a'; show(location.hash);",
        "function get() { return 'a'; }\ndocument.write(get());",
    ] {
        assert!(traced(js).is_empty(), "{js}: {:?}", traced(js));
    }
}

#[test]
fn closures_and_arrow_helpers_are_still_not_followed() {
    for js in [
        "const show = x => { document.body.innerHTML = x; };\nshow(location.hash);",
        "const show = function (x) { document.body.innerHTML = x; };\nshow(location.hash);",
    ] {
        assert!(traced(js).is_empty(), "{js}");
    }
}
