// crates/webrev-extract/src/extractors/metadata/wasm.rs
//! Recovers the host↔module boundary and endpoint-shaped strings from a
//! fetched WebAssembly binary.
//!
//! This extractor does **not** execute, decompile, or disassemble the
//! module — it only walks the binary's section structure with `wasmparser`
//! (a pure-Rust reader; nothing here instantiates or runs any wasm code) and
//! reads:
//!
//! - the **import section**: `(module, field)` pairs the module expects the
//!   host to provide — the inbound half of the host↔module boundary.
//! - the **export section**: names the module exposes to its host — the
//!   outbound half of that boundary.
//! - the **data section**: literal byte strings baked into the binary (the
//!   wasm analogue of a JS string literal), filtered to endpoint-shaped ones
//!   so this does not degenerate into dumping every byte run.
//!
//! It deliberately does not scan for secrets: that heuristic already exists
//! in [`crate::extractors::secrets`] and is not duplicated here.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use std::collections::BTreeSet;
use wasmparser::{Export, Import, Imports, Parser, Payload};
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// Same shape as the endpoint heuristic used by the JS extractors
/// ([`crate::extractors::endpoints::js_ast`], `ghost`): a URL/`/`-rooted path
/// with no whitespace. Kept narrow so a data section's incidental text
/// (version strings, panic messages, …) does not flood findings.
fn looks_like_endpoint(s: &str) -> bool {
    if s.len() < 6 || s.contains(char::is_whitespace) {
        return false;
    }
    s.starts_with("http://")
        || s.starts_with("https://")
        || s.starts_with("ws://")
        || s.starts_with("wss://")
        || (s.starts_with('/') && !s.starts_with("//") && s.len() > 1)
}

/// Split a data segment's raw bytes into printable ASCII/UTF-8 runs (as a
/// crude "strings"-style scan) and return the ones that look endpoint-shaped.
fn endpoint_strings_in(data: &[u8]) -> Vec<String> {
    let mut found = Vec::new();
    let mut run_start = 0usize;
    let mut in_run = false;
    // A run is a maximal span of printable, non-whitespace-containing ASCII.
    // Splitting on any non-printable byte is enough to isolate embedded
    // literals without needing a real UTF-8 decoder: endpoint-shaped strings
    // are themselves plain ASCII.
    for (i, &b) in data.iter().chain([0u8].iter()).enumerate() {
        let printable = b.is_ascii_graphic() || b == b' ';
        if printable && !in_run {
            run_start = i;
            in_run = true;
        } else if !printable && in_run {
            in_run = false;
            if let Ok(s) = std::str::from_utf8(&data[run_start..i]) {
                if looks_like_endpoint(s) {
                    found.push(s.to_owned());
                }
            }
        }
    }
    found
}

/// Flatten one `Imports` entry (which may bundle several items sharing a
/// module name under the compact-imports encoding) into `(module, name)`
/// pairs.
fn flatten_import(imports: &Imports<'_>) -> Vec<(String, String)> {
    match imports {
        Imports::Single(_, Import { module, name, .. }) => {
            vec![((*module).to_owned(), (*name).to_owned())]
        }
        Imports::Compact1 { module, items } => items
            .clone()
            .into_iter()
            .filter_map(Result::ok)
            .map(|item| ((*module).to_owned(), item.name.to_owned()))
            .collect(),
        Imports::Compact2 { module, names, .. } => names
            .clone()
            .into_iter()
            .filter_map(Result::ok)
            .map(|name| ((*module).to_owned(), (*name).to_owned()))
            .collect(),
    }
}

/// WebAssembly module extractor: import/export metadata and endpoint-shaped
/// data-section strings.
pub struct WasmExtractor;

impl WasmExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for WasmExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for WasmExtractor {
    fn name(&self) -> &'static str {
        "wasm"
    }

    fn priority(&self) -> u8 {
        39
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        input.kind == ContentKind::Wasm && input.bytes.is_some()
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let Some(bytes) = input.bytes.as_deref() else {
            return Vec::new();
        };

        let mut seen = BTreeSet::new();
        let mut findings = Vec::new();

        for payload in Parser::new(0).parse_all(bytes) {
            // Malformed/truncated wasm: stop walking and return whatever was
            // collected so far rather than erroring or panicking.
            let Ok(payload) = payload else { break };
            match payload {
                Payload::ImportSection(reader) => {
                    for imports in reader.into_iter().filter_map(Result::ok) {
                        for (module, name) in flatten_import(&imports) {
                            let value = format!("wasm import: {module}.{name}");
                            if seen.insert(value.clone()) {
                                findings.push(Finding::new(
                                    input.session_id,
                                    FindingKind::Config,
                                    None,
                                    value,
                                    Confidence::Low,
                                    Provenance::new(Source::JsRegex, input.url.clone()),
                                ));
                            }
                        }
                    }
                }
                Payload::ExportSection(reader) => {
                    for Export { name, .. } in reader.into_iter().filter_map(Result::ok) {
                        let value = format!("wasm export: {name}");
                        if seen.insert(value.clone()) {
                            findings.push(Finding::new(
                                input.session_id,
                                FindingKind::Config,
                                None,
                                value,
                                Confidence::Low,
                                Provenance::new(Source::JsRegex, input.url.clone()),
                            ));
                        }
                    }
                }
                Payload::DataSection(reader) => {
                    for data in reader.into_iter().filter_map(Result::ok) {
                        for endpoint in endpoint_strings_in(data.data) {
                            let key = format!("ep|{endpoint}");
                            if seen.insert(key) {
                                findings.push(Finding::new(
                                    input.session_id,
                                    FindingKind::Endpoint,
                                    Some(endpoint.clone()),
                                    format!("GET {endpoint}"),
                                    Confidence::Low,
                                    Provenance::new(Source::JsRegex, input.url.clone()),
                                ));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use webrev_core::SessionId;

    /// LEB128-encode an unsigned integer (section/vector length prefixes are
    /// always small here, but this stays correct for any value).
    fn uleb128(mut value: u32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        out
    }

    fn name_bytes(s: &str) -> Vec<u8> {
        let mut out = uleb128(u32::try_from(s.len()).unwrap());
        out.extend_from_slice(s.as_bytes());
        out
    }

    fn section(id: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![id];
        out.extend(uleb128(u32::try_from(content.len()).unwrap()));
        out.extend_from_slice(content);
        out
    }

    /// Builds a minimal, valid wasm module (hand-rolled bytes, no `wat`
    /// dependency needed) with:
    /// - one import: `env.log` (a function)
    /// - one memory
    /// - one export: `run`, aliasing the imported function
    /// - one data segment containing a non-endpoint string ("hello world",
    ///   contains whitespace) and an endpoint-shaped string (`/api/v1/wasm-endpoint`),
    ///   separated by a NUL byte so they form two distinct printable runs.
    fn build_module() -> Vec<u8> {
        let mut module = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]; // \0asm, version 1

        // Type section: type 0 = () -> ()
        let type_content = [0x01, 0x60, 0x00, 0x00];
        module.extend(section(1, &type_content));

        // Import section: env.log, func, type 0
        let mut import_content = uleb128(1);
        import_content.extend(name_bytes("env"));
        import_content.extend(name_bytes("log"));
        import_content.push(0x00); // kind = func
        import_content.extend(uleb128(0)); // type index
        module.extend(section(2, &import_content));

        // Memory section: one memory, min 1 page, no max
        let mem_content = [0x01, 0x00, 0x01];
        module.extend(section(5, &mem_content));

        // Export section: "run" -> func index 0 (the imported function)
        let mut export_content = uleb128(1);
        export_content.extend(name_bytes("run"));
        export_content.push(0x00); // kind = func
        export_content.extend(uleb128(0)); // index
        module.extend(section(7, &export_content));

        // Data section: one active segment at offset 0 in memory 0.
        let mut data_bytes = b"hello world".to_vec();
        data_bytes.push(0x00);
        data_bytes.extend_from_slice(b"/api/v1/wasm-endpoint");
        let mut data_entry = vec![0x00]; // flags = active, memory index 0
        data_entry.extend([0x41, 0x00, 0x0B]); // i32.const 0; end
        data_entry.extend(uleb128(u32::try_from(data_bytes.len()).unwrap()));
        data_entry.extend(&data_bytes);
        let mut data_content = uleb128(1);
        data_content.extend(data_entry);
        module.extend(section(11, &data_content));

        module
    }

    fn run(bytes: Vec<u8>) -> Vec<Finding> {
        let input = ExtractInput::new(
            SessionId::new(),
            Some("https://t/module.wasm".into()),
            ContentKind::Wasm,
            String::new(),
        )
        .with_bytes(bytes);
        WasmExtractor::new().extract(&input)
    }

    #[test]
    fn reports_import_export_and_endpoint_shaped_data_string() {
        let found = run(build_module());

        assert!(found
            .iter()
            .any(|f| f.kind == FindingKind::Config && f.value == "wasm import: env.log"));
        assert!(found
            .iter()
            .any(|f| f.kind == FindingKind::Config && f.value == "wasm export: run"));
        assert!(found.iter().any(|f| f.kind == FindingKind::Endpoint
            && f.url.as_deref() == Some("/api/v1/wasm-endpoint")
            && f.confidence == Confidence::Low));
    }

    #[test]
    fn does_not_report_non_endpoint_shaped_data_string() {
        let found = run(build_module());
        assert!(
            !found.iter().any(|f| f.value.contains("hello world")),
            "whitespace-containing string must not be reported: {found:?}"
        );
    }

    #[test]
    fn malformed_bytes_returns_empty_not_panic() {
        assert_eq!(run(vec![0xDE, 0xAD, 0xBE, 0xEF]), Vec::new());
        assert_eq!(run(Vec::new()), Vec::new());
    }

    #[test]
    fn dedups_repeated_findings() {
        // Two identical data segments must only yield one endpoint finding.
        let mut module = vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let mem_content = [0x01, 0x00, 0x01];
        module.extend(section(5, &mem_content));

        let one_segment = {
            let mut entry = vec![0x00];
            entry.extend([0x41, 0x00, 0x0B]);
            let data = b"/api/v1/dup".to_vec();
            entry.extend(uleb128(u32::try_from(data.len()).unwrap()));
            entry.extend(&data);
            entry
        };
        let mut data_content = uleb128(2);
        data_content.extend(one_segment.clone());
        data_content.extend(one_segment);
        module.extend(section(11, &data_content));

        let found = run(module);
        let endpoint_count = found
            .iter()
            .filter(|f| f.kind == FindingKind::Endpoint)
            .count();
        assert_eq!(
            endpoint_count, 1,
            "duplicate data strings must dedup: {found:?}"
        );
    }

    #[test]
    fn applies_only_to_wasm_with_bytes() {
        let extractor = WasmExtractor::new();
        let no_bytes = ExtractInput::new(SessionId::new(), None, ContentKind::Wasm, String::new());
        assert!(!extractor.applies_to(&no_bytes));
        assert_eq!(extractor.extract(&no_bytes), Vec::new());

        let wrong_kind = ExtractInput::new(SessionId::new(), None, ContentKind::JavaScript, "x")
            .with_bytes(vec![1, 2, 3]);
        assert!(!extractor.applies_to(&wrong_kind));
    }
}
