# Fuzzing

webrev parses JavaScript, HTML, JSON and WebAssembly that an attacker controls,
and it redacts secrets before anything is logged or reported. Both are worth
feeding garbage. The harness lives in `fuzz/` (cargo-fuzz, libFuzzer, nightly
Rust) and is its own Cargo workspace, so it never touches the product build or
the stable-toolchain CI.

## Targets

| Target | What it feeds | Properties checked |
|---|---|---|
| `extract_registry` | First byte picks HTML / JavaScript / JSON / WebAssembly, the rest is the body, through every default extractor (`ExtractorRegistry::run`, including the inline-script cascade) | No panic, no hang (10 s), no more than 2 GiB RSS |
| `domsinks_modules` | Up to 16 modules separated by `//@@` lines, served at `https://fuzz.test/m<i>.js`, through `retain_module_input` and `extract_modules` (namespace imports, re-exports, function summaries) | Same, plus: a static module candidate is never `Confirmed` |
| `redaction` | Arbitrary text through `redact_url`, `Sanitizer::scrub` and `scrub_header`, then known secrets (JWT, AWS key id, `api_key=`, `session:`, URL userinfo / `tok=` / `password=` / `id_token=`) embedded in that text | No panic, and none of the known secrets survives in the output |
| `report_redaction` | Arbitrary text planted in a report's mission name, seeds, finding value / justification / probe evidence, endpoints and a JSON document, with known secrets embedded, rendered in all eight export formats (`SessionReport::render`) | No panic, and none of the known secrets survives in any format (the report holds no secret finding, whose plaintext is kept on purpose) |

Seeds are in `fuzz/corpus/<target>/`. Each reproducer found by fuzzing is added
there as a regression seed.

## Running

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked --version 0.13.2

# from the repository root; the first build compiles swc and is slow
cargo +nightly fuzz build -s none
cargo +nightly fuzz run -s none redaction -- -max_total_time=120 -timeout=10 -rss_limit_mb=2048
```

`-s none` skips AddressSanitizer: the code is safe Rust, so the useful
failures are panics, debug assertions, overflows, hangs and memory growth, and
the build is much cheaper. Debug assertions stay on (cargo-fuzz default). To
keep the repository clean, point libFuzzer at a scratch corpus copy:
`cargo +nightly fuzz run -s none <target> /path/to/scratch-corpus`.
Crashing inputs land in `fuzz/artifacts/<target>/` (git-ignored). Shrink one
with `cargo +nightly fuzz tmin -s none <target> <file>`.

## CI

`.github/workflows/fuzz.yml` runs each target for 180 s (input `seconds` for a
manual run) every Monday and on `workflow_dispatch`. It is **not** part of the
`ci` gate: a crash uploads the failing input as an artifact and turns only that
workflow red.

## Findings so far (2026-10-18)

Local runs of 240 s per target, `-s none`, `-timeout=10`, `-rss_limit_mb=2048`:

| Target | Run | Executions | Result |
|---|---|---:|---|
| `redaction` | 240 s | 249,799 | Clean |
| `extract_registry` | 240 s | 76,205 | Clean (the crash below was not reached in this run) |
| `domsinks_modules` | 240 s | stopped early | **Crash**, see below |
| `domsinks_modules` | 180 s, after the fix | 82,458 | Clean |
| `extract_registry` | 180 s, after the fix | 1,608,991 | Clean |
| `redaction` | GitHub run 39166754778, 180 s | – | **Leak**, JWT in a path segment, see below |
| `redaction` | 300 s, after the path fix (2026-10-19) | 2,718,737 | Clean |

The second `extract_registry` run executed twenty times more inputs than the
first; the fuzzer's path through the corpus differs between runs and I did not
investigate why.

These are minutes of fuzzing, not a clean bill of health. Coverage of the
extractors is far from saturated; the scheduled job is there to keep going.

### `redact_url` leaked a JWT in a path segment (GitHub run 39166754778)

The first scheduled-workflow run on GitHub (180 s per target, triggered
manually on `main`) failed the `redaction` target: the fuzzer pulled the JWT
canary out of the comparison dictionary and placed it in the input-controlled
path, `https://user:…@host.test/ht<JWT>…?tok=…`. `redact_url` masked userinfo,
query and fragment but never looked at path segments. Fixed by analysing path
segments (see `docs/security.md`, « Suivi : trous de redaction et fuzzing »);
the input is the seed `corpus/redaction/jwt-in-path-segment` and the unit test
`masks_a_secret_glued_to_padding`.

### swc lexer assertion on hostile JavaScript

A 17-byte input is enough: `import"` newline `=======` newline `/`. swc
(`swc_ecma_parser` 46.1.1, `lexer/mod.rs`, `read_regexp`) trips
`debug_assert_eq!(self.cur(), Some(b'/'))` after an unterminated string
literal: it is positioned on `=` (61) instead of `/` (47). Valid regex literals
such as `/=/.test(x)` do not trigger it.

- Reachable through every extractor that parses JavaScript (`js-ast`, `ghost`,
  `config`, `dom-sinks`, and the cross-module pass), not only `dom-sinks`.
- In builds with debug assertions (`cargo test`, plain `cargo run`) the panic
  unwinds out of the extractor. The release profile does not enable debug
  assertions, so the assertion is compiled out there; what swc then does with
  the lexer in the wrong position was **not** measured.
- Fix: all five swc call sites now go through `crate::js_parse::guarded`, which
  turns a panic into "unparseable" so the existing fallbacks (including the regex
  extractor) still run. Regression test:
  `registry::tests::lexer_assertion_input_is_contained`, plus
  `fuzz/corpus/*/regression_swc_regexp_assert`.
- The panic message is still written to stderr by the default panic hook.
- libFuzzer's own panic hook aborts on every panic, even a contained one, so
  the `extract_registry` and `domsinks_modules` targets install a silent hook.
  A panic that escapes the extractors still unwinds out of the target and
  aborts the fuzzer.
- The root cause is upstream. Not reported to swc from here.

## Not covered

HTML parsing by `lol_html` is only reached through `extract_registry`; the TUI,
the HTTP/CDP transport and the report writers are not fuzzed. The `wasm`
extractor gets raw bytes from `extract_registry` only. There is no
differential or grammar-based JavaScript generator, so deep taint paths in
`domsinks` depend on the corpus seeds.

### Object identifiers are not canaries

The redaction targets plant credential-shaped canaries (`Zk3J…`, an AWS key, a
JWT). Since 2026-10-19 a UUID, a number or a short hex id is deliberately *not*
masked (see `docs/security.md`, « Suivi : identifiants d'objets lisibles »), so
none of those shapes may be used as a canary: the property "the known secret
never survives" would fail on correct output. The unit tests in
`security/sanitize/url.rs` pin the id side of the contract; the fuzz targets pin
the credential side.
