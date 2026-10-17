# Reliability examples (synthetic fixtures)

These snippets illustrate the behavior measured by
`crates/webrev-extract/tests/reliability_benchmark.rs`. They are not output
from a production scan.

| Input | Before | After |
| --- | --- | --- |
| `const svg = 'https://www.w3.org/2000/svg';` | Static string reported as an endpoint by the AST walker | Low-confidence static URL candidate; not inserted as a network endpoint |
| `const state = {'internalFlag': true};` | `internalFlag` emitted as an HTTP parameter | No parameter finding; no request transport is present |
| `<div id='Rj8Kpz2Wqf4Lm9Xv7Tb3Nc6Hy1Qs5Ad'>` | Opaque ID emitted as a secret candidate | Excluded as HTML identity attribute |
| `target.innerHTML = DOMPurify.sanitize(location.hash);` | Sink-only lead despite an explicit sanitizer call | No DOM XSS sink lead |
| `target.innerHTML = location.hash;` | Source and sink recognized | `Suspicious` static flow, with `location.hash → innerHTML`; it is not a confirmed vulnerability |
| `GET /callback?redirect_uri=https://...` returning a different status | Possible SSRF sink | No SSRF finding from the status difference; open-redirect check remains separate |

Old text reports did not contain status or evidence score. New reports show
those fields with detector provenance and active request/response observations
when available. Findings without a dynamic proof remain `observed` or
`suspicious`; the scanner does not label them `confirmed`.
