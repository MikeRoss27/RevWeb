# OWASP Juice Shop v19.0.0 external detector probe

Status: **exploratory project-level probe**, not a precision/recall benchmark.
This source project is held out from Webrev's maintainer-authored fixtures, but
the candidate has been inspected while constructing these cases. It is not a
blind evaluation, and the labels were not independently adjudicated. The only
scorable cases are positive browser application behaviors with explicit source
and official challenge evidence. There are no defensible negative labels or
secret ground-truth cases in this slice, so precision and false-positive rate
are not measurable.

## Identity and license

- Project: [OWASP Juice Shop](https://github.com/juice-shop/juice-shop)
- Release tag: [`v19.0.0`](https://github.com/juice-shop/juice-shop/tree/v19.0.0)
- Pinned source commit: `36870cbbdfe7864698e1adf644c7bf772f67ebb7`
- Tag object: `91a4da2909c00e766574b447003c60b1b4d1cb66`
- Commit date: 2025-09-02
- License: MIT, as stated by upstream `LICENSE`; file excerpts are attributed
  to OWASP Juice Shop contributors. No full upstream files are redistributed.
- Official DOM XSS challenge record: `data/static/challenges.yml`, case name
  `DOM XSS`, with the payload `<iframe src="javascript:alert(`xss`)">`.
- Official guided challenge: `frontend/src/hacking-instructor/challenges/domXss.ts`.
  It instructs the user to enter a payload into Search, observes markup in the
  rendered page, and states that the payload reaches the frontend without
  being sent to the server.
- Vulnerable application code: `frontend/src/app/search-result/`.
  `search-result.component.ts` reads `this.route.snapshot.queryParams.q`, passes
  the value through `bypassSecurityTrustHtml`, and stores it in `searchValue`;
  the companion template binds `searchValue` to `[innerHTML]`.
- Request/parameter case: `frontend/src/app/Services/product.service.ts`,
  `search(criteria)` issues Angular `HttpClient.get` to
  `` `${this.hostServer}/rest/products/search?q=${criteria}` ``.

`cases.jsonl` records the source paths, exact or minimally normalized excerpt,
label rationale, and official challenge/source provenance. The DOM case spans
the TypeScript component and its Angular HTML template. Its TypeScript type
annotation is removed in the excerpt solely to make the expression parseable
as JavaScript; the dataflow and sink binding are unchanged. The endpoint and
parameter excerpts retain only the `HttpClient.get` expression from the
TypeScript method, omitting its RxJS `.pipe(map((response: any) => ...))` tail
so the ES-only AST parser receives a valid JavaScript method-body fragment.
The runner wraps a leading `return` in a synthetic function body. This checks
request-call recognition, but it does not test parsing of a full `.ts` file.

## Run

```sh
cargo test -p webrev-extract --test juice_shop_external -- --nocapture
```

The test feeds the documented excerpts to the current extractors and prints
TP/FP/FN/TN per detector. It does not alter detector behavior and it does not
gate on accuracy. The DOM case is scored at project level: an extractor signal
from any listed source file would count as a hit. This intentionally exposes
the current lack of Angular template binding support. Endpoints and parameters
are scored from a request-containing frontend source excerpt.

## Measured run and initial blocker

Command: `cargo test -p webrev-extract --test juice_shop_external -- --nocapture`.
The first invocation compiled the runner but `DomSinkExtractor` panicked while
compiling the existing `NAVIGATION_SINK_HINT`: Rust's `regex` crate rejects
its `(?!=)` lookahead. The root agent corrected that expression in the shared
detector; I did not edit it. The initial diagnostic run missed all four
positives. Generic Angular `HttpClient` support was then added to the endpoint
AST, endpoint regex, and HTTP parameter extractors. The latest run on the
normalized request excerpts reports:

| Detector | TP | FP | FN | TN | Recall | Observation |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| AST endpoint | 1 | 0 | 0 | 0 | 100% | Recognizes `this.http.get` and the static route in a template URL. |
| Regex endpoint | 1 | 0 | 0 | 0 | 100% | Recognizes the `http.<verb>` template call and retains its static route prefix. |
| HTTP parameter | 1 | 0 | 0 | 0 | 100% | Extracts `q` from the Angular `HttpClient` template URL. |
| DOM source-to-sink | 0 | 0 | 1 | 0 | 0% | Route query → `bypassSecurityTrustHtml` → Angular `[innerHTML]` spans TypeScript and template files, which the JS-only flow extractor does not join. |

There are no negative cases in this external slice; precision and false
positive rate are `n/a`. The latest run result was 4 cases, 1 false negative,
and the test process succeeded because this is a diagnostic runner, not an
accuracy gate. The initial 4/4 misses remain the baseline observation; the
current result is scoped to normalized request excerpts. These observations are
exploratory only and do not estimate performance on other frontend frameworks
or applications.

## Scope and limitations

This one Angular application is useful as an external compatibility probe. It
cannot estimate general Webrev performance. It provides a documented DOM XSS
positive and a documented frontend API request with a query parameter. It does
not provide adequate cases for negatives, secrets, or broad endpoint
extraction. The service's Angular `HttpClient` syntax was outside the original
`fetch`/Axios/XHR endpoint-recognition patterns; the normalized probe now
exercises generic `http.<verb>` recognition. Because the parser accepts
ECMAScript and the upstream file is TypeScript, the probe does not establish
full-file TypeScript compatibility. DOM source and sink cross a TypeScript
component and Angular template, which the current JS-only flow extractor does
not join. Keep this artifact exploratory and separate from v1's aggregate
metrics.

## Attribution

Excerpts are from OWASP Juice Shop, Copyright (c) 2014-2025 Bjoern Kimminich
and the OWASP Juice Shop contributors, licensed under the MIT License. The
upstream license text is available in the pinned repository at
[`LICENSE`](https://github.com/juice-shop/juice-shop/blob/36870cbbdfe7864698e1adf644c7bf772f67ebb7/LICENSE).
