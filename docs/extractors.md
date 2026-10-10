# Extractors & findings

Extraction is pure and synchronous: `webrev-extract` turns already-fetched
content into `Finding`s with no network or filesystem access. The
`ExtractorRegistry` runs every applicable extractor in priority order, and for
HTML inputs it cascades into inline `<script>` bodies so embedded JS is mined
too.

## Finding kinds

| Kind | Meaning | Typical `value` |
| --- | --- | --- |
| `endpoint` | Reachable API / network endpoint | `GET /api/users` |
| `parameter` | Query name, JSON key, or form field (fuzz wordlist) | `userId` |
| `route` | Client-side SPA router path | `/users/:id` |
| `graphql` | Named GraphQL operation | `query CurrentUser` |
| `secret` | Credential, stored as a fingerprint (plaintext only with `--reveal-secrets`) | `fp:1a2b3c…` |
| `sourcemap` | `sourceMappingURL` reference | `app.js.map` |
| `technology` | Framework / BaaS / server fingerprint | `Supabase (baas/db)` |
| `form` | HTML form action + method | `POST /login` |
| `link` | Hyperlink worth noting | `/about` |
| `script` | Referenced script resource (incl. dynamic `import()` specifiers and bundler-manifest chunk paths) | `/static/app.js` |
| `config` | Embedded config constant, feature flag, or web-app-manifest setting | `featureFlag = true` |

Each finding carries a `Confidence` (`low` / `medium` / `high`) and a
`Provenance` (source + optional location).

## The extractor catalog

Listed by descending priority (higher runs first):

| Name | Priority | Applies to | Produces |
| --- | --- | --- | --- |
| `js-ast` | 90 | JS | Endpoints from `fetch`, `axios.*`, `XHR.open`, `new WebSocket/EventSource`, endpoint-shaped string literals, and dynamic `import("…")` specifiers (swc AST). |
| `html` | 80 | HTML | `<script src>`, `<a href>`, `<form>`. |
| `js-regex` | 70 | JS | Endpoint heuristics for minified/unparseable code (`fetch`, `axios`, `XHR`, `/api/*`, `ws(s)://`, absolute URLs). |
| `secret` | 65 | HTML + JS | Known credential shapes + Shannon-entropy tokens → fingerprints. |
| `sourcemap` | 60 | JS | `sourceMappingURL` references. |
| `tech` | 55 | HTML + JS | Technology/framework/BaaS/server fingerprints (body + URL + response headers). |
| `graphql` | 52 | HTML + JS | Named GraphQL operations, plus a flag when a shipped `IntrospectionQuery`/`__schema` signals the endpoint is worth probing manually. |
| `routes` | 50 | HTML + JS | SPA routes (`path: "/…"`, `<Route path>`). |
| `params` | 48 | HTML + JS | Query names, JSON keys, form field names. |
| `config` | 47 | JS | Embedded config objects/constants whose key reads as a flag or setting (`featureFlag`, `DEBUG_MODE`, `apiVersion`, …) bound to a literal (swc AST). |
| `manifest` | 45 | JSON | W3C web app manifests (`start_url`/`scope`/`id`) and build-tool asset manifests (webpack `asset-manifest.json`, Vite `manifest.json`) — surfaces every emitted chunk path, including ones no page links to directly. |

Note: the **fetch stage** (in `webrev-pipeline`) additionally fetches and parses
source maps and re-injects the recovered original sources as JS content, so the
extractors above run over the un-minified code too. It also follows
`<link rel="manifest">` and `navigator.serviceWorker.register(...)` references
so manifests and service workers get crawled even though neither is a
`<script src>` or `<a href>`.

## URL normalization

Endpoints are normalized into route templates before being written to the
`endpoints` table, so instances collapse into routes:

```text
/users/123                              -> /users/{id}
/u/550e8400-e29b-41d4-a716-446655440000 -> /u/{uuid}
/files/deadbeefdeadbeef1234             -> /files/{hash}
/search?q=1                             -> /search
```

Raw findings keep their original URL; only the endpoints side-table is
normalized. See `webrev_core::normalize_url`.

## Secret handling

By default `SecretExtractor` never emits plaintext. Each match is reduced to
`fp:<16 hex>` = the first 64 bits of `HMAC-SHA256(session_key, secret)`, where
the session key is random per run and never persisted. Findings use `url = None`
so deduplication keys on the fingerprint (distinct secrets stay distinct), and
the containing file is recorded in the provenance instead.

The opt-in `--reveal-secrets` flag additionally attaches the plaintext to the
finding (`Finding::plaintext`); the fingerprint stays the `value`, so dedup and
storage keys are unchanged. This is dangerous — real credentials then reach the
database and reports — so it is off by default. See [security.md](security.md).

## Adding an extractor

1. Create `crates/webrev-extract/src/extractors/<name>.rs` implementing the
   `Extractor` trait (`name`, `priority`, `applies_to`, `extract`). Keep it pure
   and return an empty `Vec` rather than erroring on "nothing found".
2. Declare and re-export it in `extractors/mod.rs`.
3. Register it in `ExtractorRegistry::with_defaults` and update the
   `defaults_are_priority_ordered` test.
4. If it introduces a new `FindingKind`, add the variant and its `slug()` in
   `webrev-core`, the reverse mapping in `webrev-storage`'s `parse_kind`, and the
   no-op arm in the store stage.

## Adding a technology signature

Append one row to the `SIGNATURES` table in `extractors/tech.rs`:

```rust
Signature { name: "Your Tech", category: "baas/db", markers: &["yourtech.io", "your-sdk"] },
```

Markers are lowercase substrings matched against `url + headers + body`. Prefer
distinctive host/SDK strings to keep false positives low.
