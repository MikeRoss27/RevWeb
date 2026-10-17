# VulnerableApp open redirect slice — 2026-10-16

## Scope and reproducibility

This is a focused detector benchmark against OWASP VulnerableApp source commit
`8003daf8e13044802fdeb4b665f0c9cc6d09096b`. Container images are pinned by
digest in `compose.override.yml`. The stack runs on an internal Docker network;
only loopback host ports are published. Webrev scans the facade's private
container IP as its sole scope entry.

The fixed 12-route set contains all nine `UNSECURE`
`OPEN_REDIRECT_3XX_STATUS_CODE` routes, secure levels 11 and 12, and level 8 as
a manual negative control. Each route starts with same-origin `returnTo`. The
active redirect check tries up to five randomized `.invalid` values:
absolute HTTPS, protocol-relative, authority-prefix, tab-prefixed
protocol-relative, and backslash separator forms. A result is reported only
when a 3xx `Location`, resolved against the response URL, points to the exact
randomized `.invalid` host and nonce path. Redirects are never followed.

The before and after runs used the same pinned lab, route set, one concurrent
request, 50 ms delay, and a 160-active-request global cap. The previous single
absolute-URL probe used 146 requests. The revised 12-route batch used all 160
allowed requests and executed 11 open-redirect checks before the shared cap
stopped the scan. It covered all nine labeled vulnerable routes, level 8's
manual control, and refused level 11; secure level 12 was checked separately
with a one-route active run (25 requests, one executed negative redirect
check). Reproduction and teardown commands:

```bash
git clone https://github.com/SasanLabs/VulnerableApp.git /tmp/owasp-vulnerableapp
git -C /tmp/owasp-vulnerableapp checkout 8003daf8e13044802fdeb4b665f0c9cc6d09096b
docker compose -p webrev-vapp-bench \
  -f /tmp/owasp-vulnerableapp/docker-compose.without_llm.yml \
  -f "$PWD/benchmarks/vulnerableapp/2026-10-16/open-redirect/compose.override.yml" \
  up -d --wait --wait-timeout 180
LAB=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
  webrev-vapp-bench-VulnerableApp-facade-1)
seeds=()
for level in 1 2 3 4 5 6 7 8 9 10 11 12; do
  seeds+=(--seed "http://${LAB}/VulnerableApp/Http3xxStatusCodeBasedInjection/LEVEL_${level}?returnTo=http%3A%2F%2F${LAB}%2F")
done
cargo run -p webrev-cli -- scan "${seeds[@]}" \
  --scope "$LAB" --max-pages 12 --max-depth 0 --max-concurrency 1 \
  --max-active-requests 160 --delay-min-ms 50 --delay-max-ms 50 \
  --active --report webrev-report.json --no-banner
level12="http://${LAB}/VulnerableApp/Http3xxStatusCodeBasedInjection/LEVEL_12?returnTo=http%3A%2F%2F${LAB}%2F"
cargo run -p webrev-cli -- scan --seed "$level12" \
  --scope "$LAB" --max-pages 1 --max-depth 0 --max-concurrency 1 \
  --max-active-requests 160 --delay-min-ms 50 --delay-max-ms 50 \
  --active --report control-level12-report.json --no-banner
python3 scripts/vulnerableapp_adapter.py webrev-report.json \
  --output comparator-input.json
curl -sS -H 'Content-Type: application/json' \
  --data-binary @comparator-input.json \
  "http://${LAB}/VulnerableApp/scanner/benchmark" -o comparator-result.json
docker compose -p webrev-vapp-bench \
  -f /tmp/owasp-vulnerableapp/docker-compose.without_llm.yml \
  -f "$PWD/benchmarks/vulnerableapp/2026-10-16/open-redirect/compose.override.yml" \
  down -v
```

## Results

| Metric | Before | After |
| --- | ---: | ---: |
| Active requests used | 146 | 160 batch + 25 supplemental control |
| True positives | 3 | 8 |
| False negatives | 6 | 1 |
| False positives | 0 | 0 |
| True negatives | 1 | 1 |
| Refused secure cases | 1 | 1 |
| Precision | 100% (3/3) | 100% (8/8) |
| Recall | 33.3% (3/9) | 88.9% (8/9) |
| False positive rate | 0% (0/1) | 0% (0/1) |
| False negative rate | 66.7% (6/9) | 11.1% (1/9) |

New findings are levels 2, 3, 4, 5 and 6, in addition to levels 1, 9 and 10.
The level 3/4 tab-prefixed payload resolves to a protocol-relative external
destination. Level 5 returns `\/host`; browser URL parsing treats the
backslash as a slash and resolves the external host. At level 6, the app
prefixes its authority before injected `@host`, which also resolves externally.
Chromium 154 verified these URL resolutions offline without navigation;
`browser-normalization.json` records exact inputs and outputs. The documented
`/%09/host` level 3/4 payload stays same-origin. Level 7's app-prefixed
backslash form also stays same-origin, so level 7 remains a benchmark miss.

The category confusion matrix includes nine labeled vulnerable cases and two
labeled secure controls. One secure control returned HTTP 403 and is counted as
refused; the supplemental active check made level 12 the single TN. Level 8
has no DAST ground-truth row and is excluded. The full VulnerableApp comparator
scored 8/168 expected rows detected (160 missed, 0 unmatched; 4.7619%); 159
misses concern types outside this focused run, with level 7 the remaining
open-redirect miss. These are small single-lab measurements, not a production
accuracy claim.

## Artifacts

- `baseline/` preserves the previous one-payload run and its checksums.
- `metadata.json` records the pinned inputs, run controls, coverage and paired
  measurements.
- `case-matrix.json` lists each selected case and its classification.
- `webrev-report.json` contains the after-run evidence and coverage.
- `control-level12-report.json` records the supplemental secure control run.
- `browser-normalization.json` records offline Chromium URL parsing for the
  challenge payloads.
- `comparator-input.json`, `comparator-result.json` and `adapter-review.json`
  preserve the exact mapping and lab response.
- `ground-truth-full.json`, `ground-truth-open-redirect.json` and
  `compose.override.yml` retain labels and pinned lab images.
