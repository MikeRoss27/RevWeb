# VulnerableApp open redirect slice — 2026-10-16

## Scope and reproducibility

This is a focused detector benchmark against OWASP VulnerableApp, not a full
application scan. Source is pinned to commit
`8003daf8e13044802fdeb4b665f0c9cc6d09096b`. Every container image is pinned by
digest in `compose.override.yml`. The stack uses an internal Docker network;
only loopback host ports are published. Webrev connected to the facade's
private container IP (`172.20.0.7`) and had that IP as its sole scope entry.
The Docker IP can differ on a later run; inspect the facade container and use
the resulting address consistently for `LAB` and `--scope`.

The scan used 12 seeded routes: all nine `UNSECURE` routes labeled
`OPEN_REDIRECT_3XX_STATUS_CODE`, secure levels 11 and 12, and level 8 as an
additional manual negative control (level 8 has no row in the DAST ground
truth). Each seed used a same-origin baseline `returnTo` URL. Webrev's active
check replaced it with a randomized `.invalid` URL and did not follow the
redirect. The scan used one concurrent request, a 50 ms delay, 12-page cap,
depth 0, and a shared limit of 160 active requests. It sent 146 active
requests. The persisted report records 12 open-redirect attempts, 12 executed,
0 not executed, 0 inconclusive, 0 scope refusals, 3 findings and 1 HTTP refusal.

To start and remove the pinned lab stack:

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
python3 scripts/vulnerableapp_adapter.py webrev-report.json \
  --output comparator-input.json
curl -sS -H 'Content-Type: application/json' \
  --data-binary @comparator-input.json \
  "http://${LAB}/VulnerableApp/scanner/benchmark" \
  -o comparator-result.json
# After the run:
docker compose -p webrev-vapp-bench \
  -f /tmp/owasp-vulnerableapp/docker-compose.without_llm.yml \
  -f "$PWD/benchmarks/vulnerableapp/2026-10-16/open-redirect/compose.override.yml" \
  down -v
```

The full captured ground truth and the 11 redirect rows are in
`ground-truth-full.json` and `ground-truth-open-redirect.json`. The full Webrev
report, exact comparator request/response, adapter review sidecar and image
digests are preserved beside this file.

## Results

The active detector reported only levels 1, 9 and 10. Each finding contains
the exact randomized URL in a 3xx `Location`; VulnerableApp's comparator
matched all three to ground truth. Levels 2–7 were attempted with the same
generic absolute URL probe but returned no matching redirect proof. The
comparison therefore exposes a payload coverage limitation in those filtered
levels.

| Metric | Result | Scope |
| --- | ---: | --- |
| True positives | 3 | Open redirect levels 1, 9, 10 |
| False positives | 0 | One benchmark-labeled secure case was eligible for TN; one other was refused |
| False negatives | 6 | Open redirect levels 2–7 |
| True negatives | 1 | Level 12; level 11 returned HTTP 403 and is excluded from TN |
| Refused | 1 | Secure level 11 (HTTP 403) |
| Precision | 100% (3/3) | Findings submitted for this detector slice matched ground truth |
| Recall | 33.3% (3/9) | All nine vulnerable redirect levels were selected and attempted |
| False positive rate | 0% (0/1) | One non-refused, ground-truth secure case |
| False negative rate | 66.7% (6/9) | Ground-truth vulnerable levels 2–7 |

These are measurements of this single detector, one lab revision, and one
probe strategy. The small number of clean controls does not establish a
general production false-positive rate. The additional level 8 control
returned HTTP 200 without a redirect but is not a labeled case and is excluded
from the confusion matrix.

The VulnerableApp comparator grades against all 168 `UNSECURE` DAST rows:
3 detected, 165 missed, 0 unmatched, for 1.7857% full-app coverage. This
number is retained as the comparator's literal result, but it is not a useful
standalone score for this focused run: 159 expected rows belong to other
vulnerability types that Webrev did not exercise. The open-redirect slice
metrics above are the relevant comparison. No before/after improvement is
claimed because no prior run used this pinned lab revision and case selection.

## Artifacts

- `metadata.json` — Webrev commit, image digests, scope, request limits and
  coverage counts.
- `case-matrix.json` — expected outcome and observed result for selected cases.
- `webrev-report.json` — evidence captured by Webrev.
- `comparator-input.json`, `comparator-result.json` — exact request and
  VulnerableApp response.
- `adapter-review.json` — findings not submitted as open redirect matches.
- `ground-truth-full.json`, `ground-truth-open-redirect.json` — lab labels
  fetched from the pinned running application.
