# External HTML/JavaScript benchmark source audit

Audit date: 2026-10-16. This is a source-selection audit, not a benchmark run.
No third-party code or labels are copied into this repository by this audit.
The local `benchmarks/static-corpus/v1/` remains maintainer-authored regression
data and is not represented as independent validation.

## Selection criteria

A candidate must expose source or runnable web artifacts relevant to Webrev's
specific detector, stable case-level ground truth, reproducible versioned
provenance, and a license that permits the intended use. DOM-XSS labels must
represent client-side attacker-controlled source-to-sink behavior. Dataset
labels for vulnerability in general, or vulnerable/fixed function pairs alone,
do not establish that an HTML/JS extractor should report an endpoint, HTTP
parameter, secret, or DOM flow.

## Candidates reviewed

| Candidate and pinned identity | License / provenance | Relevant data and limits | Decision |
| --- | --- | --- | --- |
| [CMU DOM XSS Web Vulnerability Dataset](https://kilthub.cmu.edu/articles/dataset/DOM_XSS_Web_Vulnerability_Dataset/13870256), DOI [10.1184/R1/13870256.v1](https://doi.org/10.1184/R1/13870256), Figshare article 13870256 | Landing page declares MIT. Authors Clement Fung, Lujo Bauer, Limin Jia. Dataset README describes an Alexa 10K crawl from 2019 using taint-tracking Chromium 57, with confirmed and unconfirmed function sets and testing/validation splits. Files were inventoried through the Figshare API on 2026-10-16. | Closest large-scale client-side DOM-XSS candidate, but the landing page reports 274.69 GiB and the Figshare API reports 292,419,426,225 bytes. Its README says each record contains only `lbl`, `wght`, token-count `feat`, and function hash `dbg`. It does not distribute function source, HTML, or endpoint/parameter/secret labels. Its `confirmed` label is tied to PoC exploitation; `unconfirmed` is taint-analysis output. | **Do not integrate for extractor scoring.** Strong evidence of DOM-XSS prevalence/labels, but no source text to feed Webrev and far outside a practical local subset. Useful as a cited research basis only. |
| [JsVul](https://github.com/jsvul/jsvul), repository commit [`036c7f77749c524c51984419a37f666685796ef6`](https://github.com/jsvul/jsvul/tree/036c7f77749c524c51984419a37f666685796ef6), dated 2026-02-05; dataset DOI [10.5281/zenodo.18195838](https://doi.org/10.5281/zenodo.18195838), superseded by active v1 artifact 10.5281/zenodo.18195839 | GitHub repository identifies GPL-3.0 for its curation code. DataCite record for the dataset DOI identifies CC-BY-4.0. The DOI metadata was queried on 2026-10-16. The project states it aggregates NVD, OSV, CVEFixes, CrossVul, JS Vulnerability Dataset, OSSF, and SecBench.JS. | Function-level vulnerable/fixed code from security-fix commits; temporal split and language-aware filtering/deduplication are useful. The paper describes labels as heuristic-based and reports source-data integrity problems, including incorrect/missing commits and test-only or non-JS changes. Vulnerability/fix labels do not identify DOM browser taint flows or Webrev's expected extraction output. Source excerpts inherit upstream licensing questions; the dataset's CC-BY record does not relicense every included upstream source file. | **Do not integrate as a general static detector benchmark.** A later, manually verified client-side DOM-XSS subset could be a candidate, but only after checking each upstream commit, browser context, label evidence, and source license. This audit did not download or redistribute the dataset. |
| [In the DOM We Trust artifact](https://github.com/jndre/In-the-DOM-We-Trust), repository commit [`67ccd274ba197c3c9e054b1995b53424990026ee`](https://github.com/jndre/In-the-DOM-We-Trust/tree/67ccd274ba197c3c9e054b1995b53424990026ee), dated 2025-09-16 | GitHub API reports no repository license at the pinned commit; root listing contains no `LICENSE`. CCS 2025 research artifact by Jan Drescher et al. README documents static/dynamic taint flows and exploit validation. | Excellent semantic fit for DOM source-to-sink research. It describes a sample app, verified markup injection flows, and script-gadget cases. It has heavy runtime dependencies (patched Chromium/Foxhound, Docker, JAW, databases) and its README's artifact demo is not a multi-detector labeled corpus. | **Do not copy or score its code in this repository absent a license grant.** Could be run as an externally fetched lab after licensing is clarified; its scope only informs DOM flows. |
| [RusDavies/security-defect-corpus](https://github.com/RusDavies/security-defect-corpus), commit [`84dd9c822eea735448353a01afe5e7e0df6549c4`](https://github.com/RusDavies/security-defect-corpus/tree/84dd9c822eea735448353a01afe5e7e0df6549c4), dated 2026-08-10 | GitHub API reports MIT. Repository provides `ground_truth/cases.json` and benchmark validity guidance. | Controlled toy fixtures with reachable/unreachable pairs across languages. The JavaScript XSS case is a small Express-style server-side handler, not a representative browser bundle; its own guidance says the cases are toy fixtures and warns against claims of independent general performance. No coverage of all Webrev extractor predicates. | **Do not count as independent validation.** Potential external integration regression for a narrow route if adapter mapping is added, but it does not address the required HTML/JS static corpus. |
| [OWASP Benchmark](https://owasp.org/www-project-benchmark/), repository commit [`b69666dde70a21297025143e57e481e8d75cf7db`](https://github.com/OWASP/Benchmark/tree/b69666dde70a21297025143e57e481e8d75cf7db), dated 2021-09-20 | OWASP project page declares GPL-2.0. GitHub repository API at the pinned commit reports no detected license file, so file-level license terms should be checked before copying. | Large runnable SAST/DAST benchmark with case-level expected outcomes, but the established corpus is Java-centric and the newer Python edition is server-side. It does not evaluate browser JS endpoint/parameter extraction, JS secrets, or source-to-sink extraction. | **Exclude from static Webrev detector metrics.** A separate compatible active web scenario may be evaluated only after detector-specific mapping; do not count unsupported cases as TN. |
| [OWASP VulnerableApp](https://owasp.github.io/www-project-vulnerableapp/), pinned source commit `8003daf8e13044802fdeb4b665f0c9cc6d09096b` | GitHub API identifies Apache-2.0 at the pinned repository; the existing Webrev archive records source revision, scope, configuration, image digests, and explicit case levels with a comparator. | Intentionally vulnerable web application for reproducible DAST. It provides useful active open-redirect ground truth, but does not validate the four static HTML/JS detector families. Existing paired result is maintained separately under `benchmarks/vulnerableapp/2026-10-16/open-redirect/`. | **Retain as separate DAST evidence only.** Do not pool with static extractor confusion metrics. |

## Verification commands and observed results

Commands run from the repository on 2026-10-16:

```sh
curl -fsSL https://api.figshare.com/v2/articles/13870256
curl -fsSL https://ndownloader.figshare.com/files/26781044
curl -fsSL https://api.datacite.org/dois/10.5281/zenodo.18195838
curl -fsSL https://api.github.com/repos/jsvul/jsvul/commits/main
curl -fsSL https://api.github.com/repos/jsvul/jsvul/license
curl -fsSL https://api.github.com/repos/jndre/In-the-DOM-We-Trust
curl -fsSL https://api.github.com/repos/jndre/In-the-DOM-We-Trust/commits/main
curl -fsSL https://api.github.com/repos/RusDavies/security-defect-corpus
curl -fsSL https://api.github.com/repos/RusDavies/security-defect-corpus/commits/HEAD
curl -fsSL https://api.github.com/repos/OWASP/Benchmark
```

Observed metadata: CMU Figshare says MIT and its file inventory lists the
292,419,426,225-byte `vulnerability-data.zip`; the downloaded README confirms
the four-field token-feature schema. DataCite reports CC-BY-4.0 for JsVul's
dataset DOI; GitHub reports GPL-3.0 for its repository. The DOM-trust GitHub
repository has no detected license and its root has no license file. GitHub
reports MIT for the security-defect corpus. The OWASP project page reports
GPL-2.0, while GitHub's API did not detect a license file in that repository
revision.

These commands verify metadata and schemas, not detector metrics. No external
corpus runner was executed because none of the reviewed sources satisfies both
the source/label relevance and licensing/provenance requirements for a valid
Webrev static-detector score. No performance result or accuracy statistic is
claimed here.

## Recommended path to independent validation

Keep the current hand-authored suite as the development regression set. Build a
small separately curated evaluation set from permissively licensed browser
applications and versioned security fixes, then have a reviewer who did not
implement the detectors label the exact expected extractor output. Store source
repository, commit, file path, license, case rationale, and evidence for each
case; retain a project-level held-out split. For DOM XSS, require an observed
attacker-controlled browser source-to-sink path or a reproducible exploit and
record transformations/sanitizers. For endpoint, parameter, and secret labels,
use actual request contexts and verify credential semantics. Keep active
VulnerableApp DAST metrics in their own report. If compatible openly licensed
cases remain too few, report Step 5 as partially validated rather than
presenting synthetic or mismatched data as independent evidence.

### Multi-file DOM XSS positive corpus

The `kanaoka-laboratory/multifile-domxss-dataset` repository was audited at
commit `28f06b4b331c6192477c8987deee3cfaf08eaf57` (Apache-2.0). Its upstream
README describes 342 positive folders from 69 source/sink combinations across
five ES-module splitting patterns; three `document.referrer` variants are
absent from one pattern. 274 cases use two JavaScript modules and 68 use three.
The authors derive the cases from Google Firing Range, so this is a useful
external academic regression suite for DOM source-to-sink coverage, especially
multi-file boundaries, but not a set of independent real-world vulnerabilities.
The variants are correlated, labels are encoded in folder names rather than
line-level flow annotations, and there are no negative cases.

Webrev's diagnostic at `benchmarks/external-domxss/multifile-v1/` preserves the
file boundaries. Of 342 positive variants, 122 fall within the current modeled
source/sink categories (25 unique pairs). The extractor emits some unrelated
flow signals on 12 cases but matches none of the expected source→sink pairs:
TP=0, FN=122, recall=0%. Precision/FPR are not measurable. This exposes a
multi-file taint coverage gap and does not validate overall Step 5 accuracy.

### JsVul paired CWE-79 subset follow-up (2026-10-17)

A read-only audit of the active [Zenodo v1 artifact, DOI
10.5281/zenodo.18195839](https://doi.org/10.5281/zenodo.18195839) found a more
practical `js_vul_pairs_only.zip` archive (about 1.9 MB) than the originally
inspected split: 2,684 function records in 1,342 vulnerable/fixed pairs. Its
test split has 316 records (158 labeled vulnerable, 158 fixed); the CWE-79
slice has 56 records, or 28 pairs. Records include JavaScript/TypeScript code,
repository, commit, file/line provenance, and vulnerability references. The
associated [paper](https://arxiv.org/abs/2609.38012) describes aggregation from
seven vulnerability sources and targeted manual verification.

This is a candidate for a small paired function-level diagnostic, not a
representative Webrev validation set. The labels are inferred from security
fixes and heuristic filters, and CWE-79 includes cases that are not browser
DOM XSS or may lack source-to-sink context. Each source repository and commit
must be checked, and eligible snippets manually adjudicated for detector
relevance. Zenodo declares CC-BY-4.0 for the artifact; the license of each
upstream source file is not encoded per record, so verify source licenses and
retain attribution before redistributing any snippet. No data was copied into
this repository and no detector metrics were run. The older dataset DOI
10.5281/zenodo.18195838 cited in the initial table is stale; use the active
10.5281/zenodo.18195839 artifact when reproducing this follow-up.

The 28 pairs were manually triaged against the vulnerable/fixed source, diff,
and license files at both revisions. The review classified 13 as DOM/client
candidates, 3 as ambiguous, 4 as sanitizer/context cases, 5 as server-side or
non-DOM issues, and 3 as doubtful labels or incomplete flows. These are triage
categories, not confirmed exploitable DOM XSS findings. Examples excluded from
DOM scoring include Astro SSRF and reflected server XSS, BigBlueButton
stored/server XSS, and `sanitize-html` library defects without an application
source-to-sink context. MediaWiki `initBodyContent`, Fast Velocity Minify's
textarea `.val()`, and Dependency-Track route definitions did not establish a
DOM flow in the reviewed function/diff.

License files were present at both revisions for all 28 pairs. The review
identified MIT/Apache terms for 17 pairs, GPL/LGPL for 5, and custom or
unidentified terms for 6. Presence of a license file does not grant permission
to redistribute all upstream excerpts; the six custom/unidentified entries
need further review. No JsVul snippets or labels were copied into the
repository, and Webrev was not run on these pairs. This paired subset improves
traceability but does not satisfy Step 5's independent, balanced,
detector-specific validation gate: it is function-level, small for CWE-79,
includes non-DOM findings, and provides no representative negative set or
runtime browser context.

| # | Project / case | Relevance to DOM XSS | License at both revisions |
|---:|---|---|---|
| 1 | DataTables — CVE-2025-5096 | DOM/client candidate: cell attributes rendered into DOM | MIT |
| 2 | StackRox — CVE-2025-5198 | DOM/client candidate: UI PDF table rendering | Apache-2.0 |
| 3 | Argo CD — CVE-2025-47933 | Ambiguous: URL helper, downstream flow not established | Apache-2.0 |
| 4 | MediaWiki Citizen — CVE-2025-49575–49579 | DOM/client candidate: `textContent` to `innerHTML` | GPL |
| 5 | MediaWiki Citizen — CVE-2025-49578 | Doubtful label: no source/sink; feature commit | GPL |
| 6 | GroupOffice — CVE-2025-48992 | Server/API preferences flow, no DOM sink shown | Custom, unresolved |
| 7 | GroupOffice — CVE-2025-48993 | DOM/client candidate: grid renderer returns HTML entity | MIT |
| 8 | GroupOffice — CVE-2025-48993 | DOM/client candidate, related renderer revision | Custom, unresolved |
| 9 | OpenList — CVE-2025-50183 | DOM/client candidate: Markdown component rendering | MIT |
| 10 | MediaWiki ShortDescription — CVE-2025-53369 | DOM/client candidate: UI subtitle escaping | GPL |
| 11 | n8n — CVE-2025-52478 | Sanitizer; server/browser context unclear | Custom, unresolved |
| 12 | CKEditor — CVE-2025-58064 | Ambiguous: detached DOM converts content to text | MIT |
| 13 | Astro — CVE-2025-58179 / 59837 | SSRF, outside DOM XSS | MIT |
| 14 | `sanitize-html` — CVE-2014-125128 | Sanitizer defect, no application DOM flow | Custom, unresolved |
| 15 | `sanitize-html` — CVE-2019-25225 | Sanitizer transform escaping, no application DOM flow | Custom, unresolved |
| 16 | Business Links — CVE-2025-58746 | DOM/client candidate: frontend URL handling | Apache-2.0 |
| 17 | Drawnix — CVE-2025-58172 | DOM/client candidate, downstream flow incomplete | MIT |
| 18 | LobeChat — CVE-2025-59417 | Ambiguous: downloaded SVG executes only after opening | Apache-2.0 |
| 19 | Mesh Web SDK — CVE-2025-59430 | DOM/client candidate: decoded URL to iframe/popup | MIT |
| 20 | BigBlueButton Pads — CVE-2025-55200 | Server-side stored XSS via Redis/Etherpad | LGPL |
| 21 | Dify — CVE-2025-58747 | DOM/client candidate: URL passed to `window.open` | Apache-2.0 |
| 22 | ClipBucket — CVE-2025-62430 / 62715 / 64336 / 64339 | DOM/client candidate: jQuery-built tag HTML | Custom, unresolved |
| 23 | MediaWiki Citizen — CVE-2025-62508 | DOM/client candidate: DOM text to `innerHTML` | GPL |
| 24 | Fast Velocity Minify — CVE-2025-12034 | Doubtful label: response assigned with textarea `.val()` | GPL |
| 25 | Sharp — CVE-2025-62798 | Sanitizer configuration; downstream sink absent | MIT |
| 26 | Astro — CVE-2025-59837 | SSRF/path validation, outside DOM XSS | MIT |
| 27 | Astro — CVE-2025-64745 | Reflected server XSS, not DOM XSS | MIT |
| 28 | Dependency-Track — CVE-2025-64758 | Doubtful/incomplete: Vue routes without source/sink | Apache-2.0 |

This is a source/diff review, not dynamic reproduction or legal advice. A
candidate tag means the function appears browser-facing and warrants further
flow/context validation; it is not a confirmed vulnerability finding.
