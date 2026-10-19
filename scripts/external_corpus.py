#!/usr/bin/env python3
"""External DOM XSS validation corpus: build, fetch, verify, report.

No third-party code is committed. ``sources.json`` pins every input (commit
SHAs, npm versions); ``manifest.json`` records the SHA-256 of every file the
corpus is made of. ``fetch`` downloads and verifies, ``report`` turns the
per-case detector output into per-source metrics.

    python3 scripts/external_corpus.py build     # maintainers: regenerate manifest.json
    python3 scripts/external_corpus.py fetch     # download + verify into the cache dir
    python3 scripts/external_corpus.py verify    # re-check cached files against manifest
    cargo test --release -p webrev-extract --test external_corpus_domxss -- --ignored --nocapture
    python3 scripts/external_corpus.py report    # metrics from results.json
"""

import argparse
import base64
import csv
import hashlib
import html
import io
import json
import math
import os
import re
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "benchmarks" / "external-corpus" / "v1"
SOURCES = CORPUS / "sources.json"
MANIFEST = CORPUS / "manifest.json"
RESULTS = CORPUS / "results.json"
SUMMARY = CORPUS / "summary.json"
CACHE = Path(os.environ.get("WEBREV_EXTERNAL_CORPUS") or CORPUS / "cache")
RAW = "https://raw.githubusercontent.com/{repo}/{ref}/{path}"
MAX_FILE_BYTES = 3_000_000
MODELED_SOURCE = re.compile(
    r"location\.(href|hash|search)|document\.referrer|postMessage|document\.cookie|window\.name|document\.URL", re.I
)


def http_get(url, tries=4):
    last = None
    for attempt in range(tries):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "webrev-external-corpus/1"})
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.read()
        except Exception as error:  # noqa: BLE001 - retried then re-raised
            last = error
            time.sleep(1 + attempt * 2)
    raise RuntimeError(f"GET {url} failed: {last}")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_rel(path):
    parts = Path(path).parts
    if not parts or any(part in ("..", "") or part.startswith("/") for part in parts):
        raise ValueError(f"unsafe corpus path {path!r}")
    return Path(*parts)


def ext_kind(path):
    suffix = Path(path).suffix.lower()
    if suffix in (".html", ".htm"):
        return "html"
    if suffix in (".js", ".mjs", ".cjs", ".jsx"):
        return "js"
    return None


# ---------------------------------------------------------------- materialize
def materialize(sources):
    """Yield (case_dict, {rel_path: bytes}) for every case, downloading as needed."""
    yield from ghsa_cases(sources["ghsa"])
    yield from sak3y_cases(sources["sak3y"])
    yield from pwnfunction_cases(sources["pwnfunction"])
    yield from domdig_cases(sources["domdig"])
    yield from npm_cases(sources["npm"])


def case(cid, source, label, provenance, license_, group, files, **extra):
    record = {
        "id": cid,
        "source": source,
        "label": label,
        "label_provenance": provenance,
        "license": license_,
        "group": group,
        "files": sorted(files),
    }
    record.update(extra)
    return record, files


def ghsa_cases(entries):
    for entry in entries:
        for side, ref in (("pre", entry["parent"]), ("post", entry["fix"])):
            blobs = {}
            for path in entry["files"]:
                body = http_get(RAW.format(repo=entry["repo"], ref=ref, path=path))
                if len(body) > MAX_FILE_BYTES:
                    print(f"  skip oversize {entry['repo']}@{ref[:8]}:{path}", file=sys.stderr)
                    continue
                blobs[f"ghsa/{entry['ghsa']}/{side}/{path}"] = body
            label = "positive" if side == "pre" else "fixed"
            yield case(
                f"ghsa/{entry['ghsa']}/{side}",
                "ghsa",
                label,
                f"GitHub Security Advisory {entry['ghsa']} ({entry['summary']}); "
                + ("files at the parent of the advisory's fix commit" if side == "pre" else "same files at the fix commit; other flows may remain"),
                entry["license"],
                entry["repo"],
                blobs,
                source_class=entry["source_class"],
                pair=f"ghsa/{entry['ghsa']}",
                repo=entry["repo"],
                commit=ref,
            )


def sak3y_cases(spec):
    url = RAW.format(repo=spec["repo"], ref=spec["commit"], path=spec["path"])
    body = http_get(url)
    if sha256(body) != spec["csv_sha256"]:
        raise RuntimeError("sak3y CSV hash mismatch")
    rows = list(csv.DictReader(io.StringIO(body.decode("utf-8"), newline="")))
    for row in rows:
        sid = row["snippet_id"]
        code = row["code"].rstrip("\n") + "\n"
        label = "positive" if row["label"].strip() == "1" else "negative"
        yield case(
            f"sak3y/{sid}",
            "sak3y",
            label,
            "single-labeller dataset label with written justification (sak3y/ML-XSS-Detector); "
            + ("sourced from public repositories" if "real" in row["task_category"].lower() else "prompt-generated snippet"),
            spec["license"],
            row["task_category"],
            {f"sak3y/{sid}.js": code.encode("utf-8")},
            task_category=row["task_category"],
            upstream_source=row["source"],
            upstream_sink=row["sink"],
            upstream_mitigation=row["mitigation"],
            real_world="real" in row["task_category"].lower(),
        )


FILTER_HINT = re.compile(r"sanitiz|\.replace\(|escape|DOMPurify|filter|encodeURI|whitelist|allowlist|blacklist|blocklist", re.I)
CODE_BLOCK = re.compile(r"\{\{< code >\}\}<code class=\"language-(\w+)\">(.*?)</code>\{\{< /code >\}\}", re.S)


def pwnfunction_cases(spec):
    for kind, names in (("warmups", spec["warmups"]), ("challenges", spec["challenges"])):
        for name in names:
            path = f"hugo/content/{kind}/{name}.md"
            text = http_get(RAW.format(repo=spec["repo"], ref=spec["commit"], path=path)).decode("utf-8")
            blocks = CODE_BLOCK.findall(text)
            if not blocks:
                print(f"  pwnfunction: no code block in {path}", file=sys.stderr)
                continue
            lang, code = blocks[0]
            code = html.unescape(code).strip() + "\n"
            suffix = ".html" if lang == "markup" else ".js"
            yield case(
                f"pwnfunction/{kind}/{name}",
                "pwnfunction",
                "positive",
                "XSS Game page with a published working exploit (alert on the sandbox origin); the challenge code is the vulnerable page",
                spec["license"],
                "pwnfunction",
                {f"pwnfunction/{kind}/{name}{suffix}": code.encode("utf-8")},
                source_class="browser",
                difficulty=re.search(r"difficulty:\s*(\w+)", text).group(1) if re.search(r"difficulty:\s*(\w+)", text) else None,
                # Fixed before any detector run: the challenge passes the input through a filter or sanitizer
                # that the published exploit has to get around, so a flow-only detector is not expected to flag it.
                filtered=bool(FILTER_HINT.search(code)),
            )


def domdig_cases(spec):
    support = {}
    for path in spec["support"]:
        support[f"domdig/{path}"] = http_get(RAW.format(repo=spec["repo"], ref=spec["commit"], path=f"test/testpages/{path}"))
    for page in spec["pages"]:
        body = http_get(RAW.format(repo=spec["repo"], ref=spec["commit"], path=f"test/testpages/{page}"))
        files = {f"domdig/{page}": body}
        files.update(support)
        label = spec.get("label_overrides", {}).get(page, "positive")
        yield case(
            f"domdig/{page}",
            "domdig",
            label,
            "domdig scanner test page: fixture written to be a DOM XSS the scanner must find (author's own test suite)"
            + ("; overridden to ambiguous before any detector run: the handler checks event.origin" if label == "ambiguous" else ""),
            spec["license"],
            "domdig",
            files,
            source_class="browser",
            primary=f"domdig/{page}",
            # Read from the page's own code: the sink family the labelled flow ends in.
            expected_sink_family=spec.get("expected_sink_family", {}).get(page),
        )


def npm_cases(entries):
    for entry in entries:
        name, version, wanted = entry["name"], entry["version"], entry["file"]
        meta = json.loads(http_get(f"https://registry.npmjs.org/{name}/{version}"))
        tarball = http_get(meta["dist"]["tarball"])
        integrity = meta["dist"].get("integrity", "")
        if integrity.startswith("sha512-"):
            digest = base64.b64encode(hashlib.sha512(tarball).digest()).decode()
            if digest != integrity[len("sha512-"):]:
                raise RuntimeError(f"npm integrity mismatch for {name}@{version}")
        member = None
        with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as archive:
            for info in archive.getmembers():
                if info.isfile() and info.name == f"package/{wanted}":
                    member = archive.extractfile(info).read()
                    break
            license_ = meta.get("license") or "see package"
        if member is None:
            print(f"  npm: {name}@{version} has no {wanted}", file=sys.stderr)
            continue
        if len(member) > MAX_FILE_BYTES:
            print(f"  npm: skip oversize {name}@{version}:{wanted}", file=sys.stderr)
            continue
        yield case(
            f"npm/{name}@{version}",
            "npm",
            "background",
            "popular library distribution file, pinned by npm version and registry integrity; NOT labelled by anyone for DOM XSS",
            license_ if isinstance(license_, str) else str(license_),
            name,
            {f"npm/{name}@{version}/{wanted}": member},
            package=name,
            version=version,
            entry=wanted,
        )


# ------------------------------------------------------------------- commands
def cmd_build(_args):
    sources = json.loads(SOURCES.read_text())
    cases = []
    CACHE.mkdir(parents=True, exist_ok=True)
    for record, blobs in materialize(sources):
        files = []
        for rel, data in sorted(blobs.items()):
            target = CACHE / safe_rel(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            files.append({"path": rel, "sha256": sha256(data), "bytes": len(data)})
        record["files"] = files
        cases.append(record)
        print(f"  {record['id']}: {len(files)} file(s)")
    manifest = {"version": "external-corpus-v1", "cases": cases}
    MANIFEST.write_text(json.dumps(manifest, indent=1) + "\n")
    print(f"wrote {MANIFEST.relative_to(ROOT)}: {len(cases)} cases")


def cmd_fetch(_args):
    sources = json.loads(SOURCES.read_text())
    manifest = json.loads(MANIFEST.read_text())
    expected = {f["path"]: f["sha256"] for c in manifest["cases"] for f in c["files"]}
    produced = 0
    for record, blobs in materialize(sources):
        for rel, data in blobs.items():
            want = expected.get(rel)
            if want is None:
                raise RuntimeError(f"{rel} is not in the manifest")
            if sha256(data) != want:
                raise RuntimeError(f"hash mismatch for {rel}: upstream content changed")
            target = CACHE / safe_rel(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            produced += 1
    print(f"fetched and verified {produced} files into {CACHE}")


def cmd_verify(_args):
    manifest = json.loads(MANIFEST.read_text())
    bad = 0
    total = 0
    for record in manifest["cases"]:
        for f in record["files"]:
            total += 1
            path = CACHE / safe_rel(f["path"])
            if not path.is_file() or sha256(path.read_bytes()) != f["sha256"]:
                print("MISMATCH", f["path"])
                bad += 1
    print(f"verified {total - bad}/{total} files in {CACHE}")
    sys.exit(1 if bad else 0)


def wilson(k, n, z=1.96):
    if n == 0:
        return None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def rate(k, n):
    return None if n == 0 else round(k / n, 4)


def metrics(rows):
    tp = sum(1 for r in rows if r["label"] == "positive" and r["detected"])
    fn = sum(1 for r in rows if r["label"] == "positive" and not r["detected"])
    fp = sum(1 for r in rows if r["label"] == "negative" and r["detected"])
    tn = sum(1 for r in rows if r["label"] == "negative" and not r["detected"])
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "positives": tp + fn, "negatives": fp + tn,
        "precision": rate(tp, tp + fp), "precision_ci95": wilson(tp, tp + fp),
        "recall": rate(tp, tp + fn), "recall_ci95": wilson(tp, tp + fn),
        "fpr": rate(fp, fp + tn), "fpr_ci95": wilson(fp, fp + tn),
    }


def sink_family(finding):
    """Sink family of a ``DOM XSS: source -> ... -> sink`` finding text."""
    sink = finding.rsplit("->", 1)[-1].strip().lower()
    if any(k in sink for k in ("eval", "function(", "settimeout", "setinterval")):
        return "code"
    if any(k in sink for k in ("innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "srcdoc")):
        return "html"
    if any(k in sink for k in ("location", "href", "src", "open(")):
        return "url"
    return "other"


def cmd_report(_args):
    manifest = json.loads(MANIFEST.read_text())
    results = json.loads(RESULTS.read_text())
    meta = {c["id"]: c for c in manifest["cases"]}
    rows = []
    stray_flows = []
    for res in results["cases"]:
        m = meta[res["id"]]
        row = {**res, "label": m["label"], "source": m["source"], "source_class": m.get("source_class"),
               "group": m["group"], "real_world": m.get("real_world")}
        want = m.get("expected_sink_family")
        if want:
            # Credit a hit only for a flow that ends in the labelled sink family;
            # any other flow is reported separately, not as a detection.
            hits = [f for f in res["findings"] if sink_family(f) == want]
            if res["detected"] and not hits:
                stray_flows.append({"id": res["id"], "expected": want, "findings": res["findings"]})
            row["detected_any_flow"] = res["detected"]
            row["detected"] = bool(hits)
        rows.append(row)
    out = {"detector_commit": results.get("commit"), "mode": results.get("mode"), "cases": len(rows), "by_source": {},
           "flows_not_matching_the_labelled_sink": stray_flows, "mismatches": []}
    for source in sorted({r["source"] for r in rows}):
        sub = [r for r in rows if r["source"] == source]
        entry = metrics(sub)
        entry["cases"] = len(sub)
        entry["not_evaluable"] = sum(1 for r in sub if r.get("evaluable") is False)
        out["by_source"][source] = entry
    ghsa = [r for r in rows if r["source"] == "ghsa" and r.get("evaluable", True)]
    for cls in ("browser", "other"):
        pos = [r for r in ghsa if r["label"] == "positive" and r["source_class"] == cls]
        out.setdefault("ghsa_by_source_class", {})[cls] = {
            "pre_fix_cases": len(pos), "pre_fix_detected": sum(1 for r in pos if r["detected"])}
    fixed = [r for r in ghsa if r["label"] == "fixed"]
    out["ghsa_fixed_detected"] = sum(1 for r in fixed if r["detected"])
    out["ghsa_fixed_cases"] = len(fixed)
    sak = [r for r in rows if r["source"] == "sak3y"]
    real = [r for r in sak if r.get("real_world")]
    out["sak3y_real_world_subset"] = {**metrics(real), "cases": len(real)} if real else None
    # Subsets defined from the detector's documented source catalogue
    # (extractors/metadata/domsinks/sources.rs), not from per-case outcomes: a
    # positive is "in-model" when the dataset names a catalogued browser source
    # and a dangerous or URL sink; a negative is "hard" when it names a
    # catalogued source (the flow is then stopped only by the safe sink or a
    # mitigation).
    in_model_pos, hard_neg = [], []
    for r in sak:
        m = meta[r["id"]]
        has_source = bool(MODELED_SOURCE.search(m.get("upstream_source", "")))
        dangerous = "DANGEROUS" in m.get("upstream_sink", "") or "URL-SINK" in m.get("upstream_sink", "")
        if r["label"] == "positive" and has_source and dangerous:
            in_model_pos.append(r)
        if r["label"] == "negative" and has_source:
            hard_neg.append(r)
    out["sak3y_in_model"] = {
        "positives": metrics(in_model_pos), "hard_negatives": metrics(hard_neg),
    }
    for flag in (True, False):
        sub = [r for r in rows if r["source"] == "pwnfunction" and meta[r["id"]].get("filtered") is flag]
        out.setdefault("pwnfunction_by_filtered", {})[str(flag).lower()] = {"cases": len(sub), "detected": sum(1 for r in sub if r["detected"])}
    conf = {}
    for r in rows:
        for c in r.get("confidences", []):
            conf[c] = conf.get(c, 0) + 1
    out["finding_confidence_counts"] = conf
    bg = [r for r in rows if r["source"] == "npm"]
    out["npm_background"] = {
        "files": len(bg),
        "files_with_flows": sum(1 for r in bg if r["detected"]),
        "flow_findings": sum(len(r["findings"]) for r in bg),
    }
    for r in rows:
        label_pos = r["label"] == "positive"
        if (label_pos and not r["detected"]) or (r["label"] == "negative" and r["detected"]) \
                or (r["label"] in ("fixed", "background") and r["detected"]):
            out["mismatches"].append({"id": r["id"], "label": r["label"], "detected": r["detected"],
                                      "findings": r["findings"][:3]})
    SUMMARY.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k != "mismatches"}, indent=1))
    print(f"{len(out['mismatches'])} mismatches listed in {SUMMARY.relative_to(ROOT)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["build", "fetch", "verify", "report"])
    args = parser.parse_args()
    {"build": cmd_build, "fetch": cmd_fetch, "verify": cmd_verify, "report": cmd_report}[args.command](args)


if __name__ == "__main__":
    main()
