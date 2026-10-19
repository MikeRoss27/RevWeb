#!/usr/bin/env python3
"""Paired, local-only Webrev runtime/RSS benchmark against a Git revision.

Builds both binaries in release mode, serves a deterministic loopback fixture,
then alternates runs to reduce drift. No external network is used.
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import platform
import random
import resource
import shutil
import socketserver
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1]


def percentile95(values: list[float]) -> float:
    ordered = sorted(values)
    # Nearest-rank percentile, specified so the result is reproducible.
    return ordered[max(0, (95 * len(ordered) + 99) // 100 - 1)]


def make_fixture(directory: pathlib.Path, pages: int) -> None:
    (directory / "assets").mkdir(parents=True)
    for i in range(8):
        js = "\n".join(
            f"const route{i}_{j} = '/api/v{i}/items/{j}?page=1';"
            for j in range(30)
        )
        (directory / "assets" / f"bundle{i}.js").write_text(js + "\n")
    for i in range(pages):
        links = " ".join(
            f'<a href="/page/{j}">page {j}</a>'
            for j in range(max(0, i - 2), min(pages, i + 3)) if j != i
        )
        scripts = " ".join(
            f'<script src="/assets/bundle{j}.js"></script>'
            for j in range(8)
        )
        body = (f'<!doctype html><html><head><title>Fixture {i}</title>{scripts}'
                f'</head><body><form action="/search/{i}" method="get">'
                '<input name="query"><input name="page"></form>'
                f'<img src="/assets/pixel{i}.png">{links}</body></html>')
        path = directory / ("index.html" if i == 0 else f"page/{i}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    (directory / "assets" / "pixel.png").write_bytes(b"\x89PNG\r\n\x1a\n")


def make_site_fixture(directory: pathlib.Path, pages: int) -> None:
    """Create a deterministic multi-section SPA-like site, served only on loopback."""
    assets = directory / "assets"
    assets.mkdir(parents=True)
    (assets / "css").mkdir()
    (assets / "img").mkdir()
    shared = {
        "runtime.js": "window.__APP__ = window.__APP__ || {};\n",
        "vendor.js": "const vendorModules = ['react','router','query','forms'];\n",
        "app.js": "const api = '/api/v1';\n",
    }
    for name, header in shared.items():
        # Repeated realistic module declarations make the downloaded assets
        # large enough to exercise decoding and extraction without external deps.
        lines = [header]
        for i in range(180):
            lines.append(
                f"export const module_{i} = {{ path: '/api/v1/resources/{i}', "
                f"load: () => fetch('/api/v1/resources/{i}?include=summary') }};\n"
            )
        (assets / name).write_text("".join(lines))
    for section in range(8):
        lines = [f"// Section {section} application chunk\n"]
        for i in range(80):
            lines.append(
                f"export function item_{section}_{i}(id) {{ return fetch("
                f"`/api/v1/section/{section}/items/${{id}}?view=full`); }}\n"
            )
        (assets / f"section-{section}.js").write_text("".join(lines))
    (assets / "css" / "app.css").write_text(
        "\n".join(f".component-{i} {{ color: #{(i * 7919) % 0xFFFFFF:06x}; }}" for i in range(500))
    )
    for i in range(12):
        (assets / "img" / f"sprite-{i}.svg").write_text(
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><title>icon {i}</title></svg>'
        )

    categories = ("account", "catalog", "orders", "support", "settings", "search")
    for i in range(pages):
        category = categories[i % len(categories)]
        neighbor_links = []
        for target in (i - 2, i - 1, i + 1, i + 2):
            if 0 <= target < pages:
                neighbor_links.append(f'<a href="/{categories[target % len(categories)]}/{target}">Open {target}</a>')
        links = "\n".join(neighbor_links)
        forms = (
            f'<form action="/api/v1/{category}/search" method="get">'
            '<input name="q"><input name="page"><button>Search</button></form>'
        )
        html = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{category.title()} {i}</title>
<link rel="stylesheet" href="/assets/css/app.css">
<script defer src="/assets/runtime.js"></script>
<script defer src="/assets/vendor.js"></script>
<script defer src="/assets/app.js"></script>
<script defer src="/assets/section-{i % 8}.js"></script>
</head><body><header><a href="/">Home</a><nav>{links}</nav></header>
<main><h1>{category.title()} record {i}</h1>{forms}
<img src="/assets/img/sprite-{i % 12}.svg" alt="icon">
<script>window.pageContext = {{category: "{category}", id: {i}}};</script>
</main><footer>Fixture page {i}</footer></body></html>'''
        path = directory / ("index.html" if i == 0 else f"{category}/{i}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html)


def build(path: pathlib.Path, target: pathlib.Path) -> pathlib.Path:
    env = dict(os.environ, CARGO_TARGET_DIR=str(target))
    subprocess.run(["cargo", "build", "--release", "--bin", "webrev"],
                   cwd=path, env=env, check=True)
    binary = target / "release" / "webrev"
    if not binary.is_file():
        raise RuntimeError(f"binary missing: {binary}")
    return binary


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "pool":
        # `benchmark_performance.py pool RESULTS.json...`: judge several invocations together.
        import benchmark_pool
        return benchmark_pool.main(sys.argv[2:])
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline-ref", default="HEAD")
    ap.add_argument("--runs", type=int, default=20)
    ap.add_argument("--pages", type=int, default=40)
    ap.add_argument("--profile", choices=("micro", "site"), default="micro")
    ap.add_argument("--output", type=pathlib.Path, required=True)
    ap.add_argument("--seed", type=int, default=20261016,
                    help="seed of the shuffled run order")
    ap.add_argument("--baseline-bin", type=pathlib.Path,
                    help="prebuilt baseline binary; skips the baseline checkout and build")
    ap.add_argument("--current-bin", type=pathlib.Path,
                    help="prebuilt current binary; skips the current build")
    ap.add_argument("--max-load", type=float, default=0.0,
                    help="wait (bounded to 15 minutes) for the 1-minute load average to drop "
                         "below this before measuring; 0 disables the wait")
    args = ap.parse_args()
    if args.runs < 10 or args.pages < 10:
        ap.error("use at least 10 runs and 10 pages")
    if not hasattr(os, "wait4"):
        ap.error("requires POSIX wait4 for per-process maximum RSS")

    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="webrev-perf-") as tmp:
        temp = pathlib.Path(tmp)
        base_tree = temp / "baseline"
        if not args.baseline_bin:
            subprocess.run(["git", "worktree", "add", "--detach", str(base_tree),
                            args.baseline_ref], cwd=ROOT, check=True,
                           stdout=subprocess.DEVNULL)
        try:
            # Use the current dependency lock for both builds when it is
            # compatible. The baseline checkout remains otherwise untouched.
            if args.baseline_bin:
                baseline_bin = args.baseline_bin.resolve()
            else:
                shutil.copy2(ROOT / "Cargo.lock", base_tree / "Cargo.lock")
                baseline_bin = build(base_tree, temp / "target-baseline")
            current_bin = (args.current_bin.resolve() if args.current_bin
                           else build(ROOT, temp / "target-current"))
            if args.max_load > 0:
                deadline = time.monotonic() + 900
                while os.getloadavg()[0] >= args.max_load and time.monotonic() < deadline:
                    time.sleep(10)

            fixture = temp / "fixture"
            (make_site_fixture if args.profile == "site" else make_fixture)(fixture, args.pages)

            class QuietHandler(http.server.SimpleHTTPRequestHandler):
                def log_message(self, *_args):
                    pass

            class ReuseServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
                daemon_threads = True
                allow_reuse_address = True

            handler = lambda *a, **kw: QuietHandler(*a, directory=str(fixture), **kw)
            server = ReuseServer(("127.0.0.1", 0), handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            port = server.server_address[1]
            launcher = temp / "measure"
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(ROOT / "scripts" / "measure_process.c"), "-o", str(launcher)], check=True)
            rows: list[dict] = []
            rng = random.Random(args.seed)
            sequence = ["baseline", "current"] * args.runs
            rng.shuffle(sequence)
            binaries = {"baseline": baseline_bin, "current": current_bin}
            # Unmeasured warm-up: the first runs of a freshly built binary page it in
            # from a cold or partly evicted page cache, which shifted baseline RSS by
            # several MiB between otherwise identical invocations.
            for label in ("baseline", "current"):
                for warm in range(2):
                    subprocess.run([str(binaries[label]), "static", "--seed",
                                    f"http://127.0.0.1:{port}/", "--scope", "127.0.0.1",
                                    "--max-pages", str(args.pages), "--max-depth", "2",
                                    "--max-concurrency", "4", "--delay-min-ms", "0",
                                    "--delay-max-ms", "0", "--report", str(temp / f"warm-{label}-{warm}.json")],
                                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for index, label in enumerate(sequence):
                report = temp / f"report-{index}.json"
                command = [str(binaries[label]), "static", "--seed",
                           f"http://127.0.0.1:{port}/", "--scope", "127.0.0.1",
                           "--max-pages", str(args.pages), "--max-depth", "2",
                           "--max-concurrency", "4", "--delay-min-ms", "0",
                           "--delay-max-ms", "0", "--report", str(report)]
                measurement = json.loads(subprocess.check_output([str(launcher), *command], text=True))
                elapsed = measurement["wall_seconds"]
                exit_code = measurement["exit_code"]
                rss_kb = measurement["max_rss_kib"]
                report_ok = False
                findings = None
                if report.exists():
                    try:
                        obj = json.loads(report.read_text())
                        report_ok = isinstance(obj, dict)
                        findings = len(obj.get("findings", []))
                    except (ValueError, OSError):
                        pass
                rows.append({"order": index, "revision": label,
                             "loadavg_1m_after": os.getloadavg()[0],
                             "exit_code": exit_code, "wall_seconds": elapsed,
                             "max_rss_kib": rss_kb, "report_valid": report_ok,
                             "finding_count": findings})
                if exit_code != 0 or not report_ok:
                    raise RuntimeError(f"unstable/invalid run: {rows[-1]}")
            server.shutdown()
            server.server_close()

            summaries = {}
            for label in ("baseline", "current"):
                sample = [r for r in rows if r["revision"] == label]
                times = [r["wall_seconds"] for r in sample]
                rss = [r["max_rss_kib"] for r in sample]
                summaries[label] = {
                    "runs": len(sample), "runtime_median_seconds": statistics.median(times),
                    "runtime_p95_seconds": percentile95(times),
                    "max_rss_kib_max": max(rss),
                    "max_rss_kib_median": statistics.median(rss),
                    "max_rss_kib_min": min(rss),
                    "binary_sha256": hashlib.sha256(binaries[label].read_bytes()).hexdigest(),
                    "finding_counts": sorted(set(r["finding_count"] for r in sample)),
                    "failures": sum(r["exit_code"] != 0 for r in sample),
                }
            b, c = summaries["baseline"], summaries["current"]
            result = {
                "schema": 1, "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "baseline_ref": args.baseline_ref,
                "baseline_commit": subprocess.check_output(
                    ["git", "rev-parse", args.baseline_ref], cwd=ROOT, text=True).strip(),
                "current_commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "worktree_dirty": bool(subprocess.check_output(
                    ["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
                "environment": {"os": platform.platform(), "machine": platform.machine(),
                                "processor": platform.processor(), "cpu_count": os.cpu_count(),
                                "rustc": subprocess.check_output(["rustc", "-V"], text=True).strip(),
                                "cargo": subprocess.check_output(["cargo", "-V"], text=True).strip()},
                "fixture": {"kind": ("deterministic SPA-like multi-asset local site"
                                      if args.profile == "site" else "deterministic local HTML/JS crawl"),
                            "profile": args.profile, "pages": args.pages,
                            "assets": sum(1 for f in fixture.rglob("*") if f.is_file()) - args.pages,
                            "max_depth": 2, "concurrency": 4,
                            "delay_ms": 0, "scope": "127.0.0.1"},
                "method": {"runs_each": args.runs, "order": "seeded shuffled alternating labels after two unmeasured warm-up runs per binary",
                           "runtime": "native monotonic clock around fork/exec/wait4 includes scanner process startup; excludes builds and launcher startup",
                           "p95": "nearest rank", "rss": "native C parent fork/exec/wait4 ru_maxrss, scanner process peak in KiB; excludes inherited Python high-water mark"},
                "summaries": summaries,
                "relative_change": {
                    "runtime_p95_percent": (c["runtime_p95_seconds"] / b["runtime_p95_seconds"] - 1) * 100,
                    "max_rss_percent": (c["max_rss_kib_max"] / b["max_rss_kib_max"] - 1) * 100,
                    "median_rss_percent": (c["max_rss_kib_median"] / b["max_rss_kib_median"] - 1) * 100,
                },
                "raw_runs": rows,
                "fixture_sha256": hashlib.sha256("".join(
                    f.relative_to(fixture).as_posix() + hashlib.sha256(f.read_bytes()).hexdigest()
                    for f in sorted(fixture.rglob("*")) if f.is_file()
                ).encode()).hexdigest(),
                "limitations": [
                    "This is a local crawl microbenchmark, not a representative production workload.",
                    "HEAD and the dirty worktree may differ in source, manifests, features and lockfile; this measures the combined revision delta, not an isolated detector cost.",
                    "Peak RSS is per scanner process; Python, the threaded fixture server and the native measurement parent are excluded.",
                ],
            }
            (args.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps({"summaries": summaries, "relative_change": result["relative_change"]}, indent=2))
        finally:
            if not args.baseline_bin:
                subprocess.run(["git", "worktree", "remove", "--force", str(base_tree)],
                               cwd=ROOT, check=False, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
