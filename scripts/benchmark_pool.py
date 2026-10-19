#!/usr/bin/env python3
"""Pool several paired benchmark invocations and judge them with an interval.

A single 30-run p95 is the 29th of 30 values and swings by about 15 points on the
same binaries, so the performance criterion in goal.md is applied to a pool of
clean invocations together with a two-level bootstrap confidence interval:
invocations are resampled first, then the runs inside each drawn invocation.

Usage: benchmark_pool.py RESULTS.json... [--max-load 4] [--output POOLED.json]
Also reachable as `benchmark_performance.py pool ...`.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import statistics
import sys

from benchmark_performance import percentile95

SEED = 20261019
ITERATIONS = 2000
CONFIDENCE = 0.95
MIN_INVOCATIONS = 3
MIN_RUNS = 90
P95_LIMIT = 20.0
RSS_LIMIT = 25.0
ANOMALY_FRACTION = 0.15


def load_invocation(path: pathlib.Path) -> dict:
    """Read one results.json into the shape the pooling code works on."""
    data = json.loads(path.read_text())
    rows = data["raw_runs"]
    return {
        "name": path.name,
        "max_load": max(r["loadavg_1m_after"] for r in rows),
        "failures": sum(r["exit_code"] != 0 for r in rows),
        "time": {rev: [r["wall_seconds"] for r in rows if r["revision"] == rev]
                 for rev in ("baseline", "current")},
        "rss": {rev: [r["max_rss_kib"] for r in rows if r["revision"] == rev]
                for rev in ("baseline", "current")},
    }


def _flatten(invocations: list[dict], key: str, rev: str) -> list[float]:
    return [v for inv in invocations for v in inv[key][rev]]


def _ratio_percent(invocations: list[dict], stat) -> float:
    base = stat(_flatten(invocations, "time", "baseline"))
    cur = stat(_flatten(invocations, "time", "current"))
    return (cur / base - 1) * 100


def bootstrap(invocations: list[dict], stat, seed: int = SEED,
              iterations: int = ITERATIONS, confidence: float = CONFIDENCE,
              key: str = "time") -> tuple[float, float]:
    """Two-level percentile bootstrap of `stat(current) / stat(baseline) - 1`."""
    rng = random.Random(seed)
    estimates = []
    for _ in range(iterations):
        drawn = [invocations[rng.randrange(len(invocations))] for _ in invocations]
        sample = []
        for inv in drawn:
            resampled = {key: {}}
            for rev in ("baseline", "current"):
                values = inv[key][rev]
                resampled[key][rev] = [values[rng.randrange(len(values))] for _ in values]
            sample.append(resampled)
        base = stat(_flatten(sample, key, "baseline"))
        cur = stat(_flatten(sample, key, "current"))
        estimates.append((cur / base - 1) * 100)
    estimates.sort()
    low = estimates[int((1 - confidence) / 2 * (iterations - 1))]
    high = estimates[int((1 + confidence) / 2 * (iterations - 1) + 0.5)]
    return low, high


def anomalous_baselines(invocations: list[dict]) -> list[str]:
    """Invocations whose baseline RSS median is >15% from the others' median."""
    medians = [statistics.median(inv["rss"]["baseline"]) for inv in invocations]
    flagged = []
    for index, inv in enumerate(invocations):
        others = medians[:index] + medians[index + 1:]
        if not others:
            continue
        reference = statistics.median(others)
        if abs(medians[index] / reference - 1) > ANOMALY_FRACTION:
            flagged.append(inv["name"])
    return flagged


def judge(invocations: list[dict], max_load: float = 4.0) -> dict:
    clean = [i for i in invocations if i["max_load"] < max_load and i["failures"] == 0]
    excluded = [{"name": i["name"], "max_load": i["max_load"], "failures": i["failures"]}
                for i in invocations if i not in clean]
    runs = min((len(_flatten(clean, "time", rev)) for rev in ("baseline", "current")),
               default=0)
    report = {"invocations_total": len(invocations), "invocations_clean": len(clean),
              "excluded": excluded, "runs_per_revision": runs,
              "max_load_limit": max_load, "seed": SEED, "iterations": ITERATIONS}
    if len(clean) < MIN_INVOCATIONS or runs < MIN_RUNS:
        report["verdict"] = "insufficient"
        report["reason"] = (f"needs >= {MIN_INVOCATIONS} clean invocations and >= "
                            f"{MIN_RUNS} runs per revision, have {len(clean)} and {runs}")
        return report

    p95_low, p95_high = bootstrap(clean, percentile95)
    med_low, med_high = bootstrap(clean, statistics.median)
    rss_med_low, rss_med_high = bootstrap(clean, statistics.median, key="rss")
    p95 = _ratio_percent(clean, percentile95)
    rss_max = (max(_flatten(clean, "rss", "current"))
               / max(_flatten(clean, "rss", "baseline")) - 1) * 100
    report["p95_percent"] = {"estimate": p95, "ci95": [p95_low, p95_high]}
    report["median_time_percent"] = {"estimate": _ratio_percent(clean, statistics.median),
                                     "ci95": [med_low, med_high]}
    rss_median = (statistics.median(_flatten(clean, "rss", "current"))
                  / statistics.median(_flatten(clean, "rss", "baseline")) - 1) * 100
    report["rss_median_percent"] = {"estimate": rss_median, "ci95": [rss_med_low, rss_med_high]}
    report["rss_max_percent"] = rss_max
    report["p95_ms"] = {rev: percentile95(_flatten(clean, "time", rev)) * 1000
                        for rev in ("baseline", "current")}
    report["anomalous_baseline_invocations"] = anomalous_baselines(clean)
    report["per_invocation_p95_percent"] = [
        {"name": i["name"], "p95_percent": _ratio_percent([i], percentile95)} for i in clean]
    report["legacy_criterion"] = {
        "invocations_over_limit": sum(
            row["p95_percent"] > P95_LIMIT for row in report["per_invocation_p95_percent"]),
        "of": len(clean)}

    if p95 > P95_LIMIT or rss_max > RSS_LIMIT:
        report["verdict"] = "fail"
    elif p95_high > P95_LIMIT:
        report["verdict"] = "not_demonstrated"
        report["reason"] = ("the estimate is within the limit but the upper bound of "
                            "the 95% interval is above it")
    else:
        report["verdict"] = "pass"
    return report


def render(report: dict) -> str:
    lines = [f"invocations: {report['invocations_clean']} clean of "
             f"{report['invocations_total']}, {report['runs_per_revision']} runs per revision"]
    for item in report["excluded"]:
        lines.append(f"  excluded {item['name']}: load {item['max_load']:.1f}, "
                     f"{item['failures']} failure(s)")
    if report["verdict"] == "insufficient":
        lines.append(f"verdict: insufficient - {report['reason']}")
        return "\n".join(lines)
    p95, med = report["p95_percent"], report["median_time_percent"]
    rss = report["rss_median_percent"]
    lines += [
        f"p95   {report['p95_ms']['baseline']:.1f} -> {report['p95_ms']['current']:.1f} ms: "
        f"{p95['estimate']:+.1f}% (95% CI {p95['ci95'][0]:+.1f}% .. {p95['ci95'][1]:+.1f}%), "
        f"limit +{P95_LIMIT:.0f}%",
        f"median time {med['estimate']:+.1f}% (95% CI {med['ci95'][0]:+.1f}% .. "
        f"{med['ci95'][1]:+.1f}%), indicative",
        f"RSS median {rss['estimate']:+.1f}% (95% CI {rss['ci95'][0]:+.1f}% .. "
        f"{rss['ci95'][1]:+.1f}%); RSS max {report['rss_max_percent']:+.1f}%, "
        f"limit +{RSS_LIMIT:.0f}%",
        f"legacy single-invocation p95 over limit: {report['legacy_criterion']['invocations_over_limit']}"
        f" of {report['legacy_criterion']['of']}",
    ]
    if report["anomalous_baseline_invocations"]:
        lines.append("anomalous baseline RSS: " + ", ".join(report["anomalous_baseline_invocations"]))
    lines.append(f"verdict: {report['verdict']}" + (f" - {report['reason']}" if "reason" in report else ""))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("results", nargs="+", type=pathlib.Path)
    ap.add_argument("--max-load", type=float, default=4.0)
    ap.add_argument("--output", type=pathlib.Path)
    args = ap.parse_args(argv)
    report = judge([load_invocation(p) for p in args.results], args.max_load)
    print(render(report))
    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
