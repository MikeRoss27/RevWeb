"""Render a `cargo llvm-cov --json --summary-only` report as Markdown.

Informational only: it prints a measurement and never fails on a low number.
"""

import json
import sys
from collections import defaultdict

# Files with fewer lines than this are left out of the "least covered" table so
# a tiny module cannot top it.
MIN_LINES = 50
LEAST_COVERED = 15


def crate_of(filename: str) -> str:
    parts = filename.replace("\\", "/").split("/")
    if "crates" in parts:
        index = parts.index("crates")
        if index + 1 < len(parts):
            return parts[index + 1]
    return "(other)"


def relative(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    marker = "/crates/"
    if marker in normalized:
        return "crates/" + normalized.split(marker, 1)[1]
    return normalized


def percent(covered: int, count: int) -> float:
    return 100.0 * covered / count if count else 0.0


def render(report: dict) -> str:
    data = report["data"][0]
    per_crate: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    files = []
    for entry in data["files"]:
        lines = entry["summary"]["lines"]
        per_crate[crate_of(entry["filename"])][0] += lines["covered"]
        per_crate[crate_of(entry["filename"])][1] += lines["count"]
        files.append((relative(entry["filename"]), lines["covered"], lines["count"]))

    totals = data["totals"]["lines"]
    out = ["## Line coverage (informational, no threshold)", ""]
    out.append(
        f"Workspace: **{percent(totals['covered'], totals['count']):.2f}%** "
        f"({totals['covered']}/{totals['count']} lines)"
    )
    out += ["", "| Crate | Lines covered | Lines | Coverage |", "|---|---:|---:|---:|"]
    for crate, (covered, count) in sorted(per_crate.items()):
        out.append(f"| {crate} | {covered} | {count} | {percent(covered, count):.2f}% |")

    sized = [item for item in files if item[2] >= MIN_LINES]
    sized.sort(key=lambda item: (percent(item[1], item[2]), item[0]))
    out += [
        "",
        f"Least covered files with at least {MIN_LINES} lines:",
        "",
        "| File | Lines covered | Lines | Coverage |",
        "|---|---:|---:|---:|",
    ]
    for name, covered, count in sized[:LEAST_COVERED]:
        out.append(f"| {name} | {covered} | {count} | {percent(covered, count):.2f}% |")
    out.append("")
    return "\n".join(out)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: coverage_summary.py <llvm-cov-summary.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        print(render(json.load(handle)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
