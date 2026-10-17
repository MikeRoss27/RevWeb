"""Keep Rust source files focused; document exceptional large files explicitly."""

from pathlib import Path

MAX_LINES = 600
# A larger file requires a concrete reason here, tied to its relative path.
EXCEPTIONS: dict[str, str] = {
    # The SWC taint visitor, parser setup, and fallback reporting share span
    # tracking; splitting them further would require widening several private
    # interfaces. Keep the regression tests in a separate sibling module.
    "crates/webrev-extract/src/extractors/metadata/domsinks.rs": (
        "AST taint analysis and regex fallback share source-span suppression"
    ),
}


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    largest = (0, "")
    failures = []
    for path in sorted((root / "crates").rglob("*.rs")):
        name = path.relative_to(root).as_posix()
        lines = len(path.read_text(encoding="utf-8").splitlines())
        largest = max(largest, (lines, name))
        if lines > MAX_LINES and not EXCEPTIONS.get(name, "").strip():
            failures.append(f"{name}: {lines} lines (limit {MAX_LINES})")
    for failure in failures:
        print(failure)
    print(f"Largest Rust file: {largest[0]} lines ({largest[1]})")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
