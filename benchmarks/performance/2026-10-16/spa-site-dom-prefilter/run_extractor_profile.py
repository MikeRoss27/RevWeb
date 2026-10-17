#!/usr/bin/env python3
"""Build and run the archived direct-extractor profiler against a workspace."""
import argparse
import json
import os
import pathlib
import platform
import subprocess
import shutil


ARCHIVE = pathlib.Path(__file__).resolve().parent
ROOT = next(p for p in ARCHIVE.parents if (p / "Cargo.toml").is_file() and (p / "crates").is_dir())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=pathlib.Path, default=ROOT)
    parser.add_argument("--fixture-assets", type=pathlib.Path,
                        default=ARCHIVE / "fixture" / "assets")
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--target-dir", type=pathlib.Path)
    parser.add_argument("--allow-lock-update", action="store_true",
                        help="allow Cargo to reconcile a copied lockfile with an older checkout")
    args = parser.parse_args()
    workspace = args.workspace.resolve()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    examples = workspace / "crates" / "webrev-extract" / "examples"
    examples_existed = examples.exists()
    examples.mkdir(parents=True, exist_ok=True)
    example_name = f"extractor_profile_diag_{os.getpid()}"
    example_source = examples / f"{example_name}.rs"
    example_source.write_bytes((ARCHIVE / "extractor_profile.rs").read_bytes())
    try:
        command = ["cargo", "run", "--offline", "--release", "-p",
                   "webrev-extract", "--example", example_name, "--",
                   str(args.fixture_assets.resolve()), str(output)]
        if not args.allow_lock_update:
            command.insert(2, "--locked")
        env = dict(os.environ)
        if args.target_dir:
            env["CARGO_TARGET_DIR"] = str(args.target_dir.resolve())
        subprocess.run(command, cwd=workspace, env=env, check=True)
    finally:
        example_source.unlink(missing_ok=True)
        if not examples_existed:
            try:
                examples.rmdir()
            except OSError:
                pass
    metadata = {
        "workspace": str(workspace),
        "workspace_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=workspace, text=True).strip(),
        "workspace_dirty": bool(subprocess.check_output(
            ["git", "status", "--porcelain"], cwd=workspace, text=True).strip()),
        "toolchain": subprocess.check_output(["rustc", "-V"], cwd=workspace, text=True).strip(),
        "platform": platform.platform(),
        "fixture_assets": str(args.fixture_assets.resolve()),
        "output": str(output),
        "mode": "direct extractor calls; no network or scanner pipeline",
    }
    output.with_suffix(".metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
