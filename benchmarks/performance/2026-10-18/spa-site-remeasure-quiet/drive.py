import json, os, statistics as st, subprocess, sys, time

P = "/tmp/claude-1000/-mnt-philips-hacking-revweb/294094c1-19f8-4c1b-8ff7-8b95d5c3632e/scratchpad/perf"
SCRIPT = "/mnt/philips/hacking/revweb/.claude/worktrees/agent-ac0213dd7035e5856/scripts/benchmark_performance.py"
base = sys.argv[1]
cur = sys.argv[2]
tag = sys.argv[3]
seeds = [int(s) for s in sys.argv[4:]]
for seed in seeds:
    out = f"{P}/{tag}-s{seed}"
    os.makedirs(out, exist_ok=True)
    l0 = os.getloadavg()[0]
    subprocess.run([sys.executable, SCRIPT, "--baseline-ref", "61b843d", "--baseline-bin", base,
                    "--current-bin", cur, "--runs", "30", "--pages", "120", "--profile", "site",
                    "--seed", str(seed), "--output", out], check=True, stdout=subprocess.DEVNULL,
                   cwd="/mnt/philips/hacking/revweb/.claude/worktrees/agent-ac0213dd7035e5856")
    d = json.load(open(f"{out}/results.json"))
    b, c, r = d["summaries"]["baseline"], d["summaries"]["current"], d["relative_change"]
    print(f"{tag} seed={seed} load0={l0:.1f} load1={os.getloadavg()[0]:.1f} "
          f"p95 b={b['runtime_p95_seconds']*1000:.1f} c={c['runtime_p95_seconds']*1000:.1f} ({r['runtime_p95_percent']:+.1f}%) "
          f"med b={b['runtime_median_seconds']*1000:.1f} c={c['runtime_median_seconds']*1000:.1f} | "
          f"rss med b={b['max_rss_kib_median']:.0f} c={c['max_rss_kib_median']:.0f} ({r['median_rss_percent']:+.1f}%) "
          f"max {r['max_rss_percent']:+.1f}%", flush=True)
    time.sleep(2)
