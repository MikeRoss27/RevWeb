import glob, json, statistics as st, sys

P = "/tmp/claude-1000/-mnt-philips-hacking-revweb/294094c1-19f8-4c1b-8ff7-8b95d5c3632e/scratchpad/perf"


def p95(v):
    v = sorted(v)
    return v[max(0, (95 * len(v) + 99) // 100 - 1)]


files = []
for pat in sys.argv[1:]:
    files += sorted(glob.glob(P + "/" + pat))
t = {"baseline": [], "current": []}
r = {"baseline": [], "current": []}
for f in files:
    d = json.load(open(f))
    for x in d["raw_runs"]:
        t[x["revision"]].append(x["wall_seconds"] * 1000)
        r[x["revision"]].append(x["max_rss_kib"])
print(len(files), "files")
for k in t:
    print(k, len(t[k]), "p95 %.1f" % p95(t[k]), "med %.1f" % st.median(t[k]),
          "rss med", st.median(r[k]), "rss min", min(r[k]), "rss max", max(r[k]))
pct = lambda a, b: (a / b - 1) * 100
print("pooled p95 %+.1f%% | median time %+.1f%% | rss median %+.1f%% | rss max %+.1f%%" % (
    pct(p95(t["current"]), p95(t["baseline"])), pct(st.median(t["current"]), st.median(t["baseline"])),
    pct(st.median(r["current"]), st.median(r["baseline"])), pct(max(r["current"]), max(r["baseline"]))))
