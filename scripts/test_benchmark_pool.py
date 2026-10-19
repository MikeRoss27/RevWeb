import random
import unittest

import benchmark_pool
from benchmark_performance import percentile95


def invocation(name, base, cur, base_rss=19000, cur_rss=21000, max_load=1.0, failures=0):
    return {"name": name, "max_load": max_load, "failures": failures,
            "time": {"baseline": base, "current": cur},
            "rss": {"baseline": [base_rss] * len(base), "current": [cur_rss] * len(cur)}}


def noisy(seed, factor, n=30, spread=0.15):
    rng = random.Random(seed)
    return [0.075 * factor * (1 + rng.uniform(-spread, spread)) for _ in range(n)]


class BootstrapTests(unittest.TestCase):
    def test_constant_ratio_gives_a_degenerate_interval(self):
        invs = [invocation(f"i{k}", [1.0] * 30, [1.1] * 30) for k in range(3)]
        low, high = benchmark_pool.bootstrap(invs, percentile95)
        self.assertAlmostEqual(low, 10.0, places=6)
        self.assertAlmostEqual(high, 10.0, places=6)

    def test_fixed_seed_is_deterministic(self):
        invs = [invocation(f"i{k}", noisy(k, 1.0), noisy(k + 50, 1.15)) for k in range(4)]
        first = benchmark_pool.bootstrap(invs, percentile95)
        second = benchmark_pool.bootstrap(invs, percentile95)
        self.assertEqual(first, second)
        self.assertLess(first[0], first[1])

    def test_interval_brackets_the_point_estimate(self):
        invs = [invocation(f"i{k}", noisy(k, 1.0), noisy(k + 50, 1.15)) for k in range(5)]
        low, high = benchmark_pool.bootstrap(invs, percentile95)
        point = benchmark_pool._ratio_percent(invs, percentile95)
        self.assertLessEqual(low, point)
        self.assertGreaterEqual(high, point)


class JudgeTests(unittest.TestCase):
    def make(self, factor, count=4, **kwargs):
        return [invocation(f"i{k}", noisy(k, 1.0), noisy(k + 50, factor), **kwargs)
                for k in range(count)]

    def test_pass_when_estimate_and_upper_bound_are_inside(self):
        report = benchmark_pool.judge(self.make(1.05))
        self.assertEqual(report["verdict"], "pass")
        self.assertLess(report["p95_percent"]["ci95"][1], 20.0)

    def test_fail_when_estimate_exceeds_the_limit(self):
        report = benchmark_pool.judge(self.make(1.40))
        self.assertEqual(report["verdict"], "fail")

    def test_not_demonstrated_when_only_the_upper_bound_exceeds(self):
        # A small noisy pool: estimate below the limit, interval reaching above it.
        invs = [invocation(f"i{k}", noisy(k, 1.0, spread=0.6), noisy(k + 50, 1.17, spread=0.6))
                for k in range(3)]
        report = benchmark_pool.judge(invs)
        self.assertEqual(report["verdict"], "not_demonstrated")
        self.assertLessEqual(report["p95_percent"]["estimate"], 20.0)
        self.assertGreater(report["p95_percent"]["ci95"][1], 20.0)

    def test_loaded_invocations_are_excluded_and_listed(self):
        invs = self.make(1.05) + [invocation("loaded", noisy(9, 1.0), noisy(10, 3.0), max_load=9.0)]
        report = benchmark_pool.judge(invs)
        self.assertEqual(report["invocations_clean"], 4)
        self.assertEqual([e["name"] for e in report["excluded"]], ["loaded"])
        self.assertEqual(report["verdict"], "pass")

    def test_failed_runs_exclude_the_invocation(self):
        invs = self.make(1.05) + [invocation("broken", noisy(9, 1.0), noisy(10, 1.0), failures=1)]
        self.assertEqual(benchmark_pool.judge(invs)["invocations_clean"], 4)

    def test_too_few_invocations_or_runs_is_insufficient(self):
        self.assertEqual(benchmark_pool.judge(self.make(1.05, count=2))["verdict"], "insufficient")
        short = [invocation(f"i{k}", noisy(k, 1.0, n=10), noisy(k + 50, 1.05, n=10)) for k in range(3)]
        self.assertEqual(benchmark_pool.judge(short)["verdict"], "insufficient")

    def test_rss_max_over_the_limit_fails(self):
        report = benchmark_pool.judge(self.make(1.0, cur_rss=26000))
        self.assertEqual(report["verdict"], "fail")

    def test_anomalous_baseline_is_flagged_not_dropped(self):
        invs = self.make(1.05, count=4)
        invs.append(invocation("cold", noisy(7, 1.0), noisy(8, 1.05), base_rss=14000))
        report = benchmark_pool.judge(invs)
        self.assertEqual(report["anomalous_baseline_invocations"], ["cold"])
        self.assertEqual(report["invocations_clean"], 5)

    def test_legacy_count_reports_single_invocation_overshoots(self):
        report = benchmark_pool.judge(self.make(1.05))
        self.assertEqual(report["legacy_criterion"]["of"], 4)
        self.assertIn("verdict:", benchmark_pool.render(report))


if __name__ == "__main__":
    unittest.main()
