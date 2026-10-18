import unittest

import coverage_summary


def entry(name, covered, count):
    return {"filename": name, "summary": {"lines": {"covered": covered, "count": count}}}


class RenderTests(unittest.TestCase):
    def report(self):
        files = [
            entry("/w/crates/a/src/x.rs", 90, 100),
            entry("/w/crates/a/src/y.rs", 5, 10),
            entry("/w/crates/b/src/z.rs", 0, 60),
        ]
        return {"data": [{"files": files, "totals": {"lines": {"covered": 95, "count": 170}}}]}

    def test_totals_and_crates(self):
        text = coverage_summary.render(self.report())
        self.assertIn("55.88%", text)
        self.assertIn("| a | 95 | 110 | 86.36% |", text)
        self.assertIn("| b | 0 | 60 | 0.00% |", text)

    def test_least_covered_skips_small_files_and_sorts(self):
        text = coverage_summary.render(self.report())
        self.assertNotIn("y.rs", text)
        self.assertLess(text.index("crates/b/src/z.rs"), text.index("crates/a/src/x.rs"))

    def test_empty_crate_does_not_divide_by_zero(self):
        self.assertEqual(coverage_summary.percent(0, 0), 0.0)


if __name__ == "__main__":
    unittest.main()
