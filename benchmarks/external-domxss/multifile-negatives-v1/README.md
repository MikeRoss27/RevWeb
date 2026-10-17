# Multi-file DOM XSS negative set (v1)

**Maintainer-authored, not independent.** No public multi-file DOM XSS dataset
with negative labels was found (the upstream `multifile-domxss-dataset` is
positive-only, Firing Range's DOM templates are all vulnerable by design).
These 20 cases mirror the negative patterns of the third-party SWIPE set
(branch-only use, numeric results, constant outputs, sanitizers) and add the
module/branch/loop/helper shapes that Webrev's export summaries handle.

Every case is labelled `negative`: no attacker-controlled value reaches an
HTML or code sink. The set can reveal false positives of cross-file linking; it
cannot estimate precision, and a zero count only means these shapes are handled.

```sh
cargo test -p webrev-extract --test domxss_multifile_negatives -- --nocapture
```
