//! `--format urls-exact` and `--format requests` list the concrete URLs the scan
//! found, with real path ids and query strings, ready to pipe into a fuzzer or
//! a replay tool. The `urls` format keeps listing normalised route templates.

mod common;

use common::{cli, scan_args, success, Fixture, SECRET};

fn export(fixture: &Fixture, format: &str, extra: &[&str]) -> String {
    let dir = tempfile::tempdir().unwrap();
    let mut args = scan_args("scan", fixture);
    args.extend(["--format", format, "--report", "-"]);
    args.extend(extra);
    let output = cli(dir.path(), &args);
    success(&output);
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn urls_exact_keeps_real_ids_and_query_strings_unlike_urls() {
    let fixture = Fixture::new();
    let base = fixture.url.trim_end_matches('/').to_owned();

    let exact = export(&fixture, "urls-exact", &[]);
    assert!(
        exact
            .lines()
            .any(|line| line == format!("{base}/api/users/123?q=hello")),
        "{exact}"
    );
    assert!(
        exact
            .lines()
            .any(|line| line == format!("{base}/api/demo?token={SECRET}")),
        "{exact}"
    );
    assert!(!exact.contains('{'), "no route templates: {exact}");

    // The route-template listing is unchanged: ids collapsed, no query string.
    let templates = export(&fixture, "urls", &[]);
    assert!(templates.contains("/api/users/{id}"), "{templates}");
    assert!(!templates.contains("q=hello"), "{templates}");
}

#[test]
fn urls_exact_is_sorted_unique_and_stable_across_runs() {
    let fixture = Fixture::new();
    let first = export(&fixture, "urls-exact", &[]);
    let second = export(&fixture, "urls-exact", &[]);
    assert_eq!(first, second);
    let lines: Vec<&str> = first.lines().collect();
    assert!(!lines.is_empty());
    let mut expected = lines.clone();
    expected.sort_unstable();
    expected.dedup();
    assert_eq!(lines, expected, "sorted and de-duplicated");
}

#[test]
fn requests_prefix_each_url_with_its_method() {
    let fixture = Fixture::new();
    let base = fixture.url.trim_end_matches('/').to_owned();
    let requests = export(&fixture, "requests", &[]);
    assert!(
        requests
            .lines()
            .all(|line| line.split_once(' ').is_some_and(|(method, url)| {
                method.chars().all(|c| c.is_ascii_uppercase()) && url.starts_with("http")
            })),
        "{requests}"
    );
    assert!(
        requests
            .lines()
            .any(|line| line.ends_with(&format!("{base}/api/users/123?q=hello"))),
        "{requests}"
    );
}

#[test]
fn redact_masks_credentials_in_exact_urls_but_keeps_object_ids() {
    let fixture = Fixture::new();
    let base = fixture.url.trim_end_matches('/').to_owned();
    for format in ["urls-exact", "requests"] {
        let masked = export(&fixture, format, &["--redact"]);
        assert!(!masked.contains(SECRET), "{format}: {masked}");
        assert!(
            masked.contains(&format!("{base}/api/users/123?q=hello")),
            "{format}: {masked}"
        );
        assert!(masked.contains("token=[REDACTED]"), "{format}: {masked}");
    }
}
