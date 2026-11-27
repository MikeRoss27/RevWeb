//! A malformed `--header` / `--cookie` must stop the run with a usage error
//! (exit 2 plus a hint) instead of silently dropping the credential.

use std::process::Command;

fn run(flag: &str, value: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_webrev"))
        .args([
            "--no-banner",
            "static",
            "--seed",
            "http://127.0.0.1:9/",
            flag,
            value,
        ])
        .output()
        .unwrap()
}

#[test]
fn malformed_header_and_cookie_exit_2_with_a_hint() {
    for (flag, value) in [("--header", "MalformedNoColon"), ("--cookie", "nocookieeq")] {
        let out = run(flag, value);
        assert_eq!(out.status.code(), Some(2), "{flag}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("malformed"), "{stderr}");
        assert!(stderr.contains("hint:"), "{stderr}");
        assert!(!stderr.contains(value), "value echoed: {stderr}");
    }
}
