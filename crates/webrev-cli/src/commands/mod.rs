// crates/webrev-cli/src/commands/mod.rs
//! Subcommand handlers. Each is a thin function that builds the mission and
//! drives the appropriate library.

mod active_scan;
mod bola;
mod compare;
mod dynamic_scan;
mod output;
mod report;
mod scan;
mod static_scan;
mod ws_replay;

use crate::cli::{Cli, Command, ScanArgs};
use serde_json::Value;
use webrev_core::{AuthConfig, EgressPolicy, Mission, MissionProfile, OpsecConfig, Scope};
use webrev_tui::TuiOptions;

/// One line on stderr when a raw report lands on disk: it holds whatever the
/// scan captured, credentials included, so it is confidential until masked.
fn warn_if_raw(redact: bool) {
    if !redact {
        eprintln!(
            "warning: the report is raw and holds captured credentials; keep it private or re-export with --redact before sharing"
        );
    }
}

/// Export a standalone scan while its session is still in memory.
async fn write_session_report(
    mission: &Mission,
    storage: &dyn webrev_storage::Storage,
    path: &std::path::Path,
    redact: bool,
) -> anyhow::Result<()> {
    let findings = storage.findings_by_session(mission.id).await?;
    let endpoints = storage.endpoints_by_session(mission.id).await?;
    let report = webrev_report::SessionReport::build(mission.clone(), findings, endpoints);
    if path == std::path::Path::new("-") {
        report::write_stdout(&report.export_json(redact)?)?;
    } else {
        output::show(&report)?;
        std::fs::write(path, report.export_json(redact)?)?;
        eprintln!("report written to {}", path.display());
        warn_if_raw(redact);
    }
    Ok(())
}

/// Resolve the seed list: explicit `--seed` values, plus stdin (one URL per
/// line) when `--stdin` is set or no seeds were given and stdin is piped. This
/// lets webrev sit at the end of a recon pipeline
/// (`subfinder -d x.com | httpx | webrev static`).
fn resolve_seeds(args: &ScanArgs) -> anyhow::Result<Vec<String>> {
    use std::io::{BufRead, IsTerminal};

    let mut seeds = args.seeds.clone();
    let want_stdin = args.stdin || (seeds.is_empty() && !std::io::stdin().is_terminal());
    if want_stdin {
        for line in std::io::stdin().lock().lines() {
            let line = line?;
            let url = line.trim();
            if !url.is_empty() && !url.starts_with('#') {
                seeds.push(url.to_owned());
            }
        }
    }

    // De-duplicate while preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    seeds.retain(|s| seen.insert(s.clone()));

    if seeds.is_empty() {
        anyhow::bail!(
            "no seeds: pass --seed <URL> (repeatable) or pipe URLs on stdin (one per line)"
        );
    }
    Ok(seeds)
}

/// Translate shared scan arguments into a mission and its opsec config.
/// When no explicit scope is given, the seeds' own hosts become the scope.
fn build_mission(args: &ScanArgs) -> anyhow::Result<(Mission, OpsecConfig)> {
    let seeds = resolve_seeds(args)?;
    let file_scope = args
        .scope_file
        .as_deref()
        .map(read_scope_file)
        .transpose()?;
    let scope = merge_scope(file_scope, &args.scope, &args.exclude, &seeds)?;
    let mission = Mission::new(args.name.clone(), scope, seeds);
    let auth = AuthConfig {
        headers: args
            .headers
            .iter()
            .filter_map(|h| h.split_once(':'))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect(),
        cookies: args
            .cookies
            .iter()
            .filter_map(|c| c.split_once('='))
            .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
            .collect(),
        bearer: args.bearer.clone(),
    };
    let opsec = OpsecConfig {
        egress: EgressPolicy {
            proxy: args.proxy.clone(),
            allow_direct: true,
        },
        delay_min_ms: args.delay_min_ms,
        delay_max_ms: args.delay_max_ms,
        max_pages: args.max_pages,
        max_depth: args.max_depth,
        max_concurrency: args.max_concurrency.max(1),
        auth,
        active: webrev_core::ActiveLimits {
            max_requests: args.max_active_requests,
            ..webrev_core::ActiveLimits::default()
        },
        ..OpsecConfig::default()
    };
    Ok((mission, opsec))
}

fn merge_scope(
    file_scope: Option<Scope>,
    cli_include: &[String],
    cli_exclude: &[String],
    seeds: &[String],
) -> anyhow::Result<Scope> {
    let mut include = file_scope
        .as_ref()
        .map_or_else(Vec::new, |scope| scope.include.clone());
    include.extend(normalize_scope_hosts(cli_include)?);
    let include = if include.is_empty() {
        seeds
            .iter()
            .filter_map(|s| Scope::host_of(s).map(str::to_owned))
            .collect()
    } else {
        include
    };
    let mut exclude = file_scope.map_or_else(Vec::new, |scope| scope.exclude);
    exclude.extend(normalize_scope_hosts(cli_exclude)?);
    Ok(Scope::new(include, exclude))
}

/// Read an explicit host-suffix allow/deny list. JSON is used here because it
/// is already a workspace dependency and makes malformed or ambiguous YAML
/// parsing unnecessary.
fn read_scope_file(path: &std::path::Path) -> anyhow::Result<Scope> {
    let bytes = std::fs::read(path)
        .map_err(|error| anyhow::anyhow!("reading scope file {}: {error}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|error| {
        anyhow::anyhow!("parsing scope file {} as JSON: {error}", path.display())
    })?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("scope file must be a JSON object"))?;
    for key in object.keys() {
        if key != "include" && key != "exclude" {
            anyhow::bail!("unknown scope file key {key:?}; expected include or exclude");
        }
    }
    let parse_hosts = |key: &str, required: bool| -> anyhow::Result<Vec<String>> {
        let Some(value) = object.get(key) else {
            if required {
                anyhow::bail!("scope file requires a non-empty `include` array");
            }
            return Ok(Vec::new());
        };
        let array = value.as_array().ok_or_else(|| {
            anyhow::anyhow!("scope file `{key}` must be an array of host strings")
        })?;
        let hosts = array
            .iter()
            .map(|entry| {
                entry.as_str().ok_or_else(|| {
                    anyhow::anyhow!("scope file `{key}` entries must be host strings")
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        normalize_scope_hosts(&hosts)
    };
    let include = parse_hosts("include", true)?;
    if include.is_empty() {
        anyhow::bail!("scope file requires a non-empty `include` array");
    }
    let exclude = parse_hosts("exclude", false)?;
    Ok(Scope::new(include, exclude))
}

fn normalize_scope_hosts(hosts: &[impl AsRef<str>]) -> anyhow::Result<Vec<String>> {
    hosts
        .iter()
        .map(|entry| {
            let host = entry.as_ref();
            if let Ok(network) = host.parse::<ipnet::IpNet>() {
                return Ok(network.to_string());
            }
            if let Ok(address) = host.parse::<std::net::IpAddr>() {
                return Ok(address.to_string());
            }
            validate_scope_host(host)?;
            Ok(host.trim_end_matches('.').to_ascii_lowercase())
        })
        .collect()
}

fn validate_scope_host(host: &str) -> anyhow::Result<()> {
    if host.is_empty()
        || host.trim() != host
        || host
            .chars()
            .any(|c| matches!(c, '/' | '?' | '#' | '@' | '*'))
        || host.contains("://")
    {
        anyhow::bail!("invalid scope host {host:?}; use a hostname or IP literal");
    }
    let domain = host.strip_suffix('.').unwrap_or(host);
    let valid = domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        anyhow::bail!("invalid scope host {host:?}; use a hostname or IP literal");
    }
    Ok(())
}

/// Dispatch the parsed CLI to its handler.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Command::Scan(args) => scan::run(args).await,
        Command::Static(args) => static_scan::run(args).await,
        Command::Dynamic(args) => dynamic_scan::run(args).await,
        Command::Active(args) => active_scan::run(args).await,
        Command::Report(args) => report::run(args),
        Command::Compare(args) => compare::run(args),
        Command::Bola(args) => bola::run(args).await,
        Command::WsReplay(args) => ws_replay::run(args).await,
        Command::Tui(args) => {
            anyhow::ensure!(!args.observation_only,
                "--observation-only is supported by dynamic and scan --dynamic; TUI browser exploration does not support this policy");
            let (mission, opsec) = build_mission(&args)?;
            webrev_tui::run(TuiOptions {
                profile: MissionProfile::new(mission, opsec),
                report_path: args.report,
                redact_report: args.redact,
            })
            .await
        }
    }
}

#[cfg(test)]
mod scope_file_tests {
    use super::*;
    use std::io::Write;

    fn scope_file(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file
    }

    #[test]
    fn parses_and_normalizes_explicit_host_scope() {
        let file = scope_file(r#"{"include":["Example.COM."],"exclude":["admin.example.com"]}"#);
        let scope = read_scope_file(file.path()).unwrap();
        assert!(scope.allows("https://api.example.com/path"));
        assert!(!scope.allows("https://admin.example.com/path"));
        assert!(!scope.allows("https://example.com.evil.test/path"));
    }

    #[test]
    fn scope_file_requires_nonempty_include_and_rejects_unknown_keys() {
        let missing = scope_file(r#"{"exclude":["private.example.com"]}"#);
        assert!(read_scope_file(missing.path()).is_err());
        let empty = scope_file(r#"{"include":[]}"#);
        assert!(read_scope_file(empty.path()).is_err());
        let typo = scope_file(r#"{"includes":["example.com"]}"#);
        assert!(read_scope_file(typo.path()).is_err());
    }

    #[test]
    fn rejects_url_and_wildcard_scope_entries() {
        let url = scope_file(r#"{"include":["https://example.com"]}"#);
        assert!(read_scope_file(url.path()).is_err());
        let wildcard = scope_file(r#"{"include":["*.example.com"]}"#);
        assert!(read_scope_file(wildcard.path()).is_err());
    }

    #[test]
    fn accepts_cidrs_and_rejects_malformed_networks() {
        let file = scope_file(r#"{"include":["192.0.2.7/24","2001:db8:1::/48"]}"#);
        let scope = read_scope_file(file.path()).unwrap();
        assert!(scope.allows("http://192.0.2.99/"));
        assert!(!scope.allows("http://192.0.3.1/"));
        assert!(scope.allows("http://[2001:db8:1::9]/"));
        let malformed = scope_file(r#"{"include":["192.0.2.0/99"]}"#);
        assert!(read_scope_file(malformed.path()).is_err());
    }

    #[test]
    fn file_and_cli_lists_union_with_exclusions_preserved() {
        let file = scope_file(r#"{"include":["example.com"],"exclude":["admin.example.com"]}"#);
        let scope = merge_scope(
            Some(read_scope_file(file.path()).unwrap()),
            &["api.other.test".into()],
            &["private.other.test".into()],
            &["https://ignored.test/".into()],
        )
        .unwrap();
        assert!(scope.allows("https://www.example.com/"));
        assert!(scope.allows("https://api.other.test/"));
        assert!(!scope.allows("https://admin.example.com/"));
        assert!(!scope.allows("https://private.other.test/"));
        assert!(!scope.allows("https://ignored.test/"));
    }

    #[test]
    fn seed_scope_fallback_remains_when_no_explicit_include_is_given() {
        let scope =
            merge_scope(None, &[], &[], &["https://seed.example.test/path".into()]).unwrap();
        assert!(scope.allows("https://seed.example.test/"));
        assert!(!scope.allows("https://other.example.test/"));
    }
}
