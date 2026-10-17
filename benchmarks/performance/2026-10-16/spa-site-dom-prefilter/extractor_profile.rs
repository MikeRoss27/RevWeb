use std::{env, fs, hint::black_box, path::PathBuf, time::Instant};
use webrev_core::SessionId;
use webrev_extract::{
    extractors::{
        BucketExtractor, ConfigExtractor, CspExtractor, DomSinkExtractor, GhostEndpointExtractor,
        GraphQlExtractor, JsAstExtractor, JsRegexExtractor, JwtExtractor, ManifestExtractor,
        ParamExtractor, SecretExtractor, SourceMapExtractor, SpaRouteExtractor, TechExtractor,
        WasmExtractor,
    },
    ContentKind, ExtractInput, Extractor,
};

fn make_extractors() -> Vec<Box<dyn Extractor>> {
    vec![
        Box::new(JsAstExtractor::new()),
        Box::new(JsRegexExtractor::new()),
        Box::new(SecretExtractor::with_random_key()),
        Box::new(SourceMapExtractor::new()),
        Box::new(TechExtractor::new()),
        Box::new(GraphQlExtractor::new()),
        Box::new(SpaRouteExtractor::new()),
        Box::new(ParamExtractor::new()),
        Box::new(ConfigExtractor::new()),
        Box::new(ManifestExtractor::new()),
        Box::new(BucketExtractor::new()),
        Box::new(JwtExtractor::new()),
        Box::new(DomSinkExtractor::new()),
        Box::new(CspExtractor::new()),
        Box::new(GhostEndpointExtractor::new()),
        Box::new(WasmExtractor::new()),
    ]
}

fn percentile95(values: &[u64]) -> u64 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[((95 * sorted.len()).div_ceil(100)).saturating_sub(1)]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let fixture = PathBuf::from(args.next().ok_or("missing fixture/assets path")?);
    let output = PathBuf::from(args.next().ok_or("missing output path")?);
    let rounds = 20usize;

    let mut files = fs::read_dir(&fixture)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "js"))
        .collect::<Vec<_>>();
    files.sort();
    let inputs = files
        .iter()
        .map(|path| {
            Ok(ExtractInput::new(
                SessionId::new(),
                Some(format!(
                    "http://127.0.0.1/assets/{}",
                    path.file_name().unwrap().to_string_lossy()
                )),
                ContentKind::JavaScript,
                fs::read_to_string(path)?,
            ))
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;

    let extractors = make_extractors();
    let mut rows = Vec::new();
    let mut summaries = Vec::new();
    for extractor in extractors {
        let name = extractor.name();
        let applicable = inputs
            .iter()
            .filter(|input| extractor.applies_to(input))
            .collect::<Vec<_>>();
        let mut per_resource = Vec::new();
        let mut round_totals = vec![0u64; rounds];
        let mut findings_total = 0usize;

        for input in &applicable {
            // Warm up allocator, regex/JIT-like caches, and code paths equally.
            for _ in 0..3 {
                black_box(extractor.extract(input));
            }
            let mut samples = Vec::with_capacity(rounds);
            let mut findings_per_call = Vec::with_capacity(rounds);
            for round in 0..rounds {
                let start = Instant::now();
                let findings = black_box(extractor.extract(input));
                let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
                round_totals[round] = round_totals[round].saturating_add(elapsed);
                findings_total += findings.len();
                findings_per_call.push(findings.len());
                samples.push(elapsed);
            }
            per_resource.push(serde_json::json!({
                "resource": input.url.as_deref(),
                "bytes": input.body.len(),
                "sample_ns": samples,
                "findings_per_call": findings_per_call,
            }));
        }

        let median_ns = {
            let mut sorted = round_totals.clone();
            sorted.sort_unstable();
            (sorted[rounds / 2 - 1] + sorted[rounds / 2]) / 2
        };
        summaries.push(serde_json::json!({
            "extractor": name,
            "resources": applicable.len(),
            "rounds": rounds,
            "round_total_median_ns": median_ns,
            "round_total_p95_ns": percentile95(&round_totals),
            "mean_findings_per_round": findings_total / rounds,
            "round_total_sample_ns": round_totals,
        }));
        rows.push(serde_json::json!({"extractor": name, "resources": per_resource}));
    }
    let result = serde_json::json!({
        "schema": 1,
        "rounds_per_resource": rounds,
        "warmup_calls_per_resource": 3,
        "workload": "direct extractor calls on the 11 JS assets from the SPA fixture; no HTTP, pipeline, deduplication, or report serialization",
        "summaries": summaries,
        "per_resource_raw": rows,
    });
    fs::write(output, serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}
