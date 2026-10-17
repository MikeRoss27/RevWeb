// crates/webrev-pipeline/tests/integration.rs
//! End-to-end pipeline test over a local HTML fixture, with no network I/O.
//!
//! Seeds the pipeline with the fixture as `Content`, runs
//! `static-extract -> store` against `InMemoryStorage`, and asserts that the
//! endpoints and source map embedded in the page are discovered and persisted.

use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use webrev_core::{
    Confidence, EndpointConfidence, Finding, FindingKind, Mission, OpsecConfig, Provenance, Scope,
    Source,
};
use webrev_extract::{ContentKind, ExtractorRegistry};
use webrev_pipeline::stages::{StaticExtractStage, StoreStage};
use webrev_pipeline::{PipelineBuilder, PipelineItem, StageContext};
use webrev_storage::{InMemoryStorage, Storage};

#[tokio::test]
async fn pipeline_extracts_and_stores_fixture_findings() {
    let html = include_str!("fixtures/sample.html");

    let mission = Mission::new(
        "fixture",
        Scope::new(vec!["fixture.test".into()], vec![]),
        vec![],
    );
    let session_id = mission.id;

    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
    storage.create_session(&mission).await.expect("session");

    let ctx = StageContext::new(
        Arc::new(mission),
        Arc::new(OpsecConfig::default()),
        Arc::new(ExtractorRegistry::with_defaults()),
        Arc::clone(&storage),
        CancellationToken::new(),
    );

    let summary = PipelineBuilder::new()
        .add_stage(Arc::new(StaticExtractStage::new()))
        .add_stage(Arc::new(StoreStage::new()))
        .run(
            ctx,
            vec![PipelineItem::Content {
                url: Some("https://fixture.test/index.html".into()),
                kind: ContentKind::Html,
                body: html.to_owned(),
                headers: vec![("Server".to_owned(), "nginx".to_owned())],
                bytes: None,
            }],
        )
        .await
        .expect("pipeline run");

    assert_eq!(summary.errors, 0, "no stage should error");
    assert_eq!(summary.stages, vec!["static-extract", "store"]);

    let stored = storage
        .findings_by_session(session_id)
        .await
        .expect("read findings");

    let endpoints = stored
        .iter()
        .filter(|f| f.kind == FindingKind::Endpoint)
        .count();
    let sourcemaps = stored
        .iter()
        .filter(|f| f.kind == FindingKind::SourceMap)
        .count();

    assert!(
        endpoints >= 2,
        "expected >= 2 endpoints, got {endpoints}: {stored:#?}"
    );
    assert!(sourcemaps >= 1, "expected >= 1 sourcemap, got {sourcemaps}");

    // The embedded AWS-style key retains plaintext alongside its dedup fingerprint.
    let secrets: Vec<&webrev_core::Finding> = stored
        .iter()
        .filter(|f| f.kind == FindingKind::Secret)
        .collect();
    assert!(!secrets.is_empty(), "expected >= 1 secret finding");
    for secret in &secrets {
        assert!(
            secret.value.starts_with("fp:"),
            "secret must be a fingerprint"
        );
        assert!(
            secret.plaintext.is_some(),
            "detected secrets must retain plaintext"
        );
    }
    assert!(secrets
        .iter()
        .any(|secret| { secret.plaintext.as_deref() == Some("AKIAZ4XB7NMPQR2STUVW") }));

    // The store stage reports exactly the unique findings it persisted.
    assert_eq!(summary.findings_emitted, stored.len());

    // Endpoints discovered from the inline script are present.
    let urls: Vec<&str> = stored.iter().filter_map(|f| f.url.as_deref()).collect();
    assert!(urls.contains(&"/api/v1/me"));
    assert!(urls.contains(&"https://api.fixture.test/v1/login"));

    // The enriched extractors (tech / GraphQL / SPA routes) also flow through.
    let has = |kind: FindingKind, needle: &str| {
        stored
            .iter()
            .any(|f| f.kind == kind && f.value.contains(needle))
    };
    assert!(has(FindingKind::Technology, "Supabase"), "tech detection");
    assert!(
        has(FindingKind::Technology, "nginx"),
        "header-based server detection"
    );
    assert!(has(FindingKind::GraphQl, "CurrentUser"), "graphql op");
    assert!(has(FindingKind::Route, "/dashboard"), "spa route");
}

#[tokio::test]
async fn endpoint_confidence_tracks_observation_and_pattern_inference() {
    let mission = Mission::new(
        "confidence",
        Scope::new(vec!["fixture.test".into()], vec![]),
        vec!["https://fixture.test".into()],
    );
    let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
    storage.create_session(&mission).await.unwrap();
    let ctx = StageContext::new(
        Arc::new(mission.clone()),
        Arc::new(OpsecConfig::default()),
        Arc::new(ExtractorRegistry::with_defaults()),
        Arc::clone(&storage),
        CancellationToken::new(),
    );
    let endpoint = |path: &str, source| {
        Finding::new(
            mission.id,
            FindingKind::Endpoint,
            Some(format!("https://fixture.test{path}")),
            format!("GET {path}"),
            Confidence::Medium,
            Provenance::new(source, None),
        )
    };
    PipelineBuilder::new()
        .add_stage(Arc::new(StoreStage::new()))
        .run(
            ctx,
            vec![
                PipelineItem::Finding(endpoint("/api/users", Source::JsAst)),
                PipelineItem::Finding(endpoint("/api/users", Source::Browser)),
                PipelineItem::Finding(endpoint("/api/users/123", Source::Browser)),
            ],
        )
        .await
        .unwrap();

    let endpoints = storage.endpoints_by_session(mission.id).await.unwrap();
    assert_eq!(endpoints.len(), 2);
    let exact = endpoints
        .iter()
        .find(|e| e.url.ends_with("/api/users"))
        .unwrap();
    assert_eq!(exact.source, Source::Browser);
    assert_eq!(exact.confidence, EndpointConfidence::Observed);
    let template = endpoints
        .iter()
        .find(|e| e.url.ends_with("/api/users/{id}"))
        .unwrap();
    assert_eq!(template.source, Source::Browser);
    assert_eq!(template.confidence, EndpointConfidence::Inferred);
}

#[tokio::test]
async fn static_stage_links_only_collected_modules_when_dom_detector_is_registered() {
    for enabled in [true, false] {
        let mission = Mission::new(
            "modules",
            Scope::new(vec!["fixture.test".into()], vec![]),
            vec![],
        );
        let session = mission.id;
        let storage: Arc<dyn Storage> = Arc::new(InMemoryStorage::new());
        storage.create_session(&mission).await.expect("session");
        let mut registry = ExtractorRegistry::new();
        if enabled {
            registry.register(Box::new(webrev_extract::extractors::DomSinkExtractor::new()));
        }
        let ctx = StageContext::new(
            Arc::new(mission),
            Arc::new(OpsecConfig::default()),
            Arc::new(registry),
            Arc::clone(&storage),
            CancellationToken::new(),
        );
        let seed = [
            ("source.js", "export const payload = location.hash;"),
            (
                "sink.js",
                "import {payload} from './source.js'; eval(payload);",
            ),
        ]
        .into_iter()
        .map(|(file, body)| PipelineItem::Content {
            url: Some(format!("https://fixture.test/{file}")),
            kind: ContentKind::JavaScript,
            body: body.to_owned(),
            headers: Vec::new(),
            bytes: None,
        })
        .collect();
        PipelineBuilder::new()
            .add_stage(Arc::new(StaticExtractStage::new()))
            .add_stage(Arc::new(StoreStage::new()))
            .run(ctx, seed)
            .await
            .expect("pipeline");
        let stored = storage
            .findings_by_session(session)
            .await
            .expect("findings");
        let flows: Vec<_> = stored
            .iter()
            .filter(|finding| finding.value == "DOM XSS: location.hash -> eval")
            .collect();
        assert_eq!(flows.len(), usize::from(enabled));
        if enabled {
            assert_eq!(flows[0].status, webrev_core::FindingStatus::Suspicious);
            assert_eq!(flows[0].provenances.len(), 2);
        }
    }
}
