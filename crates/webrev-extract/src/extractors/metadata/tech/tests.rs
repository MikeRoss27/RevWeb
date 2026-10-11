use super::*;
use webrev_core::SessionId;

fn detect(url: Option<&str>, body: &str) -> Vec<String> {
    let input = ExtractInput::new(
        SessionId::new(),
        url.map(str::to_owned),
        ContentKind::Html,
        body,
    );
    TechExtractor::new()
        .extract(&input)
        .into_iter()
        .map(|f| f.value)
        .collect()
}

#[test]
fn patterns_compile() {
    let _ = TechExtractor::new();
}

#[test]
fn detects_meta_generator_either_attribute_order() {
    let a = detect(None, r#"<meta name="generator" content="WordPress 6.4">"#);
    assert!(
        a.iter().any(|v| v == "WordPress 6.4 (generator)"),
        "got: {a:?}"
    );

    let b = detect(None, r#"<meta content="Hugo 0.120" name="generator">"#);
    assert!(
        b.iter().any(|v| v == "Hugo 0.120 (generator)"),
        "got: {b:?}"
    );
}

#[test]
fn detects_new_framework_and_backend_signatures() {
    let values = detect(
        Some("https://app.example/"),
        r#"<script src="/_astro/client.js"></script>
           <div x-data="{}"></div>"#,
    );
    assert!(
        values.iter().any(|v| v.starts_with("Astro")),
        "got: {values:?}"
    );
    assert!(
        values.iter().any(|v| v.starts_with("Alpine.js")),
        "got: {values:?}"
    );

    let input = ExtractInput::new(
        SessionId::new(),
        Some("https://x/".into()),
        ContentKind::Html,
        "",
    )
    .with_headers(vec![("Server".into(), "Werkzeug/2.3.0".into())]);
    let backend: Vec<String> = TechExtractor::new()
        .extract(&input)
        .into_iter()
        .map(|f| f.value)
        .collect();
    assert!(
        backend.iter().any(|v| v.starts_with("Flask")),
        "got: {backend:?}"
    );
}

#[test]
fn detects_framework_and_baas() {
    let values = detect(
        Some("https://app.example/"),
        r#"<div id="__next"></div><script>window.__NEXT_DATA__={};
           const c = createClient("https://xyz.supabase.co", KEY);</script>"#,
    );
    assert!(values.iter().any(|v| v.starts_with("Next.js")));
    assert!(values.iter().any(|v| v.starts_with("Supabase")));
}

#[test]
fn detects_from_url_host() {
    let values = detect(Some("https://abc.firebaseio.com/data.json"), "");
    assert!(values.iter().any(|v| v.starts_with("Firebase")));
}

#[test]
fn no_false_positive_on_plain_text() {
    assert_eq!(
        detect(None, "just some ordinary text content"),
        Vec::<String>::new()
    );
}

#[test]
fn no_false_positive_from_mentioning_edge_vendor_names() {
    // A page that merely *mentions* these vendors (blog post, a
    // cookie-consent banner naming Cloudflare, an S3-hosted image url)
    // must not mis-fingerprint the stack.
    let values = detect(
        Some("https://blog.example/post"),
        "This site uses Cloudflare and is served from an nginx box behind \
         Akamai and Fastly, with assets on https://cdn.example.s3.amazonaws.com/img.png.",
    );
    assert!(values.is_empty(), "got: {values:?}");
}

#[test]
fn detects_backend_from_headers() {
    let input = ExtractInput::new(
        SessionId::new(),
        Some("https://x/".into()),
        ContentKind::Html,
        "",
    )
    .with_headers(vec![
        ("Server".into(), "nginx/1.25".into()),
        ("X-Powered-By".into(), "Express".into()),
    ]);
    let values: Vec<String> = TechExtractor::new()
        .extract(&input)
        .into_iter()
        .map(|f| f.value)
        .collect();
    assert!(values.iter().any(|v| v.starts_with("nginx")));
    assert!(values.iter().any(|v| v.starts_with("Express")));
}
