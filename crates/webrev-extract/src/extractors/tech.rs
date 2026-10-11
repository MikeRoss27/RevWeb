// crates/webrev-extract/src/extractors/tech.rs
//! A lightweight technology fingerprinter: frameworks, and the SaaS/BaaS/DB
//! backends an app talks to (Supabase, Firebase, Hasura, Cognito, ...).
//!
//! Matching is case-insensitive substring search over the resource URL plus its
//! body, which is fast and good enough for recon signalling. Each hit is a
//! `Technology` finding whose value is `"Name (category)"`.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// One fingerprint: display name, category, and the signatures that imply it.
struct Signature {
    name: &'static str,
    category: &'static str,
    markers: &'static [&'static str],
}

/// The fingerprint table. Markers must be lowercase (the haystack is lowered).
const SIGNATURES: &[Signature] = &[
    // --- Frontend frameworks ---
    Signature { name: "Next.js", category: "framework", markers: &["__next_data__", "/_next/static", "next/dist"] },
    Signature { name: "Nuxt", category: "framework", markers: &["__nuxt__", "/_nuxt/"] },
    Signature { name: "React", category: "framework", markers: &["data-reactroot", "__react_devtools_global_hook__", "react-dom", "_reactlistening"] },
    Signature { name: "Vue.js", category: "framework", markers: &["__vue__", "__vue_devtools", "data-v-app"] },
    Signature { name: "Angular", category: "framework", markers: &["ng-version", "ng-app=", "platformbrowserdynamic"] },
    Signature { name: "Svelte/SvelteKit", category: "framework", markers: &["/_app/immutable", "__sveltekit", "svelte-"] },
    Signature { name: "Gatsby", category: "framework", markers: &["___gatsby", "/page-data/", "gatsby-"] },
    Signature { name: "Ember", category: "framework", markers: &["ember-application", "window.ember"] },
    Signature { name: "jQuery", category: "library", markers: &["/jquery", "jquery.min.js", "jquery.fn"] },
    // --- BaaS / auth / DB-as-a-service ---
    Signature { name: "Supabase", category: "baas/db", markers: &["supabase.co", "supabase.in", "supabase-js", "supabase"] },
    Signature { name: "Firebase", category: "baas/db", markers: &["firebaseio.com", "firebaseapp.com", "firestore", "identitytoolkit", "firebase"] },
    // `amazonaws.com` deliberately excluded: any S3-hosted image/font/CDN
    // asset would otherwise mis-fingerprint the whole stack as Amplify/Cognito.
    Signature { name: "AWS Amplify/Cognito", category: "baas/db", markers: &["cognito-idp", "amazon-cognito", "aws-amplify"] },
    Signature { name: "Hasura", category: "baas/db", markers: &["x-hasura", "/v1/graphql", "hasura"] },
    Signature { name: "MongoDB Atlas/Realm", category: "baas/db", markers: &["mongodb-realm", "realm.mongodb.com", "mongodb.net"] },
    Signature { name: "PlanetScale", category: "db", markers: &["psdb.cloud", "planetscale"] },
    Signature { name: "Auth0", category: "auth", markers: &["auth0.com", "auth0-spa-js", "auth0client"] },
    // --- CMS / commerce ---
    Signature { name: "WordPress", category: "cms", markers: &["/wp-content/", "/wp-includes/", "wp-json"] },
    Signature { name: "Shopify", category: "commerce", markers: &["cdn.shopify.com", "myshopify.com", "shopify."] },
    Signature { name: "Contentful", category: "cms", markers: &["cdn.contentful.com", "contentful"] },
    Signature { name: "Sanity", category: "cms", markers: &["apicdn.sanity.io", "sanity.io"] },
    // --- APIs / payments / search / analytics / errors ---
    Signature { name: "GraphQL", category: "api", markers: &["apolloclient", "apollo-client", "gql`", "/graphql"] },
    Signature { name: "Stripe", category: "payments", markers: &["js.stripe.com", "pk_live_", "pk_test_"] },
    Signature { name: "Algolia", category: "search", markers: &["algolianet.com", "algoliasearch", "algolia"] },
    Signature { name: "Sentry", category: "observability", markers: &["sentry.io", "ingest.sentry", "@sentry/"] },
    Signature { name: "Segment", category: "analytics", markers: &["cdn.segment.com", "segment.io"] },
    Signature { name: "Google Analytics/GTM", category: "analytics", markers: &["googletagmanager.com", "google-analytics.com"] },
    // --- Hosting / edge ---
    Signature { name: "Vercel", category: "hosting", markers: &["vercel.app", "/_vercel/", "x-vercel-id"] },
    Signature { name: "Netlify", category: "hosting", markers: &["netlify.app", "netlify"] },
    // Bare "cloudflare"/"cloudfront"/"fastly"/"akamai"/"nginx"/"apache" are
    // deliberately excluded below: a page merely *mentioning* the word (a
    // blog post, a cookie-consent banner naming Cloudflare) would otherwise
    // mis-fingerprint the stack. The header-prefixed markers are the
    // low-noise signal; keep to those.
    Signature { name: "Cloudflare", category: "edge", markers: &["/cdn-cgi/", "cf-ray"] },
    Signature { name: "CloudFront", category: "edge", markers: &["x-amz-cf-id"] },
    Signature { name: "Fastly", category: "edge", markers: &["x-served-by: cache", "x-fastly"] },
    Signature { name: "Akamai", category: "edge", markers: &["x-akamai"] },
    // --- Backend servers / stacks (mostly from response headers) ---
    Signature { name: "nginx", category: "server", markers: &["server: nginx"] },
    Signature { name: "Apache", category: "server", markers: &["server: apache"] },
    Signature { name: "Caddy", category: "server", markers: &["server: caddy"] },
    Signature { name: "Express", category: "backend", markers: &["x-powered-by: express"] },
    Signature { name: "PHP", category: "backend", markers: &["x-powered-by: php", "php/"] },
    Signature { name: "Laravel", category: "backend", markers: &["laravel_session", "x-laravel"] },
    Signature { name: "Ruby on Rails", category: "backend", markers: &["x-runtime", "phusion passenger", "_rails"] },
    Signature { name: "Django", category: "backend", markers: &["wsgiserver", "csrftoken"] },
    Signature { name: "ASP.NET", category: "backend", markers: &["x-aspnet-version", "x-powered-by: asp.net"] },
    Signature { name: "Kong", category: "gateway", markers: &["via: kong", "x-kong"] },
    Signature { name: "Varnish", category: "cache", markers: &["x-varnish", "via: varnish"] },
];

/// Technology fingerprint extractor.
pub struct TechExtractor;

impl TechExtractor {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for TechExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl Extractor for TechExtractor {
    fn name(&self) -> &'static str {
        "tech"
    }

    fn priority(&self) -> u8 {
        55
    }

    fn applies_to(&self, input: &ExtractInput) -> bool {
        matches!(input.kind, ContentKind::Html | ContentKind::JavaScript)
    }

    fn extract(&self, input: &ExtractInput) -> Vec<Finding> {
        let mut haystack = input.url.clone().unwrap_or_default().to_lowercase();
        // Response headers are high-signal for backend/server/edge detection.
        for (name, value) in &input.headers {
            haystack.push(' ');
            haystack.push_str(&format!("{name}: {value}").to_lowercase());
        }
        haystack.push(' ');
        haystack.push_str(&input.body.to_lowercase());

        let mut seen: BTreeSet<&'static str> = BTreeSet::new();
        let mut findings = Vec::new();
        for sig in SIGNATURES {
            if sig.markers.iter().any(|m| haystack.contains(m)) && seen.insert(sig.name) {
                findings.push(Finding::new(
                    input.session_id,
                    FindingKind::Technology,
                    None,
                    format!("{} ({})", sig.name, sig.category),
                    Confidence::High,
                    Provenance::new(Source::Html, input.url.clone()),
                ));
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
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
        assert!(detect(None, "just some ordinary text content").is_empty());
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
        let input = ExtractInput::new(SessionId::new(), Some("https://x/".into()), ContentKind::Html, "")
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
}
