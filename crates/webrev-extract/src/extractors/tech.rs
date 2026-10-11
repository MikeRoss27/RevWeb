// crates/webrev-extract/src/extractors/tech.rs
//! A lightweight technology fingerprinter: frameworks, and the SaaS/BaaS/DB
//! backends an app talks to (Supabase, Firebase, Hasura, Cognito, ...).
//!
//! Matching is case-insensitive substring search over the resource URL plus its
//! body, which is fast and good enough for recon signalling. Each hit is a
//! `Technology` finding whose value is `"Name (category)"`.

use crate::traits::{ContentKind, ExtractInput, Extractor};
use regex::Regex;
use std::collections::BTreeSet;
use webrev_core::{Confidence, Finding, FindingKind, Provenance, Source};

/// One fingerprint: display name, category, and the signatures that imply it.
struct Signature {
    name: &'static str,
    category: &'static str,
    markers: &'static [&'static str],
}

/// The fingerprint table. Markers must be lowercase (the haystack is lowered).
///
/// Every marker is chosen to be a reasonably specific token (a path, an
/// internal global, a header value, a qualified domain) rather than a bare
/// generic word — a lesson learned the hard way from `nginx`/`apache`/
/// `cloudflare`/`amazonaws.com` false-positiving on pages that merely
/// *mention* the vendor name (see the git history on this file).
const SIGNATURES: &[Signature] = &[
    // --- Frontend frameworks ---
    Signature { name: "Next.js", category: "framework", markers: &["__next_data__", "/_next/static", "next/dist"] },
    Signature { name: "Nuxt", category: "framework", markers: &["__nuxt__", "/_nuxt/"] },
    Signature { name: "React", category: "framework", markers: &["data-reactroot", "__react_devtools_global_hook__", "react-dom", "_reactlistening"] },
    Signature { name: "Vue.js", category: "framework", markers: &["__vue__", "__vue_devtools", "data-v-app"] },
    Signature { name: "Angular", category: "framework", markers: &["ng-version", "ng-app=", "platformbrowserdynamic"] },
    Signature { name: "AngularJS (1.x)", category: "framework", markers: &["ng-controller", "angular.module("] },
    Signature { name: "Svelte/SvelteKit", category: "framework", markers: &["/_app/immutable", "__sveltekit", "svelte-"] },
    Signature { name: "Gatsby", category: "framework", markers: &["___gatsby", "/page-data/", "gatsby-"] },
    Signature { name: "Ember", category: "framework", markers: &["ember-application", "window.ember"] },
    Signature { name: "Preact", category: "framework", markers: &["preact/hooks", "preact.min.js"] },
    Signature { name: "SolidJS", category: "framework", markers: &["solid-js/web", "solidjs"] },
    Signature { name: "Qwik", category: "framework", markers: &["qwikloader", "q:container", "qwik-city"] },
    Signature { name: "Astro", category: "framework", markers: &["astro-island", "/_astro/"] },
    Signature { name: "Remix", category: "framework", markers: &["__remixcontext", "__remixmanifest"] },
    Signature { name: "Alpine.js", category: "framework", markers: &["alpinejs", "alpine.min.js", "x-data="] },
    Signature { name: "htmx", category: "library", markers: &["htmx.min.js", "hx-boost="] },
    Signature { name: "Lit", category: "library", markers: &["lit-element", "lit-html"] },
    Signature { name: "Backbone.js", category: "library", markers: &["backbone.min.js", "backbone-min.js"] },
    Signature { name: "Meteor", category: "framework", markers: &["__meteor_runtime_config__"] },
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
    Signature { name: "Okta", category: "auth", markers: &["okta.com", "okta-signin-widget"] },
    Signature { name: "Clerk", category: "auth", markers: &["clerk.dev", "__clerk", "clerk-js"] },
    Signature { name: "WorkOS", category: "auth", markers: &["workos.com"] },
    Signature { name: "Keycloak", category: "auth", markers: &["keycloak"] },
    // --- CMS / commerce ---
    Signature { name: "WordPress", category: "cms", markers: &["/wp-content/", "/wp-includes/", "wp-json"] },
    Signature { name: "Shopify", category: "commerce", markers: &["cdn.shopify.com", "myshopify.com", "shopify."] },
    Signature { name: "Contentful", category: "cms", markers: &["cdn.contentful.com", "contentful"] },
    Signature { name: "Sanity", category: "cms", markers: &["apicdn.sanity.io", "sanity.io"] },
    Signature { name: "Drupal", category: "cms", markers: &["/sites/default/files/", "drupal.settings", "x-drupal-cache"] },
    Signature { name: "Joomla", category: "cms", markers: &["/media/jui/", "joomla!"] },
    Signature { name: "Magento", category: "commerce", markers: &["mage/cookies.js", "magento_"] },
    Signature { name: "PrestaShop", category: "commerce", markers: &["prestashop"] },
    Signature { name: "Ghost", category: "cms", markers: &["ghost.org", "/ghost/api/"] },
    Signature { name: "Webflow", category: "cms", markers: &["webflow.com", "data-wf-site"] },
    Signature { name: "Squarespace", category: "cms", markers: &["squarespace.com", "static1.squarespace.com"] },
    Signature { name: "Wix", category: "cms", markers: &["wixstatic.com", "wix-code"] },
    Signature { name: "Strapi", category: "cms", markers: &["strapi"] },
    Signature { name: "Craft CMS", category: "cms", markers: &["craftcms", "/cpresources/"] },
    Signature { name: "Umbraco", category: "cms", markers: &["umbraco"] },
    // --- APIs / payments / search / analytics / errors ---
    Signature { name: "GraphQL", category: "api", markers: &["apolloclient", "apollo-client", "gql`", "/graphql"] },
    Signature { name: "Stripe", category: "payments", markers: &["js.stripe.com", "pk_live_", "pk_test_"] },
    Signature { name: "PayPal", category: "payments", markers: &["paypalobjects.com", "paypal.com/sdk"] },
    Signature { name: "Braintree", category: "payments", markers: &["braintreegateway.com", "braintree-web"] },
    Signature { name: "Adyen", category: "payments", markers: &["adyen.com", "adyen-checkout"] },
    Signature { name: "Algolia", category: "search", markers: &["algolianet.com", "algoliasearch", "algolia"] },
    Signature { name: "Elasticsearch", category: "search", markers: &["x-elastic-product"] },
    Signature { name: "Meilisearch", category: "search", markers: &["meilisearch"] },
    Signature { name: "Typesense", category: "search", markers: &["typesense"] },
    Signature { name: "Sentry", category: "observability", markers: &["sentry.io", "ingest.sentry", "@sentry/"] },
    Signature { name: "Datadog RUM", category: "observability", markers: &["datadoghq.com", "ddog-gov.com"] },
    Signature { name: "New Relic", category: "observability", markers: &["newrelic.com", "nreum"] },
    Signature { name: "LogRocket", category: "observability", markers: &["logrocket.io", "logrocket.com"] },
    Signature { name: "Segment", category: "analytics", markers: &["cdn.segment.com", "segment.io"] },
    Signature { name: "Google Analytics/GTM", category: "analytics", markers: &["googletagmanager.com", "google-analytics.com"] },
    Signature { name: "Mixpanel", category: "analytics", markers: &["mixpanel.com", "cdn.mxpnl.com"] },
    Signature { name: "Amplitude", category: "analytics", markers: &["amplitude.com", "cdn.amplitude.com"] },
    Signature { name: "Hotjar", category: "analytics", markers: &["hotjar.com", "_hjsettings"] },
    Signature { name: "FullStory", category: "analytics", markers: &["fullstory.com", "_fs_namespace"] },
    Signature { name: "PostHog", category: "analytics", markers: &["posthog.com", "posthog-js"] },
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
    Signature { name: "Bunny CDN", category: "edge", markers: &["b-cdn.net"] },
    Signature { name: "KeyCDN", category: "edge", markers: &["kxcdn.com"] },
    // --- Backend servers / stacks (mostly from response headers) ---
    Signature { name: "nginx", category: "server", markers: &["server: nginx"] },
    Signature { name: "Apache", category: "server", markers: &["server: apache"] },
    Signature { name: "Caddy", category: "server", markers: &["server: caddy"] },
    Signature { name: "Microsoft IIS", category: "server", markers: &["server: microsoft-iis"] },
    Signature { name: "Gunicorn", category: "server", markers: &["server: gunicorn"] },
    Signature { name: "uWSGI", category: "server", markers: &["uwsgi"] },
    Signature { name: "Express", category: "backend", markers: &["x-powered-by: express"] },
    Signature { name: "Fastify", category: "backend", markers: &["x-powered-by: fastify"] },
    Signature { name: "NestJS", category: "backend", markers: &["nestjs"] },
    Signature { name: "Koa", category: "backend", markers: &["x-powered-by: koa"] },
    Signature { name: "PHP", category: "backend", markers: &["x-powered-by: php", "php/"] },
    Signature { name: "Laravel", category: "backend", markers: &["laravel_session", "x-laravel"] },
    Signature { name: "Ruby on Rails", category: "backend", markers: &["x-runtime", "phusion passenger", "_rails"] },
    Signature { name: "Django", category: "backend", markers: &["wsgiserver", "csrftoken"] },
    Signature { name: "Flask", category: "backend", markers: &["werkzeug"] },
    Signature { name: "FastAPI", category: "backend", markers: &["fastapi"] },
    Signature { name: "ASP.NET", category: "backend", markers: &["x-aspnet-version", "x-powered-by: asp.net"] },
    Signature { name: "Spring Boot", category: "backend", markers: &["x-application-context", "springframework"] },
    Signature { name: "Apache Tomcat", category: "backend", markers: &["jsessionid", "apache tomcat"] },
    Signature { name: "Phoenix (Elixir)", category: "backend", markers: &["phoenixframework"] },
    Signature { name: "Actix (Rust)", category: "backend", markers: &["actix-web"] },
    Signature { name: "Kong", category: "gateway", markers: &["via: kong", "x-kong"] },
    Signature { name: "Varnish", category: "cache", markers: &["x-varnish", "via: varnish"] },
    // --- Build tooling (recon signal: reveals the dev toolchain) ---
    Signature { name: "Vite", category: "build", markers: &["/@vite/client", "vite/modulepreload-polyfill"] },
    Signature { name: "Webpack", category: "build", markers: &["webpackjsonp", "__webpack_require__"] },
    Signature { name: "Parcel", category: "build", markers: &["parcelrequire"] },
    Signature { name: "Turbopack", category: "build", markers: &["__turbopack_require__"] },
];

/// Technology fingerprint extractor.
pub struct TechExtractor {
    /// `<meta name="generator" content="...">`, attribute order either way —
    /// catches CMS/site-builder/version strings the static marker table
    /// doesn't enumerate by name (`WordPress` plugins, static-site
    /// generators, page builders, ...).
    meta_generator: Regex,
}

impl TechExtractor {
    /// # Panics
    ///
    /// Never at runtime: the pattern is a constant verified by the
    /// `patterns_compile` unit test.
    #[must_use]
    pub fn new() -> Self {
        Self {
            meta_generator: Regex::new(
                r#"(?i)<meta[^>]*name=["']generator["'][^>]*content=["']([^"']{1,120})["']|<meta[^>]*content=["']([^"']{1,120})["'][^>]*name=["']generator["']"#,
            )
            .expect("constant meta-generator pattern must compile"),
        }
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

        // `<meta name="generator">` names something (often with a version)
        // that the static marker table may not enumerate at all — a plugin,
        // a static-site generator, a page builder. Lower confidence than a
        // table hit: it's free-form text supplied by the generator itself,
        // not a structural tell.
        if input.kind == ContentKind::Html {
            if let Some(cap) = self.meta_generator.captures(&input.body) {
                if let Some(value) = cap.get(1).or_else(|| cap.get(2)) {
                    let value = value.as_str().trim();
                    if !value.is_empty() {
                        findings.push(Finding::new(
                            input.session_id,
                            FindingKind::Technology,
                            None,
                            format!("{value} (generator)"),
                            Confidence::Medium,
                            Provenance::new(Source::Html, input.url.clone()),
                        ));
                    }
                }
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
    fn patterns_compile() {
        let _ = TechExtractor::new();
    }

    #[test]
    fn detects_meta_generator_either_attribute_order() {
        let a = detect(None, r#"<meta name="generator" content="WordPress 6.4">"#);
        assert!(a.iter().any(|v| v == "WordPress 6.4 (generator)"), "got: {a:?}");

        let b = detect(None, r#"<meta content="Hugo 0.120" name="generator">"#);
        assert!(b.iter().any(|v| v == "Hugo 0.120 (generator)"), "got: {b:?}");
    }

    #[test]
    fn detects_new_framework_and_backend_signatures() {
        let values = detect(
            Some("https://app.example/"),
            r#"<script src="/_astro/client.js"></script>
               <div x-data="{}"></div>"#,
        );
        assert!(values.iter().any(|v| v.starts_with("Astro")), "got: {values:?}");
        assert!(values.iter().any(|v| v.starts_with("Alpine.js")), "got: {values:?}");

        let input = ExtractInput::new(SessionId::new(), Some("https://x/".into()), ContentKind::Html, "")
            .with_headers(vec![("Server".into(), "Werkzeug/2.3.0".into())]);
        let backend: Vec<String> = TechExtractor::new()
            .extract(&input)
            .into_iter()
            .map(|f| f.value)
            .collect();
        assert!(backend.iter().any(|v| v.starts_with("Flask")), "got: {backend:?}");
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
