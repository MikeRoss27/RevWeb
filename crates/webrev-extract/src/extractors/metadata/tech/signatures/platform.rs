//! Platform technology signatures.
use super::Signature;

pub(super) const SIGNATURES: &[Signature] = &[
    // --- Hosting / edge ---
    Signature {
        name: "Vercel",
        category: "hosting",
        markers: &["vercel.app", "/_vercel/", "x-vercel-id"],
    },
    Signature {
        name: "Netlify",
        category: "hosting",
        markers: &["netlify.app", "netlify"],
    },
    // Bare "cloudflare"/"cloudfront"/"fastly"/"akamai"/"nginx"/"apache" are
    // deliberately excluded below: a page merely *mentioning* the word (a
    // blog post, a cookie-consent banner naming Cloudflare) would otherwise
    // mis-fingerprint the stack. The header-prefixed markers are the
    // low-noise signal; keep to those.
    Signature {
        name: "Cloudflare",
        category: "edge",
        markers: &["/cdn-cgi/", "cf-ray"],
    },
    Signature {
        name: "CloudFront",
        category: "edge",
        markers: &["x-amz-cf-id"],
    },
    Signature {
        name: "Fastly",
        category: "edge",
        markers: &["x-served-by: cache", "x-fastly"],
    },
    Signature {
        name: "Akamai",
        category: "edge",
        markers: &["x-akamai"],
    },
    Signature {
        name: "Bunny CDN",
        category: "edge",
        markers: &["b-cdn.net"],
    },
    Signature {
        name: "KeyCDN",
        category: "edge",
        markers: &["kxcdn.com"],
    },
    // --- Backend servers / stacks (mostly from response headers) ---
    Signature {
        name: "nginx",
        category: "server",
        markers: &["server: nginx"],
    },
    Signature {
        name: "Apache",
        category: "server",
        markers: &["server: apache"],
    },
    Signature {
        name: "Caddy",
        category: "server",
        markers: &["server: caddy"],
    },
    Signature {
        name: "Microsoft IIS",
        category: "server",
        markers: &["server: microsoft-iis"],
    },
    Signature {
        name: "Gunicorn",
        category: "server",
        markers: &["server: gunicorn"],
    },
    Signature {
        name: "uWSGI",
        category: "server",
        markers: &["uwsgi"],
    },
    Signature {
        name: "Express",
        category: "backend",
        markers: &["x-powered-by: express"],
    },
    Signature {
        name: "Fastify",
        category: "backend",
        markers: &["x-powered-by: fastify"],
    },
    Signature {
        name: "NestJS",
        category: "backend",
        markers: &["nestjs"],
    },
    Signature {
        name: "Koa",
        category: "backend",
        markers: &["x-powered-by: koa"],
    },
    Signature {
        name: "PHP",
        category: "backend",
        markers: &["x-powered-by: php", "php/"],
    },
    Signature {
        name: "Laravel",
        category: "backend",
        markers: &["laravel_session", "x-laravel"],
    },
    Signature {
        name: "Ruby on Rails",
        category: "backend",
        markers: &["x-runtime", "phusion passenger", "_rails"],
    },
    Signature {
        name: "Django",
        category: "backend",
        markers: &["wsgiserver", "csrftoken"],
    },
    Signature {
        name: "Flask",
        category: "backend",
        markers: &["werkzeug"],
    },
    Signature {
        name: "FastAPI",
        category: "backend",
        markers: &["fastapi"],
    },
    Signature {
        name: "ASP.NET",
        category: "backend",
        markers: &["x-aspnet-version", "x-powered-by: asp.net"],
    },
    Signature {
        name: "Spring Boot",
        category: "backend",
        markers: &["x-application-context", "springframework"],
    },
    Signature {
        name: "Apache Tomcat",
        category: "backend",
        markers: &["jsessionid", "apache tomcat"],
    },
    Signature {
        name: "Phoenix (Elixir)",
        category: "backend",
        markers: &["phoenixframework"],
    },
    Signature {
        name: "Actix (Rust)",
        category: "backend",
        markers: &["actix-web"],
    },
    Signature {
        name: "Kong",
        category: "gateway",
        markers: &["via: kong", "x-kong"],
    },
    Signature {
        name: "Varnish",
        category: "cache",
        markers: &["x-varnish", "via: varnish"],
    },
    // --- Build tooling (recon signal: reveals the dev toolchain) ---
    Signature {
        name: "Vite",
        category: "build",
        markers: &["/@vite/client", "vite/modulepreload-polyfill"],
    },
    Signature {
        name: "Webpack",
        category: "build",
        markers: &["webpackjsonp", "__webpack_require__"],
    },
    Signature {
        name: "Parcel",
        category: "build",
        markers: &["parcelrequire"],
    },
    Signature {
        name: "Turbopack",
        category: "build",
        markers: &["__turbopack_require__"],
    },
];
