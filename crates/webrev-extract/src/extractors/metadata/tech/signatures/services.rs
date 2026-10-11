//! Services technology signatures.
use super::Signature;

pub(super) const SIGNATURES: &[Signature] = &[
    // --- BaaS / auth / DB-as-a-service ---
    Signature {
        name: "Supabase",
        category: "baas/db",
        markers: &["supabase.co", "supabase.in", "supabase-js", "supabase"],
    },
    Signature {
        name: "Firebase",
        category: "baas/db",
        markers: &[
            "firebaseio.com",
            "firebaseapp.com",
            "firestore",
            "identitytoolkit",
            "firebase",
        ],
    },
    // `amazonaws.com` deliberately excluded: any S3-hosted image/font/CDN
    // asset would otherwise mis-fingerprint the whole stack as Amplify/Cognito.
    Signature {
        name: "AWS Amplify/Cognito",
        category: "baas/db",
        markers: &["cognito-idp", "amazon-cognito", "aws-amplify"],
    },
    Signature {
        name: "Hasura",
        category: "baas/db",
        markers: &["x-hasura", "/v1/graphql", "hasura"],
    },
    Signature {
        name: "MongoDB Atlas/Realm",
        category: "baas/db",
        markers: &["mongodb-realm", "realm.mongodb.com", "mongodb.net"],
    },
    Signature {
        name: "PlanetScale",
        category: "db",
        markers: &["psdb.cloud", "planetscale"],
    },
    Signature {
        name: "Auth0",
        category: "auth",
        markers: &["auth0.com", "auth0-spa-js", "auth0client"],
    },
    Signature {
        name: "Okta",
        category: "auth",
        markers: &["okta.com", "okta-signin-widget"],
    },
    Signature {
        name: "Clerk",
        category: "auth",
        markers: &["clerk.dev", "__clerk", "clerk-js"],
    },
    Signature {
        name: "WorkOS",
        category: "auth",
        markers: &["workos.com"],
    },
    Signature {
        name: "Keycloak",
        category: "auth",
        markers: &["keycloak"],
    },
    // --- CMS / commerce ---
    Signature {
        name: "WordPress",
        category: "cms",
        markers: &["/wp-content/", "/wp-includes/", "wp-json"],
    },
    Signature {
        name: "Shopify",
        category: "commerce",
        markers: &["cdn.shopify.com", "myshopify.com", "shopify."],
    },
    Signature {
        name: "Contentful",
        category: "cms",
        markers: &["cdn.contentful.com", "contentful"],
    },
    Signature {
        name: "Sanity",
        category: "cms",
        markers: &["apicdn.sanity.io", "sanity.io"],
    },
    Signature {
        name: "Drupal",
        category: "cms",
        markers: &["/sites/default/files/", "drupal.settings", "x-drupal-cache"],
    },
    Signature {
        name: "Joomla",
        category: "cms",
        markers: &["/media/jui/", "joomla!"],
    },
    Signature {
        name: "Magento",
        category: "commerce",
        markers: &["mage/cookies.js", "magento_"],
    },
    Signature {
        name: "PrestaShop",
        category: "commerce",
        markers: &["prestashop"],
    },
    Signature {
        name: "Ghost",
        category: "cms",
        markers: &["ghost.org", "/ghost/api/"],
    },
    Signature {
        name: "Webflow",
        category: "cms",
        markers: &["webflow.com", "data-wf-site"],
    },
    Signature {
        name: "Squarespace",
        category: "cms",
        markers: &["squarespace.com", "static1.squarespace.com"],
    },
    Signature {
        name: "Wix",
        category: "cms",
        markers: &["wixstatic.com", "wix-code"],
    },
    Signature {
        name: "Strapi",
        category: "cms",
        markers: &["strapi"],
    },
    Signature {
        name: "Craft CMS",
        category: "cms",
        markers: &["craftcms", "/cpresources/"],
    },
    Signature {
        name: "Umbraco",
        category: "cms",
        markers: &["umbraco"],
    },
    // --- APIs / payments / search / analytics / errors ---
    Signature {
        name: "GraphQL",
        category: "api",
        markers: &["apolloclient", "apollo-client", "gql`", "/graphql"],
    },
    Signature {
        name: "Stripe",
        category: "payments",
        markers: &["js.stripe.com", "pk_live_", "pk_test_"],
    },
    Signature {
        name: "PayPal",
        category: "payments",
        markers: &["paypalobjects.com", "paypal.com/sdk"],
    },
    Signature {
        name: "Braintree",
        category: "payments",
        markers: &["braintreegateway.com", "braintree-web"],
    },
    Signature {
        name: "Adyen",
        category: "payments",
        markers: &["adyen.com", "adyen-checkout"],
    },
    Signature {
        name: "Algolia",
        category: "search",
        markers: &["algolianet.com", "algoliasearch", "algolia"],
    },
    Signature {
        name: "Elasticsearch",
        category: "search",
        markers: &["x-elastic-product"],
    },
    Signature {
        name: "Meilisearch",
        category: "search",
        markers: &["meilisearch"],
    },
    Signature {
        name: "Typesense",
        category: "search",
        markers: &["typesense"],
    },
    Signature {
        name: "Sentry",
        category: "observability",
        markers: &["sentry.io", "ingest.sentry", "@sentry/"],
    },
    Signature {
        name: "Datadog RUM",
        category: "observability",
        markers: &["datadoghq.com", "ddog-gov.com"],
    },
    Signature {
        name: "New Relic",
        category: "observability",
        markers: &["newrelic.com", "nreum"],
    },
    Signature {
        name: "LogRocket",
        category: "observability",
        markers: &["logrocket.io", "logrocket.com"],
    },
    Signature {
        name: "Segment",
        category: "analytics",
        markers: &["cdn.segment.com", "segment.io"],
    },
    Signature {
        name: "Google Analytics/GTM",
        category: "analytics",
        markers: &["googletagmanager.com", "google-analytics.com"],
    },
    Signature {
        name: "Mixpanel",
        category: "analytics",
        markers: &["mixpanel.com", "cdn.mxpnl.com"],
    },
    Signature {
        name: "Amplitude",
        category: "analytics",
        markers: &["amplitude.com", "cdn.amplitude.com"],
    },
    Signature {
        name: "Hotjar",
        category: "analytics",
        markers: &["hotjar.com", "_hjsettings"],
    },
    Signature {
        name: "FullStory",
        category: "analytics",
        markers: &["fullstory.com", "_fs_namespace"],
    },
    Signature {
        name: "PostHog",
        category: "analytics",
        markers: &["posthog.com", "posthog-js"],
    },
];
