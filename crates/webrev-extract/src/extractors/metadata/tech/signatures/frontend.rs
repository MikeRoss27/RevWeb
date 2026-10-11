//! Frontend technology signatures.
use super::Signature;

pub(super) const SIGNATURES: &[Signature] = &[
    // --- Frontend frameworks ---
    Signature {
        name: "Next.js",
        category: "framework",
        markers: &["__next_data__", "/_next/static", "next/dist"],
    },
    Signature {
        name: "Nuxt",
        category: "framework",
        markers: &["__nuxt__", "/_nuxt/"],
    },
    Signature {
        name: "React",
        category: "framework",
        markers: &[
            "data-reactroot",
            "__react_devtools_global_hook__",
            "react-dom",
            "_reactlistening",
        ],
    },
    Signature {
        name: "Vue.js",
        category: "framework",
        markers: &["__vue__", "__vue_devtools", "data-v-app"],
    },
    Signature {
        name: "Angular",
        category: "framework",
        markers: &["ng-version", "ng-app=", "platformbrowserdynamic"],
    },
    Signature {
        name: "AngularJS (1.x)",
        category: "framework",
        markers: &["ng-controller", "angular.module("],
    },
    Signature {
        name: "Svelte/SvelteKit",
        category: "framework",
        markers: &["/_app/immutable", "__sveltekit", "svelte-"],
    },
    Signature {
        name: "Gatsby",
        category: "framework",
        markers: &["___gatsby", "/page-data/", "gatsby-"],
    },
    Signature {
        name: "Ember",
        category: "framework",
        markers: &["ember-application", "window.ember"],
    },
    Signature {
        name: "Preact",
        category: "framework",
        markers: &["preact/hooks", "preact.min.js"],
    },
    Signature {
        name: "SolidJS",
        category: "framework",
        markers: &["solid-js/web", "solidjs"],
    },
    Signature {
        name: "Qwik",
        category: "framework",
        markers: &["qwikloader", "q:container", "qwik-city"],
    },
    Signature {
        name: "Astro",
        category: "framework",
        markers: &["astro-island", "/_astro/"],
    },
    Signature {
        name: "Remix",
        category: "framework",
        markers: &["__remixcontext", "__remixmanifest"],
    },
    Signature {
        name: "Alpine.js",
        category: "framework",
        markers: &["alpinejs", "alpine.min.js", "x-data="],
    },
    Signature {
        name: "htmx",
        category: "library",
        markers: &["htmx.min.js", "hx-boost="],
    },
    Signature {
        name: "Lit",
        category: "library",
        markers: &["lit-element", "lit-html"],
    },
    Signature {
        name: "Backbone.js",
        category: "library",
        markers: &["backbone.min.js", "backbone-min.js"],
    },
    Signature {
        name: "Meteor",
        category: "framework",
        markers: &["__meteor_runtime_config__"],
    },
    Signature {
        name: "jQuery",
        category: "library",
        markers: &["/jquery", "jquery.min.js", "jquery.fn"],
    },
];
