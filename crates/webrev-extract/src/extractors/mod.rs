//! Extractors grouped by responsibility.
mod endpoints;
mod metadata;
mod secrets;

pub(crate) use endpoints::inline_scripts;
pub use endpoints::{
    GhostEndpointExtractor, GraphQlExtractor, HtmlExtractor, JsAstExtractor, JsRegexExtractor,
    NextJsExtractor, SourceMapExtractor, SpaRouteExtractor,
};
pub use metadata::{
    BucketExtractor, ConfigExtractor, CspExtractor, DomSinkExtractor, ManifestExtractor,
    ParamExtractor, TechExtractor, WasmExtractor,
};
pub use secrets::{JwtExtractor, SecretExtractor};
