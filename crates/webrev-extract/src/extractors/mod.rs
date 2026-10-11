//! Extractors grouped by responsibility.
mod endpoints;
mod metadata;
mod secrets;

pub(crate) use endpoints::inline_scripts;
pub use endpoints::{
    GraphQlExtractor, HtmlExtractor, JsAstExtractor, JsRegexExtractor, SourceMapExtractor,
    SpaRouteExtractor,
};
pub use metadata::{
    BucketExtractor, ConfigExtractor, CspExtractor, DomSinkExtractor, ManifestExtractor,
    ParamExtractor, TechExtractor,
};
pub use secrets::{JwtExtractor, SecretExtractor};
