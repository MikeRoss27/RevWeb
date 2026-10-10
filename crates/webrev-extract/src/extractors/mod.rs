// crates/webrev-extract/src/extractors/mod.rs
//! The concrete extractor implementations, one per strategy.

mod graphql;
mod html;
mod js_ast;
mod js_regex;
mod params;
mod routes;
mod secrets;
mod sourcemaps;
mod tech;

pub use graphql::GraphQlExtractor;
pub use html::HtmlExtractor;
pub use js_ast::JsAstExtractor;
pub use js_regex::JsRegexExtractor;
pub use params::ParamExtractor;
pub use routes::SpaRouteExtractor;
pub use secrets::SecretExtractor;
pub use sourcemaps::SourceMapExtractor;
pub use tech::TechExtractor;

pub(crate) use html::inline_scripts;
