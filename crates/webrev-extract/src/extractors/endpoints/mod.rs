//! Endpoint and resource discovery strategies.

mod ghost;
mod graphql;
mod html;
mod js_ast;
mod js_regex;
mod routes;
mod sourcemaps;

pub use ghost::GhostEndpointExtractor;
pub use graphql::GraphQlExtractor;
pub use html::HtmlExtractor;
pub use js_ast::JsAstExtractor;
pub use js_regex::JsRegexExtractor;
pub use routes::SpaRouteExtractor;
pub use sourcemaps::SourceMapExtractor;

pub(crate) use html::inline_scripts;
