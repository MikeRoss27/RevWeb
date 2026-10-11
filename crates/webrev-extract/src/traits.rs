// crates/webrev-extract/src/traits.rs
//! The extractor abstraction and its input type.

use webrev_core::{Finding, SessionId};

/// What flavour of content an [`ExtractInput`] carries, so extractors can
/// cheaply opt out of inputs they do not understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// An HTML document.
    Html,
    /// A JavaScript source file (external or inlined).
    JavaScript,
    /// A JSON document (web app manifest, webpack/Vite asset manifest, …).
    Json,
    /// A WebAssembly binary module.
    Wasm,
}

/// One unit of content handed to the registry.
#[derive(Debug, Clone)]
pub struct ExtractInput {
    /// Session the resulting findings belong to.
    pub session_id: SessionId,
    /// Origin URL of this content, used for finding provenance. `None` for
    /// inline or synthetic content.
    pub url: Option<String>,
    pub kind: ContentKind,
    /// The raw body text. Empty for binary content (e.g. [`ContentKind::Wasm`]):
    /// a binary body is never lossily decoded to UTF-8, it is carried in
    /// [`bytes`](Self::bytes) instead.
    pub body: String,
    /// Response headers (`name`, `value`), when the content came over HTTP.
    /// Empty for inline/synthetic content. Used by the tech fingerprinter to
    /// read `Server`, `X-Powered-By`, `Set-Cookie`, etc.
    pub headers: Vec<(String, String)>,
    /// The raw, untouched bytes of this content, when it is binary (e.g. a
    /// fetched `.wasm` module). `None` for text content, where `body` already
    /// carries everything.
    pub bytes: Option<Vec<u8>>,
}

impl ExtractInput {
    #[must_use]
    pub fn new(
        session_id: SessionId,
        url: Option<String>,
        kind: ContentKind,
        body: impl Into<String>,
    ) -> Self {
        Self {
            session_id,
            url,
            kind,
            body: body.into(),
            headers: Vec::new(),
            bytes: None,
        }
    }

    /// Attach HTTP response headers.
    #[must_use]
    pub fn with_headers(mut self, headers: Vec<(String, String)>) -> Self {
        self.headers = headers;
        self
    }

    /// Attach the raw bytes of a binary body (e.g. a fetched `.wasm` module).
    #[must_use]
    pub fn with_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.bytes = Some(bytes);
        self
    }
}

/// A single-responsibility extractor.
///
/// Implementations must be pure (no I/O, no interior mutability that affects
/// output) and cheap to call repeatedly: the registry may run every extractor
/// against every input. `Send + Sync` is required so the registry can live
/// inside an async pipeline stage shared across tasks.
pub trait Extractor: Send + Sync {
    /// Stable identifier, surfaced in logs and the TUI.
    fn name(&self) -> &'static str;

    /// Relative priority; higher runs (and is listed) first. Used to order the
    /// registry so higher-trust sources (AST) precede heuristics (regex).
    fn priority(&self) -> u8;

    /// Whether this extractor wants to process `input`.
    fn applies_to(&self, input: &ExtractInput) -> bool;

    /// Produce findings for `input`. Must return an empty vec rather than error
    /// when it simply finds nothing.
    fn extract(&self, input: &ExtractInput) -> Vec<Finding>;
}
