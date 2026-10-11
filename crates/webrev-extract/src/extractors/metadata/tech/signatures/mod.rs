//! Technology signature catalog, grouped by stack layer.
mod frontend;
mod platform;
mod services;

/// One fingerprint: display name, category, and the signatures that imply it.
pub(super) struct Signature {
    pub(super) name: &'static str,
    pub(super) category: &'static str,
    pub(super) markers: &'static [&'static str],
}

pub(super) fn all() -> impl Iterator<Item = &'static Signature> {
    frontend::SIGNATURES
        .iter()
        .chain(services::SIGNATURES)
        .chain(platform::SIGNATURES)
}
