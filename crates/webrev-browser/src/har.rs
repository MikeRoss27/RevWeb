// crates/webrev-browser/src/har.rs
//! A minimal HAR-like capture model retaining original CDP request data.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use webrev_core::{Endpoint, Method, Source};

/// One captured request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarEntry {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
}

/// A collection of captured requests.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Har {
    pub entries: Vec<HarEntry>,
}

impl Har {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a captured entry.
    pub fn push(&mut self, entry: HarEntry) {
        self.entries.push(entry);
    }

    /// Derive endpoints from the captured requests.
    #[must_use]
    pub fn endpoints(&self) -> Vec<Endpoint> {
        self.entries
            .iter()
            .map(|e| Endpoint::new(e.url.clone(), Method::parse(&e.method), Source::Browser))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_credentials_and_builds_endpoints() {
        let mut har = Har::new();
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_owned(), "Bearer sekret".to_owned());
        headers.insert("Accept".to_owned(), "application/json".to_owned());
        har.push(HarEntry {
            method: "GET".to_owned(),
            url: "https://api.test/v1/data?token=AKIAZ4XB7NMPQR2STUVW".to_owned(),
            headers,
        });

        let entry = &har.entries[0];
        assert_eq!(entry.headers["Authorization"], "Bearer sekret");
        assert_eq!(entry.headers["Accept"], "application/json");

        let endpoints = har.endpoints();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].method, Method::Get);
        assert_eq!(endpoints[0].source, Source::Browser);
        assert!(endpoints[0].url.contains("AKIAZ4XB7NMPQR2STUVW"));
    }
}
