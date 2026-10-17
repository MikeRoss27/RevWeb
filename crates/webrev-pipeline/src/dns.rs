//! Per-client DNS pinning to prevent rebinding between scope validation and
//! connection establishment, including hosts reached through HTTP redirects.
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::Mutex;
use webrev_core::Scope;

fn filter_scope_addresses(
    scope: &Scope,
    hostname: &str,
    addresses: impl IntoIterator<Item = SocketAddr>,
    trusted_proxy: bool,
) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .filter(|address| trusted_proxy || scope.allows_resolved_ip(hostname, address.ip()))
        .collect()
}

#[derive(Default)]
pub(crate) struct PinnedDnsResolver {
    answers: Arc<Mutex<HashMap<String, Vec<SocketAddr>>>>,
    scope: Scope,
    trusted_proxy_hosts: HashSet<String>,
}

impl Resolve for PinnedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_ascii_lowercase();
        let answers = Arc::clone(&self.answers);
        let scope = self.scope.clone();
        let trusted_proxy = self.trusted_proxy_hosts.contains(&host);
        Box::pin(async move {
            let mut answers = answers.lock().await;
            if let Some(cached) = answers.get(&host) {
                let addrs: Addrs = Box::new(cached.clone().into_iter());
                return Ok(addrs);
            }

            // Keep the lock through lookup so concurrent requests for the same
            // host cannot observe different DNS answers during one scan.
            let resolved = filter_scope_addresses(
                &scope,
                &host,
                tokio::net::lookup_host((host.as_str(), 0)).await?,
                trusted_proxy,
            );
            if resolved.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("DNS addresses for {host} are outside the configured scope"),
                )
                .into());
            }
            answers.insert(host, resolved.clone());
            let addrs: Addrs = Box::new(resolved.into_iter());
            Ok(addrs)
        })
    }
}

pub(crate) fn pinned_resolver(scope: Scope, proxy: Option<&str>) -> Arc<dyn Resolve> {
    let trusted_proxy_hosts = proxy
        .and_then(|proxy| reqwest::Url::parse(proxy).ok())
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .into_iter()
        .collect();
    Arc::new(PinnedDnsResolver {
        answers: Arc::default(),
        scope,
        trusted_proxy_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn pins_all_localhost_answers_for_lifetime_of_resolver() {
        let resolver = PinnedDnsResolver {
            answers: Arc::default(),
            scope: Scope::new(vec!["localhost".into()], vec![]),
            trusted_proxy_hosts: HashSet::new(),
        };
        let name = Name::from_str("localhost").unwrap();
        let first: Vec<_> = resolver.resolve(name).await.unwrap().collect();
        let name = Name::from_str("LOCALHOST").unwrap();
        let second: Vec<_> = resolver.resolve(name).await.unwrap().collect();
        assert!(!first.is_empty());
        assert_eq!(first, second);
        assert!(first.iter().all(|addr| addr.port() == 0));
    }

    #[test]
    fn cidr_scope_filters_dns_answers_before_connector_sees_them() {
        let scope = Scope::new(vec!["192.0.2.0/24".into()], vec![]);
        let candidates = [
            "192.0.2.11:0".parse().unwrap(),
            "198.51.100.9:0".parse().unwrap(),
        ];
        let filtered = filter_scope_addresses(&scope, "api.outside.test", candidates, false);
        assert_eq!(filtered, ["192.0.2.11:0".parse().unwrap()]);
    }

    #[test]
    fn excluded_cidr_filters_addresses_of_an_in_scope_hostname() {
        let scope = Scope::new(
            vec!["app.example.test".into()],
            vec!["192.0.2.128/25".into()],
        );
        let candidates = [
            "192.0.2.11:0".parse().unwrap(),
            "192.0.2.200:0".parse().unwrap(),
        ];
        let filtered = filter_scope_addresses(&scope, "app.example.test", candidates, false);
        assert_eq!(filtered, ["192.0.2.11:0".parse().unwrap()]);
    }
}
