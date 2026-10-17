//! Denylist of state-changing-looking URLs, applied before any probe or crawl
//! request. A GET to `/logout`, `/delete?id=3` or `?action=unsubscribe` can
//! mutate state even though the verb is "safe"; these are refused and recorded.
//!
//! Heuristic only: whole-token matching on path segments and decoded query
//! names/values. It cannot know that an innocently named GET handler mutates.

/// Keep in sync with `destructive_keyword` in `webrev-browser/src/policy.rs`.
const TOKENS: &[&str] = &[
    "logout",
    "logoff",
    "signout",
    "delete",
    "remove",
    "destroy",
    "unsubscribe",
    "deactivate",
    "terminate",
    "purge",
    "wipe",
    "revoke",
    "checkout",
    "purchase",
    "pay",
    "buy",
    "transfer",
    "withdraw",
    "cancel",
    "reset",
    "erase",
    "drop",
    "close_account",
    "log_out",
    "sign_out",
    "log_off",
];

fn keyword(text: &str) -> Option<&'static str> {
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for ch in text.chars() {
        if !ch.is_alphanumeric() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            previous_lower = false;
            continue;
        }
        if ch.is_uppercase() && previous_lower && !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
        previous_lower = ch.is_lowercase();
        current.extend(ch.to_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    for (index, token) in tokens.iter().enumerate() {
        let joined = tokens.get(index + 1).map(|next| format!("{token}_{next}"));
        for word in TOKENS {
            if token == word || joined.as_deref() == Some(word) {
                return Some(word);
            }
        }
    }
    None
}

/// The destructive keyword found in the URL's path or query, if any.
pub(crate) fn destructive_keyword(url: &str) -> Option<&'static str> {
    let parsed = reqwest::Url::parse(url).ok()?;
    // Static assets (bundles named delete-icon.svg, remove.js) cannot be handlers.
    let last = parsed.path().rsplit('/').next().unwrap_or("");
    if let Some((_, ext)) = last.rsplit_once('.') {
        if [
            "js", "mjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "woff", "woff2",
            "ttf",
        ]
        .iter()
        .any(|asset| ext.eq_ignore_ascii_case(asset))
        {
            return None;
        }
    }
    if let Some(word) = keyword(&percent_decode(parsed.path())) {
        return Some(word);
    }
    parsed
        .query_pairs()
        .find_map(|(name, value)| keyword(&name).or_else(|| keyword(&value)))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(u8::try_from(h * 16 + l).unwrap_or(b'?'));
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::destructive_keyword;

    #[test]
    fn destructive_urls_are_recognized() {
        for url in [
            "http://x.test/logout",
            "http://x.test/account/delete?id=3",
            "http://x.test/app?action=delete&id=1",
            "http://x.test/app?do=unsubscribe",
            "http://x.test/users/5/deleteAccount",
            "http://x.test/sign-out",
            "http://x.test/api/%64elete/5",
            "http://x.test/checkout",
        ] {
            assert!(destructive_keyword(url).is_some(), "{url}");
        }
    }

    #[test]
    fn ordinary_read_urls_are_not_flagged() {
        for url in [
            "http://x.test/api/users/101",
            "http://x.test/search?q=term&page=2",
            "http://x.test/payload?x=1",
            "http://x.test/dropdown/menu",
            "http://x.test/static/delete-icon.svg",
            "http://x.test/payments/12",
        ] {
            assert_eq!(destructive_keyword(url), None, "{url}");
        }
    }
}
