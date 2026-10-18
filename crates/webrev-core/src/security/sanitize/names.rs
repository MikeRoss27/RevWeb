// crates/webrev-core/src/security/sanitize/names.rs
//! What is a credential and what is merely an identifier.
//!
//! Redaction hides credentials. An object identifier (`/orders/<uuid>`,
//! `?account_id=42`) is not one, and masking it makes a BOLA/IDOR result
//! useless: the reader can no longer tell which object leaked. These helpers
//! keep the two apart.

/// Words that name a credential when they appear as a whole word of a
/// parameter or key name (`access_token`, `apiKey`, `SAMLResponse`).
/// `author_id`, `passenger_id` and `sort_key_order` do not match: matching is
/// per word, never per substring.
const CREDENTIAL_WORDS: [&str; 32] = [
    "key",
    "keys",
    "secret",
    "secrets",
    "pass",
    "passwd",
    "password",
    "passwords",
    "passcode",
    "pwd",
    "auth",
    "authorization",
    "sig",
    "signature",
    "session",
    "sessions",
    "sid",
    "jwt",
    "bearer",
    "credential",
    "credentials",
    "csrf",
    "xsrf",
    "saml",
    "hmac",
    "ticket",
    "token",
    "tokens",
    "cookie",
    "cookies",
    "sessid",
    "sessionid",
];

/// Fragments that mark a single compound word as a credential
/// (`accesstoken`, `PHPSESSID`, `clientsecret`).
const CREDENTIAL_FRAGMENTS: [&str; 12] = [
    "token",
    "secret",
    "password",
    "passwd",
    "sessid",
    "sessionid",
    "apikey",
    "credential",
    "bearer",
    "csrf",
    "xsrf",
    "passphrase",
];

/// Split a name into lower-case words on non-alphanumerics and on case
/// changes: `accessToken` and `access_token` give `access`, `token`;
/// `SAMLResponse` gives `saml`, `response`.
fn words(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut out = Vec::new();
    let mut current = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        let prev = i.checked_sub(1).map(|p| chars[p]);
        let next = chars.get(i + 1).copied();
        let lower_to_upper = c.is_ascii_uppercase()
            && prev.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit());
        let acronym_end = c.is_ascii_uppercase()
            && prev.is_some_and(|p| p.is_ascii_uppercase())
            && next.is_some_and(|n| n.is_ascii_lowercase());
        if (lower_to_upper || acronym_end) && !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// True when a parameter, header or JSON key name says its value is a
/// credential.
pub(super) fn is_credential_name(name: &str) -> bool {
    words(name).iter().any(|word| {
        CREDENTIAL_WORDS.contains(&word.as_str())
            || (word.len() >= 6
                && CREDENTIAL_FRAGMENTS
                    .iter()
                    .any(|fragment| word.contains(fragment)))
    })
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

/// The shape of an identifier an application hands out for its own objects: a
/// number, a UUID, or a hexadecimal id of up to 32 digits (a Mongo `ObjectId`,
/// a UUID without dashes, a short hash). Longer hex strings (SHA-1, SHA-256)
/// are not treated as identifiers.
///
/// The shape alone proves nothing about secrecy, so it exempts a value from
/// the credential-shaped heuristics only; a credential *name* or a
/// credential-naming path segment (`/reset/<id>`) still masks it.
pub(super) fn looks_like_object_id(value: &str) -> bool {
    !value.is_empty()
        && (value.bytes().all(|b| b.is_ascii_digit())
            || is_uuid(value)
            || (value.len() <= 32 && value.bytes().all(|b| b.is_ascii_hexdigit())))
}

/// Path segments after which the next segment is a credential, not an object:
/// `/reset/<token>`, `/invite/<code>`, `/verify/<token>`.
const CREDENTIAL_PATH_HINTS: [&str; 16] = [
    "reset",
    "recover",
    "recovery",
    "forgot",
    "token",
    "tokens",
    "invite",
    "invitation",
    "verify",
    "verification",
    "confirm",
    "confirmation",
    "activate",
    "activation",
    "magic",
    "unsubscribe",
];

/// True when `previous` is a segment that introduces a credential.
pub(super) fn introduces_credential(previous: &str) -> bool {
    let lower = previous.to_ascii_lowercase();
    CREDENTIAL_PATH_HINTS.contains(&lower.as_str())
        || lower.ends_with("-token")
        || lower.ends_with("_token")
}

/// A segment worth masking after [`introduces_credential`]: long enough and
/// mixed enough to be a token or an identifier standing in for one, not a word
/// (`/reset/confirm`) or a short number.
pub(super) fn follows_credential_shape(segment: &str) -> bool {
    segment.len() >= 8
        && segment.bytes().any(|b| b.is_ascii_digit())
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_names_match_per_word() {
        for name in [
            "token",
            "access_token",
            "accessToken",
            "Api_Key",
            "apiKey",
            "id_token",
            "csrf_token",
            "SAMLResponse",
            "session_id",
            "sessionId",
            "PHPSESSID",
            "password",
            "db_password",
            "X-Client-Secret",
            "user[token]",
            "sig",
            "ticket",
        ] {
            assert!(is_credential_name(name), "{name}");
        }
        for name in [
            "author_id",
            "authorId",
            "passenger_id",
            "design_id",
            "signup",
            "monkey_id",
            "residence_id",
            "order_id",
            "account_id",
            "page",
            "sort",
            "encode",
            "barcode",
            "postcode",
            "title",
        ] {
            assert!(!is_credential_name(name), "{name}");
        }
    }

    #[test]
    fn object_ids_are_numbers_uuids_and_short_hex() {
        for id in [
            "42",
            "1700000000000",
            "550e8400-e29b-41d4-a716-446655440000",
            "550E8400-E29B-41D4-A716-446655440000",
            "550e8400e29b41d4a716446655440000",
            "507f1f77bcf86cd799439011",
        ] {
            assert!(looks_like_object_id(id), "{id}");
        }
        for not_id in [
            "",
            "Zk3Jq9XvT2bLm8Rw4NpYs7Ad",
            "9f86d081884c7d659a2feaa0c55ad0159f86d081",
            "550e8400-e29b-41d4-a716-44665544000g",
            "order-1234",
        ] {
            assert!(!looks_like_object_id(not_id), "{not_id}");
        }
    }

    #[test]
    fn credential_paths_introduce_a_credential() {
        for hint in ["reset", "Invite", "verify", "api-token", "csrf_token"] {
            assert!(introduces_credential(hint), "{hint}");
        }
        for plain in ["users", "orders", "api", "tokenizer", "keys"] {
            assert!(!introduces_credential(plain), "{plain}");
        }
        assert!(follows_credential_shape(
            "550e8400-e29b-41d4-a716-446655440000"
        ));
        assert!(follows_credential_shape("a1b2c3d4e5"));
        assert!(!follows_credential_shape("confirm"));
        assert!(!follows_credential_shape("12345"));
        assert!(!follows_credential_shape("deadbeefcafe"));
    }
}
