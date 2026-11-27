//! Captured WebSocket frame types and the pre-send destructive-payload check.
//!
//! Split out of `ws_replay.rs` to keep each source file under the repository
//! size gate; the parent module re-exports the public items unchanged.

use super::super::destructive::payload_keyword;
use webrev_core::{Finding, FindingKind};

/// Which side sent a captured frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDirection {
    Sent,
    Received,
}

/// A captured WebSocket frame, as recorded by `webrev-browser`'s
/// `FindingKind::WebSocketFrame` (`provenance.location` = `"<direction>
/// <socket url>"`, `value` = payload, possibly truncated with a trailing
/// `…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrameCandidate {
    pub socket_url: String,
    pub direction: WsDirection,
    pub payload: String,
    /// True when the capture truncated this payload (`MAX_WS_PAYLOAD_CHARS`
    /// in `dynamic.rs`). A truncated frame is never replayed: resending a cut
    /// payload is not the frame that was actually observed.
    pub truncated: bool,
}

/// A literal, single-occurrence substring substitution applied to a frame's
/// payload before it is resent. Generic on purpose: this module has no model
/// of any particular frame's JSON schema, so it cannot name "the object id
/// field" the way `bola_diff` can for a URL path segment. The caller supplies
/// the exact substring to replace (typically a captured id) and its
/// replacement (e.g. another account's id, to mirror the BOLA cross-account
/// check over WebSocket instead of HTTP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsMutation {
    pub find: String,
    pub replace: String,
}

impl WsMutation {
    pub(super) fn apply(&self, payload: &str) -> String {
        payload.replacen(&self.find, &self.replace, 1)
    }
}

/// Extract candidate frames from captured findings. Only `FindingKind::
/// WebSocketFrame` entries are considered; everything else is ignored.
#[must_use]
pub fn ws_frame_candidates(findings: &[Finding]) -> Vec<WsFrameCandidate> {
    findings
        .iter()
        .filter(|f| f.kind == FindingKind::WebSocketFrame)
        .filter_map(|f| {
            let location = f.provenance.location.as_deref()?;
            let (direction, socket_url) = location.split_once(' ')?;
            let direction = match direction {
                "sent" => WsDirection::Sent,
                "received" => WsDirection::Received,
                _ => return None,
            };
            let truncated = f.value.ends_with('…');
            let payload = if truncated {
                f.value.trim_end_matches('…').to_owned()
            } else {
                f.value.clone()
            };
            Some(WsFrameCandidate {
                socket_url: socket_url.to_owned(),
                direction,
                payload,
                truncated,
            })
        })
        .collect()
}

/// Money-shaped field names, scanned on top of `payload_keyword`'s action
/// verbs. A JSON field with one of these names and a numeric value reads as
/// a state-changing amount even without an action verb, e.g.
/// `{"amount":500,"to":"acct_2"}`.
///
/// Heuristic only, with known gaps: it is blind to non-JSON payloads, to an
/// amount carried as a string (`"500.00"`), to a money-shaped key whose
/// value is actually an id or a count, and to any field name it does not
/// list. It can only ever be a denylist, never a proof that a frame is safe.
const MONEY_KEYS: &[&str] = &[
    "amount", "balance", "price", "total", "quantity", "sum", "credit", "debit", "payment",
];

fn money_field(payload: &str) -> Option<&'static str> {
    serde_json::from_str::<serde_json::Value>(payload)
        .ok()
        .and_then(|value| find_money_field(&value))
}

fn find_money_field(value: &serde_json::Value) -> Option<&'static str> {
    match value {
        serde_json::Value::Object(map) => map.iter().find_map(|(key, v)| {
            let lower = key.to_ascii_lowercase();
            MONEY_KEYS
                .iter()
                .find(|money| lower == **money || lower.ends_with(&format!("_{money}")))
                .filter(|_| v.is_number())
                .copied()
                .or_else(|| find_money_field(v))
        }),
        serde_json::Value::Array(items) => items.iter().find_map(find_money_field),
        _ => None,
    }
}

/// Why a frame is refused before anything is sent, if at all. Checked on the
/// payload that would actually be sent (post-mutation), so a mutation cannot
/// be used to smuggle a destructive-looking frame past the guard.
///
/// Documented limits: this is word/field-shape matching, not an
/// understanding of the target's API. A delete endpoint named `/sync` with a
/// payload `{"op":7}` is not recognised; a harmless frame that happens to
/// contain the word "cancel" in an unrelated string is refused anyway. See
/// `destructive::payload_keyword` and [`MONEY_KEYS`] for the exact rules.
#[must_use]
pub fn destructive_frame_keyword(payload: &str) -> Option<&'static str> {
    payload_keyword(payload).or_else(|| money_field(payload))
}
