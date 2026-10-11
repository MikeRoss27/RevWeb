// crates/webrev-pipeline/src/stages/mod.rs
//! The concrete pipeline stages plus a shared jitter helper.

mod fetch;
mod static_extract;
mod store;

pub use fetch::FetchStage;
pub use static_extract::StaticExtractStage;
pub use store::StoreStage;

use rand_distr::{Distribution, Normal};
use std::time::Duration;
use webrev_core::OpsecConfig;

/// Sample an inter-request delay from a normal distribution centred in the
/// configured `[min, max]` window (≈99.7% of samples fall inside it) and clamp
/// to the bounds. This spaces out traffic to stay polite rather than hammering
/// a target, which is both courteous and reduces the chance of tripping rate
/// limits during authorized testing.
fn sample_jitter_ms(opsec: &OpsecConfig) -> u64 {
    let (lo, hi) = opsec.delay_window();
    if lo >= hi {
        return lo;
    }
    #[allow(clippy::cast_precision_loss)] // ms magnitudes are tiny; f64 is exact here
    let (lo_f, hi_f) = (lo as f64, hi as f64);
    let mean = lo_f.midpoint(hi_f);
    let std_dev = (hi_f - lo_f) / 6.0;
    // Normal::new only fails for a non-finite/negative std_dev, impossible here.
    match Normal::new(mean, std_dev) {
        Ok(dist) => {
            let sample = dist.sample(&mut rand::rng()).clamp(lo_f, hi_f);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                sample.round() as u64
            }
        }
        Err(_) => lo,
    }
}

/// Stretch a base delay by `strikes` consecutive waves that drew a 429/503
/// from the target: each strike doubles it, capped at 16x, with a 500ms floor
/// once backing off at all. Pulled out of [`sleep_with_jitter`] so the backoff
/// curve itself is unit-testable without sleeping.
fn backoff_delay_ms(base_ms: u64, strikes: u32) -> u64 {
    let multiplier = 1u64 << strikes.min(4);
    base_ms
        .saturating_mul(multiplier)
        .max(if strikes > 0 { 500 } else { 0 })
}

/// Sleep for a jittered delay, stretched by `strikes` (see
/// [`backoff_delay_ms`]). This is what lets the crawler react to a
/// WAF/rate limiter by slowing down instead of hammering it at a fixed
/// cadence until the engagement gets blocked outright.
pub(crate) async fn sleep_with_jitter(opsec: &OpsecConfig, strikes: u32) {
    let ms = backoff_delay_ms(sample_jitter_ms(opsec), strikes);
    if ms > 0 {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_per_strike_and_floors_at_500ms() {
        assert_eq!(backoff_delay_ms(100, 0), 100);
        assert_eq!(backoff_delay_ms(100, 1), 500); // 200 < 500 floor
        assert_eq!(backoff_delay_ms(400, 1), 800);
        assert_eq!(backoff_delay_ms(100, 2), 500); // 400 < 500 floor
        assert_eq!(backoff_delay_ms(1000, 2), 4000);
        // Capped at 2^4 = 16x regardless of how high strikes climbs.
        assert_eq!(backoff_delay_ms(1000, 4), backoff_delay_ms(1000, 10));
    }
}
