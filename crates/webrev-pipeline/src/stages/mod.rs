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
    let mean = (lo_f + hi_f) / 2.0;
    let std_dev = (hi_f - lo_f) / 6.0;
    // Normal::new only fails for a non-finite/negative std_dev, impossible here.
    match Normal::new(mean, std_dev) {
        Ok(dist) => {
            let sample = dist.sample(&mut rand::thread_rng()).clamp(lo_f, hi_f);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            {
                sample.round() as u64
            }
        }
        Err(_) => lo,
    }
}

/// Sleep for a jittered delay, unless the window is zero.
pub(crate) async fn sleep_with_jitter(opsec: &OpsecConfig) {
    let ms = sample_jitter_ms(opsec);
    if ms > 0 {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}
