use regex::Regex;
use std::time::Instant;
use std::hint::black_box;
fn main() {
    let mut rows = Vec::new();
    {
        let old = r####"(?:[A-Za-z_$][\w$]*\.)*http\.(get|post|put|delete|patch)\s*\(\s*`([^`]*)`"####;
        let new = r####"http\.(get|post|put|delete|patch)\s*\(\s*`([^`]*)`"####;
        let mut old_ns = 0u128;
        let mut new_ns = 0u128;
        for index in 0..100 {
            for (is_old, pattern) in if index % 2 == 0 { [(true, old), (false, new)] } else { [(false, new), (true, old)] } {
                let start = Instant::now();
                let compiled = Regex::new(pattern).unwrap();
                let elapsed = start.elapsed().as_nanos();
                black_box(compiled);
                if is_old { old_ns += elapsed; } else { new_ns += elapsed; }
            }
        }
        rows.push(format!(r#"{{"pattern":"http_client","iterations":100,"legacy_mean_ns":{},"optimized_mean_ns":{}}}"#, old_ns / 100, new_ns / 100));
    }
    {
        let old = r####"(?:fetch|axios\.(?:get|post|put|patch|delete)|(?:[A-Za-z_$][\w$]*\.)*http\.(?:get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]+)["'`]"####;
        let new = r####"(?:fetch|axios\.(?:get|post|put|patch|delete)|http\.(?:get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]+)["'`]"####;
        let mut old_ns = 0u128;
        let mut new_ns = 0u128;
        for index in 0..100 {
            for (is_old, pattern) in if index % 2 == 0 { [(true, old), (false, new)] } else { [(false, new), (true, old)] } {
                let start = Instant::now();
                let compiled = Regex::new(pattern).unwrap();
                let elapsed = start.elapsed().as_nanos();
                black_box(compiled);
                if is_old { old_ns += elapsed; } else { new_ns += elapsed; }
            }
        }
        rows.push(format!(r#"{{"pattern":"network_url","iterations":100,"legacy_mean_ns":{},"optimized_mean_ns":{}}}"#, old_ns / 100, new_ns / 100));
    }
    println!("[{}]", rows.join(","));
}
