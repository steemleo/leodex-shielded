//! Writes the deterministic signer fixtures used by the SDK and app
//! tests and `scripts/verify-release.mjs`:
//!   cargo run --example gen_fixtures
#[path = "../tests/common/mod.rs"]
mod common;

use common::*;
use serde_json::json;

fn main() {
    let sc = scenario();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    std::fs::create_dir_all(&dir).unwrap();
    let write = |name: &str, v: serde_json::Value| {
        std::fs::write(dir.join(name), serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    };
    let meta = json!({
        "seed_phrase": SEED,
        "account": 0,
        "target_height": TARGET_HEIGHT,
        "own_ua": own_ua(),
        "own_zs1": own_zs1(),
    });
    write("fresh.json", json!({ "meta": meta, "anchor_hex": sc.s2.anchor_hex, "notes": sc.s2.notes }));
    let stale = sc.stale_mixed();
    write(
        "stale-mixed.json",
        json!({ "meta": meta, "anchor_hex": stale.anchor_hex, "stale_anchor_hex": sc.s1.anchor_hex, "notes": stale.notes }),
    );
    write(
        "addresses.json",
        json!({
            "unified_with_sapling": own_ua(),
            "sapling": own_zs1(),
            "transparent_p2pkh": t1(),
            "transparent_p2sh": t3(),
            "tex": tex(),
            "orchard_only_unified": orchard_only_ua(),
        }),
    );
    println!("fixtures written to {}", dir.display());
}
