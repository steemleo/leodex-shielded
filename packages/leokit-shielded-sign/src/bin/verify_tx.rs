//! verify_tx <tx_hex|@file> [--anchor <hex>] [--target <height>] [--nu7 <height>] [--params <dir>]
//!
//! Verifies a built Sapling v5 transaction (header, branch, expiry, anchor,
//! ZIP-317 fee, Groth16 proofs, spend-auth and binding signatures). Prints a
//! JSON report; exits non-zero on any failure.

use std::{env, fs, path::PathBuf, process::exit};

fn main() {
    let mut args = env::args().skip(1);
    let mut tx = None;
    let mut anchor = None;
    let mut target = None;
    let mut nu7 = None;
    let mut params_dir = env::var("ZCASH_PARAMS_DIR").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env::var("HOME").unwrap_or_default())
            .join(".zcash-params")
    });
    while let Some(a) = args.next() {
        match a.as_str() {
            "--anchor" => anchor = args.next(),
            "--target" => target = args.next().and_then(|v| v.parse::<u32>().ok()),
            "--nu7" => nu7 = args.next().and_then(|v| v.parse::<u32>().ok()),
            "--params" => params_dir = args.next().map(PathBuf::from).unwrap_or(params_dir),
            other => tx = Some(other.to_string()),
        }
    }
    let Some(tx) = tx else {
        eprintln!("usage: verify_tx <tx_hex|@file> [--anchor hex] [--target height] [--nu7 height] [--params dir]");
        exit(2);
    };
    let tx_hex = match tx.strip_prefix('@') {
        Some(path) => fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("read {path}: {e}");
            exit(2)
        }),
        None => tx,
    };
    let spend = fs::read(params_dir.join("sapling-spend.params")).expect("sapling-spend.params");
    let output = fs::read(params_dir.join("sapling-output.params")).expect("sapling-output.params");
    match leokit_shielded_sign::verify::verify_tx(&tx_hex, anchor.as_deref(), target, nu7, &spend, &output) {
        Ok(report) => println!("{}", serde_json::to_string_pretty(&report).unwrap()),
        Err(e) => {
            eprintln!("INVALID: {e}");
            exit(1);
        }
    }
}
