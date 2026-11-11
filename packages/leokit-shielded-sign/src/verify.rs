//! Native-only transaction verifier: parses a built transaction and checks
//! what a Zcash node checks for a Sapling-only v5 spend, so every
//! transaction can be proven valid before it is broadcast.
//!
//! Header constants are hardcoded from ZIP 225 / ZIP 258 / ZIP 259, not
//! taken from the crates under test.

use sapling_crypto::BatchValidator;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;

use crate::{os_rng, zip317_fee};

const V5_HEADER: u32 = 0x8000_0005;
const V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
const NU6_3_BRANCH_ID: u32 = 0x37A5_165B;
const NU7_BRANCH_ID: u32 = 0x7719_0AD9;
/// ZIP 259 mainnet NU7 height; `--nu7` overrides it only to test the verifier.
const NU7_ACTIVATION: u32 = 3_543_405;
/// ZIP 203 (Blossom) and ZIP 218 (NU7) default expiry deltas; zcashd's
/// TX_EXPIRING_SOON_THRESHOLD.
const EXPIRY_DELTA_PRE_NU7: u32 = 40;
const EXPIRY_DELTA_NU7: u32 = 120;
const EXPIRING_SOON: u32 = 3;

/// The branch a node enforces at `target` (independent of the crate's
/// mapping): NU6.3 below the NU7 height, NU7 from it.
fn expected_branch(target: u32, nu7: u32) -> u32 {
    if target >= nu7 { NU7_BRANCH_ID } else { NU6_3_BRANCH_ID }
}

/// The expiry a correct signer sets for `target`, written out here rather
/// than taken from the signer: the default delta, clamped to the block
/// before NU7 when it would cross it; None when nothing valid can be built.
fn expected_expiry(target: u32, nu7: u32) -> Option<u32> {
    if target >= nu7 {
        Some(target + EXPIRY_DELTA_NU7)
    } else if target + EXPIRY_DELTA_PRE_NU7 >= nu7 {
        (nu7 > target + EXPIRING_SOON).then_some(nu7 - 1)
    } else {
        Some(target + EXPIRY_DELTA_PRE_NU7)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct VerifyReport {
    pub txid: String,
    pub branch_id: String,
    pub expiry_height: u32,
    pub anchor_hex: String,
    pub spends: usize,
    pub sapling_outputs: usize,
    pub transparent_outputs: usize,
    pub fee_zats: i64,
    pub expected_fee_zats: u64,
    pub proofs_and_signatures_valid: bool,
}

pub fn verify_tx(
    tx_hex: &str,
    expected_anchor_hex: Option<&str>,
    target_height: Option<u32>,
    nu7_activation_height: Option<u32>,
    spend_params: &[u8],
    output_params: &[u8],
) -> Result<VerifyReport, String> {
    let bytes = hex::decode(tx_hex.trim()).map_err(|e| format!("tx hex: {e}"))?;
    if bytes.len() < 12 {
        return Err("tx too short".into());
    }
    let word = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
    if word(0) != V5_HEADER {
        return Err(format!("header 0x{:08x} != v5 0x{V5_HEADER:08x}", word(0)));
    }
    if word(4) != V5_VERSION_GROUP_ID {
        return Err(format!("version group 0x{:08x} != 0x{V5_VERSION_GROUP_ID:08x}", word(4)));
    }
    let branch = word(8);
    let nu7 = nu7_activation_height.unwrap_or(NU7_ACTIVATION);
    match target_height {
        Some(t) => {
            let want = expected_branch(t, nu7);
            if branch != want {
                return Err(format!("branch id 0x{branch:08x} != 0x{want:08x} expected at {t}"));
            }
        }
        None if branch != NU6_3_BRANCH_ID && branch != NU7_BRANCH_ID => {
            return Err(format!("branch id 0x{branch:08x} is neither NU6.3 nor NU7"));
        }
        None => {}
    }
    let branch_id = BranchId::try_from(branch).map_err(|e| format!("branch id: {e}"))?;

    let tx = Transaction::read(&bytes[..], branch_id).map_err(|e| format!("parse: {e}"))?;
    if tx.version() != TxVersion::V5 {
        return Err(format!("parsed version {:?} != V5", tx.version()));
    }
    let expiry = u32::from(tx.expiry_height());
    if let Some(t) = target_height {
        let want = expected_expiry(t, nu7).ok_or(format!("no valid expiry for target {t} (NU7 at {nu7})"))?;
        if expiry != want {
            return Err(format!("expiry {expiry} != {want} expected for target {t}"));
        }
    }
    if tx.orchard_bundle().is_some() {
        return Err("unexpected Orchard bundle".into());
    }
    if tx.transparent_bundle().is_some_and(|b| !b.vin.is_empty()) {
        return Err("unexpected transparent inputs".into());
    }

    let bundle = tx.sapling_bundle().ok_or("no Sapling bundle")?;
    let spends = bundle.shielded_spends();
    let first = spends.first().ok_or("no Sapling spends")?;
    let anchor = first.anchor().to_bytes();
    if spends.iter().any(|s| s.anchor().to_bytes() != anchor) {
        return Err("spends disagree on anchor".into());
    }
    let anchor_hex = hex::encode(anchor);
    if let Some(expected) = expected_anchor_hex {
        if !expected.eq_ignore_ascii_case(&anchor_hex) {
            return Err(format!("anchor {anchor_hex} != expected {expected}"));
        }
    }

    let t_out: Vec<u64> = tx
        .transparent_bundle()
        .map(|b| b.vout.iter().map(|o| o.value().into_u64()).collect())
        .unwrap_or_default();
    let fee = i64::from(*bundle.value_balance()) - t_out.iter().sum::<u64>() as i64;
    let expected_fee = zip317_fee(spends.len(), t_out.len(), bundle.shielded_outputs().len());
    if fee != expected_fee as i64 {
        return Err(format!("fee {fee} != ZIP-317 {expected_fee}"));
    }

    // ZIP 244: with no transparent inputs (checked above) the shielded
    // signature digest is the txid digest (zcash_primitives sighash_v5.rs:42).
    let sighash: [u8; 32] = *tx.txid().as_ref();
    let params = zcash_proofs::parse_parameters(spend_params, output_params, None);
    let mut validator = BatchValidator::new();
    let consensus_ok = validator.check_bundle(bundle.clone(), sighash);
    let batch_ok = consensus_ok
        && validator.validate(
            &params.spend_params.verifying_key(),
            &params.output_params.verifying_key(),
            os_rng(),
        );
    if !batch_ok {
        return Err("Sapling proofs / signatures failed verification".into());
    }

    Ok(VerifyReport {
        txid: tx.txid().to_string(),
        branch_id: format!("0x{:08x}", word(8)),
        expiry_height: expiry,
        anchor_hex,
        spends: spends.len(),
        sapling_outputs: bundle.shielded_outputs().len(),
        transparent_outputs: t_out.len(),
        fee_zats: fee,
        expected_fee_zats: expected_fee,
        proofs_and_signatures_valid: true,
    })
}

