mod common;

use common::*;
use leokit_shielded_sign::{
    address_info, build_tx, consensus_branch_id_for_height, signer_info, verify::verify_tx,
    witness_root_hex, zip317_fee, LeokitNetwork, NU7_MAINNET,
};
use zcash_protocol::consensus::{BlockHeight, MainNetwork, NetworkUpgrade, Parameters, TestNetwork};
use serde_json::json;

// Branch IDs and activation heights hardcoded from ZIP 200 / 253 / 255 /
// 256 / 258 / 259 (never imported from the crates under test).
const NU6_1_BRANCH_ID: u32 = 0x4DEC_4DF0;
const NU6_2_BRANCH_ID: u32 = 0x5437_F330;
const NU6_3_BRANCH_ID: u32 = 0x37A5_165B;
const NU7_BRANCH_ID: u32 = 0x7719_0AD9;
const NU6_2_ACTIVATION: u32 = 3_364_600;
const NU6_3_ACTIVATION: u32 = 3_428_143;
/// ZIP 259: NU7 on mainnet and testnet.
const H: u32 = 3_543_405;
const NU7_TESTNET_ACTIVATION: u32 = 4_465_026;
/// v5 header (0x80000005) + version group 0x26A7270A, little-endian (ZIP 225).
const V5_PREFIX_HEX: &str = "050000800a27a726";

fn note_json(n: &NoteFixture) -> String {
    serde_json::to_string(n).unwrap()
}

fn le_hex(v: u32) -> String {
    hex::encode(v.to_le_bytes())
}

#[test]
fn branch_ids_follow_the_mainnet_schedule() {
    assert_eq!(consensus_branch_id_for_height(NU6_2_ACTIVATION - 1, None), NU6_1_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(NU6_2_ACTIVATION, None), NU6_2_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(NU6_3_ACTIVATION - 1, None), NU6_2_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(NU6_3_ACTIVATION, None), NU6_3_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(TARGET_HEIGHT, None), NU6_3_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(H - 1, None), NU6_3_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(H, None), NU7_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(H + 1, None), NU7_BRANCH_ID);
    assert_eq!(consensus_branch_id_for_height(10_000_000, None), NU7_BRANCH_ID);
}

#[test]
fn nu7_is_built_in_at_zip_259s_height() {
    assert_eq!(MainNetwork.activation_height(NetworkUpgrade::Nu7), Some(BlockHeight::from_u32(H)));
    assert_eq!(
        TestNetwork.activation_height(NetworkUpgrade::Nu7),
        Some(BlockHeight::from_u32(NU7_TESTNET_ACTIVATION))
    );
    assert_eq!(NU7_MAINNET, H);
}

#[test]
fn a_caller_nu7_height_is_only_a_cross_check() {
    for h in [H - 1, H, H + 1, TARGET_HEIGHT] {
        assert_eq!(
            consensus_branch_id_for_height(h, Some(H)),
            consensus_branch_id_for_height(h, None),
            "equal caller height changes nothing at {h}"
        );
    }
    // Any other height (a different multiple of 3, the testnet one, junk) matches no branch.
    for bad in [H - 3, H + 3, NU7_TESTNET_ACTIVATION, NU6_3_ACTIVATION, 0, u32::MAX] {
        assert_eq!(consensus_branch_id_for_height(H, Some(bad)), 0, "{bad}");
        assert_eq!(consensus_branch_id_for_height(TARGET_HEIGHT, Some(bad)), 0, "{bad}");
        let err = LeokitNetwork::new(Some(bad)).unwrap_err();
        assert!(err.starts_with("INVALID_INPUT: "), "{bad}: {err}");
    }
}

#[test]
fn a_disagreeing_caller_height_is_refused_before_proving() {
    let sc = scenario();
    let mut args: serde_json::Value = serde_json::from_str(&build_args(
        &sc.s2,
        &[0],
        json!([{ "recipient": own_ua(), "amount_zats": 1_000_000 }]),
        None,
        H + 10,
    ))
    .unwrap();
    args["nu7_activation_height"] = json!(H + 3);
    let err = build_tx(&args.to_string(), &[], &[]).unwrap_err();
    assert!(err.starts_with("INVALID_INPUT: nu7_activation_height"), "{err}");
}

#[test]
fn expiry_matches_the_sdk_rules() {
    for net in [LeokitNetwork::new(None).unwrap(), LeokitNetwork::new(Some(H)).unwrap()] {
        let e = |t: u32| net.expiry_for(BlockHeight::from_u32(t)).map(u32::from);
        // Well before H: the ZIP 203 delta.
        assert_eq!(e(TARGET_HEIGHT), Ok(TARGET_HEIGHT + 40));
        assert_eq!(e(H - 100), Ok(H - 60));
        assert_eq!(e(H - 41), Ok(H - 1));
        // The default would cross H: clamp to H-1 so an NU6.3 tx can't outlive the upgrade.
        assert_eq!(e(H - 40), Ok(H - 1));
        assert_eq!(e(H - 20), Ok(H - 1));
        assert_eq!(e(H - 4), Ok(H - 1));
        // Too close for nodes to accept (zcashd TX_EXPIRING_SOON_THRESHOLD = 3).
        for t in [H - 3, H - 2, H - 1] {
            let err = e(t).unwrap_err();
            assert!(err.starts_with("UPGRADE_IMMINENT: "), "{t}: {err}");
        }
        // At and after H: ZIP 218's 120-block delta.
        assert_eq!(e(H), Ok(H + 120));
        assert_eq!(e(H + 500), Ok(H + 620));
    }
}

#[test]
fn refuses_to_build_right_before_nu7() {
    let sc = scenario();
    for t in [H - 3, H - 2, H - 1] {
        let args = build_args(&sc.s2, &[0], json!([{ "recipient": own_ua(), "amount_zats": 1_000_000 }]), None, t);
        let err = build_tx(&args, &[], &[]).unwrap_err();
        assert!(err.starts_with("UPGRADE_IMMINENT: "), "{t}: {err}");
    }
}

#[test]
fn signer_info_reports_version_nu63_and_nu7() {
    let info: serde_json::Value = serde_json::from_str(&signer_info()).unwrap();
    assert_eq!(info["signer_version"], "0.0.8");
    assert_eq!(info["tx_version"], "v5");
    let upgrade = |name: &str| info["upgrades"].as_array().unwrap().iter().find(|u| u["name"] == name).cloned().unwrap();
    assert_eq!(upgrade("NU6.3")["activation_height"], NU6_3_ACTIVATION);
    assert_eq!(upgrade("NU6.3")["branch_id"], "0x37a5165b");
    assert_eq!(upgrade("NU7")["activation_height"], H);
    assert_eq!(upgrade("NU7")["branch_id"], "0x77190ad9");
    assert_eq!(info["nu7"]["branch_id"], "0x77190ad9");
    assert_eq!(info["nu7"]["mainnet_activation_height"], H);
    assert_eq!(info["nu7"]["testnet_activation_height"], NU7_TESTNET_ACTIVATION);
}

#[test]
fn committed_fixtures_match_the_generator() {
    let sc = scenario();
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let read = |name: &str| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(dir.join(name)).unwrap()).unwrap()
    };
    let fresh = read("fresh.json");
    assert_eq!(fresh["anchor_hex"], json!(sc.s2.anchor_hex));
    assert_eq!(fresh["notes"], serde_json::to_value(&sc.s2.notes).unwrap());
    assert_eq!(fresh["meta"]["own_ua"], json!(own_ua()));
    assert_eq!(fresh["meta"]["target_height"], json!(TARGET_HEIGHT));
    let stale = read("stale-mixed.json");
    assert_eq!(stale["stale_anchor_hex"], json!(sc.s1.anchor_hex));
    assert_eq!(stale["notes"], serde_json::to_value(&sc.stale_mixed().notes).unwrap());
    assert_eq!(read("addresses.json")["orchard_only_unified"], json!(orchard_only_ua()));
}

#[test]
fn witness_root_equals_anchor_only_for_fresh_witnesses() {
    let sc = scenario();
    assert_ne!(sc.s1.anchor_hex, sc.s2.anchor_hex);
    for n in &sc.s2.notes {
        assert_eq!(witness_root_hex(&note_json(n)).unwrap(), sc.s2.anchor_hex);
    }
    let stale = sc.stale_mixed();
    for (i, n) in stale.notes.iter().enumerate() {
        let root = witness_root_hex(&note_json(n)).unwrap();
        if i < 3 {
            assert_eq!(root, sc.s1.anchor_hex, "stale note {i} roots to the old anchor");
            assert_ne!(root, stale.anchor_hex);
        } else {
            assert_eq!(root, stale.anchor_hex);
        }
    }
}

#[test]
fn witness_root_rejects_malformed_notes() {
    let sc = scenario();
    let mut bad = sc.s2.notes[0].clone();
    bad.witness.pop();
    let err = witness_root_hex(&note_json(&bad)).unwrap_err();
    assert!(err.starts_with("INVALID_INPUT:"), "{err}");
}

#[test]
fn address_info_classifies_every_recipient_kind() {
    let ua = address_info(&own_ua());
    assert_eq!((ua.kind, ua.has_sapling, ua.payable), ("unified", true, true));
    let zs = address_info(&own_zs1());
    assert_eq!((zs.kind, zs.payable), ("sapling", true));
    for t in [t1(), t3()] {
        let info = address_info(&t);
        assert_eq!((info.kind, info.has_transparent, info.payable), ("transparent", true, true));
    }
    let tex = address_info(&tex());
    assert_eq!((tex.kind, tex.payable), ("tex", false));
    let orchard = address_info(&orchard_only_ua());
    assert_eq!((orchard.kind, orchard.has_sapling, orchard.has_orchard, orchard.payable), ("unified", false, true, false));
    assert_eq!(address_info("not-an-address").kind, "invalid");
    assert_eq!(address_info("tmXYZ").kind, "wrong_network");
}

#[test]
fn zip317_fee_counts_sapling_padding() {
    assert_eq!(zip317_fee(1, 0, 2), 10_000); // 1 spend → recipient + change
    assert_eq!(zip317_fee(1, 1, 1), 15_000); // 1 spend → t1 + change (padded to 2)
    assert_eq!(zip317_fee(1, 1, 2), 15_000); // MAYA memo shape: t1 + memo + change
    assert_eq!(zip317_fee(3, 0, 2), 15_000); // 3 spends → 1 output + change
    assert_eq!(zip317_fee(1, 2, 1), 20_000);
}

#[test]
fn rejects_unpayable_recipients_before_proving() {
    let sc = scenario();
    for (addr, code) in [
        (orchard_only_ua(), "NO_SAPLING_RECEIVER:"),
        (tex(), "UNSUPPORTED_RECIPIENT:"),
        ("garbage".to_string(), "INVALID_RECIPIENT:"),
    ] {
        let args = build_args(&sc.s2, &[0], json!([{ "recipient": addr, "amount_zats": 1_000_000 }]), None, TARGET_HEIGHT);
        let err = build_tx(&args, &[], &[]).unwrap_err();
        assert!(err.starts_with(code), "{addr}: {err}");
    }
}

#[test]
fn rejects_insufficient_funds_with_a_stable_code() {
    let sc = scenario();
    let args = build_args(&sc.s2, &[0], json!([{ "recipient": own_ua(), "amount_zats": NOTE_VALUES[0] }]), None, TARGET_HEIGHT);
    let err = build_tx(&args, &[], &[]).unwrap_err();
    assert!(err.starts_with("INSUFFICIENT_FUNDS:"), "{err}");
}

// ---- real proving (needs the Sapling params; ~seconds each natively) ----

fn require_params() -> Option<(Vec<u8>, Vec<u8>)> {
    let p = params();
    if p.is_none() {
        eprintln!("SKIP: Sapling params not found (set ZCASH_PARAMS_DIR)");
    }
    p
}

#[test]
fn stale_mixed_witnesses_fail_with_anchor_mismatch() {
    let Some((spend, output)) = require_params() else { return };
    let sc = scenario();
    let stale = sc.stale_mixed();
    let args = build_args(&stale, &[0, 1], json!([{ "recipient": own_ua(), "amount_zats": 50_000_000 }]), None, TARGET_HEIGHT);
    let err = build_tx(&args, &spend, &output).unwrap_err();
    assert!(err.starts_with("ANCHOR_MISMATCH: note[0]"), "{err}");
    assert!(err.contains("AnchorMismatch"), "keeps the builder detail: {err}");
}

fn shapes() -> Vec<(&'static str, Vec<usize>, serde_json::Value, Option<serde_json::Value>)> {
    vec![
        ("1 spend → own UA", vec![0], json!([{ "recipient": own_ua(), "amount_zats": 10_000_000, "memo": "hi" }]), None),
        ("1 spend → zs1", vec![1], json!([{ "recipient": own_zs1(), "amount_zats": 10_000_000 }]), None),
        ("1 spend → t1 (deshield, padded)", vec![0], json!([{ "recipient": t1(), "amount_zats": 10_000_000 }]), None),
        (
            "MAYA memo shape: t1 principal + 0-value memo note",
            vec![1],
            json!([{ "recipient": t1(), "amount_zats": 20_000_000 }]),
            Some(json!({ "recipient_ua": own_ua(), "memo_text": "=:e:0x0000000000000000000000000000000000000000" })),
        ),
        ("3 spends → 1 output", vec![0, 1, 3], json!([{ "recipient": own_ua(), "amount_zats": 110_000_000 }]), None),
    ]
}

/// Every fee shape, at a pre-NU7 target and a post-NU7 target.
#[test]
fn fee_shapes_build_and_verify_on_both_branches() {
    let Some((spend, output)) = require_params() else { return };
    let sc = scenario();
    let s2 = &sc.s2;
    for (target, branch) in [(TARGET_HEIGHT, NU6_3_BRANCH_ID), (H + 10, NU7_BRANCH_ID)] {
        for (name, notes, outputs, memo_note) in shapes() {
            let args = build_args(s2, &notes, outputs, memo_note, target);
            let built = build_tx(&args, &spend, &output).unwrap_or_else(|e| panic!("{name} @ {target}: {e}"));
            let report = verify_tx(&built.tx_hex, Some(&s2.anchor_hex), Some(target), None, &spend, &output)
                .unwrap_or_else(|e| panic!("{name} @ {target}: verify_tx: {e}"));
            assert_eq!(report.branch_id, format!("0x{branch:08x}"), "{name} @ {target}");
            assert!(built.tx_hex.starts_with(V5_PREFIX_HEX), "{name} @ {target}: v5 header");
            assert_eq!(&built.tx_hex[16..24], le_hex(branch), "{name} @ {target}: header branch");
            assert_eq!(report.fee_zats as u64, built.fee_zats, "{name} @ {target}");
            assert_eq!(report.expected_fee_zats, built.fee_zats, "{name} @ {target}");
            assert_eq!(report.txid, built.txid, "{name} @ {target}");
            assert!(report.sapling_outputs >= 2, "{name} @ {target}: Sapling bundle padded");
        }
    }
}

#[test]
fn exact_amount_without_change_balances() {
    let Some((spend, output)) = require_params() else { return };
    let sc = scenario();
    let s2 = &sc.s2;
    // 1 spend → own UA, no change: padded to 2 outputs → fee 10,000.
    let amount = NOTE_VALUES[0] - 10_000;
    let args = build_args(s2, &[0], json!([{ "recipient": own_ua(), "amount_zats": amount }]), None, TARGET_HEIGHT);
    let built = build_tx(&args, &spend, &output).unwrap();
    assert_eq!(built.fee_zats, 10_000);
    verify_tx(&built.tx_hex, Some(&s2.anchor_hex), Some(TARGET_HEIGHT), None, &spend, &output).unwrap();
}

#[test]
fn verify_tx_rejects_a_pre_nu63_build() {
    let Some((spend, output)) = require_params() else { return };
    let sc = scenario();
    let target = NU6_3_ACTIVATION - 10;
    let args = build_args(&sc.s2, &[0], json!([{ "recipient": own_ua(), "amount_zats": 1_000_000 }]), None, target);
    let built = build_tx(&args, &spend, &output).unwrap();
    let err = verify_tx(&built.tx_hex, None, None, None, &spend, &output).unwrap_err();
    assert!(err.contains("branch id 0x5437f330"), "negative control: {err}");
}

fn build_at(snap: &Snapshot, target: u32, nu7: Option<u32>, spend: &[u8], output: &[u8]) -> Result<leokit_shielded_sign::BuiltTx, String> {
    let mut args: serde_json::Value = serde_json::from_str(&build_args(
        snap,
        &[0],
        json!([{ "recipient": own_ua(), "amount_zats": 1_000_000 }]),
        None,
        target,
    ))
    .unwrap();
    if let Some(h) = nu7 {
        args["nu7_activation_height"] = json!(h);
    }
    build_tx(&args.to_string(), spend, output)
}

/// The two NU7 boundary cases: a pre-H tx signs NU6.3 with expiry ≤ H-1 (the
/// clamp), a post-H tx signs NU7 as v5. With and without the caller height.
#[test]
fn builds_and_verifies_on_both_sides_of_nu7() {
    let Some((spend, output)) = require_params() else { return };
    let sc = scenario();
    // (target, expected branch, expected expiry)
    let cases = [
        (H - 100, NU6_3_BRANCH_ID, H - 60),
        (H - 41, NU6_3_BRANCH_ID, H - 1),
        (H - 20, NU6_3_BRANCH_ID, H - 1),
        (H - 4, NU6_3_BRANCH_ID, H - 1),
        (H, NU7_BRANCH_ID, H + 120),
        (H + 1, NU7_BRANCH_ID, H + 121),
        (H + 50, NU7_BRANCH_ID, H + 170),
    ];
    for nu7 in [None, Some(H)] {
        for (target, branch, expiry) in cases {
            let built = build_at(&sc.s2, target, nu7, &spend, &output).unwrap_or_else(|e| panic!("{target}/{nu7:?}: {e}"));
            let report = verify_tx(&built.tx_hex, Some(&sc.s2.anchor_hex), Some(target), None, &spend, &output)
                .unwrap_or_else(|e| panic!("{target}/{nu7:?}: verify_tx: {e}"));
            assert_eq!(report.branch_id, format!("0x{branch:08x}"), "{target}");
            assert_eq!(report.expiry_height, expiry, "{target}");
            assert!(expiry < H || branch == NU7_BRANCH_ID, "an NU6.3 tx never outlives H-1");
            assert!(built.tx_hex.starts_with(V5_PREFIX_HEX), "{target}: v5 header");
            assert_eq!(&built.tx_hex[16..24], le_hex(branch), "{target}: header branch");
            assert_eq!(&built.tx_hex[32..40], le_hex(expiry), "{target}: header expiry");
            assert_eq!(report.txid, built.txid, "{target}");
        }
    }
}

#[test]
fn verify_tx_rejects_an_nu63_tx_targeted_after_nu7() {
    let Some((spend, output)) = require_params() else { return };
    let sc = scenario();
    // An honest NU6.3 tx, checked as if it were mined after H: the branch is wrong there.
    let built = build_at(&sc.s2, H - 20, None, &spend, &output).unwrap();
    let err = verify_tx(&built.tx_hex, None, Some(H + 10), None, &spend, &output).unwrap_err();
    assert!(err.contains("branch id 0x37a5165b != 0x77190ad9"), "negative control: {err}");
    // And an NU7 tx checked as if mined before H.
    let built = build_at(&sc.s2, H, None, &spend, &output).unwrap();
    let err = verify_tx(&built.tx_hex, None, Some(H - 1), None, &spend, &output).unwrap_err();
    assert!(err.contains("branch id 0x77190ad9 != 0x37a5165b"), "negative control: {err}");
}
