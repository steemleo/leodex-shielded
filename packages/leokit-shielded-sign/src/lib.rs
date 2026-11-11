//! leokit-shielded-sign — browser WASM crate that builds + signs Zcash
//! Sapling transactions client-side. Transactions are pinned to v5: valid
//! under NU6.3 (Ironwood) and NU7, and the format every downstream parser
//! handles.
//!
//! NU7 (ZIP 259): mainnet height 3,543,405, branch 0x77190ad9, built in from
//! the stable `zcash_protocol 0.11.0`. A caller may pass
//! `nu7_activation_height` as a cross-check; any other value is refused.
//!
//! Errors are strings prefixed with a stable code (`ANCHOR_MISMATCH: ...`)
//! so the SDK can map them without guessing at wording.
//!
//! Trust model: the seed phrase and derived spending key NEVER leave this
//! WASM module's memory. The leokit-shielded server provides only
//! view-only material (notes, witnesses, anchor) via /scanner/delta —
//! everything that requires the spending authority happens here.

use bip39::Mnemonic;
use sapling_crypto::{
    Anchor, Node, PaymentAddress,
    note::{Note as SaplingNote, Rseed},
    value::NoteValue,
    zip32::ExtendedSpendingKey,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Browser-console log helper for stage-level tracing inside the signer.
/// Prefixed so the JS side can grep [shielded-sign] in DevTools.
#[cfg(target_arch = "wasm32")]
fn log(msg: &str) {
    web_sys::console::log_1(&format!("[shielded-sign] {}", msg).into());
}

#[cfg(not(target_arch = "wasm32"))]
fn log(_msg: &str) {}

fn coded(code: &str, msg: impl std::fmt::Display) -> String {
    format!("{code}: {msg}")
}
use zcash_keys::address::Address as ZcashAddress;
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedSpendingKey};
use zcash_primitives::transaction::{
    builder::{BuildConfig, BuildResult, Builder, BundlePadding},
    fees::{zip317::FeeRule as Zip317FeeRule, FeeRule},
    TxVersion,
};
use zcash_transparent::builder::TransparentSigningSet;
mod prover;
use prover::LeokitTxProver;
#[cfg(not(target_arch = "wasm32"))]
pub mod verify;
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, MainNetwork, NetworkType, NetworkUpgrade, Parameters},
    memo::{Memo, MemoBytes},
    value::Zatoshis,
};

#[wasm_bindgen(start)]
pub fn __init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn leokit_sign_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[wasm_bindgen]
pub fn leokit_sign_hello(name: &str) -> String {
    format!("leokit-shielded-sign ready — hello, {name}")
}

/// Derive the default Unified Address for a (seed_phrase, account) pair
/// entirely client-side. Pure ZIP-32 + ZIP-316; no network, no params,
/// no proving. Mainnet only for now.
#[wasm_bindgen]
pub fn derive_default_unified_address(
    seed_phrase: &str,
    account: u32,
) -> Result<String, JsError> {
    default_unified_address(seed_phrase, account).map_err(|e| JsError::new(&e))
}

pub fn default_unified_address(seed_phrase: &str, account: u32) -> Result<String, String> {
    let usk = derive_usk(seed_phrase, account)?;
    let ufvk = usk.to_unified_full_viewing_key();
    let (ua, _di) = ufvk
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| coded("KEY_DERIVATION", format!("UA derivation failed: {e:?}")))?;
    Ok(ua.encode(&MainNetwork))
}

fn derive_usk(seed_phrase: &str, account: u32) -> Result<UnifiedSpendingKey, String> {
    let m = Mnemonic::parse_normalized(seed_phrase.trim())
        .map_err(|e| coded("INVALID_INPUT", format!("invalid mnemonic: {e}")))?;
    let seed_bytes: [u8; 64] = m.to_seed("");
    let account_id = zip32::AccountId::try_from(account)
        .map_err(|_| coded("INVALID_INPUT", "account index out of range (must fit u31)"))?;
    UnifiedSpendingKey::from_seed(&MainNetwork, &seed_bytes, account_id)
        .map_err(|e| coded("KEY_DERIVATION", format!("USK derivation failed: {e:?}")))
}

/// OS randomness for proving and signing (crypto.getRandomValues on wasm32).
pub(crate) fn os_rng() -> rand_core::UnwrapErr<rand::rngs::SysRng> {
    rand_core::UnwrapErr(rand::rngs::SysRng)
}

/// ZIP 259's mainnet NU7 height, hardcoded so a crate that reports another
/// one is refused rather than followed.
pub const NU7_MAINNET: u32 = 3_543_405;
/// Default expiry deltas (ZIP 203 before NU7; ZIP 218's 120 blocks after).
const EXPIRY_DELTA_PRE_NU7: u32 = 40;
const EXPIRY_DELTA_NU7: u32 = 120;
/// zcashd TX_EXPIRING_SOON_THRESHOLD: nodes refuse a tx expiring this close.
const TX_EXPIRING_SOON_THRESHOLD: u32 = 3;

/// Mainnet consensus parameters: the crate's `MainNetwork`, accepted only
/// while its NU7 height is ZIP 259's. A caller-supplied NU7 height is a
/// cross-check: absent or equal is fine, anything else is refused.
#[derive(Clone, Copy, Debug)]
pub struct LeokitNetwork {
    nu7: BlockHeight,
}

impl LeokitNetwork {
    pub fn new(nu7_activation_height: Option<u32>) -> Result<Self, String> {
        let crate_h = MainNetwork.activation_height(NetworkUpgrade::Nu7).map(u32::from);
        if crate_h != Some(NU7_MAINNET) {
            return Err(coded(
                "BUILD_FAILED",
                format!("zcash_protocol reports mainnet NU7 at {crate_h:?}, not ZIP 259's {NU7_MAINNET}"),
            ));
        }
        if let Some(h) = nu7_activation_height {
            if h != NU7_MAINNET {
                return Err(coded(
                    "INVALID_INPUT",
                    format!("nu7_activation_height {h} disagrees with the signer's {NU7_MAINNET} (ZIP 259)"),
                ));
            }
        }
        Ok(Self { nu7: BlockHeight::from_u32(NU7_MAINNET) })
    }

    fn nu7_height(&self) -> Option<BlockHeight> {
        Some(self.nu7)
    }

    /// nExpiryHeight for a transaction targeting `target`, matching the SDK's
    /// `expiryFor`: the upgrade's default delta, clamped to the block before a
    /// pending activation so an old-branch tx can't linger past it. Refuses to
    /// build when the clamp leaves nodes too little room to accept it.
    pub fn expiry_for(&self, target: BlockHeight) -> Result<BlockHeight, String> {
        let t = u32::from(target);
        match self.nu7_height().map(u32::from) {
            Some(h) if t >= h => Ok(BlockHeight::from_u32(t + EXPIRY_DELTA_NU7)),
            Some(h) if t + EXPIRY_DELTA_PRE_NU7 >= h => {
                let clamped = h - 1;
                if clamped < t + TX_EXPIRING_SOON_THRESHOLD {
                    Err(coded(
                        "UPGRADE_IMMINENT",
                        format!("NU7 activates at {h}; a tx targeting {t} can't be mined before it"),
                    ))
                } else {
                    Ok(BlockHeight::from_u32(clamped))
                }
            }
            _ => Ok(BlockHeight::from_u32(t + EXPIRY_DELTA_PRE_NU7)),
        }
    }
}

impl Parameters for LeokitNetwork {
    fn network_type(&self) -> NetworkType {
        NetworkType::Main
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match nu {
            NetworkUpgrade::Nu7 => self.nu7_height(),
            _ => MainNetwork.activation_height(nu),
        }
    }
}

/// Consensus branch ID the network enforces for a transaction mined at
/// `height` (mainnet). The SDK compares this against its own table before
/// signing, so a signer that predates a network upgrade can never build an
/// invalid transaction silently again. `nu7_activation_height` is optional;
/// a value other than ZIP 259's returns 0, which matches no branch.
#[wasm_bindgen]
pub fn consensus_branch_id_for_height(height: u32, nu7_activation_height: Option<u32>) -> u32 {
    match LeokitNetwork::new(nu7_activation_height) {
        Ok(net) => u32::from(BranchId::for_height(&net, BlockHeight::from_u32(height))),
        Err(_) => 0,
    }
}

const KNOWN_UPGRADES: [(&str, NetworkUpgrade); 11] = [
    ("Overwinter", NetworkUpgrade::Overwinter),
    ("Sapling", NetworkUpgrade::Sapling),
    ("Blossom", NetworkUpgrade::Blossom),
    ("Heartwood", NetworkUpgrade::Heartwood),
    ("Canopy", NetworkUpgrade::Canopy),
    ("NU5", NetworkUpgrade::Nu5),
    ("NU6", NetworkUpgrade::Nu6),
    ("NU6.1", NetworkUpgrade::Nu6_1),
    ("NU6.2", NetworkUpgrade::Nu6_2),
    ("NU6.3", NetworkUpgrade::Nu6_3),
    ("NU7", NetworkUpgrade::Nu7),
];

/// Diagnostics: signer version plus every mainnet upgrade it knows about.
#[wasm_bindgen]
pub fn signer_info() -> String {
    let upgrades: Vec<serde_json::Value> = KNOWN_UPGRADES
        .iter()
        .filter_map(|(name, nu)| {
            let h = MainNetwork.activation_height(*nu)?;
            Some(serde_json::json!({
                "name": name,
                "activation_height": u32::from(h),
                "branch_id": format!("0x{:08x}", consensus_branch_id_for_height(u32::from(h), None)),
            }))
        })
        .collect();
    serde_json::json!({
        "signer_version": env!("CARGO_PKG_VERSION"),
        "tx_version": "v5",
        "upgrades": upgrades,
        "nu7": {
            "branch_id": format!("0x{:08x}", u32::from(BranchId::Nu7)),
            "mainnet_activation_height": MainNetwork.activation_height(NetworkUpgrade::Nu7).map(u32::from),
            "testnet_activation_height": zcash_protocol::consensus::TestNetwork
                .activation_height(NetworkUpgrade::Nu7)
                .map(u32::from),
        },
    })
    .to_string()
}

/// The Merkle root implied by a note's own witness: the exact predicate the
/// Sapling builder checks (`root == anchor`), exposed so callers can reject
/// stale material before downloading params or proving.
#[wasm_bindgen]
pub fn note_witness_root(note_json: &str) -> Result<String, JsError> {
    witness_root_hex(note_json).map_err(|e| JsError::new(&e))
}

pub fn witness_root_hex(note_json: &str) -> Result<String, String> {
    let n: NoteJson = serde_json::from_str(note_json)
        .map_err(|e| coded("INVALID_INPUT", format!("note parse error: {e}")))?;
    let (note, path) = decode_note(&n).map_err(|e| coded("INVALID_INPUT", e))?;
    let leaf = Node::from_cmu(&note.cmu());
    Ok(hex::encode(path.root(leaf).to_bytes()))
}

#[derive(Serialize, Debug, PartialEq)]
pub struct AddressInfo {
    /// "unified" | "sapling" | "transparent" | "tex" | "wrong_network" | "invalid"
    pub kind: &'static str,
    pub has_sapling: bool,
    pub has_orchard: bool,
    pub has_transparent: bool,
    /// Receivers this signer can't pay (Orchard, Ironwood, unknown typecodes).
    pub other_receivers: usize,
    /// True when `build_sapling_tx_v5` can pay this address.
    pub payable: bool,
}

/// Classify a recipient without touching the network or proving params.
#[wasm_bindgen]
pub fn inspect_address(addr: &str) -> String {
    serde_json::to_string(&address_info(addr)).unwrap_or_default()
}

pub fn address_info(addr: &str) -> AddressInfo {
    use zcash_address::unified::{self, Container, Encoding};
    let a = addr.trim();
    let mut info = AddressInfo {
        kind: "invalid",
        has_sapling: false,
        has_orchard: false,
        has_transparent: false,
        other_receivers: 0,
        payable: false,
    };
    if a.starts_with("u1") {
        if let Ok((net, _revision, ua)) = unified::Address::decode(a) {
            if net != zcash_protocol::consensus::NetworkType::Main {
                info.kind = "wrong_network";
                return info;
            }
            info.kind = "unified";
            for r in ua.items() {
                match r {
                    unified::Receiver::Sapling(_) => info.has_sapling = true,
                    unified::Receiver::Orchard(_) => {
                        info.has_orchard = true;
                        info.other_receivers += 1;
                    }
                    unified::Receiver::P2pkh(_) | unified::Receiver::P2sh(_) => {
                        info.has_transparent = true
                    }
                    _ => info.other_receivers += 1,
                }
            }
            info.payable = info.has_sapling;
        }
        return info;
    }
    if a.starts_with("utest") || a.starts_with("ztestsapling") || a.starts_with("tm") {
        info.kind = "wrong_network";
        return info;
    }
    match ZcashAddress::decode(&MainNetwork, a) {
        Some(ZcashAddress::Sapling(_)) => {
            info.kind = "sapling";
            info.has_sapling = true;
            info.payable = true;
        }
        Some(ZcashAddress::Transparent(_)) => {
            info.kind = "transparent";
            info.has_transparent = true;
            info.payable = true;
        }
        Some(ZcashAddress::Tex(_)) => info.kind = "tex",
        Some(ZcashAddress::Unified(_)) | None => {}
    }
    info
}

// -- Inputs from JS --------------------------------------------------------

#[derive(Deserialize)]
struct NoteJson {
    /// Hex of the raw 43-byte recipient (diversifier + pk_d), as sent by
    /// /scanner/delta.
    recipient: String,
    amount_zats: u64,
    /// Hex (66 chars) — leading byte is the rseed version per the Sapling
    /// spec; remaining 32 bytes are the rseed.
    rseed: String,
    /// Note-commitment-tree leaf index.
    position: u64,
    /// Sapling tree authentication path. Each element is a 32-byte hex
    /// hash, ordered from leaf-sibling up to root. Length == 32.
    witness: Vec<String>,
}

#[derive(Deserialize)]
struct OutputJson {
    /// Recipient address. Any of:
    ///   - u1…  ZIP-316 Unified Address — picks the Sapling receiver,
    ///     output stays shielded.
    ///   - t1…/t3…  transparent P2PKH/P2SH — output is **deshielded**
    ///     and publicly observable on-chain (amount + recipient).
    ///   - zs1…  legacy Sapling z-address — stays shielded.
    recipient: String,
    amount_zats: u64,
    /// UTF-8 memo, 0–512 bytes after Memo encoding. Only applies to
    /// shielded outputs — transparent recipients ignore this.
    memo: Option<String>,
}

/// Optional 0-value Sapling note carried alongside the principal outputs
/// for protocols that read swap instructions out of an encrypted memo
/// (MAYAChain ZEC: `ZECSHIELDEDMEMOENABLED=1`).
///
/// Concrete shape on the wire: a Sapling output with `value=0` to
/// `recipient_ua` (must be a UA with a Sapling receiver — MAYA's
/// `ZECUnifiedAddress` for the swap case), `memo_text` encrypted into
/// the note plaintext. Only the holder of the recipient's UIVK can
/// decrypt it (for MAYA: their `ZECUIVK`).
///
/// IMPORTANT: per MAYA's quote `notes`, principal value MUST NOT be
/// placed in this note (funds would be lost). This note is exclusively
/// a memo carrier — no economic value.
#[derive(Deserialize)]
struct MemoNoteJson {
    /// UA of the memo recipient (e.g. MAYA's `ZECUnifiedAddress`). MUST
    /// include a Sapling receiver — Orchard-only UAs are rejected
    /// because our signer is Sapling-only.
    recipient_ua: String,
    /// Plain UTF-8 swap memo (e.g. `=:e:0xRecipient`). Up to 512 bytes
    /// after MemoBytes encoding (Sapling protocol cap).
    memo_text: String,
}

#[derive(Deserialize)]
struct BuildArgs {
    seed_phrase: String,
    account: u32,
    notes: Vec<NoteJson>,
    /// 32-byte Sapling commitment-tree root, hex-encoded. From
    /// /scanner/delta's `anchor` field. Witnesses MUST have been computed
    /// against this anchor.
    anchor_hex: String,
    outputs: Vec<OutputJson>,
    fee_zats: u64,
    target_height: u32,
    /// Optional cross-check of the NU7 mainnet height (ZIP 259: 3,543,405).
    /// Absent: the built-in height applies. Any other value is refused.
    #[serde(default)]
    nu7_activation_height: Option<u32>,
    /// Optional 0-value Sapling memo-note. Used by the swap path for
    /// MAYA-style "shielded memo, transparent principal" deposits. When
    /// absent, no extra output is added.
    #[serde(default)]
    memo_note: Option<MemoNoteJson>,
}

#[derive(Serialize, Debug)]
pub struct BuiltTx {
    pub tx_hex: String,
    pub txid: String,
    /// Fee the transaction actually pays (ZIP-317, padding included).
    pub fee_zats: u64,
}

const ZIP317_MARGINAL_FEE_ZATS: u64 = 5_000;
const ZIP317_GRACE_ACTIONS: u64 = 2;
const MIN_SAPLING_OUTPUTS: usize = 2;

/// ZIP-317 fee for a Sapling-spending transaction, matching
/// `Zip317FeeRule` exactly: the Sapling bundle is padded to at least two
/// outputs, and transparent outputs are additive (`t_out + max(spends,
/// padded sapling outputs)`). Assumes standard P2PKH/P2SH outputs.
pub fn zip317_fee(spends: usize, transparent_outputs: usize, sapling_outputs: usize) -> u64 {
    let padded_outputs = if spends > 0 || sapling_outputs > 0 {
        std::cmp::max(sapling_outputs, MIN_SAPLING_OUTPUTS)
    } else {
        0
    };
    let sapling_actions = std::cmp::max(spends, padded_outputs);
    let logical_actions = (transparent_outputs + sapling_actions) as u64;
    ZIP317_MARGINAL_FEE_ZATS * std::cmp::max(ZIP317_GRACE_ACTIONS, logical_actions)
}

/// Build a fully-authorized, ready-to-broadcast Zcash v5 transaction
/// that spends one or more Sapling notes and produces one or more
/// Sapling outputs.
#[wasm_bindgen]
pub fn build_sapling_tx_v5(
    args_json: &str,
    spend_params: &[u8],
    output_params: &[u8],
) -> Result<JsValue, JsError> {
    let out = build_tx(args_json, spend_params, output_params).map_err(|e| JsError::new(&e))?;
    serde_wasm_bindgen::to_value(&out)
        .map_err(|e| JsError::new(&format!("result encode: {e}")))
}

pub fn build_tx(
    args_json: &str,
    spend_params: &[u8],
    output_params: &[u8],
) -> Result<BuiltTx, String> {
    log("build_sapling_tx_v5 called");
    let args: BuildArgs = serde_json::from_str(args_json)
        .map_err(|e| coded("INVALID_INPUT", format!("args parse error: {e}")))?;
    log(&format!(
        "parsed args — notes={}, outputs={}, target_height={}, anchor_hex_len={}, spend_params={}B, output_params={}B",
        args.notes.len(),
        args.outputs.len(),
        args.target_height,
        args.anchor_hex.len(),
        spend_params.len(),
        output_params.len(),
    ));

    if args.notes.is_empty() {
        return Err(coded("INVALID_INPUT", "no notes to spend"));
    }

    // -- key derivation --------------------------------------------------
    let usk = derive_usk(&args.seed_phrase, args.account)?;
    let sapling_extsk: &ExtendedSpendingKey = usk.sapling();
    let sapling_dfvk = sapling_extsk.to_diversifiable_full_viewing_key();
    let sapling_ovk = sapling_dfvk.fvk().ovk;
    log("USK + Sapling DFVK derived");

    // -- anchor ----------------------------------------------------------
    let anchor_bytes = hex_to_32(&args.anchor_hex)
        .map_err(|e| coded("INVALID_INPUT", format!("anchor: {e}")))?;
    let anchor_node = Node::from_bytes(anchor_bytes)
        .into_option()
        .ok_or_else(|| coded("INVALID_INPUT", "anchor: not a valid Sapling tree root"))?;
    let anchor: Anchor = anchor_node.into();
    log("anchor decoded");

    // -- builder ---------------------------------------------------------
    let network = LeokitNetwork::new(args.nu7_activation_height)?;
    let target_height = BlockHeight::from_u32(args.target_height);
    let expiry_height = network.expiry_for(target_height)?;
    log(&format!(
        "consensus — branch=0x{:08x} expiry={} nu7={:?}",
        u32::from(BranchId::for_height(&network, target_height)),
        u32::from(expiry_height),
        args.nu7_activation_height,
    ));
    let build_config = BuildConfig::Standard {
        sapling_anchor: Some(anchor),
        orchard_anchor: None,
        ironwood_anchor: None,
        orchard_padding: BundlePadding::DEFAULT,
        ironwood_padding: BundlePadding::DEFAULT,
    };
    let mut builder =
        Builder::new(network, target_height, build_config).with_expiry_height(expiry_height);
    // From NU6.3 the builder would default to v6. v5 stays valid under NU6.3
    // and NU7 and is the format MAYA's observer and every explorer parse.
    builder
        .propose_version::<<Zip317FeeRule as FeeRule>::Error>(TxVersion::V5)
        .map_err(|e| coded("BUILD_FAILED", format!("propose_version v5: {e:?}")))?;

    // -- spends ----------------------------------------------------------
    for (i, n) in args.notes.iter().enumerate() {
        log(&format!(
            "spend[{}]: recipient_len={} rseed_len={} witness_count={} position={} amount_zats={}",
            i, n.recipient.len(), n.rseed.len(), n.witness.len(), n.position, n.amount_zats,
        ));
        let (note, path) =
            decode_note(n).map_err(|e| coded("INVALID_INPUT", format!("note[{i}]: {e}")))?;
        builder
            .add_sapling_spend::<<Zip317FeeRule as FeeRule>::Error>(
                sapling_dfvk.fvk().clone(),
                note,
                path,
            )
            .map_err(|e| {
                let detail = format!("note[{i}] add_spend: {e:?}");
                if detail.contains("AnchorMismatch") {
                    coded("ANCHOR_MISMATCH", detail)
                } else {
                    coded("BUILD_FAILED", detail)
                }
            })?;
        log(&format!("spend[{}] added", i));
    }

    // -- outputs ---------------------------------------------------------
    let mut transparent_outputs: usize = 0;
    let mut sapling_outputs: usize = 0;
    // Dispatch on the parsed Address variant: shielded recipients use
    // add_sapling_output (private), transparent recipients use
    // add_transparent_output (deshielding — output becomes public).
    for (i, o) in args.outputs.iter().enumerate() {
        log(&format!(
            "output[{}]: recipient_prefix={} amount_zats={} memo={}",
            i,
            &o.recipient[..o.recipient.len().min(12)],
            o.amount_zats,
            if o.memo.is_some() { "yes" } else { "no" },
        ));
        let info = address_info(&o.recipient);
        if !info.payable {
            return Err(match info.kind {
                "unified" => coded(
                    "NO_SAPLING_RECEIVER",
                    format!("output[{i}].recipient: UA has no Sapling receiver (Orchard-only UAs not yet supported)"),
                ),
                "tex" => coded(
                    "UNSUPPORTED_RECIPIENT",
                    format!("output[{i}].recipient: TEX (ZIP-320 transparent-source-only) addresses not supported"),
                ),
                "wrong_network" => coded(
                    "INVALID_RECIPIENT",
                    format!("output[{i}].recipient: not a mainnet address"),
                ),
                _ => coded("INVALID_RECIPIENT", format!("output[{i}].recipient: invalid ZEC address")),
            });
        }
        let value = Zatoshis::from_u64(o.amount_zats)
            .map_err(|_| coded("INVALID_INPUT", format!("output[{i}].amount_zats out of range")))?;
        if info.kind == "transparent" {
            // Memo silently dropped for transparent outputs — Sapling
            // memos are encrypted into the output's note plaintext,
            // which transparent outputs don't have.
            let Some(ZcashAddress::Transparent(t)) = ZcashAddress::decode(&MainNetwork, o.recipient.trim())
            else {
                return Err(coded("INVALID_RECIPIENT", format!("output[{i}].recipient: invalid ZEC address")));
            };
            builder
                .add_transparent_output(&t, value)
                .map_err(|e| coded("BUILD_FAILED", format!("output[{i}] add_transparent_output: {e:?}")))?;
            transparent_outputs += 1;
        } else {
            let pa = sapling_receiver(&o.recipient).ok_or_else(|| {
                coded("NO_SAPLING_RECEIVER", format!("output[{i}].recipient: no Sapling receiver"))
            })?;
            let memo = encode_memo(o.memo.as_deref())
                .map_err(|e| coded("INVALID_INPUT", format!("output[{i}].memo: {e}")))?;
            builder
                .add_sapling_output::<<Zip317FeeRule as FeeRule>::Error>(Some(sapling_ovk), pa, value, memo)
                .map_err(|e| coded("BUILD_FAILED", format!("output[{i}] add_sapling_output: {e:?}")))?;
            sapling_outputs += 1;
        }
    }

    // -- memo-note output (MAYA / shielded-memo deposits) ----------------
    // A 0-value Sapling output to the protocol's UA carrying the swap
    // memo in the note plaintext. Only the protocol's UIVK can decrypt
    // it. ZERO value — per MAYA's own quote `notes`: "Do not send value
    // to shielded note/memo (funds will be lost)".
    if let Some(memo_note) = args.memo_note.as_ref() {
        log(&format!(
            "memo-note: recipient_prefix={} memo_text_len={}",
            &memo_note.recipient_ua[..memo_note.recipient_ua.len().min(12)],
            memo_note.memo_text.len(),
        ));
        let memo_pa = sapling_receiver(&memo_note.recipient_ua).ok_or_else(|| {
            coded(
                "NO_SAPLING_RECEIVER",
                "memo_note.recipient_ua: must be a UA with a Sapling receiver or a Sapling address \
                 (MAYA's ZECUnifiedAddress should carry one)",
            )
        })?;
        let memo_bytes = encode_memo(Some(memo_note.memo_text.as_str()))
            .map_err(|e| coded("INVALID_INPUT", format!("memo_note.memo_text: {e}")))?;
        builder
            .add_sapling_output::<<Zip317FeeRule as FeeRule>::Error>(
                Some(sapling_ovk),
                memo_pa,
                Zatoshis::ZERO,
                memo_bytes,
            )
            .map_err(|e| coded("BUILD_FAILED", format!("memo_note add_output failed: {e:?}")))?;
        sapling_outputs += 1;
        log("memo-note added (0-value Sapling output carrying swap memo)");
    }

    // -- change output ---------------------------------------------------
    // The builder refuses to build unless inputs == outputs + fee exactly,
    // with the fee computed by Zip317FeeRule over the PADDED bundle. Work
    // out whether a change output is needed and what the fee is with and
    // without it, then pick the shape that balances.
    let total_in_zats: u64 = args.notes.iter().map(|n| n.amount_zats).sum();
    let total_out_zats: u64 = args.outputs.iter().map(|o| o.amount_zats).sum();
    let spends = args.notes.len();
    let fee_with_change = zip317_fee(spends, transparent_outputs, sapling_outputs + 1);
    let fee_without_change = zip317_fee(spends, transparent_outputs, sapling_outputs);
    let available = total_in_zats.checked_sub(total_out_zats).ok_or_else(|| {
        coded(
            "INSUFFICIENT_FUNDS",
            format!("notes total {total_in_zats} zats < outputs {total_out_zats} zats"),
        )
    })?;
    let (change_zats, fee_zats) = if available > fee_with_change {
        (Some(available - fee_with_change), fee_with_change)
    } else if available == fee_without_change {
        (None, fee_without_change)
    } else if available == fee_with_change {
        // Exactly enough for the padded shape with a change slot: fill the
        // slot with a 0-value change note so the fee rule balances.
        (Some(0), fee_with_change)
    } else {
        return Err(coded(
            "INSUFFICIENT_FUNDS",
            format!(
                "notes total {total_in_zats} zats cannot cover outputs {total_out_zats} + fee {fee_without_change} zats"
            ),
        ));
    };
    log(&format!(
        "change calc — in={} out={} fee={} t_out={} sapling_out={} → change={:?}",
        total_in_zats, total_out_zats, fee_zats, transparent_outputs, sapling_outputs, change_zats
    ));
    if let Some(change) = change_zats {
        let (_di, change_addr) = sapling_dfvk.default_address();
        builder
            .add_sapling_output::<<Zip317FeeRule as FeeRule>::Error>(
                Some(sapling_ovk),
                change_addr,
                Zatoshis::from_u64(change)
                    .map_err(|_| coded("INVALID_INPUT", "change out of range"))?,
                MemoBytes::empty(),
            )
            .map_err(|e| coded("BUILD_FAILED", format!("change add_output failed: {e:?}")))?;
        log("change output added (back to own default Sapling receiver)");
    }

    // -- prove + sign + serialize ---------------------------------------
    log("loading LocalTxProver from supplied params…");
    let prover = LeokitTxProver::from_bytes(spend_params, output_params);
    log("prover ready");

    // No transparent inputs, no orchard spends — Sapling-only v5.
    let transparent_signing_set = TransparentSigningSet::new();
    let orchard_saks: [orchard::keys::SpendAuthorizingKey; 0] = [];
    let sapling_extsks = [sapling_extsk.clone()];

    log("building transaction (Groth16 proofs run here)…");
    let fee_rule = Zip317FeeRule::standard();
    let result: BuildResult = builder
        .build(
            &transparent_signing_set,
            &sapling_extsks,
            &orchard_saks,
            os_rng(),
            &prover,
            &prover,
            &fee_rule,
        )
        .map_err(|e| {
            let detail = format!("build failed: {e:?}");
            if detail.contains("InsufficientFunds") {
                coded("INSUFFICIENT_FUNDS", detail)
            } else if detail.contains("AnchorMismatch") {
                coded("ANCHOR_MISMATCH", detail)
            } else {
                coded("BUILD_FAILED", detail)
            }
        })?;
    let transaction = result.transaction();
    log("transaction built + signed");

    // Never hand back a transaction the network would reject for its header:
    // the builder's own defaults (v6 from NU6.3, its expiry) must not leak in.
    let expected_branch = BranchId::for_height(&network, target_height);
    if transaction.version() != TxVersion::V5
        || transaction.consensus_branch_id() != expected_branch
        || transaction.expiry_height() != expiry_height
    {
        return Err(coded(
            "BUILD_FAILED",
            format!(
                "built tx header {:?} / {:?} / expiry {} != V5 / {:?} / expiry {}",
                transaction.version(),
                transaction.consensus_branch_id(),
                u32::from(transaction.expiry_height()),
                expected_branch,
                u32::from(expiry_height),
            ),
        ));
    }

    // Sanity-only: the caller's pre-quote fee estimate; ZIP-317 already
    // enforced the real value inside the builder.
    let _ = args.fee_zats;

    let mut tx_bytes = Vec::with_capacity(2048);
    transaction
        .write(&mut tx_bytes)
        .map_err(|e| coded("BUILD_FAILED", format!("tx serialize: {e}")))?;
    let txid = transaction.txid().to_string();

    let tx_hex = hex::encode(&tx_bytes);
    log(&format!(
        "serialized tx — bytes={}, txid={}",
        tx_bytes.len(),
        txid
    ));
    Ok(BuiltTx { tx_hex, txid, fee_zats })
}

// -- helpers ---------------------------------------------------------------

fn decode_note(n: &NoteJson) -> Result<(SaplingNote, sapling_crypto::MerklePath), String> {
    let recipient = decode_recipient(&n.recipient).map_err(|e| format!("recipient: {e}"))?;
    let rseed = decode_rseed(&n.rseed).map_err(|e| format!("rseed: {e}"))?;
    let note = SaplingNote::from_parts(recipient, NoteValue::from_raw(n.amount_zats), rseed);
    let path = decode_merkle_path(&n.witness, n.position).map_err(|e| format!("witness: {e}"))?;
    Ok((note, path))
}

/// Sapling receiver of a UA or zs1 address (mainnet).
fn sapling_receiver(addr: &str) -> Option<PaymentAddress> {
    match ZcashAddress::decode(&MainNetwork, addr.trim())? {
        ZcashAddress::Unified(u) => u.sapling().copied(),
        ZcashAddress::Sapling(pa) => Some(*pa),
        _ => None,
    }
}

fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// /scanner/delta serialises Sapling recipients as plain hex of the raw
/// 43-byte payment address (11-byte diversifier + 32-byte pk_d).
/// (The server writes `hex::encode(note.recipient().to_bytes())`.)
fn decode_recipient(s: &str) -> Result<PaymentAddress, String> {
    let data = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if data.len() != 43 {
        return Err(format!("expected 43 bytes, got {}", data.len()));
    }
    let mut bytes = [0u8; 43];
    bytes.copy_from_slice(&data);
    PaymentAddress::from_bytes(&bytes).ok_or_else(|| "invalid payment address".to_string())
}

fn decode_rseed(s: &str) -> Result<Rseed, String> {
    let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 33 {
        return Err(format!("expected 33 bytes, got {}", bytes.len()));
    }
    let mut rseed_bytes = [0u8; 32];
    rseed_bytes.copy_from_slice(&bytes[1..]);
    // Server encoding of the rseed version byte:
    //   0x00 = BeforeZip212 (legacy, rseed is a jubjub::Fr scalar)
    //   0x01 = AfterZip212  (modern, rseed is 32 raw bytes used in PRF)
    // Post-Canopy notes are always AfterZip212.
    match bytes[0] {
        0x00 => {
            let ct: Option<jubjub::Fr> = jubjub::Fr::from_bytes(&rseed_bytes).into();
            ct.map(Rseed::BeforeZip212)
                .ok_or_else(|| "invalid BeforeZip212 rseed scalar".to_string())
        }
        _ => Ok(Rseed::AfterZip212(rseed_bytes)),
    }
}

fn decode_merkle_path(
    witness: &[String],
    position: u64,
) -> Result<sapling_crypto::MerklePath, String> {
    use sapling_crypto::NOTE_COMMITMENT_TREE_DEPTH;
    let depth: usize = NOTE_COMMITMENT_TREE_DEPTH as usize;
    if witness.len() != depth {
        return Err(format!(
            "expected {} witness siblings, got {}",
            depth,
            witness.len()
        ));
    }
    let mut nodes = Vec::with_capacity(witness.len());
    for (i, h) in witness.iter().enumerate() {
        let raw = hex_to_32(h).map_err(|e| format!("sibling[{i}]: {e}"))?;
        let node = Node::from_bytes(raw)
            .into_option()
            .ok_or_else(|| format!("sibling[{i}]: not a valid node"))?;
        nodes.push(node);
    }
    sapling_crypto::MerklePath::from_parts(nodes, position.into())
        .map_err(|_| "merkle path construction failed".to_string())
}

fn encode_memo(text: Option<&str>) -> Result<MemoBytes, String> {
    match text {
        None => Ok(MemoBytes::empty()),
        Some(s) => {
            let memo = Memo::from_bytes(s.as_bytes())
                .map_err(|e| format!("memo too long: {e:?}"))?;
            Ok(MemoBytes::from(&memo))
        }
    }
}
