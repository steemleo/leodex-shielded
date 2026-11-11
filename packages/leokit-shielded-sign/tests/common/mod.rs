//! Deterministic fixture toolkit shared by the signer tests and
//! `examples/gen_fixtures.rs`. Builds a synthetic Sapling commitment tree
//! holding notes owned by the BIP-39 test vector `abandon ×11 about`
//! (ZIP-32 account 0), with two snapshots so stale witnesses can be
//! reproduced byte-for-byte.
#![allow(dead_code)]

use sapling_crypto::{
    value::NoteValue, CommitmentTree, IncrementalWitness, Node, Note, PaymentAddress, Rseed,
};
use serde::Serialize;
use zcash_address::unified::{self, Encoding};
use zcash_keys::{address::Address, keys::UnifiedSpendingKey};
use zcash_protocol::consensus::{MainNetwork, NetworkType};
use zcash_transparent::address::TransparentAddress;

pub const SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
pub const TARGET_HEIGHT: u32 = 3_508_800;
pub const NOTE_VALUES: [u64; 3] = [40_000_000, 50_000_000, 120_000_000];
pub const LATE_NOTE_VALUE: u64 = 30_000_000;

pub fn own_payment_address() -> PaymentAddress {
    let seed = bip39::Mnemonic::parse_normalized(SEED).unwrap().to_seed("");
    let usk = UnifiedSpendingKey::from_seed(&MainNetwork, &seed, zip32::AccountId::ZERO).unwrap();
    usk.sapling().to_diversifiable_full_viewing_key().default_address().1
}

pub fn own_ua() -> String {
    leokit_shielded_sign::default_unified_address(SEED, 0).unwrap()
}

pub fn own_zs1() -> String {
    Address::Sapling(Box::new(own_payment_address())).encode(&MainNetwork)
}

pub fn t1() -> String {
    Address::Transparent(TransparentAddress::PublicKeyHash([7u8; 20])).encode(&MainNetwork)
}

pub fn t3() -> String {
    Address::Transparent(TransparentAddress::ScriptHash([9u8; 20])).encode(&MainNetwork)
}

pub fn tex() -> String {
    Address::Tex([7u8; 20]).encode(&MainNetwork)
}

pub fn orchard_only_ua() -> String {
    unified::Address::try_from_items(
        unified::Revision::R0,
        vec![unified::Uitem::Data(unified::Receiver::Orchard([1u8; 43]))],
    )
        .unwrap()
        .encode(&NetworkType::Main)
}

fn note(value: u64, tag: u8) -> Note {
    Note::from_parts(own_payment_address(), NoteValue::from_raw(value), Rseed::AfterZip212([tag; 32]))
}

#[derive(Serialize, Clone, Debug)]
pub struct NoteFixture {
    pub recipient: String,
    pub amount_zats: u64,
    pub rseed: String,
    pub position: u64,
    pub witness: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Snapshot {
    pub anchor_hex: String,
    pub notes: Vec<NoteFixture>,
}

pub struct Scenario {
    /// After N1..N3 are mined (plus fillers): witnesses + anchor A1.
    pub s1: Snapshot,
    /// After more fillers and N4: refreshed witnesses for N1..N4 + anchor A2.
    pub s2: Snapshot,
}

impl Scenario {
    /// Stale-witness case: N1..N3 witnesses from A1, N4 fresh, anchor A2.
    pub fn stale_mixed(&self) -> Snapshot {
        let mut notes: Vec<NoteFixture> = self.s1.notes.clone();
        notes.push(self.s2.notes[3].clone());
        Snapshot { anchor_hex: self.s2.anchor_hex.clone(), notes }
    }
}

fn fixture(n: &Note, w: &IncrementalWitness) -> NoteFixture {
    let path = w.path().expect("witness path");
    let mut rseed = vec![1u8];
    match n.rseed() {
        Rseed::AfterZip212(b) => rseed.extend_from_slice(b),
        Rseed::BeforeZip212(_) => unreachable!(),
    }
    NoteFixture {
        recipient: hex::encode(n.recipient().to_bytes()),
        amount_zats: n.value().inner(),
        rseed: hex::encode(rseed),
        position: u64::from(path.position()),
        witness: path.path_elems().iter().map(|e| hex::encode(e.to_bytes())).collect(),
    }
}

fn filler(tag: u8) -> Node {
    Node::from_cmu(&note(1, tag).cmu())
}

fn append(tree: &mut CommitmentTree, witnesses: &mut [IncrementalWitness], node: Node) {
    tree.append(node).unwrap();
    for w in witnesses.iter_mut() {
        w.append(node).unwrap();
    }
}

pub fn scenario() -> Scenario {
    let mut tree = CommitmentTree::empty();
    let mut witnesses: Vec<IncrementalWitness> = Vec::new();
    let mut notes: Vec<Note> = Vec::new();
    for i in 0..40u8 {
        append(&mut tree, &mut witnesses, filler(100 + i));
    }
    for (i, v) in NOTE_VALUES.iter().enumerate() {
        let n = note(*v, 10 + i as u8);
        append(&mut tree, &mut witnesses, Node::from_cmu(&n.cmu()));
        witnesses.push(IncrementalWitness::from_tree(tree.clone()).unwrap());
        notes.push(n);
    }
    for i in 0..5u8 {
        append(&mut tree, &mut witnesses, filler(150 + i));
    }
    let s1 = Snapshot {
        anchor_hex: hex::encode(tree.root().to_bytes()),
        notes: notes.iter().zip(&witnesses).map(|(n, w)| fixture(n, w)).collect(),
    };
    for i in 0..7u8 {
        append(&mut tree, &mut witnesses, filler(170 + i));
    }
    let late = note(LATE_NOTE_VALUE, 13);
    append(&mut tree, &mut witnesses, Node::from_cmu(&late.cmu()));
    witnesses.push(IncrementalWitness::from_tree(tree.clone()).unwrap());
    notes.push(late);
    append(&mut tree, &mut witnesses, filler(190));
    let s2 = Snapshot {
        anchor_hex: hex::encode(tree.root().to_bytes()),
        notes: notes.iter().zip(&witnesses).map(|(n, w)| fixture(n, w)).collect(),
    };
    Scenario { s1, s2 }
}

pub fn build_args(snap: &Snapshot, notes: &[usize], outputs: serde_json::Value, memo_note: Option<serde_json::Value>, target: u32) -> String {
    let picked: Vec<&NoteFixture> = notes.iter().map(|i| &snap.notes[*i]).collect();
    let mut v = serde_json::json!({
        "seed_phrase": SEED,
        "account": 0,
        "notes": picked,
        "anchor_hex": snap.anchor_hex,
        "outputs": outputs,
        "fee_zats": 0,
        "target_height": target,
    });
    if let Some(m) = memo_note {
        v["memo_note"] = m;
    }
    v.to_string()
}

pub fn params() -> Option<(Vec<u8>, Vec<u8>)> {
    let dir = std::env::var("ZCASH_PARAMS_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| {
        std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join(".zcash-params")
    });
    let spend = std::fs::read(dir.join("sapling-spend.params")).ok()?;
    let output = std::fs::read(dir.join("sapling-output.params")).ok()?;
    Some((spend, output))
}
