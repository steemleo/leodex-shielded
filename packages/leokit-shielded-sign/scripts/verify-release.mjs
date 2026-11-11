#!/usr/bin/env node
// Release gate for the signer wasm in pkg/. Run before uploading a new
// /wasm/leokit-shielded-sign/vX.Y.Z/ build:
//
//   node scripts/verify-release.mjs [--negative <old pkg dir>]... [--params <dir>] [--out <dir>]
//
// 1. pkg/SHA256SUMS matches the files on disk.
// 2. The NU6.3 (0x37a5165b) and NU7 (0x77190ad9) branch ids are embedded;
//    the built wasm reports NU6.2 before NU6.3, NU6.3 up to H-1 and NU7
//    from H = 3,543,405 (ZIP 259) with no height supplied, and refuses a
//    supplied height that isn't H.
// 3. Required exports exist; signer_info reports H.
// 4. Real transactions are built THROUGH THE WASM from the committed
//    fixtures, before H, clamped near H, at H and after H. Each header is
//    decoded here (version, group, branch, expiry) and each tx is checked by
//    the native verify_tx (branch, expiry, proofs, sigs, fee). --out keeps
//    the tx hexes (txs.jsonl) for an outside decoder.
// 5. --negative <dir>: an older signer build must fail this gate (no NU7
//    bytes, or no built-in H).
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir, homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = join(root, "pkg");
const args = process.argv.slice(2);
const opt = name => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const paramsDir =
  opt("--params") ?? process.env.ZCASH_PARAMS_DIR ?? join(homedir(), ".zcash-params");

const NU6_2 = 0x5437f330;
const NU6_3 = 0x37a5165b;
const NU7 = 0x77190ad9;
const NU6_3_ACTIVATION = 3_428_143;
const REQUIRED_EXPORTS = [
  "build_sapling_tx_v5",
  "derive_default_unified_address",
  "consensus_branch_id_for_height",
  "note_witness_root",
  "inspect_address",
  "signer_info",
  "leokit_sign_version"
];

let failures = 0;
const check = (ok, msg) => {
  console.log(`${ok ? "PASS" : "FAIL"} ${msg}`);
  if (!ok) failures++;
};
const sha256 = buf => createHash("sha256").update(buf).digest("hex");
const embedsBranch = (bytes, id) => {
  const le = Buffer.alloc(4);
  le.writeUInt32LE(id);
  return Buffer.from(bytes).indexOf(le) >= 0;
};

const NU7_H = 3_543_405;
const negatives = args.flatMap((a, i) => (a === "--negative" ? [args[i + 1]] : []));
for (const dir of negatives) {
  const oldWasm = readFileSync(join(dir, "leokit_shielded_sign_bg.wasm"));
  const scanFails = !embedsBranch(oldWasm, NU7);
  let behaviourFails = false;
  if (!scanFails) {
    const old = await import(join(dir, "leokit_shielded_sign.js"));
    old.initSync({ module: oldWasm });
    behaviourFails = old.consensus_branch_id_for_height(NU7_H) !== NU7;
  }
  check(scanFails || behaviourFails, `negative control: ${dir} fails the gate (${scanFails ? "no NU7 branch bytes" : behaviourFails ? "no built-in H" : "PASSES: gate too weak"})`);
}

const sums = readFileSync(join(pkg, "SHA256SUMS"), "utf8").trim().split("\n");
for (const line of sums) {
  const [hash, file] = line.split(/\s+/);
  check(sha256(readFileSync(join(pkg, file))) === hash, `sha256 ${file} = ${hash.slice(0, 12)}…`);
}

const wasmBytes = readFileSync(join(pkg, "leokit_shielded_sign_bg.wasm"));
check(embedsBranch(wasmBytes, NU6_3), "wasm embeds NU6.3 branch id 0x37a5165b");
check(embedsBranch(wasmBytes, NU7), "wasm embeds NU7 branch id 0x77190ad9");

const signer = await import(join(pkg, "leokit_shielded_sign.js"));
signer.initSync({ module: wasmBytes });
for (const name of REQUIRED_EXPORTS) check(typeof signer[name] === "function", `export ${name}`);
check(signer.leokit_sign_version() === JSON.parse(readFileSync(join(pkg, "package.json"), "utf8")).version, "crate version == pkg/package.json version");
check(signer.consensus_branch_id_for_height(NU6_3_ACTIVATION - 1) === NU6_2, "branch @ NU6.3-1 == NU6.2");
check(signer.consensus_branch_id_for_height(3_508_800) === NU6_3, "branch @ 3,508,800 == NU6.3");
check(signer.consensus_branch_id_for_height(NU7_H - 1) === NU6_3, "branch @ H-1 (no height supplied) == NU6.3");
check(signer.consensus_branch_id_for_height(NU7_H) === NU7, "branch @ H (no height supplied) == NU7");
check(signer.consensus_branch_id_for_height(NU7_H + 1) === NU7, "branch @ H+1 (no height supplied) == NU7");
check(signer.consensus_branch_id_for_height(NU7_H, NU7_H) === NU7, "branch @ H (H supplied) == NU7");
check(signer.consensus_branch_id_for_height(NU7_H - 1, NU7_H) === NU6_3, "branch @ H-1 (H supplied) == NU6.3");
for (const bad of [NU7_H - 3, NU7_H + 3, 4_465_026]) {
  check(signer.consensus_branch_id_for_height(NU7_H, bad) === 0, `branch with a disagreeing height ${bad} == 0 (matches no branch)`);
}
const info = JSON.parse(signer.signer_info());
check(info.nu7?.mainnet_activation_height === NU7_H && info.nu7?.branch_id === "0x77190ad9", "signer_info reports NU7 at 3,543,405 / 0x77190ad9");
check(info.tx_version === "v5", "signer_info tx_version v5");

const fresh = JSON.parse(readFileSync(join(root, "tests/fixtures/fresh.json"), "utf8"));
const stale = JSON.parse(readFileSync(join(root, "tests/fixtures/stale-mixed.json"), "utf8"));
check(signer.note_witness_root(JSON.stringify(fresh.notes[0])) === fresh.anchor_hex, "note_witness_root(fresh) == anchor");
check(signer.note_witness_root(JSON.stringify(stale.notes[0])) === stale.stale_anchor_hex, "note_witness_root(stale) == old anchor");
const addresses = JSON.parse(readFileSync(join(root, "tests/fixtures/addresses.json"), "utf8"));
check(JSON.parse(signer.inspect_address(addresses.orchard_only_unified)).payable === false, "inspect_address: Orchard-only UA not payable");

const spend = readFileSync(join(paramsDir, "sapling-spend.params"));
const output = readFileSync(join(paramsDir, "sapling-output.params"));
const buildArgs = {
  seed_phrase: fresh.meta.seed_phrase,
  account: 0,
  notes: [fresh.notes[1]],
  anchor_hex: fresh.anchor_hex,
  outputs: [{ recipient: fresh.meta.own_ua, amount_zats: 10_000_000 }],
  fee_zats: 0,
  target_height: fresh.meta.target_height
};
const dir = opt("--out") ?? mkdtempSync(join(tmpdir(), "verify-release-"));
const txLog = [];
const le32 = (hex, byte) => Buffer.from(hex.slice(byte * 2, byte * 2 + 8), "hex").readUInt32LE(0);
// [label, target, nu7 height supplied, expected branch, expected expiry]
const cases = [
  ["before H (fixture target)", fresh.meta.target_height, undefined, "0x37a5165b", fresh.meta.target_height + 40],
  ["before H, expiry clamped to H-1", NU7_H - 20, undefined, "0x37a5165b", NU7_H - 1],
  ["before H, clamped, H supplied", NU7_H - 4, NU7_H, "0x37a5165b", NU7_H - 1],
  ["at H", NU7_H, undefined, "0x77190ad9", NU7_H + 120],
  ["at H, H supplied", NU7_H, NU7_H, "0x77190ad9", NU7_H + 120],
  ["after H", NU7_H + 50, undefined, "0x77190ad9", NU7_H + 170]
];
for (const [label, target, nu7, branch, expiry] of cases) {
  const args = { ...buildArgs, target_height: target, ...(nu7 ? { nu7_activation_height: nu7 } : {}) };
  const t0 = Date.now();
  const built = signer.build_sapling_tx_v5(JSON.stringify(args), spend, output);
  console.log(`     ${label}: built through wasm in ${Date.now() - t0} ms, txid ${built.txid}, fee ${built.fee_zats}`);
  const hx = built.tx_hex;
  check(
    le32(hx, 0) === 0x80000005 && le32(hx, 4) === 0x26a7270a && le32(hx, 8) === Number(branch) && le32(hx, 16) === expiry,
    `${label}: decoded header v5 / group 0x26a7270a / ${branch} / expiry ${expiry}`
  );
  txLog.push({ label, target, nu7: nu7 ?? null, branch, expiry, txid: built.txid, tx_hex: hx });
  writeFileSync(join(dir, "tx.hex"), hx);
  try {
    const report = execFileSync(
      "cargo",
      ["run", "-q", "--features", "tools", "--bin", "verify_tx", "--", `@${join(dir, "tx.hex")}`, "--anchor", fresh.anchor_hex, "--target", String(target), "--params", paramsDir],
      { cwd: root, encoding: "utf8" }
    );
    const r = JSON.parse(report);
    check(
      r.proofs_and_signatures_valid && r.branch_id === branch && r.expiry_height === expiry && r.txid === built.txid,
      `${label}: wasm-built tx passes native verify_tx (proofs, sigs, ${branch}, expiry ${expiry}, fee)`
    );
  } catch (e) {
    check(false, `${label}: verify_tx: ${e.stderr || e.message}`);
  }
}
writeFileSync(join(dir, "txs.jsonl"), txLog.map(t => JSON.stringify(t)).join("\n") + "\n");
console.log(`     tx hexes: ${join(dir, "txs.jsonl")}`);
try {
  signer.build_sapling_tx_v5(JSON.stringify({ ...buildArgs, target_height: NU7_H - 2 }), spend, output);
  check(false, "a build 2 blocks before H must be refused");
} catch (e) {
  check(String(e.message ?? e).startsWith("UPGRADE_IMMINENT"), `2 blocks before H → ${String(e.message ?? e).slice(0, 40)}`);
}
try {
  signer.build_sapling_tx_v5(JSON.stringify({ ...buildArgs, target_height: NU7_H, nu7_activation_height: NU7_H + 3 }), spend, output);
  check(false, "a disagreeing NU7 height must be refused");
} catch (e) {
  check(String(e.message ?? e).startsWith("INVALID_INPUT: nu7_activation_height"), `disagreeing NU7 height → ${String(e.message ?? e).slice(0, 50)}`);
}
try {
  signer.build_sapling_tx_v5(JSON.stringify({ ...buildArgs, notes: [stale.notes[0]], anchor_hex: stale.anchor_hex }), spend, output);
  check(false, "stale witness must fail");
} catch (e) {
  check(String(e.message ?? e).startsWith("ANCHOR_MISMATCH: note[0]"), `stale witness → ${String(e.message ?? e).slice(0, 60)}`);
}

console.log(failures ? `\n${failures} check(s) FAILED` : "\nverify-release: all checks passed");
process.exit(failures ? 1 : 0);
