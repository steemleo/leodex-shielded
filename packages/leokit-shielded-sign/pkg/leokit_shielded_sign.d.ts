/* tslint:disable */
/* eslint-disable */
/**
 * Build a fully-authorized, ready-to-broadcast Zcash v5 transaction
 * that spends one or more Sapling notes and produces one or more
 * Sapling outputs.
 */
export function build_sapling_tx_v5(args_json: string, spend_params: Uint8Array, output_params: Uint8Array): any;
/**
 * Consensus branch ID the network enforces for a transaction mined at
 * `height` (mainnet). The SDK compares this against its own table before
 * signing, so a signer that predates a network upgrade can never build an
 * invalid transaction silently again. `nu7_activation_height` is optional;
 * a value other than ZIP 259's returns 0, which matches no branch.
 */
export function consensus_branch_id_for_height(height: number, nu7_activation_height?: number | null): number;
/**
 * Diagnostics: signer version plus every mainnet upgrade it knows about.
 */
export function signer_info(): string;
/**
 * Classify a recipient without touching the network or proving params.
 */
export function inspect_address(addr: string): string;
/**
 * Derive the default Unified Address for a (seed_phrase, account) pair
 * entirely client-side. Pure ZIP-32 + ZIP-316; no network, no params,
 * no proving. Mainnet only for now.
 */
export function derive_default_unified_address(seed_phrase: string, account: number): string;
/**
 * The Merkle root implied by a note's own witness: the exact predicate the
 * Sapling builder checks (`root == anchor`), exposed so callers can reject
 * stale material before downloading params or proving.
 */
export function note_witness_root(note_json: string): string;
export function leokit_sign_hello(name: string): string;
export function __init(): void;
export function leokit_sign_version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly build_sapling_tx_v5: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => void;
  readonly consensus_branch_id_for_height: (a: number, b: number) => number;
  readonly derive_default_unified_address: (a: number, b: number, c: number, d: number) => void;
  readonly inspect_address: (a: number, b: number, c: number) => void;
  readonly leokit_sign_hello: (a: number, b: number, c: number) => void;
  readonly leokit_sign_version: (a: number) => void;
  readonly note_witness_root: (a: number, b: number, c: number) => void;
  readonly signer_info: (a: number) => void;
  readonly __init: () => void;
  readonly rustsecp256k1_v0_14_context_create: (a: number) => number;
  readonly rustsecp256k1_v0_14_context_destroy: (a: number) => void;
  readonly rustsecp256k1_v0_14_default_error_callback_fn: (a: number, b: number) => void;
  readonly rustsecp256k1_v0_14_default_illegal_callback_fn: (a: number, b: number) => void;
  readonly __wbindgen_export_0: (a: number, b: number) => number;
  readonly __wbindgen_export_1: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_2: (a: number, b: number, c: number) => void;
  readonly __wbindgen_export_3: (a: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
