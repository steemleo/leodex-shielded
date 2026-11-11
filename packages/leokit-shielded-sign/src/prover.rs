//! Vendored Sapling proving-key holder + SpendProver/OutputProver impls.
//!
//! Mirrors `zcash_proofs::prover::LocalTxProver::from_bytes` exactly,
//! but without depending on the `local-prover` feature flag (which pulls
//! `directories` → `home`, neither of which has a wasm32 cfg path and
//! both refuse to compile for our target).
//!
//! All construction goes through `LeokitTxProver::from_bytes`. The
//! `zcash_proofs::parse_parameters` helper that does the heavy lifting
//! (Groth16 key parsing + hash verification) is publicly exported with
//! no feature gate, so we can call it directly.

use rand_core::Rng;
use sapling_crypto::{
    bundle::GrothProofBytes,
    circuit::{OutputParameters, SpendParameters},
    keys::EphemeralSecretKey,
    prover::{OutputProver, SpendProver},
    value::{NoteValue, ValueCommitTrapdoor},
    Diversifier, MerklePath, PaymentAddress, ProofGenerationKey, Rseed,
};

pub struct LeokitTxProver {
    spend_params: SpendParameters,
    output_params: OutputParameters,
}

impl LeokitTxProver {
    /// Build the prover from raw param bytes. Caller is responsible for
    /// having SHA-256-verified the input against the official hashes.
    /// Internally `parse_parameters` re-checks the embedded Groth16
    /// hashes and panics on mismatch.
    pub fn from_bytes(spend_param_bytes: &[u8], output_param_bytes: &[u8]) -> Self {
        let p = zcash_proofs::parse_parameters(spend_param_bytes, output_param_bytes, None);
        Self {
            spend_params: p.spend_params,
            output_params: p.output_params,
        }
    }
}

// sapling-crypto 0.9 implements the prover traits on the parameter types
// themselves (Groth16 moved to its own crate); delegate to them.
impl SpendProver for LeokitTxProver {
    type Proof = <SpendParameters as SpendProver>::Proof;

    fn prepare_circuit(
        proof_generation_key: ProofGenerationKey,
        diversifier: Diversifier,
        rseed: Rseed,
        value: NoteValue,
        alpha: jubjub::Fr,
        rcv: ValueCommitTrapdoor,
        anchor: bls12_381::Scalar,
        merkle_path: MerklePath,
    ) -> Option<sapling_crypto::circuit::Spend> {
        <SpendParameters as SpendProver>::prepare_circuit(
            proof_generation_key,
            diversifier,
            rseed,
            value,
            alpha,
            rcv,
            anchor,
            merkle_path,
        )
    }

    fn create_proof<R: Rng>(&self, circuit: sapling_crypto::circuit::Spend, rng: &mut R) -> Self::Proof {
        self.spend_params.create_proof(circuit, rng)
    }

    fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
        <SpendParameters as SpendProver>::encode_proof(proof)
    }
}

impl OutputProver for LeokitTxProver {
    type Proof = <OutputParameters as OutputProver>::Proof;

    fn prepare_circuit(
        esk: &EphemeralSecretKey,
        payment_address: PaymentAddress,
        rcm: jubjub::Fr,
        value: NoteValue,
        rcv: ValueCommitTrapdoor,
    ) -> sapling_crypto::circuit::Output {
        <OutputParameters as OutputProver>::prepare_circuit(esk, payment_address, rcm, value, rcv)
    }

    fn create_proof<R: Rng>(&self, circuit: sapling_crypto::circuit::Output, rng: &mut R) -> Self::Proof {
        self.output_params.create_proof(circuit, rng)
    }

    fn encode_proof(proof: Self::Proof) -> GrothProofBytes {
        <OutputParameters as OutputProver>::encode_proof(proof)
    }
}
