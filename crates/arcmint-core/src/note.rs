use crate::crypto::{
    generators, pedersen_commit, random_scalar, random_serial, BlindingFactor, GroupElement,
    Scalar, SerialNumber,
};
use crate::error::{ArcMintError, Result};
use curve25519_dalek::scalar::Scalar as DalekScalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentPair {
    pub a_commit: GroupElement,
    pub b_commit: GroupElement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoteCommitmentData {
    pub serial: SerialNumber,
    pub denomination: u64,
    pub c_theta: GroupElement,
    pub pairs: Vec<CommitmentPair>,
}

#[derive(Clone, Debug)]
pub struct UnsignedNote {
    pub data: NoteCommitmentData,
    pub rho: BlindingFactor,
    pub pair_randomness: Vec<(Scalar, Scalar)>,
    pub a_bits: Vec<u8>,
    pub b_bits: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedNote {
    pub data: NoteCommitmentData,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NoteState {
    Valid,
    PendingBurn { htlc_id: String, timeout_block: u64 },
    Spent,
}

impl Zeroize for UnsignedNote {
    fn zeroize(&mut self) {
        self.rho.zeroize();
        for (ra, rb) in &mut self.pair_randomness {
            ra.zeroize();
            rb.zeroize();
        }
        self.a_bits.zeroize();
        self.b_bits.zeroize();
    }
}

impl Drop for UnsignedNote {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub fn generate_note_candidate<R>(
    theta_u: &[u8; 32],
    denomination: u64,
    k: usize,
    rng: &mut R,
) -> Result<UnsignedNote>
where
    R: CryptoRng + RngCore,
{
    let max_bits = theta_u.len() * 8;
    if k > max_bits {
        return Err(ArcMintError::InvalidNote(
            "k exceeds number of bits in theta_u".to_string(),
        ));
    }

    let serial = random_serial(rng);
    let (g, h) = generators();

    let theta_scalar = Scalar(DalekScalar::from_bytes_mod_order(*theta_u));
    let rho_scalar = random_scalar(rng);
    let rho = BlindingFactor(rho_scalar);
    let c_theta = pedersen_commit(&theta_scalar, &rho.0, &g, &h);

    let mut pairs = Vec::with_capacity(k);
    let mut pair_randomness = Vec::with_capacity(k);
    let mut a_bits = Vec::with_capacity(k);
    let mut b_bits = Vec::with_capacity(k);

    for i in 0..k {
        let a_bit = (rng.next_u32() & 1) as u8;

        let byte_index = i / 8;
        let bit_index = i % 8;
        let theta_byte = theta_u[byte_index];
        let theta_bit = (theta_byte >> bit_index) & 1;

        let b_bit = theta_bit ^ a_bit;

        let ra_i = random_scalar(rng);
        let rb_i = random_scalar(rng);

        let a_scalar = Scalar(DalekScalar::from(a_bit as u64));
        let b_scalar = Scalar(DalekScalar::from(b_bit as u64));

        let a_commit = pedersen_commit(&a_scalar, &ra_i, &g, &h);
        let b_commit = pedersen_commit(&b_scalar, &rb_i, &g, &h);

        pairs.push(CommitmentPair { a_commit, b_commit });
        pair_randomness.push((ra_i, rb_i));
        a_bits.push(a_bit);
        b_bits.push(b_bit);
    }

    let data = NoteCommitmentData {
        serial,
        denomination,
        c_theta,
        pairs,
    };

    Ok(UnsignedNote {
        data,
        rho,
        pair_randomness,
        a_bits,
        b_bits,
    })
}

pub fn note_hash(data: &NoteCommitmentData) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"arcmint:note:v1");
    let encoded = serde_json::to_vec(data).map_err(|e| {
        ArcMintError::InvalidNote(format!("failed to serialize note commitment data: {e}"))
    })?;
    hasher.update(&encoded);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}
