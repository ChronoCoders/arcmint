use crate::crypto::{pedersen_commit, verify_pedersen_opening, GroupElement, Scalar};
use crate::error::{ArcMintError, Result};
use crate::note::{note_hash, NoteCommitmentData, UnsignedNote};
use crate::protocol::{RevealedScalar, SpendProof, UnsignedNoteReveal, WhichCommitment};
use curve25519_dalek::scalar::Scalar as DalekScalar;

pub fn generate_spend_proof(note: &UnsignedNote, challenge_bits: &[u8]) -> Result<SpendProof> {
    let k = note.data.pairs.len();
    if challenge_bits.len() != k {
        return Err(ArcMintError::InvalidProof(
            "challenge length does not match note".to_string(),
        ));
    }
    if note.a_bits.len() != k || note.b_bits.len() != k || note.pair_randomness.len() != k {
        return Err(ArcMintError::InvalidNote(
            "note internal lengths inconsistent".to_string(),
        ));
    }

    let mut revealed_scalars = Vec::with_capacity(k);

    for (i, challenge) in challenge_bits.iter().copied().enumerate() {
        let (bit, blinding, which) = match challenge {
            0 => {
                let (ra_i, _) = note.pair_randomness[i].clone();
                (note.a_bits[i], ra_i, WhichCommitment::A)
            }
            1 => {
                let (_, rb_i) = note.pair_randomness[i].clone();
                (note.b_bits[i], rb_i, WhichCommitment::B)
            }
            _ => {
                return Err(ArcMintError::InvalidProof(format!(
                    "invalid challenge bit at position {i}"
                )));
            }
        };

        let value_scalar = DalekScalar::from(bit as u64);
        let value_bytes = value_scalar.to_bytes().to_vec();
        let blinding_bytes = blinding.0.to_bytes().to_vec();

        revealed_scalars.push(RevealedScalar {
            bit_index: i,
            value_scalar: value_bytes,
            blinding_scalar: blinding_bytes,
            which,
        });
    }

    Ok(SpendProof {
        serial: note.data.serial,
        revealed_scalars,
    })
}

pub fn verify_spend_proof(
    data: &NoteCommitmentData,
    proof: &SpendProof,
    challenge_bits: &[u8],
    g: &GroupElement,
    h: &GroupElement,
) -> Result<()> {
    let k = data.pairs.len();
    if challenge_bits.len() != k {
        return Err(ArcMintError::InvalidProof(
            "challenge length does not match note".to_string(),
        ));
    }
    if proof.revealed_scalars.len() != k {
        return Err(ArcMintError::InvalidProof(
            "incorrect number of revealed scalars".to_string(),
        ));
    }
    if proof.serial != data.serial {
        return Err(ArcMintError::InvalidProof(
            "serial mismatch in spend proof".to_string(),
        ));
    }

    let mut by_index: Vec<Option<&RevealedScalar>> = vec![None; k];
    for rs in &proof.revealed_scalars {
        let idx = rs.bit_index;
        if idx >= k {
            return Err(ArcMintError::InvalidProof(format!(
                "bit index {idx} out of range in spend proof"
            )));
        }
        if by_index[idx].is_some() {
            return Err(ArcMintError::InvalidProof(format!(
                "duplicate bit index {idx} in spend proof"
            )));
        }
        by_index[idx] = Some(rs);
    }

    for i in 0..k {
        let rs = by_index[i].ok_or_else(|| {
            ArcMintError::InvalidProof(format!("missing revealed scalar at position {i}"))
        })?;

        let challenge = challenge_bits[i];
        match (challenge, &rs.which) {
            (0, WhichCommitment::A) | (1, WhichCommitment::B) => {}
            _ => {
                return Err(ArcMintError::InvalidProof(format!(
                    "which-commitment mismatch at position {i}"
                )));
            }
        }

        let value = scalar_from_bytes(&rs.value_scalar, i, "value")?;
        let blinding = scalar_from_bytes(&rs.blinding_scalar, i, "blinding")?;

        let recomputed = pedersen_commit(&value, &blinding, g, h);
        let pair = &data.pairs[i];
        let expected = match rs.which {
            WhichCommitment::A => &pair.a_commit,
            WhichCommitment::B => &pair.b_commit,
        };

        if recomputed.0 != expected.0 {
            return Err(ArcMintError::InvalidProof(format!(
                "commitment mismatch at position {i}"
            )));
        }
    }

    Ok(())
}

pub fn verify_opened_candidate(
    candidate: &NoteCommitmentData,
    reveal: &UnsignedNoteReveal,
    g: &GroupElement,
    h: &GroupElement,
) -> Result<()> {
    let k = candidate.pairs.len();
    if reveal.a_bits.len() != k || reveal.b_bits.len() != k || reveal.pair_randomness.len() != k {
        return Err(ArcMintError::InvalidProof(
            "opened candidate length mismatch".to_string(),
        ));
    }

    if candidate.denomination == 0 {
        return Err(ArcMintError::InvalidProof(
            "opened candidate has zero denomination".to_string(),
        ));
    }

    if reveal.serial.0.iter().all(|b| *b == 0) {
        return Err(ArcMintError::InvalidProof(
            "opened candidate has zero serial".to_string(),
        ));
    }

    for i in 0..k {
        let (ra_bytes, rb_bytes) = &reveal.pair_randomness[i];

        if ra_bytes.len() != 32 || rb_bytes.len() != 32 {
            return Err(ArcMintError::InvalidProof(format!(
                "invalid randomness length at position {i}"
            )));
        }

        let mut ra_arr = [0u8; 32];
        ra_arr.copy_from_slice(ra_bytes);
        let mut rb_arr = [0u8; 32];
        rb_arr.copy_from_slice(rb_bytes);

        let ra = Scalar(DalekScalar::from_bytes_mod_order(ra_arr));
        let rb = Scalar(DalekScalar::from_bytes_mod_order(rb_arr));

        let a_bit = reveal.a_bits[i];
        let b_bit = reveal.b_bits[i];

        if a_bit > 1 || b_bit > 1 {
            return Err(ArcMintError::InvalidProof(format!(
                "opened bits must be 0 or 1 at position {i}"
            )));
        }

        let a_scalar = Scalar(DalekScalar::from(a_bit as u64));
        let b_scalar = Scalar(DalekScalar::from(b_bit as u64));

        let pair = &candidate.pairs[i];

        if !verify_pedersen_opening(&pair.a_commit, &a_scalar, &ra, g, h) {
            return Err(ArcMintError::InvalidProof(format!(
                "invalid A opening at position {i}"
            )));
        }

        if !verify_pedersen_opening(&pair.b_commit, &b_scalar, &rb, g, h) {
            return Err(ArcMintError::InvalidProof(format!(
                "invalid B opening at position {i}"
            )));
        }
    }

    Ok(())
}

pub fn verify_all_opened_candidates(
    candidates: &[NoteCommitmentData],
    reveals: &[UnsignedNoteReveal],
    open_indices: &[usize],
    g: &GroupElement,
    h: &GroupElement,
) -> Result<()> {
    if candidates.is_empty() {
        return Err(ArcMintError::InvalidProof(
            "no candidates in session".to_string(),
        ));
    }

    if open_indices.len() != candidates.len().saturating_sub(1) {
        return Err(ArcMintError::InvalidProof(
            "open_indices length mismatch".to_string(),
        ));
    }

    if reveals.len() != open_indices.len() {
        return Err(ArcMintError::InvalidProof(
            "reveal length mismatch".to_string(),
        ));
    }

    let mut seen_serials = Vec::with_capacity(reveals.len());

    for reveal in reveals {
        seen_serials.push(reveal.serial.0);
    }

    seen_serials.sort_unstable();
    seen_serials.dedup();
    if seen_serials.len() != reveals.len() {
        return Err(ArcMintError::InvalidProof(
            "duplicate serials in opened candidates".to_string(),
        ));
    }

    for (reveal, idx) in reveals.iter().zip(open_indices.iter()) {
        if *idx >= candidates.len() {
            return Err(ArcMintError::InvalidProof(
                "open index out of range".to_string(),
            ));
        }
        let candidate = &candidates[*idx];
        if candidate.serial != reveal.serial {
            return Err(ArcMintError::InvalidProof(
                "serial mismatch in opened candidate".to_string(),
            ));
        }
        verify_opened_candidate(candidate, reveal, g, h)?;
    }

    Ok(())
}

pub fn verify_frost_signature(
    data: &NoteCommitmentData,
    signature_bytes: &[u8],
    public_key_package: &frost_ristretto255::keys::PublicKeyPackage,
) -> Result<()> {
    if signature_bytes.len() != 64 {
        return Err(ArcMintError::SigningError(
            "invalid signature length".to_string(),
        ));
    }
    let mut serialized = [0u8; 64];
    serialized.copy_from_slice(signature_bytes);
    let signature = frost_ristretto255::Signature::deserialize(serialized)
        .map_err(|e| ArcMintError::SigningError(format!("invalid signature encoding: {e}")))?;
    let message = note_hash(data)?;
    public_key_package
        .verifying_key()
        .verify(&message, &signature)
        .map_err(|e| ArcMintError::SigningError(format!("signature verification failed: {e}")))?;
    Ok(())
}

fn scalar_from_bytes(bytes: &[u8], position: usize, field: &str) -> Result<Scalar> {
    if bytes.len() != 32 {
        return Err(ArcMintError::InvalidProof(format!(
            "invalid {field} scalar length at position {position}"
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(Scalar(DalekScalar::from_bytes_mod_order(arr)))
}
