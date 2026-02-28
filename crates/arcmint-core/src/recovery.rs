use crate::error::{ArcMintError, Result};
use crate::protocol::SpendProof;

pub fn recover_theta_u(
    transcript_a: &SpendProof,
    challenge_a: &[u8],
    transcript_b: &SpendProof,
    challenge_b: &[u8],
    k: usize,
) -> Result<[u8; 32]> {
    if challenge_a.len() != k || challenge_b.len() != k {
        return Err(ArcMintError::InvalidProof(
            "challenge length does not match k".to_string(),
        ));
    }

    if !challenges_differ(challenge_a, challenge_b) {
        return Err(ArcMintError::InvalidProof(
            "challenges do not differ".to_string(),
        ));
    }

    let mut a_by_index = vec![None; k];
    for rs in &transcript_a.revealed_scalars {
        let idx = rs.bit_index;
        if idx >= k {
            return Err(ArcMintError::InvalidProof(format!(
                "bit index {idx} out of range in transcript A"
            )));
        }
        if a_by_index[idx].is_some() {
            return Err(ArcMintError::InvalidProof(format!(
                "duplicate bit index {idx} in transcript A"
            )));
        }
        a_by_index[idx] = Some(rs);
    }

    let mut b_by_index = vec![None; k];
    for rs in &transcript_b.revealed_scalars {
        let idx = rs.bit_index;
        if idx >= k {
            return Err(ArcMintError::InvalidProof(format!(
                "bit index {idx} out of range in transcript B"
            )));
        }
        if b_by_index[idx].is_some() {
            return Err(ArcMintError::InvalidProof(format!(
                "duplicate bit index {idx} in transcript B"
            )));
        }
        b_by_index[idx] = Some(rs);
    }

    let mut theta_bits = vec![0u8; k];
    let mut resolved = 0usize;

    for i in 0..k {
        let ca = challenge_a[i];
        let cb = challenge_b[i];

        let rs_a = a_by_index[i].ok_or_else(|| {
            ArcMintError::InvalidProof(format!("missing revealed scalar at position {i} in A"))
        })?;
        let rs_b = b_by_index[i].ok_or_else(|| {
            ArcMintError::InvalidProof(format!("missing revealed scalar at position {i} in B"))
        })?;

        if ca > 1 || cb > 1 {
            return Err(ArcMintError::InvalidProof(format!(
                "invalid challenge bit at position {i}"
            )));
        }

        if ca != cb {
            let bit_a = bit_from_scalar_bytes(&rs_a.value_scalar, i, "A")?;
            let bit_b = bit_from_scalar_bytes(&rs_b.value_scalar, i, "B")?;
            theta_bits[i] = bit_a ^ bit_b;
            resolved += 1;
        } else {
            let bit = bit_from_scalar_bytes(&rs_a.value_scalar, i, "A")?;
            let bit2 = bit_from_scalar_bytes(&rs_b.value_scalar, i, "B")?;
            if bit != bit2 {
                return Err(ArcMintError::InvalidProof(format!(
                    "same-challenge positions yield different bits at position {i}"
                )));
            }
            theta_bits[i] = 0;
        }
    }

    if resolved == 0 {
        return Err(ArcMintError::InvalidProof(
            "no differing challenge positions — cannot recover any theta bits".to_string(),
        ));
    }

    let mut theta = [0u8; 32];
    for (i, bit) in theta_bits.iter().enumerate() {
        if *bit & 1 == 1 {
            let byte_index = i / 8;
            if byte_index >= 32 {
                break;
            }
            let bit_index = i % 8;
            theta[byte_index] |= 1 << bit_index;
        }
    }

    Ok(theta)
}

pub fn challenges_differ(c1: &[u8], c2: &[u8]) -> bool {
    let len = c1.len().min(c2.len());
    for i in 0..len {
        if c1[i] != c2[i] {
            return true;
        }
    }
    c1.len() != c2.len()
}

pub fn double_spend_escape_probability(k: usize) -> f64 {
    2.0_f64.powi(-(k as i32))
}

fn bit_from_scalar_bytes(bytes: &[u8], position: usize, label: &str) -> Result<u8> {
    if bytes.len() != 32 {
        return Err(ArcMintError::InvalidProof(format!(
            "invalid scalar length for {label} at position {position}"
        )));
    }
    Ok(bytes[0] & 1)
}
