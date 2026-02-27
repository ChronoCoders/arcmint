use crate::error::{ArcMintError, Result};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use frost_ristretto255::aggregate;
use frost_ristretto255::keys::{self, IdentifierList, KeyPackage, PublicKeyPackage};
use frost_ristretto255::round1::{self, SigningCommitments, SigningNonces};
use frost_ristretto255::round2::{self, SignatureShare};
use frost_ristretto255::Identifier as FrostIdentifier;
use frost_ristretto255::SigningPackage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerIdentifier(pub FrostIdentifier);

impl From<FrostIdentifier> for SignerIdentifier {
    fn from(id: FrostIdentifier) -> Self {
        SignerIdentifier(id)
    }
}

impl From<SignerIdentifier> for FrostIdentifier {
    fn from(id: SignerIdentifier) -> Self {
        id.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartialSignature {
    pub signer_id: SignerIdentifier,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningCommitment {
    pub signer_id: SignerIdentifier,
    pub hiding: Vec<u8>,
    pub binding: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AggregatedSignature(pub Vec<u8>);

pub fn generate_key_package(
    threshold: u16,
    max_signers: u16,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<Vec<(KeyPackage, PublicKeyPackage)>> {
    warn!(
        "Using trusted dealer FROST key generation (generate_with_dealer); \
         this is for development/testing only and MUST be replaced with DKG in production"
    );

    let (shares, pubkey_package) =
        keys::generate_with_dealer(max_signers, threshold, IdentifierList::Default, rng)
            .map_err(|e| ArcMintError::CryptoError(format!("dealer key generation failed: {e}")))?;

    let mut result = Vec::with_capacity(shares.len());
    for (_identifier, secret_share) in shares {
        let key_package = KeyPackage::try_from(secret_share).map_err(|e| {
            ArcMintError::CryptoError(format!("invalid secret share for key package: {e}"))
        })?;
        result.push((key_package, pubkey_package.clone()));
    }

    Ok(result)
}

pub fn load_key_package(path: &Path) -> Result<KeyPackage> {
    let data = fs::read(path)
        .map_err(|e| ArcMintError::CryptoError(format!("failed to read key package file: {e}")))?;
    let package = serde_json::from_slice(&data)?;
    Ok(package)
}

pub fn save_key_package(package: &KeyPackage, path: &Path) -> Result<()> {
    let data = serde_json::to_vec(package)?;
    fs::write(path, &data)
        .map_err(|e| ArcMintError::CryptoError(format!("failed to write key package file: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| {
            ArcMintError::CryptoError(format!("failed to set key package permissions: {e}"))
        })?;
    }

    Ok(())
}

pub fn load_public_key_package(path: &Path) -> Result<PublicKeyPackage> {
    let data = fs::read(path).map_err(|e| {
        ArcMintError::CryptoError(format!("failed to read public key package file: {e}"))
    })?;
    let package = serde_json::from_slice(&data)?;
    Ok(package)
}

pub fn save_public_key_package(package: &PublicKeyPackage, path: &Path) -> Result<()> {
    let data = serde_json::to_vec(package)?;
    fs::write(path, &data).map_err(|e| {
        ArcMintError::CryptoError(format!("failed to write public key package file: {e}"))
    })?;
    Ok(())
}

pub fn distribute_dev_keys(
    threshold: u16,
    max_signers: u16,
    output_dir: &Path,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<()> {
    let mut packages = generate_key_package(threshold, max_signers, rng)?;

    fs::create_dir_all(output_dir).map_err(|e| {
        ArcMintError::CryptoError(format!(
            "failed to create dev key output directory {output_dir:?}: {e}"
        ))
    })?;

    let mut public_key_package = None;

    for i in 1..=max_signers {
        let (key_package, pubkey_package) = packages
            .pop()
            .ok_or_else(|| ArcMintError::CryptoError("missing key package".to_string()))?;

        match &public_key_package {
            Some(existing) if existing != &pubkey_package => {
                return Err(ArcMintError::CryptoError(
                    "inconsistent public key package from dealer".to_string(),
                ));
            }
            Some(_) => {}
            None => {
                public_key_package = Some(pubkey_package.clone());
            }
        }

        let file_name = format!("signer_{i}_key.json");
        let path: PathBuf = output_dir.join(file_name);
        save_key_package(&key_package, &path)?;
    }

    let pub_path = output_dir.join("public_key.json");
    if let Some(pubkey_package) = public_key_package {
        save_public_key_package(&pubkey_package, &pub_path)?;
    } else {
        return Err(ArcMintError::CryptoError(
            "no public key package generated".to_string(),
        ));
    }

    info!(
        "Dev keys written to {}. DO NOT use in production.",
        output_dir.display()
    );

    Ok(())
}

pub fn generate_nonce_and_commitment(
    key_package: &KeyPackage,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(SigningNonces, SigningCommitment)> {
    let (nonces, commitments) = round1::commit(key_package.signing_share(), rng);
    let serialized = commitments
        .serialize()
        .map_err(|e| ArcMintError::SigningError(format!("failed to serialize commitments: {e}")))?;
    let signer_id = SignerIdentifier(*key_package.identifier());

    let commitment = SigningCommitment {
        signer_id,
        hiding: serialized,
        binding: Vec::new(),
    };

    Ok((nonces, commitment))
}

pub fn produce_partial_signature(
    key_package: &KeyPackage,
    nonces: &SigningNonces,
    message: &[u8],
    commitments: &[(SignerIdentifier, SigningCommitment)],
) -> Result<PartialSignature> {
    let mut commitments_map: BTreeMap<FrostIdentifier, SigningCommitments> = BTreeMap::new();

    for (signer_id, commitment) in commitments {
        let id: FrostIdentifier = signer_id.clone().into();
        let value = SigningCommitments::deserialize(&commitment.hiding).map_err(|e| {
            ArcMintError::SigningError(format!("invalid signing commitment bytes: {e}"))
        })?;
        commitments_map.insert(id, value);
    }

    let signing_package = SigningPackage::new(commitments_map, message);

    let sig_share = round2::sign(&signing_package, nonces, key_package).map_err(|e| {
        ArcMintError::SigningError(format!("failed to produce partial signature: {e}"))
    })?;

    let bytes = serde_json::to_vec(&sig_share)?;
    let signer_id = SignerIdentifier(*key_package.identifier());

    Ok(PartialSignature { signer_id, bytes })
}

pub fn aggregate_signatures(
    message: &[u8],
    commitments: &[(SignerIdentifier, SigningCommitment)],
    partial_sigs: &[PartialSignature],
    public_key_package: &PublicKeyPackage,
) -> Result<AggregatedSignature> {
    let mut commitments_map: BTreeMap<FrostIdentifier, SigningCommitments> = BTreeMap::new();

    for (signer_id, commitment) in commitments {
        let id: FrostIdentifier = signer_id.clone().into();
        let value = SigningCommitments::deserialize(&commitment.hiding).map_err(|e| {
            ArcMintError::SigningError(format!("invalid signing commitment bytes: {e}"))
        })?;
        commitments_map.insert(id, value);
    }

    let mut sig_shares: BTreeMap<FrostIdentifier, SignatureShare> = BTreeMap::new();
    for partial in partial_sigs {
        let id: FrostIdentifier = partial.signer_id.clone().into();
        let share: SignatureShare = serde_json::from_slice(&partial.bytes)?;
        sig_shares.insert(id, share);
    }

    let signing_package = SigningPackage::new(commitments_map, message);

    let signature = aggregate(&signing_package, &sig_shares, public_key_package)
        .map_err(|e| ArcMintError::SigningError(format!("failed to aggregate signatures: {e}")))?;

    public_key_package
        .verifying_key()
        .verify(message, &signature)
        .map_err(|e| {
            ArcMintError::SigningError(format!("aggregated signature verification failed: {e}"))
        })?;

    let bytes = signature.serialize().to_vec();
    Ok(AggregatedSignature(bytes))
}
