use core::fmt;

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar as DalekScalar,
};
use rand_core::{CryptoRng, RngCore};
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

#[derive(Clone, Debug)]
pub struct GroupElement(pub RistrettoPoint);

#[derive(Clone, Debug, Zeroize)]
pub struct Scalar(pub DalekScalar);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SerialNumber(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IdentityHash(pub [u8; 32]);

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct BlindingFactor(pub Scalar);

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.0.to_bytes();
        let hex_str = hex::encode(bytes);
        serializer.serialize_str(&hex_str)
    }
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a 64-character lowercase hex string encoding a Scalar")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        let bytes_vec = hex::decode(v).map_err(E::custom)?;
        if bytes_vec.len() != 32 {
            return Err(E::custom("invalid scalar length"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);
        Ok(Scalar(DalekScalar::from_bytes_mod_order(bytes)))
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ScalarVisitor)
    }
}

impl Serialize for GroupElement {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let compressed = self.0.compress();
        let bytes = compressed.to_bytes();
        let hex_str = hex::encode(bytes);
        serializer.serialize_str(&hex_str)
    }
}

struct GroupElementVisitor;

impl<'de> Visitor<'de> for GroupElementVisitor {
    type Value = GroupElement;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a 64-character lowercase hex string encoding a Ristretto point")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        let bytes_vec = hex::decode(v).map_err(E::custom)?;
        if bytes_vec.len() != 32 {
            return Err(E::custom("invalid Ristretto point length"));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&bytes_vec);
        let compressed = CompressedRistretto::from_slice(&bytes).map_err(E::custom)?;
        let point = compressed
            .decompress()
            .ok_or_else(|| E::custom("invalid Ristretto point encoding"))?;
        Ok(GroupElement(point))
    }
}

impl<'de> Deserialize<'de> for GroupElement {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(GroupElementVisitor)
    }
}

impl fmt::Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex_str = hex::encode(self.0);
        f.write_str(&hex_str)
    }
}

impl fmt::Display for IdentityHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let hex_str = hex::encode(self.0);
        f.write_str(&hex_str)
    }
}

pub fn random_scalar<R>(rng: &mut R) -> Scalar
where
    R: CryptoRng + RngCore,
{
    Scalar(DalekScalar::random(rng))
}

pub fn random_serial<R>(rng: &mut R) -> SerialNumber
where
    R: CryptoRng + RngCore,
{
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    SerialNumber(bytes)
}

pub fn hash_identity(identity_id: &str) -> IdentityHash {
    let mut hasher = Sha256::new();
    hasher.update(identity_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    IdentityHash(bytes)
}

pub fn compute_theta(identity_hash: &IdentityHash, r_u: &Scalar) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(identity_hash.0);
    hasher.update(r_u.0.to_bytes());
    let digest = hasher.finalize();
    let mut theta = [0u8; 32];
    theta.copy_from_slice(&digest);
    theta
}

pub fn pedersen_commit(
    value: &Scalar,
    blinding: &Scalar,
    g: &GroupElement,
    h: &GroupElement,
) -> GroupElement {
    let gv = g.0 * value.0;
    let hb = h.0 * blinding.0;
    GroupElement(gv + hb)
}

pub fn verify_pedersen_opening(
    commitment: &GroupElement,
    value: &Scalar,
    blinding: &Scalar,
    g: &GroupElement,
    h: &GroupElement,
) -> bool {
    let recomputed = pedersen_commit(value, blinding, g, h);
    recomputed.0 == commitment.0
}

pub fn generators() -> (GroupElement, GroupElement) {
    let g = GroupElement(RISTRETTO_BASEPOINT_POINT);
    let h_bytes = b"arcmint:h:generator:v1";
    let mut hasher = Sha512::new();
    hasher.update(h_bytes);
    let digest = hasher.finalize();
    let mut uniform = [0u8; 64];
    uniform.copy_from_slice(&digest);
    let h_point = RistrettoPoint::from_uniform_bytes(&uniform);
    let h = GroupElement(h_point);
    (g, h)
}
