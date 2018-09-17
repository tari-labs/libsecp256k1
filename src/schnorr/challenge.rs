use secp256k1::{PublicKey, SecretKey};
use secp256k1::Message;
use secp256k1::Error;
use sha2::{ Digest, Sha256 };

/// Objects implementing Combinable can be serialized as bytes for use in producing hash challenges
/// e.g. H( R || T || m)
pub trait Combinable {
    fn as_bytes(&self) -> Vec<u8>;
}

impl Combinable for PublicKey {
    fn as_bytes(&self) -> Vec<u8> {
        let b = self.serialize();
        b.to_vec()
    }
}

impl Combinable for [u8; 32] {
    fn as_bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

/// A Challenge of the form H(P || R || ... || m).
/// Challenges are often used in constructing signatures. Since we use SHA256 to derive H(...), the value is a scalar
/// and can be used as a secret key. Thus if we let
/// e = H(R || P || m), we can derive a signature for m,
/// where s = r + e.k and R and P are published:
/// s.G = (r + e.k)G = R + e.P
///
/// For Schnorr signatures and the like, R is replaced by a partial (R+T), but the same structure is valid
pub struct Challenge([u8; 32]);

#[allow(non_snake_case)]
impl Challenge {
    pub fn new(keys: &[&Combinable]) -> Challenge {
        let mut hasher = Sha256::new();
        for &k in keys {
            hasher.input(k.as_bytes().as_ref());
        }
        let hash = hasher.result();
        assert!(hash.len() >= 32);
        let mut h: [u8; 32] = [0u8; 32];
        h.copy_from_slice(hash.as_slice());

        Challenge(h)
    }

    pub fn as_scalar(&self) -> Result<SecretKey, Error> {
        SecretKey::parse(&self.0)
    }
}

impl Combinable for Challenge {
    fn as_bytes(&self) -> Vec<u8> {
        self.as_scalar().unwrap().serialize().to_vec()
    }
}

impl Combinable for Message {
    fn as_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
}

