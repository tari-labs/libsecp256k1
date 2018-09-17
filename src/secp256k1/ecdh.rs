use secp256k1::digest::{FixedOutput, Input};
use ecmult::{ECMultContext, ECMULT_CONTEXT};
use secp256k1::group::{Affine, Jacobian};
use secp256k1::scalar::Scalar;
use super::sha2::Sha256;
use secp256k1::keys::{ PublicKey, SecretKey };
use secp256k1::error::Error;

impl ECMultContext {
    pub fn ecdh_raw(&self, point: &Affine, scalar: &Scalar) -> Option<[u8; 32]> {
        let mut pt = point.clone();
        let s = scalar.clone();

        let mut result = [0u8; 32];
        if s.is_zero() {
            return None;
        }

        let mut res = Jacobian::default();
        self.ecmult_const(&mut res, &pt, &s);
        pt.set_gej(&res);

        pt.x.normalize();
        pt.y.normalize();

        let x = pt.x.b32();
        let y = 0x02 | (if pt.y.is_odd() { 1 } else { 0 });

        let mut sha = Sha256::default();
        sha.process(&[y]);
        sha.process(&x);
        let generic = sha.fixed_result();

        for i in 0..32 {
            result[i] = generic[i];
        }

        Some(result)
    }
}

/// Shared secret using ECDH.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedSecret([u8; 32]);

impl SharedSecret {
    pub fn new(pubkey: &PublicKey, seckey: &SecretKey) -> Result<SharedSecret, Error> {
        let inner = match ECMULT_CONTEXT.ecdh_raw(&pubkey.0, &seckey.0) {
            Some(val) => val,
            None => return Err(Error::InvalidSecretKey),
        };

        Ok(SharedSecret(inner))
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
