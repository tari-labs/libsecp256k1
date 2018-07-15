//! Pure Rust implementation of the secp256k1 curve and fast ECDSA
//! signatures. The secp256k1 curve is used excusively in Bitcoin and
//! Ethereum alike cryptocurrencies.

#![no_std]
extern crate digest;
extern crate hmac_drbg;
extern crate rand;
extern crate sha2;
extern crate typenum;
#[macro_use]
extern crate arrayref;

#[macro_use]
mod field;
#[macro_use]
mod group;
mod ecdh;
mod ecdsa;
mod ecmult;
mod error;
mod scalar;

use hmac_drbg::HmacDRBG;
use sha2::Sha256;
use typenum::U32;

use scalar::Scalar;

use ecmult::{ECMULT_CONTEXT, ECMULT_GEN_CONTEXT};

pub use error::Error;

pub mod keys;
pub use keys::{SecretKey, PublicKey};

/// Curve related structs.
pub mod curve {
    pub use field::Field;
    pub use group::{Affine, AffineStorage, Jacobian, AFFINE_G, CURVE_B};
    pub use scalar::Scalar;

    pub use ecmult::{ECMultContext, ECMultGenContext, ECMULT_CONTEXT, ECMULT_GEN_CONTEXT};
}

pub mod util;

#[derive(Debug, Clone, Eq, PartialEq)]
/// An ECDSA signature.
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// Tag used for public key recovery from signatures.
pub struct RecoveryId(u8);

#[derive(Debug, Clone, Eq, PartialEq)]
/// Hashed message input to an ECDSA signature.
pub struct Message(pub Scalar);

#[derive(Debug, Clone, Eq, PartialEq)]
/// Shared secret using ECDH.
pub struct SharedSecret([u8; 32]);

impl Signature {
    pub fn parse(p: &[u8; 64]) -> Signature {
        let mut r = Scalar::default();
        let mut s = Scalar::default();

        r.set_b32(array_ref!(p, 0, 32));
        s.set_b32(array_ref!(p, 32, 32));

        Signature { r, s }
    }

    pub fn serialize(&self) -> [u8; 64] {
        let mut ret = [0u8; 64];
        self.r.fill_b32(array_mut_ref!(ret, 0, 32));
        self.s.fill_b32(array_mut_ref!(ret, 32, 32));
        ret
    }
}

impl Message {
    pub fn parse(p: &[u8; 32]) -> Message {
        let mut m = Scalar::default();
        m.set_b32(p);

        Message(m)
    }

    pub fn serialize(&self) -> [u8; 32] {
        self.0.b32()
    }
}

impl RecoveryId {
    pub fn parse(p: u8) -> Result<RecoveryId, Error> {
        if p < 4 {
            Ok(RecoveryId(p))
        } else {
            Err(Error::InvalidRecoveryId)
        }
    }

    pub fn serialize(&self) -> u8 {
        self.0
    }
}

impl Into<u8> for RecoveryId {
    fn into(self) -> u8 {
        self.0
    }
}

impl Into<i32> for RecoveryId {
    fn into(self) -> i32 {
        self.0 as i32
    }
}

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

/// Check signature is a valid message signed by public key.
pub fn verify(message: &Message, signature: &Signature, pubkey: &PublicKey) -> bool {
    ECMULT_CONTEXT.verify_raw(&signature.r, &signature.s, &pubkey.0, &message.0)
}

/// Recover public key from a signed message.
pub fn recover(
    message: &Message,
    signature: &Signature,
    recovery_id: &RecoveryId,
) -> Result<PublicKey, Error> {
    ECMULT_CONTEXT
        .recover_raw(&signature.r, &signature.s, recovery_id.0, &message.0)
        .map(|v| PublicKey(v))
}

/// Sign a message using the secret key.
pub fn sign(message: &Message, seckey: &SecretKey) -> Result<(Signature, RecoveryId), Error> {
    let seckey_b32 = seckey.0.b32();
    let message_b32 = message.0.b32();

    let mut drbg = HmacDRBG::<Sha256>::new(&seckey_b32, &message_b32, &[]);
    let generated = drbg.generate::<U32>(None);
    let mut nonce = Scalar::default();
    let mut overflow = nonce.set_b32(array_ref!(generated, 0, 32));

    while overflow || nonce.is_zero() {
        let generated = drbg.generate::<U32>(None);
        overflow = nonce.set_b32(array_ref!(generated, 0, 32));
    }

    let result = ECMULT_GEN_CONTEXT.sign_raw(&seckey.0, &message.0, &nonce);
    #[allow(unused_assignments)]
        {
            nonce = Scalar::default();
        }
    if let Ok((sigr, sigs, recid)) = result {
        return Ok((Signature { r: sigr, s: sigs }, RecoveryId(recid)));
    } else {
        return Err(result.err().unwrap());
    }
}
