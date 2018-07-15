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
pub mod ecmult;
mod error;
mod scalar;

pub use error::Error;

mod keys;
pub mod signature;
pub mod util;
pub mod message;

pub use ecdh::SharedSecret;
pub use keys::{PublicKey, SecretKey};
pub use signature::{recover, verify, Signature};
pub use message::Message;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// Tag used for public key recovery from signatures.
pub struct RecoveryId(u8);

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
