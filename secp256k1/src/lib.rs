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
pub mod field;
#[macro_use]
pub mod group;
mod ecdh;
mod ecdsa;
pub mod ecmult;
mod error;
mod keys;
mod message;
mod recovery_id;
mod scalar;
pub mod signature;
pub mod util;

pub use ecdh::SharedSecret;
pub use error::Error;
pub use keys::{PublicKey, SecretKey};
pub use message::Message;
pub use recovery_id::RecoveryId;
pub use signature::Signature;

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate secp256k1_test;
