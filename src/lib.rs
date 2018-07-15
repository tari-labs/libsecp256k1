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
mod recovery_id;
pub mod signature;
pub mod util;
mod message;

pub use ecdh::SharedSecret;
pub use keys::{PublicKey, SecretKey};
pub use signature::{recover, verify, Signature};
pub use message::Message;
pub use recovery_id::RecoveryId;

