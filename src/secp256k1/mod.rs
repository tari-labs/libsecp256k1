//! Pure Rust implementation of the secp256k1 curve and fast ECDSA
//! signatures. The secp256k1 curve is used excusively in Bitcoin and
//! Ethereum alike cryptocurrencies.

extern crate digest;
extern crate hmac_drbg;
extern crate rand;
extern crate sha2;
extern crate typenum;


#[macro_use]
pub mod field;
#[macro_use]
pub mod group;

mod ecdh;
mod ecdsa;
mod error;
mod keys;
mod message;
mod recovery_id;
mod scalar;
pub mod signature;
pub mod util;

pub use self::ecdh::SharedSecret;
pub use self::error::Error;
pub use self::keys::{PublicKey, SecretKey};
pub use self::message::Message;
pub use self::recovery_id::RecoveryId;
pub use self::signature::Signature;
pub use self::scalar::Scalar;

#[cfg(test)]
extern crate hex;
#[cfg(test)]
extern crate secp256k1_test;
