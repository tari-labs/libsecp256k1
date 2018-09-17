#[macro_use]
extern crate arrayref;
extern crate sha2;

#[macro_use]
pub mod secp256k1;

#[cfg(test)]
extern crate secp256k1_test;
#[cfg(test)]
extern crate hex;

pub mod ecmult;
pub mod schnorr;


pub use secp256k1::SharedSecret;
pub use secp256k1::Error;
pub use secp256k1::{PublicKey, SecretKey};
pub use secp256k1::Message;
pub use secp256k1::RecoveryId;
pub use secp256k1::signature::Signature;

