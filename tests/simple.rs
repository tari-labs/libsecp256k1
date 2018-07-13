extern crate rand;
extern crate secp256k1;

use rand::thread_rng;
use secp256k1::{PublicKey, SecretKey};

#[test]
fn create_secret() {
    let _ = SecretKey::random(&mut thread_rng());
}

#[test]
fn negate_twice() {
    let k = SecretKey::random(&mut thread_rng());
    let k2 = -k;
    assert_ne!(k, k2);
    assert_eq!(k, -k2);
}

#[test]
fn add_scalar_is_associative() {
    let k1 = SecretKey::random(&mut thread_rng());
    let k2 = SecretKey::random(&mut thread_rng());
    assert_eq!(k1 + k2, k2 + k1);
}

#[test]
fn add_scalar() {
    let one = small(1);
    let two = small(2);
    let three = small(3);
    assert_eq!(one + two, three);
    assert_ne!(one, two);
}

#[test]
fn mul_scalar_is_associative() {
    let k1 = SecretKey::random(&mut thread_rng());
    let k2 = SecretKey::random(&mut thread_rng());
    assert_eq!(k1 * k2, k2 * k1);
}

#[test]
fn mul_scalar() {
    let one = small(1);
    let two = small(2);
    assert_eq!(one * two, two);
}

fn small(val: u8) -> SecretKey {
    SecretKey::parse(&[
        0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, val,
    ]).unwrap()
}
