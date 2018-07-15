extern crate hex;
extern crate rand;
extern crate secp256k1;
#[macro_use]
extern crate arrayref;

use rand::thread_rng;
use secp256k1::Error;
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

#[test]
fn valid_keys() {
    let key = from_hex("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba");
    assert!(key.is_ok());
    let key = from_hex("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443");
    assert!(key.is_ok());
    let key = from_hex("0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07");
    assert!(key.is_ok());
    let key = from_hex("");
    assert_eq!(key.err().unwrap(), Error::InvalidPublicKey);
    let key = from_hex("0abcdefgh");
    assert_eq!(key.err().unwrap(), Error::InvalidHex);
    let key = from_hex("9384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07");
    assert_eq!(key.err().unwrap(), Error::InvalidPublicKey);
    let key = from_hex("04fe53c78e36b86aae8082484a4007b706d5678cabb92d178fc95020d4d8dc41ef44cfbb8dfa7a593c7910a5b6f94d079061a7766cbeed73e24ee4f654f1e51904");
    assert!(key.is_ok());
}

#[test]
fn serlialize_deserialize() {
    let key = from_hex("0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07").unwrap();
    let des = key.serialize();
    let key2 = PublicKey::parse(&des).unwrap();
    println!("{:?}\n{:?}", key, key2);
    assert_eq!(key, key2);

    let key = from_hex("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba").unwrap();
    let des = key.serialize_compressed();
    let key2 = PublicKey::parse_compressed(&des).unwrap();
    assert_eq!(key, key2);

    let key = from_hex("04fe53c78e36b86aae8082484a4007b706d5678cabb92d178fc95020d4d8dc41ef44cfbb8dfa7a593c7910a5b6f94d079061a7766cbeed73e24ee4f654f1e51904").unwrap();
    let des = key.serialize();
    let key2 = PublicKey::parse(&des).unwrap();
    assert_eq!(key, key2);
}

#[test]
fn add_public_keys() {
    let p1 =
        from_hex("0241cc121c419921942add6db6482fb36243faf83317c866d2a28d8c6d7089f7ba").unwrap();
    let p2 =
        from_hex("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443").unwrap();
    let exp_sum =
        from_hex("0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07").unwrap();
    let sum = p1 + p2;
    assert_eq!(p2 + p1, sum);
    assert_eq!(sum, exp_sum);
}

#[test]
fn scalar_multiplication_is_addition() {
    let p1 = from_hex("04fe53c78e36b86aae8082484a4007b706d5678cabb92d178fc95020d4d8dc41ef44cfbb8dfa7a593c7910a5b6f94d079061a7766cbeed73e24ee4f654f1e51904").unwrap();
    let k = small(3);
    assert_eq!(p1 + p1 + p1, k * p1);
}

pub fn from_hex(h: &str) -> Result<PublicKey, Error> {
    let data = hex::decode(h).or(Err(Error::InvalidHex))?;
    match data.len() {
        33 => PublicKey::parse_compressed(array_ref!(data, 0, 33)),
        65 => PublicKey::parse(array_ref!(data, 0, 65)),
        _ => Err(Error::InvalidPublicKey),
    }
}
