//! "Raw" signature tests. The tests in this module illustrate features of digital signatures using raw ECC.
extern crate rand;
extern crate secp256k1;

use secp256k1::{ Message, PublicKey, SecretKey };
use secp256k1::schnorr::{ Schnorr, Challenge };

/// In a standard signature, we want to provide some information that proves that I know the private key for a
/// signature for some message.
/// So, everyone knows my public key, P, which corresponds to my private key k.
/// I produce a challenge, e, (which is ultimately a scalar) = H(R || P || m)
/// where R = r.G, a nonce value.
/// I then calculate s = r + e.k, and publish R, m, and s (P is already known).
///
/// Now s.G = (r + e.k)G = rG + ekG = R + eP
///
/// So anyone can calculate R + eP and check that it is equal to sG. But only I can calculate s since I'm the
/// only person who knows k.
#[test]
#[allow(non_snake_case)]
fn standard_signature() {
    let mut rng = rand::thread_rng();
    let k = SecretKey::random(&mut rng);
    let P = PublicKey::from_secret_key(&k);
    let nonce = SecretKey::random(&mut rng);
    let R = PublicKey::from_secret_key(&nonce);
    let m = Message::hash(b"password").unwrap();
    let e = Challenge::new(&[&R, &P, &m]).as_scalar().unwrap();

    // Signature
    let s = nonce + e * k;
    //Verify
    let sg = PublicKey::from_secret_key(&s);
    let check = R + e * P;
    assert_eq!(sg, check);
}

/// Why do we need a nonce in the standard signature?
///
/// Let's say we naiively sign a message m with
/// e = H(R || m)
///
/// s = ek
///
/// sG =? ekG = eP
/// So far so good. But anyone can read your private key now because s is a scalar, so k = e/s is not hard to do.
/// With the nonce you have to solve k = (s - r)/e, but r is unknown
#[test]
#[allow(non_snake_case)]
fn no_nonce() {
    let mut rng = rand::thread_rng();
    let k = SecretKey::random(&mut rng);
    let P = PublicKey::from_secret_key(&k);
    let m = Message::hash(b"password").unwrap();
    let e = Challenge::new(&[&P, &m]).as_scalar().unwrap();

    // Signature
    let s = e * k;
    let hacked = s * e.inv();
    assert_eq!(k, hacked);
}

#[test]
#[allow(non_snake_case)]
fn schnorr_signature() {
    // Create some keys
    let (k, P, r, R) = get_keyset();
    let (t, T, _r, _R) = get_keyset();
    let m = Message::hash(b"password").unwrap();
    // Let's construct a Schnorr signature from a partial signature
    // e = H(R || P || H(m))
    let e = Challenge::new(&[&(R + T), &T, &m]).as_scalar().unwrap();
    let s = r + t + e * k;
    let s_partial = r + e * k;
    // Note that s = s' + t
    assert_eq!(s, s_partial + t);
    // s' is a signature, but for nonce R+T rather than R:
    // At this point, s', R, T and e are known
    let s_p_check = PublicKey::from_secret_key(&s_partial);
    let s_check = PublicKey::from_secret_key(&s);
    assert_eq!(s_p_check, R + e * P);
    assert_ne!(s_p_check, R + T + e * P);
    assert_eq!(s_check, R + T + e * P);
}

/// What happens if the Challenge is too simple?
/// Consider this attempt at a 2-of-2 signature for m
/// e = H( Ra + Rb || Pa + Pb || m)
/// Alice publishes Pa, R
/// Bob can forge signatures if Bob is sneaky (and he is)
#[test]
#[allow(non_snake_case)]
fn cancellation_attack() {
    // Create some keys for Alice and Bob
    let (_k_a, P_a, _r_a, R_a) = get_keyset();
    let (k_b, P_b, r_b, R_b) = get_keyset();
    let m = Message::hash(b"password").unwrap();
    // Alice publishes P_a and R_a, which Bob uses to calculate Fr, a "fake" public nonce, and Fk, a fake Public key
    let F_r = R_b - R_a;
    let F_k = P_b - P_a;
    // Bob publishes F_b, F_r and everyone calculates e
    let e = Challenge::new(&[ &(R_a + F_r), &(P_a + F_k), &m]).as_scalar().unwrap();
    // Now the "combined" public nonce is Bob's public nonce, and he knows the secret key for that!
    assert_eq!(R_a + F_r, R_b);
    assert_eq!(P_a + F_k, P_b);
    // Now Bob can forge the multisignature with
    let s_forged = r_b + e * k_b;
    // We show that this is a valid signature for e
    let s_check_original = R_a + F_r + e * (P_a + F_k);
    assert_eq!(PublicKey::from_secret_key(&s_forged), s_check_original);
    // This doesn't work if Bob has to publish any keys in advance
}

#[test]
#[allow(non_snake_case)]
fn two_two_multisig() {
    let mut rng = rand::thread_rng();
    let m = Message::hash(b"password").unwrap();
    // Bob chooses b (secret key), rb (nonce), t (adapter)
    let rb = SecretKey::random(&mut rng);
    let b = SecretKey::random(&mut rng);
    let t = SecretKey::random(&mut rng);
    // Alice chooses a (secret key), ra (nonce)
    let ra = SecretKey::random(&mut rng);
    let a = SecretKey::random(&mut rng);
    // Bob and Alice both share the Public keys related to their secret keys
    let Rb = PublicKey::from_secret_key(&rb);
    let Pb = PublicKey::from_secret_key(&b);
    let T = PublicKey::from_secret_key(&t);

    let Ra = PublicKey::from_secret_key(&ra);
    let Pa = PublicKey::from_secret_key(&a);
    // Both calculate the Joint Public key, H( H(Pa || Pb) || Pa
    // Both construct the challenge, e = H( H(Pa || Pb) || Pa
    let Jab = Schnorr::partial_joint_key_from(&Pa, &Pb);
    // Both alice and Bob are able to calculate e
    let e = Challenge::new(&[&Jab, &(Ra + Rb + T), &m]).as_scalar().unwrap();
    let (p_a, p_b) = Schnorr::partial_joint_hashes_from(&Pa, &Pb);
    // Bob calculates the adapter signature for Jab || Ra + Rb || m, using his private key for the joint key
    let kb = p_b * b;
    let s_b = rb + e * kb;
    // Alice checks that the signature is valid
    assert_eq!(PublicKey::from_secret_key(&s_b), Rb + e * p_b * Pb, "Bob's partial signature is invalid");
    // It matches, so Alice sends Bob her signature
    let ka = p_a * a;
    let s_a = ra + e * ka;
    // Bob verifies Alice's signature
    assert_eq!(PublicKey::from_secret_key(&s_a), Ra + e * p_a * Pa, "Alice's signature failed");
    // It also matches, so bob can send over the final signature
    let s_agg = s_a + s_b + t;
    // Alice knows s_a from before and generated s_b herself, so can calculate t:
    assert_eq!(t, s_agg - s_a - s_b, "Alice could not correctly calculate t");
    // And check that the signature is valid
    assert_eq!(PublicKey::from_secret_key(&s_agg), Ra + Rb + e * Jab + T, "The joint signature is invalid")

}

#[allow(non_snake_case)]
fn get_keyset() -> (SecretKey, PublicKey, SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let k = SecretKey::random(&mut rng);
    let P = PublicKey::from_secret_key(&k);
    let r = SecretKey::random(&mut rng);
    let R = PublicKey::from_secret_key(&r);
    (k, P, r, R)
}
