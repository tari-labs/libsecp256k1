use secp256k1::{ PublicKey, SecretKey };
use schnorr::challenge::Challenge;

#[allow(non_snake_case)]
pub struct Schnorr {}

#[allow(non_snake_case)]
impl Schnorr {

    /// Return the partial joint hashes for Schnorr signatures:
    /// P_A' = H(H(P_A||P_B) || P_A) and
    /// P_B' = H(H(P_A||P_B) || P_B)
    pub fn partial_joint_hashes_from(Pa : &PublicKey, Pb: &PublicKey) -> (SecretKey, SecretKey) {
        let hPaPb = Challenge::new(&[Pa, Pb]);
        let partial_a = Challenge::new(&[&hPaPb, Pa]).as_scalar().unwrap();
        let partial_b = Challenge::new(&[&hPaPb, Pb]).as_scalar().unwrap();
        (partial_a, partial_b)
    }

    /// Derive a joint public key from two independent public keys given by the formulae:
    /// P_A' = H(H(P_A||P_B) || P_A) * P_A ,
    /// P_B' = H(H(P_A||P_B) || P_B) * P_B ,
    /// joint_key = P_A' + P_B'
    pub fn partial_joint_key_from(Pa : &PublicKey, Pb: &PublicKey) -> PublicKey {
        let (p_a, p_b) = Schnorr::partial_joint_hashes_from(Pa, Pb);
        let partial_a = p_a * *Pa;
        let partial_b = p_b * *Pb;
        partial_a + partial_b
    }

}

