use ecmult::ECMULT_CONTEXT;
use scalar::Scalar;
use {Error, Message, PublicKey, RecoveryId};

#[derive(Debug, Clone, Eq, PartialEq)]
/// An ECDSA signature.
pub struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

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
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;
    use super::ECMULT_CONTEXT;
    use {Message, PublicKey, RecoveryId, SecretKey, SharedSecret, Signature};
    use secp256k1_test::ecdh::SharedSecret as SecpSharedSecret;
    use secp256k1_test::key;
    use secp256k1_test::{
        Message as SecpMessage, RecoverableSignature as SecpRecoverableSignature,
        RecoveryId as SecpRecoveryId, Secp256k1, Signature as SecpSignature,
    };

    #[test]
    fn test_verify() {
        let secp256k1 = Secp256k1::new();

        let message_arr = [5u8; 32];
        let (privkey, pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
        let message = SecpMessage::from_slice(&message_arr).unwrap();
        let signature = secp256k1.sign(&message, &privkey).unwrap();

        let pubkey_arr = pubkey.serialize_vec(&secp256k1, false);
        assert!(pubkey_arr.len() == 65);
        let mut pubkey_a = [0u8; 65];
        for i in 0..65 {
            pubkey_a[i] = pubkey_arr[i];
        }

        let ctx_pubkey = PublicKey::parse(&pubkey_a).unwrap();
        let ctx_message = Message::parse(&message_arr);
        let signature_arr = signature.serialize_compact(&secp256k1);
        assert!(signature_arr.len() == 64);
        let mut signature_a = [0u8; 64];
        for i in 0..64 {
            signature_a[i] = signature_arr[i];
        }
        let ctx_sig = Signature::parse(&signature_a);

        secp256k1.verify(&message, &signature, &pubkey).unwrap();
        assert!(Signature::verify(&ctx_message, &ctx_sig, &ctx_pubkey));
        let mut f_ctx_sig = ctx_sig.clone();
        f_ctx_sig.r.set_int(0);
        if f_ctx_sig.r != ctx_sig.r {
            assert!(!ECMULT_CONTEXT.verify_raw(
                &f_ctx_sig.r,
                &ctx_sig.s,
                &ctx_pubkey.clone().into(),
                &ctx_message.0
            ));
        }
        f_ctx_sig.r.set_int(1);
        if f_ctx_sig.r != ctx_sig.r {
            assert!(!ECMULT_CONTEXT.verify_raw(
                &f_ctx_sig.r,
                &ctx_sig.s,
                &ctx_pubkey.clone().into(),
                &ctx_message.0
            ));
        }
    }

    #[test]
    fn test_recover() {
        let secp256k1 = Secp256k1::new();

        let message_arr = [5u8; 32];
        let (privkey, pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
        let message = SecpMessage::from_slice(&message_arr).unwrap();
        let signature = secp256k1.sign_recoverable(&message, &privkey).unwrap();

        let pubkey_arr = pubkey.serialize_vec(&secp256k1, false);
        assert!(pubkey_arr.len() == 65);
        let mut pubkey_a = [0u8; 65];
        for i in 0..65 {
            pubkey_a[i] = pubkey_arr[i];
        }

        let ctx_message = Message::parse(&message_arr);
        let (rec_id, signature_arr) = signature.serialize_compact(&secp256k1);
        assert!(signature_arr.len() == 64);
        let mut signature_a = [0u8; 64];
        for i in 0..64 {
            signature_a[i] = signature_arr[i];
        }
        let ctx_sig = Signature::parse(&signature_a);

        // secp256k1.recover(&message, &signature).unwrap();
        let ctx_pubkey = Signature::recover(
            &ctx_message,
            &ctx_sig,
            &RecoveryId::parse(rec_id.to_i32() as u8).unwrap(),
        ).unwrap();
        let sp = ctx_pubkey.serialize();

        let sps: &[u8] = &sp;
        let gps: &[u8] = &pubkey_a;
        assert_eq!(sps, gps);
    }

    #[test]
    fn test_convert_key1() {
        let secret: [u8; 32] = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let expected: &[u8] = &[
            0x04, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
            0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
            0xf8, 0x17, 0x98, 0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc,
            0x0e, 0x11, 0x08, 0xa8, 0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0,
            0x8f, 0xfb, 0x10, 0xd4, 0xb8,
        ];
        let seckey = SecretKey::parse(&secret).unwrap();
        let pubkey = PublicKey::from_secret_key(&seckey);
        let public = pubkey.serialize();
        let pubkey_a: &[u8] = &public;

        assert_eq!(expected, pubkey_a);
    }

    #[test]
    fn test_convert_key2() {
        let secret: [u8; 32] = [
            0x4d, 0x5d, 0xb4, 0x10, 0x7d, 0x23, 0x7d, 0xf6, 0xa3, 0xd5, 0x8e, 0xe5, 0xf7, 0x0a, 0xe6,
            0x3d, 0x73, 0xd7, 0x65, 0x8d, 0x40, 0x26, 0xf2, 0xee, 0xfd, 0x2f, 0x20, 0x4c, 0x81, 0x68,
            0x2c, 0xb7,
        ];
        let expected: &[u8] = &[
            0x04, 0x3f, 0xa8, 0xc0, 0x8c, 0x65, 0xa8, 0x3f, 0x6b, 0x4e, 0xa3, 0xe0, 0x4e, 0x1c, 0xc7,
            0x0c, 0xbe, 0x3c, 0xd3, 0x91, 0x49, 0x9e, 0x3e, 0x05, 0xab, 0x7d, 0xed, 0xf2, 0x8a, 0xff,
            0x9a, 0xfc, 0x53, 0x82, 0x00, 0xff, 0x93, 0xe3, 0xf2, 0xb2, 0xcb, 0x50, 0x29, 0xf0, 0x3c,
            0x7e, 0xbe, 0xe8, 0x20, 0xd6, 0x3a, 0x4c, 0x5a, 0x95, 0x41, 0xc8, 0x3a, 0xce, 0xbe, 0x29,
            0x3f, 0x54, 0xca, 0xcf, 0x0e,
        ];
        let seckey = SecretKey::parse(&secret).unwrap();
        let pubkey = PublicKey::from_secret_key(&seckey);
        let public = pubkey.serialize();
        let pubkey_a: &[u8] = &public;

        assert_eq!(expected, pubkey_a);
    }

    #[test]
    fn test_convert_anykey() {
        let secp256k1 = Secp256k1::new();
        let (secp_privkey, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();

        let mut secret = [0u8; 32];
        for i in 0..32 {
            secret[i] = secp_privkey[i];
        }

        let seckey = SecretKey::parse(&secret).unwrap();
        let pubkey = PublicKey::from_secret_key(&seckey);
        let public = pubkey.serialize();
        let public_compressed = pubkey.serialize_compressed();
        let pubkey_r: &[u8] = &public;
        let pubkey_compressed_r: &[u8] = &public_compressed;

        let secp_pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
        assert!(secp_pubkey_arr.len() == 65);
        let secp_pubkey_compressed_arr = secp_pubkey.serialize_vec(&secp256k1, true);
        assert!(secp_pubkey_compressed_arr.len() == 33);
        let mut secp_pubkey_a = [0u8; 65];
        for i in 0..65 {
            secp_pubkey_a[i] = secp_pubkey_arr[i];
        }
        let mut secp_pubkey_compressed_a = [0u8; 33];
        for i in 0..33 {
            secp_pubkey_compressed_a[i] = secp_pubkey_compressed_arr[i];
        }
        let secp_pubkey_r: &[u8] = &secp_pubkey_a;
        let secp_pubkey_compressed_r: &[u8] = &secp_pubkey_compressed_a;

        assert_eq!(secp_pubkey_r, pubkey_r);
        assert_eq!(secp_pubkey_compressed_r, pubkey_compressed_r);
    }

    #[test]
    fn test_sign_verify() {
        let secp256k1 = Secp256k1::new();

        let message_arr = [6u8; 32];
        let (secp_privkey, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();

        let secp_message = SecpMessage::from_slice(&message_arr).unwrap();
        let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
        assert!(pubkey_arr.len() == 65);
        let mut pubkey_a = [0u8; 65];
        for i in 0..65 {
            pubkey_a[i] = pubkey_arr[i];
        }
        let pubkey = PublicKey::parse(&pubkey_a).unwrap();
        let mut seckey_a = [0u8; 32];
        for i in 0..32 {
            seckey_a[i] = secp_privkey[i];
        }
        let seckey = SecretKey::parse(&seckey_a).unwrap();
        let message = Message::parse(&message_arr);

        let (sig, recid) = Message::sign(&message, &seckey).unwrap();

        // Self verify
        assert!(Signature::verify(&message, &sig, &pubkey));

        // Self recover
        let recovered_pubkey = Signature::recover(&message, &sig, &recid).unwrap();
        let rpa = recovered_pubkey.serialize();
        let opa = pubkey.serialize();
        let rpr: &[u8] = &rpa;
        let opr: &[u8] = &opa;
        assert_eq!(rpr, opr);

        let signature_a = sig.serialize();
        let secp_recid = SecpRecoveryId::from_i32(recid.into()).unwrap();
        let secp_rec_signature =
            SecpRecoverableSignature::from_compact(&secp256k1, &signature_a, secp_recid).unwrap();
        let secp_signature = SecpSignature::from_compact(&secp256k1, &signature_a).unwrap();

        // External verify
        secp256k1
            .verify(&secp_message, &secp_signature, &secp_pubkey)
            .unwrap();

        // External recover
        let recovered_pubkey = secp256k1
            .recover(&secp_message, &secp_rec_signature)
            .unwrap();
        let rpa = recovered_pubkey.serialize_vec(&secp256k1, false);
        let rpr: &[u8] = &rpa;
        assert_eq!(rpr, opr);
    }

    #[test]
    fn test_failing_sign_verify() {
        let seckey_a: [u8; 32] = [
            169, 195, 92, 103, 2, 159, 75, 46, 158, 79, 249, 49, 208, 28, 48, 210, 5, 47, 136, 77, 21,
            51, 224, 54, 213, 165, 90, 122, 233, 199, 0, 248,
        ];
        let seckey = SecretKey::parse(&seckey_a).unwrap();
        let pubkey = PublicKey::from_secret_key(&seckey);
        let message_arr = [6u8; 32];
        let message = Message::parse(&message_arr);

        let (sig, recid) = Message::sign(&message, &seckey).unwrap();
        let tmp: u8 = recid.into();
        assert_eq!(tmp, 1u8);

        let recovered_pubkey = Signature::recover(&message, &sig, &recid).unwrap();
        let rpa = recovered_pubkey.serialize();
        let opa = pubkey.serialize();
        let rpr: &[u8] = &rpa;
        let opr: &[u8] = &opa;
        assert_eq!(rpr, opr);
    }

    fn genkey(secp256k1: &Secp256k1) -> (key::PublicKey, key::SecretKey, PublicKey, SecretKey) {
        let (secp_privkey, secp_pubkey) = secp256k1.generate_keypair(&mut thread_rng()).unwrap();
        let pubkey_arr = secp_pubkey.serialize_vec(&secp256k1, false);
        assert!(pubkey_arr.len() == 65);
        let mut pubkey_a = [0u8; 65];
        for i in 0..65 {
            pubkey_a[i] = pubkey_arr[i];
        }
        let pubkey = PublicKey::parse(&pubkey_a).unwrap();
        let mut seckey_a = [0u8; 32];
        for i in 0..32 {
            seckey_a[i] = secp_privkey[i];
        }
        let seckey = SecretKey::parse(&seckey_a).unwrap();

        (secp_pubkey, secp_privkey, pubkey, seckey)
    }

    #[test]
    fn test_shared_secret() {
        let secp256k1 = Secp256k1::new();

        let (spub1, ssec1, pub1, sec1) = genkey(&secp256k1);
        let (spub2, ssec2, pub2, sec2) = genkey(&secp256k1);

        let shared1 = SharedSecret::new(&pub1, &sec2).unwrap();
        let shared2 = SharedSecret::new(&pub2, &sec1).unwrap();

        let secp_shared1 = SecpSharedSecret::new(&secp256k1, &spub1, &ssec2);
        let secp_shared2 = SecpSharedSecret::new(&secp256k1, &spub2, &ssec1);

        assert_eq!(shared1, shared2);

        for i in 0..32 {
            assert_eq!(shared1.as_ref()[i], secp_shared1[i]);
        }

        for i in 0..32 {
            assert_eq!(shared2.as_ref()[i], secp_shared2[i]);
        }
    }

}
