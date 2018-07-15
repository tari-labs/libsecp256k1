use scalar::Scalar;
use { Message, PublicKey, SecretKey, RecoveryId, Error};
use hmac_drbg::HmacDRBG;
use typenum::U32;
use sha2::Sha256;
use ecmult::{ ECMULT_CONTEXT, ECMULT_GEN_CONTEXT};

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

/// Sign a message using the secret key.
pub fn sign(message: &Message, seckey: &SecretKey) -> Result<(Signature, RecoveryId), Error> {
    let seckey_b32 = seckey.0.b32();
    let message_b32 = message.0.b32();

    let mut drbg = HmacDRBG::<Sha256>::new(&seckey_b32, &message_b32, &[]);
    let generated = drbg.generate::<U32>(None);
    let mut nonce = Scalar::default();
    let mut overflow = nonce.set_b32(array_ref!(generated, 0, 32));

    while overflow || nonce.is_zero() {
        let generated = drbg.generate::<U32>(None);
        overflow = nonce.set_b32(array_ref!(generated, 0, 32));
    }

    let result = ECMULT_GEN_CONTEXT.sign_raw(&seckey.0, &message.0, &nonce);
    #[allow(unused_assignments)]
        {
            nonce = Scalar::default();
        }
    if let Ok((sigr, sigs, recid)) = result {
        return Ok((Signature { r: sigr, s: sigs }, RecoveryId(recid)));
    } else {
        return Err(result.err().unwrap());
    }
}
