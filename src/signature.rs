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
