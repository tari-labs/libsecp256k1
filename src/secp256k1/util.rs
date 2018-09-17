//! Utilities to manipulate the secp256k1 curve parameters.
pub const TAG_PUBKEY_EVEN: u8 = 0x02;
pub const TAG_PUBKEY_ODD: u8 = 0x03;
pub const TAG_PUBKEY_UNCOMPRESSED: u8 = 0x04;
pub const TAG_PUBKEY_HYBRID_EVEN: u8 = 0x06;
pub const TAG_PUBKEY_HYBRID_ODD: u8 = 0x07;

pub use ecmult::{
    odd_multiples_table, ECMULT_TABLE_SIZE_A, ECMULT_TABLE_SIZE_G, WINDOW_A, WINDOW_G,
};
pub use secp256k1::group::{globalz_set_table_gej, set_table_gej_var, AFFINE_INFINITY, JACOBIAN_INFINITY};
