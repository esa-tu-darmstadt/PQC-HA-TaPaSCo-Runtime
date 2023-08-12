use log::trace;

/// A Deterministic "Random" Number Generator
///
/// Rust re-implementation of the weird C Random Number Generator from NIST in `rng.{h,c}` used by
/// `PQCgenKAT.c`
pub struct Drng {
    v: u128, // is V in `rng.c`
    key: [u8; 32],
}

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};

impl Drng {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            v: 0,
            key: [0_u8; 32],
        }
    }

    pub fn randombytes_init(&mut self, seed: &[u8; 48]) {
        // Apply AES-256 ECB Encryption three times with zero as key and 1, 2, 3 respectively as
        // `v`
        let temp: Vec<u8> = (1..=3)
            .map(|v: u128| Self::aes(&[0; 32], v.to_be_bytes()))
            .collect::<Vec<[u8; 16]>>()
            .concat()
            .iter_mut()
            // Then Xor each byte in temp with each byte in seed
            .zip(seed)
            .map(|(t, s)| *t ^ *s)
            .collect();

        trace!("AES_CTR_DRBG_temp = {}", hex::encode_upper(&temp));

        // The first 32 byte form the `key`
        self.key.copy_from_slice(&temp[..32]);
        // The last 16 byte form the `v`
        self.v = u128::from_be_bytes(temp[32..48].try_into().expect("48 - 32 should be 16.."));
    }

    /// Call `randombytes` to get 32 "random" bytes deterministically
    pub fn randombytes(&mut self) -> [u8; 32] {
        // Apply AES-256 ECB Encryption 5 times with the current `key` and increment the current `v`
        // each time
        let temp = (1..=5)
            .map(|i| Self::aes(&self.key, self.v.wrapping_add(i).to_be_bytes()))
            .collect::<Vec<[u8; 16]>>();

        // The first two encrypted blocks are the random data that is returned
        let random: [u8; 32] = temp[..2]
            .concat()
            .try_into()
            .expect("2 * 16 should be 32..");

        // The next two encrypted blocks are used to form the new key
        self.key = temp[2..4]
            .concat()
            .try_into()
            .expect("2 * 16 should be 32..");

        // The last encrypted block is used for the new `v`
        self.v = u128::from_be_bytes(temp[4]);

        trace!("randombytes_x = {}", hex::encode_upper(random));

        random
    }

    // AES-256 ECB Encryption for one block consisting of 16 bytes
    fn aes(key: &[u8; 32], mut plain: [u8; 16]) -> [u8; 16] {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let block = GenericArray::from_mut_slice(&mut plain);

        cipher.encrypt_block(block);

        block
            .as_slice()
            .try_into()
            .expect("When I give you 16 bytes, I want 16 bytes back, please.")
    }
}
