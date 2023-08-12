// Using this implementation needs the environment variable `RUST_MIN_STACK=800000000` defined to
// set the stack size for the large arrays.
//
// See:
// https://docs.rs/pqcrypto-classicmceliece/0.1.7/pqcrypto_classicmceliece/#notes
//
use tapasco::device::Device;

use crate::drng::Drng;
use crate::pqc_algorithm::PqcAlgorithm;

use hex::encode_upper;

use log::info;

use snafu::ResultExt;

use super::{
    ApplyKemResult, ApplyResult, ArgumentLengthSnafu, KeyPair, NotImplementedSnafu, ParseError,
    ParseSnafu, Result, VerifyKemResult, VerifyResult,
};

// Software reference implementation from PQClean:
use pqcrypto_classicmceliece::{
    mceliece348864, mceliece460896, mceliece6688128, mceliece6960119, mceliece8192128,
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret as PQSharedSecret};

// To grow the stack for the software reference implementation:
use stacker;

use devtimer::DevTime;

use crate::{kem_apply_sw, kem_verify_sw};

pub enum SoftwareReference {
    McEliece348864 = 1,
    McEliece460896 = 3,
    McEliece6688128 = 5,
    McEliece6960119 = 6,
    McEliece8192128 = 7,
}

impl PqcAlgorithm for SoftwareReference {
    fn keypair(&self, _: Option<&Device>) -> Result<KeyPair> {
        stacker::grow(800_000_000, || match self {
            Self::McEliece348864 => {
                let (pk, sk) = mceliece348864::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::McEliece460896 => {
                let (pk, sk) = mceliece460896::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::McEliece6688128 => {
                let (pk, sk) = mceliece6688128::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::McEliece6960119 => {
                let (pk, sk) = mceliece6960119::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::McEliece8192128 => {
                let (pk, sk) = mceliece8192128::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
        })
    }

    fn apply(
        &self,
        _: Option<&Device>,
        keypair: Option<&KeyPair>,
        unused: Option<&[u8]>,
    ) -> Result<ApplyResult> {
        if unused.is_some() {
            eprintln!("The `data` parameter is not used by this implementation!");
        }

        stacker::grow(800_000_000, || {
            let (shared_secret, ciphertext) = match self {
                Self::McEliece348864 => {
                    kem_apply_sw! {keypair, "Classic McEliece 1 (348864)", mceliece348864}
                }
                Self::McEliece460896 => {
                    kem_apply_sw! {keypair, "Classic McEliece 3 (460896)", mceliece460896}
                }
                Self::McEliece6688128 => {
                    kem_apply_sw! {keypair, "Classic McEliece 5 (6688128)", mceliece6688128}
                }
                Self::McEliece6960119 => {
                    kem_apply_sw! {keypair, "Classic McEliece 6 (6960119)", mceliece6960119}
                }
                Self::McEliece8192128 => {
                    kem_apply_sw! {keypair, "Classic McEliece 7 (8192128)", mceliece8192128}
                }
            };

            Ok(ApplyResult::ApplyKemResult(ApplyKemResult {
                ciphertext,
                shared_secret,
            }))
        })
    }

    fn verify(
        &self,
        _: Option<&Device>,
        keypair: Option<&KeyPair>,
        ciphertext: Option<&[u8]>,
    ) -> Result<VerifyResult> {
        stacker::grow(800_000_000, || {
            let shared_secret = match self {
                Self::McEliece348864 => {
                    kem_verify_sw! {keypair, ciphertext, "Classic McEliece 1 (348864)", mceliece348864}
                }
                Self::McEliece460896 => {
                    kem_verify_sw! {keypair, ciphertext, "Classic McEliece 3 (460896)", mceliece460896}
                }
                Self::McEliece6688128 => {
                    kem_verify_sw! {keypair, ciphertext, "Classic McEliece 5 (6688128)", mceliece6688128}
                }
                Self::McEliece6960119 => {
                    kem_verify_sw! {keypair, ciphertext, "Classic McEliece 6 (6960119)", mceliece6960119}
                }
                Self::McEliece8192128 => {
                    kem_verify_sw! {keypair, ciphertext, "Classic McEliece 7 (8192128)", mceliece8192128}
                }
            };

            Ok(VerifyResult::VerifyKemResult(VerifyKemResult {
                shared_secret,
            }))
        })
    }

    fn default_kat_filename(&self) -> &str {
        ""
    }

    fn kat_name(&self) -> &str {
        ""
    }

    fn test_kat(
        &self,
        _: Option<&Device>,
        _: &str,
        _: &mut Drng,
        _: bool,
        _: bool,
    ) -> Result<String> {
        //unimplemented!("This software implementation uses randomness that cannot be seeded. Therefore Known Answer Tests are not supported.")
        NotImplementedSnafu {}.fail()
    }
}

impl TryFrom<u8> for SoftwareReference {
    type Error = ParseError;

    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            1 => Ok(Self::McEliece348864),
            3 => Ok(Self::McEliece460896),
            5 => Ok(Self::McEliece6688128),
            6 => Ok(Self::McEliece6960119),
            7 => Ok(Self::McEliece8192128),
            value => ParseSnafu {
                value,
                name: "Classic McEliece",
                possible_values: vec![1, 3, 5, 6, 7],
            }
            .fail(),
        }
    }
}
