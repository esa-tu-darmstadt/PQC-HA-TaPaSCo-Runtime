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
use pqcrypto_hqc::{hqcrmrs128, hqcrmrs192, hqcrmrs256};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret as PQSharedSecret};

use devtimer::DevTime;

use crate::{kem_apply_sw, kem_verify_sw};

pub enum SoftwareReference {
    Light = 1,
    Recommended = 3,
    Paranoid = 5,
}

impl PqcAlgorithm for SoftwareReference {
    fn keypair(&self, _: Option<&Device>) -> Result<KeyPair> {
        match self {
            Self::Light => {
                let (pk, sk) = hqcrmrs128::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::Recommended => {
                let (pk, sk) = hqcrmrs192::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::Paranoid => {
                let (pk, sk) = hqcrmrs256::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
        }
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

        let (shared_secret, ciphertext) = match self {
            Self::Light => {
                kem_apply_sw! {keypair, "HQC 1", hqcrmrs128}
            }
            Self::Recommended => {
                kem_apply_sw! {keypair, "HQC 3", hqcrmrs192}
            }
            Self::Paranoid => {
                kem_apply_sw! {keypair, "HQC 5", hqcrmrs256}
            }
        };

        Ok(ApplyResult::ApplyKemResult(ApplyKemResult {
            ciphertext,
            shared_secret,
        }))
    }

    fn verify(
        &self,
        _: Option<&Device>,
        keypair: Option<&KeyPair>,
        ciphertext: Option<&[u8]>,
    ) -> Result<VerifyResult> {
        let shared_secret = match self {
            Self::Light => {
                kem_verify_sw! {keypair, ciphertext, "HQC 1", hqcrmrs128}
            }
            Self::Recommended => {
                kem_verify_sw! {keypair, ciphertext, "HQC 3", hqcrmrs192}
            }
            Self::Paranoid => {
                kem_verify_sw! {keypair, ciphertext, "HQC 5", hqcrmrs256}
            }
        };

        Ok(VerifyResult::VerifyKemResult(VerifyKemResult {
            shared_secret,
        }))
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
            1 => Ok(Self::Light),
            3 => Ok(Self::Recommended),
            5 => Ok(Self::Paranoid),
            value => ParseSnafu {
                value,
                name: "HQC",
                possible_values: vec![1, 3, 5],
            }
            .fail(),
        }
    }
}
