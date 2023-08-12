use tapasco::device::Device;

use crate::drng::Drng;
use crate::pqc_algorithm::PqcAlgorithm;

use hex::encode_upper;

use log::info;

use rand::prelude::*;

use snafu::ResultExt;

use super::{
    ApplyDsaResult, ApplyResult, ArgumentLengthSnafu, KeyPair, NotImplementedSnafu, ParseError,
    ParseSnafu, Result, VerifyDsaResult, VerifyResult,
};

// Software reference implementation from PQClean:
use pqcrypto_sphincsplus::{
    sphincssha256128frobust, sphincssha256192frobust, sphincssha256256frobust,
};
use pqcrypto_sphincsplus::{
    sphincsshake256128frobust, sphincsshake256192frobust, sphincsshake256256frobust,
};
//use pqcrypto_sphincsplus::{sphincsharaka128frobust, sphincsharaka192frobust, sphincsharaka256frobust};
use pqcrypto_sphincsplus::{
    sphincssha256128fsimple, sphincssha256192fsimple, sphincssha256256fsimple,
};
use pqcrypto_sphincsplus::{
    sphincsshake256128fsimple, sphincsshake256192fsimple, sphincsshake256256fsimple,
};
//use pqcrypto_sphincsplus::{sphincsharaka128fsimple, sphincsharaka192fsimple, sphincsharaka256fsimple};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

use devtimer::DevTime;

use crate::{dsa_apply_sw, dsa_verify_sw};

macro_rules! sphincs_implementation {
    (
        $impl_name: ident,
        $light_module: ident,
        $recommended_module: ident,
        $paranoid_module: ident
    ) => {
        pub enum $impl_name {
            Light = 1,
            Recommended = 3,
            Paranoid = 5,
        }

        impl PqcAlgorithm for $impl_name {
            fn keypair(&self, _: Option<&Device>) -> Result<KeyPair> {
                match self {
                    Self::Light => {
                        let (pk, sk) = $light_module::keypair();

                        Ok(KeyPair {
                            secret_key: sk.as_bytes().to_owned(),
                            public_key: pk.as_bytes().to_owned(),
                        })
                    }
                    Self::Recommended => {
                        let (pk, sk) = $recommended_module::keypair();

                        Ok(KeyPair {
                            secret_key: sk.as_bytes().to_owned(),
                            public_key: pk.as_bytes().to_owned(),
                        })
                    }
                    Self::Paranoid => {
                        let (pk, sk) = $paranoid_module::keypair();

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
                message: Option<&[u8]>,
            ) -> Result<ApplyResult> {
                // If we don't get a message via CLI, generate a random message
                let message = message.map_or_else(
                    || {
                        let mut random = [0_u8; 64];
                        thread_rng().fill(&mut random);
                        random.to_vec()
                    },
                    <[u8]>::to_vec,
                );

                info!(
                    "Message (lossy utf-8): {}",
                    String::from_utf8_lossy(&message)
                );
                info!("Message (hex-encoded): {}", encode_upper(&message));

                let signed_message = match self {
                    Self::Light => {
                        dsa_apply_sw! {keypair, message, "SPHINCS+ 1", $light_module}
                    }
                    Self::Recommended => {
                        dsa_apply_sw! {keypair, message, "SPHINCS+ 3", $recommended_module}
                    }
                    Self::Paranoid => {
                        dsa_apply_sw! {keypair, message, "SPHINCS+ 5", $paranoid_module}
                    }
                };

                Ok(ApplyResult::ApplyDsaResult(ApplyDsaResult {
                    signed_message,
                }))
            }

            fn verify(
                &self,
                _: Option<&Device>,
                keypair: Option<&KeyPair>,
                signed_message: Option<&[u8]>,
            ) -> Result<VerifyResult> {
                // Own Option of byte slice to an Option of byte Vector to satisfy the borrow checker
                let signed_message = signed_message.map(<[u8]>::to_vec);

                // If we don't get a message via CLI, generate a random signed message
                let mut random = [0_u8; 64];
                if signed_message.is_none() {
                    thread_rng().fill(&mut random);
                }

                let verified_message = match self {
                    Self::Light => {
                        dsa_verify_sw! {keypair, signed_message, random, "SPHINCS+ 1", $light_module}
                    }
                    Self::Recommended => {
                        dsa_verify_sw! {keypair, signed_message, random, "SPHINCS+ 3", $recommended_module}
                    }
                    Self::Paranoid => {
                        dsa_verify_sw! {keypair, signed_message, random, "SPHINCS+ 5", $paranoid_module}
                    }
                };

                Ok(VerifyResult::VerifyDsaResult(VerifyDsaResult {
                    message: verified_message,
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

        impl TryFrom<u8> for $impl_name {
            type Error = ParseError;

            fn try_from(other: u8) -> Result<Self, Self::Error> {
                match other {
                    1 => Ok(Self::Light),
                    3 => Ok(Self::Recommended),
                    5 => Ok(Self::Paranoid),
                    value => ParseSnafu {
                        value,
                        name: "SPHINCS+",
                        possible_values: vec![1, 3, 5],
                    }
                    .fail(),
                }
            }
        }
    };
}

// Generate implementations for the different SPHINCS+ parameter sets:
sphincs_implementation! { SoftwareSphincsShakeRobust, sphincsshake256128frobust, sphincsshake256192frobust, sphincsshake256256frobust }

sphincs_implementation! { SoftwareSphincsShaRobust, sphincssha256128frobust, sphincssha256192frobust, sphincssha256256frobust }

//sphincs_implementation! { SoftwareSphincsHarakaRobust, sphincsharaka128frobust, sphincsharaka192frobust, sphincsharaka256frobust }

sphincs_implementation! { SoftwareSphincsShakeSimple, sphincsshake256128fsimple, sphincsshake256192fsimple, sphincsshake256256fsimple }

sphincs_implementation! { SoftwareSphincsShaSimple, sphincssha256128fsimple, sphincssha256192fsimple, sphincssha256256fsimple }

//sphincs_implementation! { SoftwareSphincsHarakaSimple, sphincsharaka128fsimple, sphincsharaka192fsimple, sphincsharaka256fsimple }
