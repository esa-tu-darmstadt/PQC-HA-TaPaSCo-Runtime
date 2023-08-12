use tapasco::device::Device;

use crate::drng::Drng;
use crate::pqc_algorithm::{DsaTestCases, PqcAlgorithm};
use crate::tapasco_pqc::{dsa_sign, dsa_test, dsa_verify};

use hex::encode_upper;

use log::info;

use rand::prelude::*;

use snafu::{OptionExt, ResultExt};

use super::{
    ApplyDsaResult, ApplyResult, ArgumentLengthSnafu, ImplementationNeedsTapascoSnafu,
    KatParseSnafu, KeyPair, NotImplementedSnafu, ParseError, ParseSnafu, Result, TapascoSnafu,
    VerifyDsaResult, VerifyResult,
};

// Software reference implementation from PQClean:
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{PublicKey, SecretKey, SignedMessage};

/// The Security Levels for CRYSTALS Dilithium NIST PQC Round 3, Values: Light (2), Recommended (3),
/// Paranoid (5).
#[derive(Debug)]
pub enum Dilithium {
    Light(&'static str, &'static str),
    Recommended(&'static str, &'static str),
    Paranoid(&'static str, &'static str),
}

#[macro_export]
macro_rules! dsa_apply_tapasco {
    (
        $keypair: ident,
        $device: ident,
        $pe_name_sign: ident,
        $message: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        let sk: [u8; $algorithm_module::secret_key_bytes()] = if let Some(keypair) = $keypair {
            keypair
                .secret_key
                .as_slice()
                .try_into()
                .context(ArgumentLengthSnafu {
                    what: "Secret Key",
                    algorithm: $algorithm_name,
                    expected_length: $algorithm_module::secret_key_bytes() as u32,
                })?
        } else {
            let (pk, sk) = $algorithm_module::keypair();

            info!("Public Key: {}", encode_upper(pk.as_bytes()));

            sk.as_bytes().try_into().unwrap()
        };

        info!("Secret Key: {}", encode_upper(sk));

        dsa_sign::<
            { $algorithm_module::signature_bytes() },
            { $algorithm_module::secret_key_bytes() },
        >($device, $pe_name_sign, &sk, &$message)
        .context(TapascoSnafu {})?
        .to_vec()
    };
}

#[macro_export]
macro_rules! dsa_verify_tapasco {
    (
        $keypair: ident,
        $device: ident,
        $pe_name_verify: ident,
        $signed_message: ident,
        $random: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        let (pk, sk): (
            [u8; $algorithm_module::public_key_bytes()],
            $algorithm_module::SecretKey,
        ) = if let Some(keypair) = $keypair {
            let pk = keypair
                .public_key
                .as_slice()
                .try_into()
                .context(ArgumentLengthSnafu {
                    what: "Public Key",
                    algorithm: $algorithm_name,
                    expected_length: $algorithm_module::public_key_bytes() as u32,
                })?;

            let sk = $algorithm_module::SecretKey::from_bytes(
                &[0_u8; $algorithm_module::secret_key_bytes()],
            )
            .unwrap();

            (pk, sk)
        } else {
            let (pk, sk) = $algorithm_module::keypair();

            info!("Secret Key: {}", encode_upper(sk.as_bytes()));

            (pk.as_bytes().try_into().unwrap(), sk)
        };

        info!("Public Key: {}", encode_upper(pk));

        let signed_message = $signed_message.map_or_else(
            || $algorithm_module::sign(&$random, &sk).as_bytes().to_owned(),
            |s| s.to_owned(),
        );

        info!(
            "Signed Message (lossy utf-8): {}",
            String::from_utf8_lossy(&signed_message)
        );
        info!(
            "Signed Message (hex-encoded): {}",
            encode_upper(&signed_message)
        );

        dsa_verify::<
            { $algorithm_module::signature_bytes() },
            { $algorithm_module::public_key_bytes() },
        >($device, $pe_name_verify, &pk, &signed_message)
        .context(TapascoSnafu {})?
        .to_vec()
    };
}

impl PqcAlgorithm for Dilithium {
    fn keypair(&self, _: Option<&Device>) -> Result<KeyPair> {
        //unimplemented!("This implementation does not support key generation.")
        NotImplementedSnafu {}.fail()
    }

    fn apply(
        &self,
        device: Option<&Device>,
        keypair: Option<&KeyPair>,
        message: Option<&[u8]>,
    ) -> Result<ApplyResult> {
        // Check if we got a TaPaSCo device
        let device = &device.context(ImplementationNeedsTapascoSnafu {})?;

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
            Self::Light(pe_name_sign, _) => {
                dsa_apply_tapasco! {keypair, device, pe_name_sign, message, "Dilithium 2", dilithium2}
            }
            Self::Recommended(pe_name_sign, _) => {
                dsa_apply_tapasco! {keypair, device, pe_name_sign, message, "Dilithium 3", dilithium3}
            }
            Self::Paranoid(pe_name_sign, _) => {
                dsa_apply_tapasco! {keypair, device, pe_name_sign, message, "Dilithium 5", dilithium5}
            }
        };

        //Ok(format!("Signed Message: {}", encode_upper(signed_message)))
        Ok(ApplyResult::ApplyDsaResult(ApplyDsaResult {
            signed_message,
        }))
    }

    fn verify(
        &self,
        device: Option<&Device>,
        keypair: Option<&KeyPair>,
        signed_message: Option<&[u8]>,
    ) -> Result<VerifyResult> {
        // Check if we got a TaPaSCo device
        let device = &device.context(ImplementationNeedsTapascoSnafu {})?;

        // If we don't get a message via CLI, generate a random signed message
        let mut random = [0_u8; 64];
        if signed_message.is_none() {
            thread_rng().fill(&mut random);
        }

        let verified_message = match self {
            Self::Light(_, pe_name_verify) => {
                dsa_verify_tapasco! {keypair, device, pe_name_verify, signed_message, random, "Dilithium 2", dilithium2}
            }
            Self::Recommended(_, pe_name_verify) => {
                dsa_verify_tapasco! {keypair, device, pe_name_verify, signed_message, random, "Dilithium 3", dilithium3}
            }
            Self::Paranoid(_, pe_name_verify) => {
                dsa_verify_tapasco! {keypair, device, pe_name_verify, signed_message, random, "Dilithium 5", dilithium5}
            }
        };

        Ok(VerifyResult::VerifyDsaResult(VerifyDsaResult {
            message: verified_message,
        }))
    }

    fn default_kat_filename(&self) -> &str {
        match self {
            Self::Light(..) => "PQCsignKAT_Dilithium2.rsp",
            Self::Recommended(..) => "PQCsignKAT_Dilithium3.rsp",
            Self::Paranoid(..) => "PQCsignKAT_Dilithium5.rsp",
        }
    }

    fn kat_name(&self) -> &str {
        match self {
            Self::Light(..) => "Dilithium2",
            Self::Recommended(..) => "Dilithium3",
            Self::Paranoid(..) => "Dilithium5",
        }
    }

    fn test_kat(
        &self,
        device: Option<&Device>,
        kat: &str,
        _: &mut Drng,
        test_sign: bool,
        test_verify: bool,
    ) -> Result<String> {
        // Check if we got a TaPaSCo device
        let device = &device.context(ImplementationNeedsTapascoSnafu {})?;

        let test_results = match self {
            Self::Light(pe_name_sign, pe_name_verify) => dsa_test::<
                { dilithium2::signature_bytes() },
                { dilithium2::public_key_bytes() },
                { dilithium2::secret_key_bytes() },
            >(
                device,
                pe_name_sign,
                pe_name_verify,
                &kat.parse::<DsaTestCases<
                    { dilithium2::public_key_bytes() },
                    { dilithium2::secret_key_bytes() },
                >>()
                .context(KatParseSnafu {})?
                .0,
                test_sign,
                test_verify,
            ),
            Self::Recommended(pe_name_sign, pe_name_verify) => dsa_test::<
                { dilithium3::signature_bytes() },
                { dilithium3::public_key_bytes() },
                { dilithium3::secret_key_bytes() },
            >(
                device,
                pe_name_sign,
                pe_name_verify,
                &kat.parse::<DsaTestCases<
                    { dilithium3::public_key_bytes() },
                    { dilithium3::secret_key_bytes() },
                >>()
                .context(KatParseSnafu {})?
                .0,
                test_sign,
                test_verify,
            ),
            Self::Paranoid(pe_name_sign, pe_name_verify) => dsa_test::<
                { dilithium5::signature_bytes() },
                { dilithium5::public_key_bytes() },
                { dilithium5::secret_key_bytes() },
            >(
                device,
                pe_name_sign,
                pe_name_verify,
                &kat.parse::<DsaTestCases<
                    { dilithium5::public_key_bytes() },
                    { dilithium5::secret_key_bytes() },
                >>()
                .context(KatParseSnafu {})?
                .0,
                test_sign,
                test_verify,
            ),
        };

        Ok(test_results)
    }
}

impl TryFrom<u8> for Dilithium {
    type Error = ParseError;

    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            2 => Ok(Self::Light(
                "esa.cs.tu-darmstadt.de:hls:dilithium2_sign:0.2",
                "esa.cs.tu-darmstadt.de:hls:dilithium2_verify:0.2",
            )),
            3 => Ok(Self::Recommended(
                "esa.cs.tu-darmstadt.de:hls:dilithium3_sign:0.2",
                "esa.cs.tu-darmstadt.de:hls:dilithium3_verify:0.2",
            )),
            5 => Ok(Self::Paranoid(
                "esa.cs.tu-darmstadt.de:hls:dilithium5_sign:0.2",
                "esa.cs.tu-darmstadt.de:hls:dilithium5_verify:0.2",
            )),
            value => ParseSnafu {
                value,
                name: "Dilithium",
                possible_values: vec![2, 3, 5],
            }
            .fail(),
        }
    }
}

use devtimer::DevTime;

pub enum SoftwareReference {
    Light = 2,
    Recommended = 3,
    Paranoid = 5,
}

#[macro_export]
macro_rules! dsa_apply_sw {
    (
        $keypair: ident,
        $message: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        let sk: $algorithm_module::SecretKey = if let Some(keypair) = $keypair {
            let sk: [u8; $algorithm_module::secret_key_bytes()] = keypair
                .secret_key
                .as_slice()
                .try_into()
                .context(ArgumentLengthSnafu {
                    what: "Secret Key",
                    algorithm: $algorithm_name,
                    expected_length: $algorithm_module::secret_key_bytes() as u32,
                })?;

            $algorithm_module::SecretKey::from_bytes(&sk).unwrap()
        } else {
            let (pk, sk) = $algorithm_module::keypair();

            info!("Public Key: {}", encode_upper(pk.as_bytes()));

            sk
        };

        info!("Secret Key: {}", encode_upper(sk.as_bytes()));

        let mut timer = DevTime::new_simple();

        timer.start();
        let sm = $algorithm_module::sign(&$message, &sk);
        timer.stop();

        info!(
            "Performance: Software:   {:9} ns",
            timer.time_in_nanos().unwrap()
        );

        sm.as_bytes().to_vec()
    };
}

#[macro_export]
macro_rules! dsa_verify_sw {
    (
        $keypair: ident,
        $signed_message: ident,
        $random: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        let (pk, sk): ($algorithm_module::PublicKey, $algorithm_module::SecretKey) =
            if let Some(keypair) = $keypair {
                let pk: [u8; $algorithm_module::public_key_bytes()] = keypair
                    .public_key
                    .as_slice()
                    .try_into()
                    .context(ArgumentLengthSnafu {
                        what: "Public Key",
                        algorithm: $algorithm_name,
                        expected_length: $algorithm_module::public_key_bytes() as u32,
                    })?;

                let pk = $algorithm_module::PublicKey::from_bytes(&pk).unwrap();
                let sk = $algorithm_module::SecretKey::from_bytes(
                    &[0_u8; $algorithm_module::secret_key_bytes()],
                )
                .unwrap();

                (pk, sk)
            } else {
                let (pk, sk) = $algorithm_module::keypair();

                info!("Secret Key: {}", encode_upper(sk.as_bytes()));

                (pk, sk)
            };

        info!("Public Key: {}", encode_upper(pk.as_bytes()));

        let signed_message = $signed_message.map_or_else(
            || $algorithm_module::sign(&$random, &sk),
            |s| $algorithm_module::SignedMessage::from_bytes(&s).unwrap(),
        );

        info!(
            "Signed Message (lossy utf-8): {}",
            String::from_utf8_lossy(signed_message.as_bytes())
        );
        info!(
            "Signed Message (hex-encoded): {}",
            encode_upper(signed_message.as_bytes())
        );

        let mut timer = DevTime::new_simple();

        timer.start();
        let verified_message = $algorithm_module::open(&signed_message, &pk).unwrap();
        timer.stop();

        info!(
            "Performance: Software:   {:9} ns",
            timer.time_in_nanos().unwrap()
        );

        verified_message.to_vec()
    };
}

impl PqcAlgorithm for SoftwareReference {
    fn keypair(&self, _: Option<&Device>) -> Result<KeyPair> {
        match self {
            Self::Light => {
                let (pk, sk) = dilithium2::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::Recommended => {
                let (pk, sk) = dilithium3::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::Paranoid => {
                let (pk, sk) = dilithium5::keypair();

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
                dsa_apply_sw! {keypair, message, "Dilithium 2", dilithium2}
            }
            Self::Recommended => {
                dsa_apply_sw! {keypair, message, "Dilithium 3", dilithium3}
            }
            Self::Paranoid => {
                dsa_apply_sw! {keypair, message, "Dilithium 5", dilithium5}
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
                dsa_verify_sw! {keypair, signed_message, random, "Dilithium 2", dilithium2}
            }
            Self::Recommended => {
                dsa_verify_sw! {keypair, signed_message, random, "Dilithium 3", dilithium3}
            }
            Self::Paranoid => {
                dsa_verify_sw! {keypair, signed_message, random, "Dilithium 5", dilithium5}
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

impl TryFrom<u8> for SoftwareReference {
    type Error = ParseError;

    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            2 => Ok(Self::Light),
            3 => Ok(Self::Recommended),
            5 => Ok(Self::Paranoid),
            value => ParseSnafu {
                value,
                name: "Dilithium",
                possible_values: vec![2, 3, 5],
            }
            .fail(),
        }
    }
}
