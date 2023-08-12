use tapasco::device::Device;

use crate::drng::Drng;
use crate::pqc_algorithm::{KemTestCases, PqcAlgorithm};
use crate::tapasco_pqc::{kem_dec, kem_enc, kem_test};

use hex::{encode_upper, FromHex};

use log::info;

use rand::prelude::*;

use snafu::{OptionExt, ResultExt};

use super::{
    ApplyKemResult, ApplyResult, ArgumentLengthSnafu, ImplementationNeedsTapascoSnafu,
    KatParseSnafu, KeyPair, NotImplementedSnafu, ParseError, ParseHexSnafu, ParseSnafu, Result,
    TapascoSnafu, VerifyKemResult, VerifyResult,
};

// Software reference implementation from PQClean:
use pqcrypto_kyber::{kyber1024, kyber512, kyber768};
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret as PQSharedSecret};

/// The Security Levels for CRYSTALS Kyber NIST PQC Round 3, Values: Light (1), Recommended (3),
/// Paranoid (5).
#[derive(Debug)]
pub enum Kyber {
    Light(&'static str, &'static str),
    Recommended(&'static str, &'static str),
    Paranoid(&'static str, &'static str),
}

#[macro_export]
macro_rules! kem_apply_tapasco {
    (
        $keypair: ident,
        $device: ident,
        $pe_name_enc: ident,
        $random_buffer: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        // Generate a keypair if we don't receive a public key over the command line
        let pk: [u8; $algorithm_module::public_key_bytes()] = if let Some(keypair) = $keypair {
            keypair
                .public_key
                .as_slice()
                .try_into()
                .context(ArgumentLengthSnafu {
                    what: "Public Key",
                    algorithm: $algorithm_name,
                    expected_length: $algorithm_module::public_key_bytes() as u32,
                })?
        } else {
            let (pk, sk) = $algorithm_module::keypair();
            //let (pk, sk) = $algorithm_module;

            info!("Secret Key: {}", encode_upper(sk.as_bytes()));

            pk.as_bytes().try_into().unwrap()
        };

        info!("Public Key: {}", encode_upper(pk));

        let (shared_secret, ciphertext) = kem_enc::<
            { $algorithm_module::ciphertext_bytes() },
            { $algorithm_module::public_key_bytes() },
        >($device, $pe_name_enc, &pk, &$random_buffer)
        .context(TapascoSnafu {})?;

        (shared_secret.to_vec(), ciphertext.to_vec())
    };
}

#[macro_export]
macro_rules! kem_verify_tapasco {
    (
        $keypair: ident,
        $device: ident,
        $pe_name_dec: ident,
        $ciphertext: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        let (sk, pk): (
            [u8; $algorithm_module::secret_key_bytes()],
            $algorithm_module::PublicKey,
        ) = if let Some(keypair) = $keypair {
            let sk: [u8; $algorithm_module::secret_key_bytes()] = keypair
                .secret_key
                .as_slice()
                .try_into()
                .context(ArgumentLengthSnafu {
                    what: "Secret Key",
                    algorithm: $algorithm_name,
                    expected_length: $algorithm_module::secret_key_bytes() as u32,
                })?;

            let pk = $algorithm_module::PublicKey::from_bytes(
                &[0_u8; $algorithm_module::public_key_bytes()],
            )
            .unwrap();

            (sk, pk)
        } else {
            let (pk, sk) = $algorithm_module::keypair();

            info!("Public Key: {}", encode_upper(pk.as_bytes()));

            (sk.as_bytes().try_into().unwrap(), pk)
        };

        info!("Secret Key: {}", encode_upper(sk));

        let ct: [u8; $algorithm_module::ciphertext_bytes()] = if let Some(ct) = $ciphertext {
            ct.try_into().context(ArgumentLengthSnafu {
                what: "Ciphertext",
                algorithm: $algorithm_name,
                expected_length: $algorithm_module::ciphertext_bytes() as u32,
            })?
        } else {
            let (_, ct) = $algorithm_module::encapsulate(&pk);
            ct.as_bytes().try_into().unwrap()
        };

        info!("Ciphertext: {}", encode_upper(ct));

        kem_dec($device, $pe_name_dec, &ct, &sk)
            .context(TapascoSnafu {})?
            .to_vec()
    };
}

impl PqcAlgorithm for Kyber {
    fn keypair(&self, _: Option<&Device>) -> Result<KeyPair> {
        //unimplemented!("This implementation does not support key generation.")
        NotImplementedSnafu {}.fail()
    }

    fn apply(
        &self,
        device: Option<&Device>,
        keypair: Option<&KeyPair>,
        random_buffer: Option<&[u8]>,
    ) -> Result<ApplyResult> {
        // Check if we got a TaPaSCo device
        let device = &device.context(ImplementationNeedsTapascoSnafu {})?;

        // If we don't get a message via CLI, generate a random message
        let random_buffer: [u8; 64] = if let Some(r) = random_buffer {
            <[u8; 64]>::from_hex(r).context(ParseHexSnafu {})?
        } else {
            let mut random = [0_u8; 64];
            thread_rng().fill(&mut random);
            random
        };

        info!(
            "Random Buffer (hex-encoded): {}",
            encode_upper(random_buffer)
        );

        let (shared_secret, ciphertext) = match self {
            Self::Light(pe_name_enc, _) => {
                kem_apply_tapasco! {keypair, device, pe_name_enc, random_buffer, "Kyber 1", kyber512}
            }
            Self::Recommended(pe_name_enc, _) => {
                kem_apply_tapasco! {keypair, device, pe_name_enc, random_buffer, "Kyber 3", kyber768}
            }
            Self::Paranoid(pe_name_enc, _) => {
                kem_apply_tapasco! {keypair, device, pe_name_enc, random_buffer, "Kyber 5", kyber1024}
            }
        };

        Ok(ApplyResult::ApplyKemResult(ApplyKemResult {
            ciphertext,
            shared_secret,
        }))
    }

    fn verify(
        &self,
        device: Option<&Device>,
        keypair: Option<&KeyPair>,
        ciphertext: Option<&[u8]>,
    ) -> Result<VerifyResult> {
        // Check if we got a TaPaSCo device
        let device = &device.context(ImplementationNeedsTapascoSnafu {})?;

        let shared_secret = match self {
            Self::Light(_, pe_name_dec) => {
                kem_verify_tapasco! {keypair, device, pe_name_dec, ciphertext, "Kyber 1", kyber512}
            }
            Self::Recommended(_, pe_name_dec) => {
                kem_verify_tapasco! {keypair, device, pe_name_dec, ciphertext, "Kyber 3", kyber768}
            }
            Self::Paranoid(_, pe_name_dec) => {
                kem_verify_tapasco! {keypair, device, pe_name_dec, ciphertext, "Kyber 5", kyber1024}
            }
        };
        //.context(TapascoSnafu {})?;

        //Ok(format!("Shared Secret: {}", encode_upper(shared_secret)))
        Ok(VerifyResult::VerifyKemResult(VerifyKemResult {
            shared_secret,
        }))
    }

    fn default_kat_filename(&self) -> &str {
        match self {
            Self::Light(..) => "PQCkemKAT_1632.rsp",
            Self::Recommended(..) => "PQCkemKAT_2400.rsp",
            Self::Paranoid(..) => "PQCkemKAT_3168.rsp",
        }
    }

    fn kat_name(&self) -> &str {
        match self {
            Self::Light(..) => "Kyber512",
            Self::Recommended(..) => "Kyber768",
            Self::Paranoid(..) => "Kyber1024",
        }
    }

    fn test_kat(
        &self,
        device: Option<&Device>,
        kat: &str,
        drng: &mut Drng,
        test_encapsulation: bool,
        test_decapsulation: bool,
    ) -> Result<String> {
        // Check if we got a TaPaSCo device
        let device = &device.context(ImplementationNeedsTapascoSnafu {})?;

        let test_results = match self {
            Self::Light(pe_name_enc, pe_name_dec) => kem_test(
                device,
                pe_name_enc,
                pe_name_dec,
                &kat.parse::<KemTestCases<
                    { kyber512::ciphertext_bytes() },
                    { kyber512::public_key_bytes() },
                    { kyber512::secret_key_bytes() },
                >>()
                .context(KatParseSnafu {})?
                .0,
                drng,
                test_encapsulation,
                test_decapsulation,
            ),
            Self::Recommended(pe_name_enc, pe_name_dec) => kem_test(
                device,
                pe_name_enc,
                pe_name_dec,
                &kat.parse::<KemTestCases<
                    { kyber768::ciphertext_bytes() },
                    { kyber768::public_key_bytes() },
                    { kyber768::secret_key_bytes() },
                >>()
                .context(KatParseSnafu {})?
                .0,
                drng,
                test_encapsulation,
                test_decapsulation,
            ),
            Self::Paranoid(pe_name_enc, pe_name_dec) => kem_test(
                device,
                pe_name_enc,
                pe_name_dec,
                &kat.parse::<KemTestCases<
                    { kyber1024::ciphertext_bytes() },
                    { kyber1024::public_key_bytes() },
                    { kyber1024::secret_key_bytes() },
                >>()
                .context(KatParseSnafu {})?
                .0,
                drng,
                test_encapsulation,
                test_decapsulation,
            ),
        };

        Ok(test_results)
    }
}

impl TryFrom<u8> for Kyber {
    type Error = ParseError;

    fn try_from(other: u8) -> Result<Self, Self::Error> {
        match other {
            1 => Ok(Self::Light(
                "esa.cs.tu-darmstadt.de:hls:kyber2_enc:0.2",
                "esa.cs.tu-darmstadt.de:hls:kyber2_dec:0.2",
            )),
            3 => Ok(Self::Recommended(
                "esa.cs.tu-darmstadt.de:hls:kyber3_enc:0.2",
                "esa.cs.tu-darmstadt.de:hls:kyber3_dec:0.2",
            )),
            5 => Ok(Self::Paranoid(
                "esa.cs.tu-darmstadt.de:hls:kyber4_enc:0.2",
                "esa.cs.tu-darmstadt.de:hls:kyber4_dec:0.2",
            )),
            value => ParseSnafu {
                value,
                name: "Kyber",
                possible_values: vec![1, 3, 5],
            }
            .fail(),
        }
    }
}

use devtimer::DevTime;

pub enum SoftwareReference {
    Light = 1,
    Recommended = 3,
    Paranoid = 5,
}

#[macro_export]
macro_rules! kem_apply_sw {
    (
        $keypair: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        // Generate a keypair if we don't receive a public key over the command line
        let pk: $algorithm_module::PublicKey = if let Some(keypair) = $keypair {
            let pk: [u8; $algorithm_module::public_key_bytes()] = keypair
                .public_key
                .as_slice()
                .try_into()
                .context(ArgumentLengthSnafu {
                    what: "Public Key",
                    algorithm: $algorithm_name,
                    expected_length: $algorithm_module::public_key_bytes() as u32,
                })?;

            $algorithm_module::PublicKey::from_bytes(&pk).unwrap()
        } else {
            let (pk, sk) = $algorithm_module::keypair();

            info!("Secret Key: {}", encode_upper(sk.as_bytes()));

            pk
        };

        info!("Public Key: {}", encode_upper(pk.as_bytes()));

        let mut timer = DevTime::new_simple();

        timer.start();
        let (ss, ct) = $algorithm_module::encapsulate(&pk);
        timer.stop();

        info!(
            "Performance: Software:   {:9} ns",
            timer.time_in_nanos().unwrap()
        );

        (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
    };
}

#[macro_export]
macro_rules! kem_verify_sw {
    (
        $keypair: ident,
        $ciphertext: ident,
        $algorithm_name: expr,
        $algorithm_module: ident
        ) => {
        let (sk, pk): ($algorithm_module::SecretKey, $algorithm_module::PublicKey) =
            if let Some(keypair) = $keypair {
                let sk: [u8; $algorithm_module::secret_key_bytes()] = keypair
                    .secret_key
                    .as_slice()
                    .try_into()
                    .context(ArgumentLengthSnafu {
                        what: "Secret Key",
                        algorithm: $algorithm_name,
                        expected_length: $algorithm_module::secret_key_bytes() as u32,
                    })?;

                let sk = $algorithm_module::SecretKey::from_bytes(&sk).unwrap();
                let pk = $algorithm_module::PublicKey::from_bytes(
                    &[0_u8; $algorithm_module::public_key_bytes()],
                )
                .unwrap();

                (sk, pk)
            } else {
                let (pk, sk) = $algorithm_module::keypair();

                info!("Public Key: {}", encode_upper(pk.as_bytes()));

                (sk, pk)
            };

        info!("Secret Key: {}", encode_upper(sk.as_bytes()));

        let ct: $algorithm_module::Ciphertext = if let Some(ct) = $ciphertext {
            let ct: [u8; $algorithm_module::ciphertext_bytes()] =
                ct.try_into().context(ArgumentLengthSnafu {
                    what: "Ciphertext",
                    algorithm: $algorithm_name,
                    expected_length: $algorithm_module::ciphertext_bytes() as u32,
                })?;

            $algorithm_module::Ciphertext::from_bytes(&ct).unwrap()
        } else {
            let (_, ct) = $algorithm_module::encapsulate(&pk);
            ct
        };

        info!("Ciphertext: {}", encode_upper(ct.as_bytes()));

        let mut timer = DevTime::new_simple();

        timer.start();
        let ss = $algorithm_module::decapsulate(&ct, &sk);
        timer.stop();

        info!(
            "Performance: Software:   {:9} ns",
            timer.time_in_nanos().unwrap()
        );

        ss.as_bytes().to_vec()
    };
}

impl PqcAlgorithm for SoftwareReference {
    fn keypair(&self, _: Option<&Device>) -> Result<KeyPair> {
        match self {
            Self::Light => {
                let (pk, sk) = kyber512::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::Recommended => {
                let (pk, sk) = kyber768::keypair();

                Ok(KeyPair {
                    secret_key: sk.as_bytes().to_owned(),
                    public_key: pk.as_bytes().to_owned(),
                })
            }
            Self::Paranoid => {
                let (pk, sk) = kyber1024::keypair();

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
                kem_apply_sw! {keypair, "Kyber 1", kyber512}
            }
            Self::Recommended => {
                kem_apply_sw! {keypair, "Kyber 3", kyber768}
            }
            Self::Paranoid => {
                kem_apply_sw! {keypair, "Kyber 5", kyber1024}
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
                kem_verify_sw! {keypair, ciphertext, "Kyber 1", kyber512}
            }
            Self::Recommended => {
                kem_verify_sw! {keypair, ciphertext, "Kyber 3", kyber768}
            }
            Self::Paranoid => {
                kem_verify_sw! {keypair, ciphertext, "Kyber 5", kyber1024}
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
                name: "Kyber",
                possible_values: vec![1, 3, 5],
            }
            .fail(),
        }
    }
}
