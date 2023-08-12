use std::array::TryFromSliceError;
use std::fmt;

mod kyber;
use kyber::{Kyber, SoftwareReference as KyberReference};

mod dilithium;
use dilithium::{Dilithium, SoftwareReference as DilithiumReference};

mod falcon;
use falcon::SoftwareReference as FalconReference;

mod sphincsplus;
use sphincsplus::SoftwareSphincsShakeRobust as SphincsplusReference;

mod classic_mceliece;
use classic_mceliece::SoftwareReference as McElieceReference;

mod hqc;
use hqc::SoftwareReference as HqcReference;

use hex::{decode, encode_upper, FromHexError};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use snafu::{Backtrace, ResultExt, Snafu};

pub const IMPLEMENTATIONS: &[&str] = &[
    "kyber_hls",
    "dilithium_hls",
    "kyber_sw",
    "dilithium_sw",
    "falcon_sw",
    "sphincsplus_sw",
    "classic_mceliece_sw",
    "hqc_sw",
];

#[derive(Debug, Snafu)]
#[snafu(display(
    "Invalid Security Level {value} for {name}! Possible values: {possible_values:?}"
))]
pub struct ParseError {
    value: u8,
    name: &'static str,
    possible_values: Vec<u8>,
    backtrace: Backtrace,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Error while in TaPaSCo: {source}"))]
    Tapasco {
        #[snafu(backtrace)]
        source: crate::tapasco_pqc::Error,
    },

    #[snafu(display("Error parsing Known Answer Test File: {source}"))]
    KatParse {
        #[snafu(backtrace)]
        source: crate::known_answer_tests::ParseError,
    },

    #[snafu(display("Invalid Security Level: {source}"))]
    InvalidSecurityLevel {
        #[snafu(backtrace)]
        source: ParseError,
    },

    #[snafu(display("Unknown Algorithm: {name}. Possible values: {possible_values:?}"))]
    UnknownAlgorithm {
        name: String,
        possible_values: Vec<&'static str>,
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Length mismatch in {what} for {algorithm}! Expecting size of {expected_length} bytes."
    ))]
    ArgumentLength {
        source: TryFromSliceError,
        what: &'static str,
        algorithm: &'static str,
        expected_length: u32,
        backtrace: Backtrace,
    },

    #[snafu(display("Cannot parse hex-encoded string! {source}"))]
    ParseHex {
        source: hex::FromHexError,
        backtrace: Backtrace,
    },

    #[snafu(display("This implementation needs a loaded TaPaSCo bitstream and kernel module."))]
    ImplementationNeedsTapasco { backtrace: Backtrace },

    #[snafu(display("This implementation does not support this operation, sorry."))]
    NotImplemented { backtrace: Backtrace },

    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error>, Some)))]
        source: Option<Box<dyn std::error::Error>>,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

pub type KatSeed = [u8; 48];
pub type SharedSecret = [u8; 32];

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl fmt::Display for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "sk = {}", encode_upper(&self.secret_key))?;
        writeln!(f, "pk = {}", encode_upper(&self.public_key))
    }
}

impl From<&[u8]> for KeyPair {
    fn from(item: &[u8]) -> Self {
        Self {
            secret_key: item.to_owned(),
            public_key: item.to_owned(),
        }
    }
}

impl From<Vec<u8>> for KeyPair {
    fn from(item: Vec<u8>) -> Self {
        Self {
            secret_key: item.clone(),
            public_key: item,
        }
    }
}

impl TryFrom<&str> for KeyPair {
    type Error = FromHexError;

    fn try_from(item: &str) -> Result<Self, Self::Error> {
        Ok(decode(item)?.into())
    }
}

impl TryFrom<String> for KeyPair {
    type Error = FromHexError;

    fn try_from(item: String) -> Result<Self, Self::Error> {
        Ok(decode(item)?.into())
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyKemResult {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl fmt::Display for ApplyKemResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ct = {}", encode_upper(&self.ciphertext))?;
        writeln!(f, "ss = {}", encode_upper(&self.shared_secret))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyDsaResult {
    pub signed_message: Vec<u8>,
}

impl fmt::Display for ApplyDsaResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "sm = {}", encode_upper(&self.signed_message))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApplyResult {
    ApplyKemResult(ApplyKemResult),
    ApplyDsaResult(ApplyDsaResult),
}

impl fmt::Display for ApplyResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::ApplyKemResult(r) => writeln!(f, "{r}"),
            Self::ApplyDsaResult(r) => writeln!(f, "{r}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyKemResult {
    pub shared_secret: Vec<u8>,
}

impl fmt::Display for VerifyKemResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "ss = {}", encode_upper(&self.shared_secret))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyDsaResult {
    pub message: Vec<u8>,
}

impl fmt::Display for VerifyDsaResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "msg = {}", encode_upper(&self.message))?;
        writeln!(f, "txt = {}", String::from_utf8_lossy(&self.message))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyResult {
    VerifyKemResult(VerifyKemResult),
    VerifyDsaResult(VerifyDsaResult),
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::VerifyKemResult(r) => writeln!(f, "{r}"),
            Self::VerifyDsaResult(r) => writeln!(f, "{r}"),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemTestCase<
    const CIPHERTEXT_SIZE: usize,
    const PUBLIC_KEY_SIZE: usize,
    const SECRET_KEY_SIZE: usize,
> {
    pub count: u64,
    #[serde(with = "BigArray")]
    pub seed: KatSeed,
    #[serde(with = "BigArray")]
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    #[serde(with = "BigArray")]
    pub secret_key: [u8; SECRET_KEY_SIZE],
    #[serde(with = "BigArray")]
    pub ciphertext: [u8; CIPHERTEXT_SIZE],
    pub shared_secret: SharedSecret,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KemTestCases<
    const CIPHERTEXT_SIZE: usize,
    const PUBLIC_KEY_SIZE: usize,
    const SECRET_KEY_SIZE: usize,
>(pub Vec<KemTestCase<CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE>>);

/// A KEM (Key Encapsulation Mechanism) Test Case consists of:
/// 1. `count` acting as unique Id of the Test Case
/// 2. `seed` from which the keypair is generated
/// 3. `pk` the Public Key
/// 4. `sk` the Secret Key
/// 5. `ct` the Ciphertext
/// 6. `ss` the Shared Secret
impl<const CIPHERTEXT_SIZE: usize, const PUBLIC_KEY_SIZE: usize, const SECRET_KEY_SIZE: usize>
    fmt::Display for KemTestCase<CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "count = {}", self.count)?;
        writeln!(f, "seed = {}", encode_upper(self.seed))?;
        writeln!(f, "pk = {}", encode_upper(self.public_key))?;
        writeln!(f, "sk = {}", encode_upper(self.secret_key))?;
        writeln!(f, "ct = {}", encode_upper(self.ciphertext))?;
        writeln!(f, "ss = {}", encode_upper(self.shared_secret))
    }
}

// Code from:
// https://gist.github.com/Gisleburt/ec443278c597623b0fef5c9d55dfacd1#file-id4v-impl-display-for-albums-rs
impl<const CIPHERTEXT_SIZE: usize, const PUBLIC_KEY_SIZE: usize, const SECRET_KEY_SIZE: usize>
    fmt::Display for KemTestCases<CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.iter().fold(Ok(()), |result, elem| {
            result.and_then(|_| writeln!(f, "{elem}"))
        })
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsaTestCase<const PUBLIC_KEY_SIZE: usize, const SECRET_KEY_SIZE: usize> {
    pub count: u64,
    #[serde(with = "BigArray")]
    pub seed: KatSeed,
    pub message: Vec<u8>,
    #[serde(with = "BigArray")]
    pub public_key: [u8; PUBLIC_KEY_SIZE],
    #[serde(with = "BigArray")]
    pub secret_key: [u8; SECRET_KEY_SIZE],
    pub signed_message: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DsaTestCases<const PUBLIC_KEY_SIZE: usize, const SECRET_KEY_SIZE: usize>(
    pub Vec<DsaTestCase<PUBLIC_KEY_SIZE, SECRET_KEY_SIZE>>,
);

/// A DSA (Digital Signature Algorithm) Test Case consists of:
/// 1. `count` acting as unique Id of the Test Case
/// 2. `seed` from which the keypair is generated
/// 3. `msg` the message to be signed
/// 4. `pk` the Public Key
/// 5. `sk` the Secret Key
/// 6. `sm` the Signed Message (Message concatenated with Signature)
impl<const PUBLIC_KEY_SIZE: usize, const SECRET_KEY_SIZE: usize> fmt::Display
    for DsaTestCase<PUBLIC_KEY_SIZE, SECRET_KEY_SIZE>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "count = {}", self.count)?;
        writeln!(f, "seed = {}", encode_upper(self.seed))?;
        writeln!(f, "mlen = {}", self.message.len())?;
        writeln!(f, "msg = {}", encode_upper(&self.message))?;
        writeln!(f, "pk = {}", encode_upper(self.public_key))?;
        writeln!(f, "sk = {}", encode_upper(self.secret_key))?;
        writeln!(f, "smlen = {}", self.signed_message.len())?;
        writeln!(f, "sm = {}", encode_upper(&self.signed_message))
    }
}

// Code from:
// https://gist.github.com/Gisleburt/ec443278c597623b0fef5c9d55dfacd1#file-id4v-impl-display-for-albums-rs
impl<const PUBLIC_KEY_SIZE: usize, const SECRET_KEY_SIZE: usize> fmt::Display
    for DsaTestCases<PUBLIC_KEY_SIZE, SECRET_KEY_SIZE>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.iter().fold(Ok(()), |result, elem| {
            result.and_then(|_| writeln!(f, "{elem}"))
        })
    }
}

use crate::drng::Drng;
use tapasco::device::Device;

/// The interface for all NIST PQC algorithm implementations.
///
/// It provides methods to generate a keypair, apply the first step of the algorithm, verify
/// data processed by the algorithm and run its Known Answer Tests (KAT). `Apply` usually means
/// encapsulation for a KEM and signing for a DSA respectively. So does `verify` mean
/// decapsulation for a KEM and verification of the signature for a DSA.
///
/// # Examples
///
/// To get a trait object of an implemented algorithm use the [`new`] function, to use e.g. CRYSTALS
/// Kyber on the recommended security level 3:
///
/// ```
/// # use tapasco_pqc_runtime::PqcAlgorithm;
/// let algorithm = <dyn PqcAlgorithm>::new("kyber_sw", 3)?;
/// # Ok::<(), tapasco_pqc_runtime::Error>(())
/// ```
///
/// To then encapsulate something, use the [`apply`] method:
///
/// ```
/// # use tapasco_pqc_runtime::PqcAlgorithm;
/// # let algorithm = <dyn PqcAlgorithm>::new("kyber_sw", 3)?;
/// algorithm.apply(None, None, None)?;
/// # Ok::<(), tapasco_pqc_runtime::Error>(())
/// ```
///
/// This can fail for various reasons. An implementation may even decide not to implement this
/// method. In case it succeeds, you can decapsulate it with the [`verify`] method.
///
/// Run the Known Answer Test (KAT) mechanism to verify your implementation with the test files
/// provided by NIST in the [`test_kat`] method.
///
/// [`new`]: #method.new
/// [`apply`]: #method.apply
/// [`verify`]: #method.verify
/// [`test_kat`]: #method.test_kat
///
/// # Implementing this interface
///
/// To implement this interface for your own implementation, look into the instructions in the
/// source of this module!
pub trait PqcAlgorithm {
    /// Create a keypair consisting of a secret and a public key
    ///
    /// # Errors
    ///
    /// This can fail for various reasons. Either this method is not implemented or there is an
    /// error using `TaPaSCo`.
    fn keypair(&self, device: Option<&Device>) -> Result<KeyPair>;

    /// Apply the algorithm to some optional data.
    ///
    /// This usually means encapsulation for a KEM and signing for a DSA respectively.
    ///
    /// # Errors
    ///
    /// This can fail for various reasons. Either this method is not implemented, the input
    /// parameters are invalid or there is an error using `TaPaSCo`.
    fn apply(
        &self,
        device: Option<&Device>,
        keypair: Option<&KeyPair>,
        data: Option<&[u8]>,
    ) -> Result<ApplyResult>;

    /// Verify some optional data with the algorithm.
    ///
    /// This means decapsulation for a KEM and signature verification for a DSA respectively.
    ///
    /// # Errors
    ///
    /// This can fail for various reasons. Either this method is not implemented, the input
    /// parameters are invalid or there is an error using `TaPaSCo`.
    fn verify(
        &self,
        device: Option<&Device>,
        keypair: Option<&KeyPair>,
        data: Option<&[u8]>,
    ) -> Result<VerifyResult>;

    /// Supply a default filename for the Known Answer Test (KAT) response file, usually having the
    /// suffix `.rsp`
    fn default_kat_filename(&self) -> &str;

    fn kat_name(&self) -> &str;

    /// Verify your algorithm with Known Answer Test (KAT) files provided by NIST.
    ///
    /// # Errors
    ///
    /// This can fail for various reasons. Either this method is not implemented, the input
    /// parameters are invalid or there is an error using `TaPaSCo`.
    fn test_kat(
        &self,
        device: Option<&Device>,
        kat: &str,
        drng: &mut Drng,
        test_apply: bool,
        test_verify: bool,
    ) -> Result<String>;
}

impl dyn PqcAlgorithm {
    /// Create a new trait object for an algorithm that implements the NIST PQC interface:
    ///
    /// ```should_panic
    /// # use tapasco_pqc_runtime::PqcAlgorithm;
    /// let algorithm = <dyn PqcAlgorithm>::new("dilithium_hls", 5)?;
    /// algorithm.apply(None, None, None)?;
    /// # let device = None;
    /// # let drng = &mut tapasco_pqc_runtime::Drng::new();
    /// algorithm.test_kat(device, "<your_kat_filename>", drng, true, true)?;
    /// # panic!("This test panics here because we don't give it a necessary tapasco device");
    /// # Ok::<(), tapasco_pqc_runtime::Error>(())
    /// ```
    ///
    /// Or using a software implementation:
    ///
    /// ```
    /// use tapasco_pqc_runtime::{PqcAlgorithm, ApplyResult, VerifyResult};
    /// let algorithm = <dyn PqcAlgorithm>::new("kyber_sw", 3)?;
    /// let keypair = algorithm.keypair(None)?;
    /// let result = algorithm.apply(None, Some(&keypair), None)?;
    /// let (ciphertext, shared_secret) = match result {
    ///     ApplyResult::ApplyDsaResult(_) => panic!("This should return a KEM result!"),
    ///     ApplyResult::ApplyKemResult(r) => (r.ciphertext, r.shared_secret),
    /// };
    /// let result = algorithm.verify(None, Some(&keypair), Some(ciphertext.as_slice()))?;
    /// let decapsulated_shared_secret = match result {
    ///     VerifyResult::VerifyDsaResult(_) => panic!("This should return a KEM result!"),
    ///     VerifyResult::VerifyKemResult(r) => r.shared_secret,
    /// };
    /// assert_eq!(shared_secret, decapsulated_shared_secret);
    /// # Ok::<(), tapasco_pqc_runtime::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// This can fail if the name or the respective security level for the algorithm is invalid.
    pub fn new(name: &str, level: u8) -> Result<Box<dyn PqcAlgorithm>> {
        match name {
            "dilithium_hls" => {
                let algorithm: Dilithium =
                    level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            "kyber_hls" => {
                let algorithm: Kyber = level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            "dilithium_sw" => {
                let algorithm: DilithiumReference =
                    level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            "kyber_sw" => {
                let algorithm: KyberReference =
                    level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            "falcon_sw" => {
                let algorithm: FalconReference =
                    level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            "sphincsplus_sw" => {
                let algorithm: SphincsplusReference =
                    level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            "classic_mceliece_sw" => {
                let algorithm: McElieceReference =
                    level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            "hqc_sw" => {
                let algorithm: HqcReference =
                    level.try_into().context(InvalidSecurityLevelSnafu {})?;
                Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            }
            // 1. If you want to add a new algorithm, follow this scheme to create a trait object
            //    for your algorithm:
            //"new_algorithm" => {
            //    let algorithm = match level {
            //        1 => NewAlgorithm::SecurityLevel1,
            //        2 => NewAlgorithm::SecurityLevel2,
            //        3 => NewAlgorithm::SecurityLevel3,
            //        _ => ParseContext { value: level, name: "NewAlgorithm", possible_values: vec![1, 2, 3] }.fail().context(InvalidSecurityLevelSnafu {})?,
            //    };

            //    Ok(Box::new(algorithm) as Box<dyn PqcAlgorithm>)
            //}
            // And then add the name of your algorithm here:
            _ => UnknownAlgorithmSnafu {
                name: name.to_string(),
                possible_values: IMPLEMENTATIONS.to_vec(),
            }
            .fail(),
        }
    }
}

impl<P: PqcAlgorithm + ?Sized> PqcAlgorithm for Box<P> {
    fn keypair(&self, device: Option<&Device>) -> Result<KeyPair> {
        (**self).keypair(device)
    }

    fn apply(
        &self,
        device: Option<&Device>,
        key: Option<&KeyPair>,
        data: Option<&[u8]>,
    ) -> Result<ApplyResult> {
        (**self).apply(device, key, data)
    }

    fn verify(
        &self,
        device: Option<&Device>,
        key: Option<&KeyPair>,
        data: Option<&[u8]>,
    ) -> Result<VerifyResult> {
        (**self).verify(device, key, data)
    }

    fn default_kat_filename(&self) -> &str {
        (**self).default_kat_filename()
    }

    fn kat_name(&self) -> &str {
        (**self).kat_name()
    }

    fn test_kat(
        &self,
        device: Option<&Device>,
        kat: &str,
        drng: &mut Drng,
        test_apply: bool,
        test_verify: bool,
    ) -> Result<String> {
        (**self).test_kat(device, kat, drng, test_apply, test_verify)
    }
}

// 2. Then define a struct or an enum storing information that differs between security levels:
//    (Implement this in a new module in the `pqc_algorithm` directory)
//pub enum NewAlgorithm {
//    SecurityLevel1,
//    SecurityLevel2,
//    SecurityLevel3,
//}

// 3. Finally, implement the `PqcAlgorithm` trait for it:
//impl PqcAlgorithm for NewAlgorithm {
//    fn keypair(&self, device: Option<&Device>) -> Result<KeyPair> {
//        todo!()
//    }
//
//    fn apply(&self, device: Option<&Device>, key: Option<&KeyPair>, data: Option<&[u8]>) -> Result<String> {
//        todo!()
//    }
//
//    fn verify(&self, device: Option<&Device>, key: Option<&KeyPair>, data: Option<&[u8]>) -> Result<String> {
//        todo!()
//    }
//
//    fn default_kat_filename(&self) -> &str {
//        todo!()
//    }
//
//    fn kat_name(&self) -> &str {
//        todo!()
//    }
//
//    fn test_kat(&self, device: Option<&Device>, kat: &str, drng: &mut Drng, test_apply: bool, test_verify: bool) -> Result<String> {
//        todo!()
//    }
//}
