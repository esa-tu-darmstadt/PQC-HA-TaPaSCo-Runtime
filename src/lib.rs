/// `TaPaSCo` PQC library
///
/// For most of the functionality, see the [`pqc_algorithm`] module.
///
mod drng;
pub use drng::*;

pub mod pqc_algorithm;
pub use pqc_algorithm::*;

// Internal modules
mod tapasco_pqc;

mod known_answer_tests;

// Tests
#[cfg(test)]
mod tests {
    use super::*;

    type Result<T, E = Error> = std::result::Result<T, E>;

    #[test]
    fn all_sw_test() -> Result<()> {
        // KEM
        sw_test_kem("kyber_sw", 1)?;
        sw_test_kem("kyber_sw", 3)?;
        sw_test_kem("kyber_sw", 5)?;

        sw_test_kem("classic_mceliece_sw", 1)?;
        sw_test_kem("classic_mceliece_sw", 3)?;
        sw_test_kem("classic_mceliece_sw", 5)?;
        sw_test_kem("classic_mceliece_sw", 6)?;
        sw_test_kem("classic_mceliece_sw", 7)?;

        sw_test_kem("hqc_sw", 1)?;
        sw_test_kem("hqc_sw", 3)?;
        sw_test_kem("hqc_sw", 5)?;

        // DSA
        sw_test_dsa("dilithium_sw", 2)?;
        sw_test_dsa("dilithium_sw", 3)?;
        sw_test_dsa("dilithium_sw", 5)?;

        sw_test_dsa("falcon_sw", 1)?;
        sw_test_dsa("falcon_sw", 5)?;

        sw_test_dsa("sphincsplus_sw", 1)?;
        sw_test_dsa("sphincsplus_sw", 3)?;
        sw_test_dsa("sphincsplus_sw", 5)?;

        Ok(())
    }

    fn sw_test_kem(name: &str, level: u8) -> Result<()> {
        let algorithm = <dyn PqcAlgorithm>::new(name, level)?;

        let keypair = algorithm.keypair(None)?;

        let result = algorithm.apply(None, Some(&keypair), None)?;

        let (ciphertext, shared_secret) = match result {
            ApplyResult::ApplyDsaResult(_) => panic!("This should return a KEM result!"),
            ApplyResult::ApplyKemResult(r) => (r.ciphertext, r.shared_secret),
        };

        let result = algorithm.verify(None, Some(&keypair), Some(ciphertext.as_slice()))?;

        let decapsulated_shared_secret = match result {
            VerifyResult::VerifyDsaResult(_) => panic!("This should return a KEM result!"),
            VerifyResult::VerifyKemResult(r) => r.shared_secret,
        };

        assert_eq!(
            shared_secret, decapsulated_shared_secret,
            "{name} {level}: Shared secret mismatch!"
        );

        Ok(())
    }

    fn sw_test_dsa(name: &str, level: u8) -> Result<()> {
        let message = "This is a test message.".as_bytes();

        let algorithm = <dyn PqcAlgorithm>::new(name, level)?;

        let keypair = algorithm.keypair(None)?;

        let result = algorithm.apply(None, Some(&keypair), Some(message))?;

        let signed_message = match result {
            ApplyResult::ApplyKemResult(_) => panic!("This should return a DSA result!"),
            ApplyResult::ApplyDsaResult(r) => r.signed_message,
        };

        let result = algorithm.verify(None, Some(&keypair), Some(signed_message.as_slice()))?;

        let verified_message = match result {
            VerifyResult::VerifyKemResult(_) => panic!("This should return a DSA result!"),
            VerifyResult::VerifyDsaResult(r) => r.message,
        };

        assert_eq!(
            message, verified_message,
            "{name} {level}: Message mismatch!"
        );

        Ok(())
    }
}
