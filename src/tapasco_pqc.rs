use crate::drng::Drng;
use tapasco::device::{DataTransferAlloc, Device, PEParameter};

use devtimer::DevTime;

use log::info;

use snafu::{ResultExt, Snafu};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to decode TLKM device: {source}"))]
    DeviceInit {
        #[snafu(backtrace)]
        source: tapasco::device::Error,
    },

    #[snafu(display("Error while executing Job: {source}"))]
    Job {
        #[snafu(backtrace)]
        source: tapasco::job::Error,
    },

    #[snafu(display("The PE {pe_name} returned a non-zero exit code: {exit_code}"))]
    PEExitCode { pe_name: String, exit_code: u64 },

    #[snafu(display("Invalid Size of Signed Message: {signed_message_size}"))]
    InvalidSignatureSize { signed_message_size: usize },
}

type Result<T, E = Error> = std::result::Result<T, E>;

use crate::pqc_algorithm::{DsaTestCase, DsaTestCases, KemTestCase, KemTestCases, SharedSecret};

/// Try to acquire the PE with the given ID on the given device and pass the given arguments
fn call_pe(device: &Device, pe_name: &str, args: Vec<PEParameter>) -> Result<Vec<Box<[u8]>>> {
    let mut pe = device
        .acquire_pe(device.get_pe_id(pe_name).context(DeviceInitSnafu)?)
        .context(DeviceInitSnafu)?;

    let mut timer_start = DevTime::new_simple();
    let mut timer_wait = DevTime::new_simple();
    let mut timer_release = DevTime::new_simple();

    timer_start.start();
    pe.start(args).context(JobSnafu)?;
    timer_start.stop();

    timer_wait.start();
    pe.wait_for_completion().context(JobSnafu)?;
    timer_wait.stop();

    timer_release.start();
    let (exit_code, result) = pe.release(true, true).context(JobSnafu)?;
    timer_release.stop();

    info!(
        "Performance: PE Start:   {:9} ns",
        timer_start.time_in_nanos().unwrap()
    );
    info!(
        "Performance: PE Wait:    {:9} ns",
        timer_wait.time_in_nanos().unwrap()
    );
    info!(
        "Performance: PE Release: {:9} ns",
        timer_release.time_in_nanos().unwrap()
    );

    if exit_code != 0 {
        return PEExitCodeSnafu { pe_name, exit_code }.fail();
    }

    Ok(result)
}

/// Create a `PEParameter::DataTransferAlloc` from a simple &Vec<u8>
fn vec_transfer_alloc(
    device: &Device,
    v: &[u8],
    to_device: bool,
    from_device: bool,
) -> PEParameter {
    PEParameter::DataTransferAlloc(DataTransferAlloc {
        data: v.to_owned().into_boxed_slice(),
        free: true,
        from_device,
        to_device,
        memory: device
            .default_memory()
            .context(DeviceInitSnafu)
            .expect("Could not allocate Memory for transfer to Device!"),
        fixed: None,
    })
}

/// Generic function for the Encapsulation PE
pub fn kem_enc<const CIPHERTEXT_SIZE: usize, const PUBLIC_KEY_SIZE: usize>(
    device: &Device,
    pe_name: &str,
    public_key: &[u8; PUBLIC_KEY_SIZE],
    random_buffer: &[u8; 64],
) -> Result<(SharedSecret, [u8; CIPHERTEXT_SIZE])> {
    let result = call_pe(
        device,
        pe_name,
        vec![
            // crypto_kem_enc takes three arguments:
            // 1. output ciphertext `ct`
            vec_transfer_alloc(device, &[0_u8; CIPHERTEXT_SIZE], false, true),
            // 2. output shared secret `ss`
            vec_transfer_alloc(device, &SharedSecret::default(), false, true),
            // 3. input public key `pk`
            vec_transfer_alloc(device, public_key, true, false),
            // 4. pre-filled random buffer `buf`
            vec_transfer_alloc(device, random_buffer, true, false),
        ],
    )?;

    let ciphertext: [u8; CIPHERTEXT_SIZE] = result
        .get(0)
        .expect("I expect to get the Ciphertext back from the PE")
        .to_vec()
        .try_into()
        .expect("I expect the Ciphertext to have the correct length");
    let shared_secret: SharedSecret = result
        .get(1)
        .expect("I expect to get the Shared Secret back from the PE")
        .to_vec()
        .try_into()
        .expect("I expect the Shared Secret to be 32 bytes long");

    Ok((shared_secret, ciphertext))
}

/// Generic function for the Decapsulation PE
pub fn kem_dec<const CIPHERTEXT_SIZE: usize, const SECRET_KEY_SIZE: usize>(
    device: &Device,
    pe_name: &str,
    ciphertext: &[u8; CIPHERTEXT_SIZE],
    secret_key: &[u8; SECRET_KEY_SIZE],
) -> Result<SharedSecret> {
    let result = call_pe(
        device,
        pe_name,
        vec![
            // crypto_kem_dec takes three arguments:
            // 1. output shared secret `ss`
            vec_transfer_alloc(device, &SharedSecret::default(), false, true),
            // 2. input ciphertext `ct`
            vec_transfer_alloc(device, ciphertext, true, false),
            // 3. input secret key `sk`
            vec_transfer_alloc(device, secret_key, true, false),
        ],
    )?;

    let shared_secret: SharedSecret = result
        .get(0)
        .expect("I expect to get the shared secret back from the PE")
        .to_vec()
        .try_into()
        .expect("I expect the shared secret to be 32 bytes long");

    Ok(shared_secret)
}

pub fn kem_test<const C: usize, const P: usize, const S: usize>(
    device: &Device,
    pe_name_enc: &str,
    pe_name_dec: &str,
    test_cases: &[KemTestCase<C, P, S>],
    drng: &mut Drng,
    test_encapsulation: bool,
    test_decapsulation: bool,
) -> String {
    let mut test_results = Vec::new();

    for t in test_cases {
        // Initialize Deterministic "Random" Number Generator
        drng.randombytes_init(&t.seed);

        // Invocate `randombytes` two times that are usually called by the keypair generation
        // to get the correct random buffer for encapsulation
        for _ in 0..2 {
            let _ = drng.randombytes();
        }

        // Expand the 32 "random" bytes to the 64 bytes buffer that is expected by the PE
        let mut random_buffer = [0_u8; 64];
        random_buffer[..32].copy_from_slice(&drng.randombytes());

        // Generate a Ciphertext and a Shared Secret with the Encapsulation PE
        let (result_enc_shared_secret, result_ciphertext) = if test_encapsulation {
            kem_enc(device, pe_name_enc, &t.public_key, &random_buffer)
                .map_or_else(|_| (SharedSecret::default(), [0_u8; C]), |r| r)
        } else {
            info!("Skipping Encapsulation!");

            (t.shared_secret, t.ciphertext)
        };

        //debug!("Shared Secret from Encapsulation: {}", hex::encode_upper(&result_enc_shared_secret));

        // Verify ciphertext with the Decapsulation PE
        let result_dec_shared_secret = if test_decapsulation {
            kem_dec(device, pe_name_dec, &result_ciphertext, &t.secret_key)
                .map_or_else(|_| SharedSecret::default(), |r| r)
        } else {
            info!("Skipping Decapsulation!");

            t.shared_secret
        };

        //debug!("Shared Secret from Decapsulation: {}", hex::encode_upper(&result_dec_shared_secret));

        info!(
            "T#{:02}: Shared Secret recovered: {}, Ciphertext equals KAT: {}, Shared Secret equals KAT: {}",
            t.count,
            result_enc_shared_secret == result_dec_shared_secret,
            t.ciphertext == result_ciphertext,
            t.shared_secret == result_enc_shared_secret
         );

        let test_result = KemTestCase {
            count: t.count,
            seed: t.seed,
            public_key: t.public_key,
            secret_key: t.secret_key,
            ciphertext: result_ciphertext,
            shared_secret: result_dec_shared_secret,
        };

        test_results.push(test_result);
    }

    // Count how many test results match the KAT response file
    let count_ciphertext_equals_kat = test_cases
        .iter()
        .zip(test_results.iter())
        .filter(|(c, r)| c.ciphertext == r.ciphertext)
        .count();
    let count_shared_secret_equals_kat = test_cases
        .iter()
        .zip(test_results.iter())
        .filter(|(c, r)| c.shared_secret == r.shared_secret)
        .count();

    println!(
        "Tests: {}, Ciphertext equals KAT: {}, Shared Secret equals KAT: {}.",
        test_results.len(),
        count_ciphertext_equals_kat,
        count_shared_secret_equals_kat
    );

    if test_encapsulation {
        if count_ciphertext_equals_kat == test_results.len() {
            println!("Encapsulation PE is working.");
        } else {
            println!("Encapsulation PE is broken!");
        }
    } else {
        println!("Encapsulationing has been skipped.");
    }

    if test_decapsulation {
        if count_shared_secret_equals_kat == test_results.len() {
            println!("Decapsulation PE is working.");
        } else {
            println!("Decapsulation PE is broken!");
        }
    } else {
        println!("Decapsulation has been skipped.");
    }

    format!("{}", KemTestCases(test_results))
}

/// Generic function for the Signature PE
pub fn dsa_sign<const SIGNATURE_SIZE: usize, const SECRET_KEY_SIZE: usize>(
    device: &Device,
    pe_name: &str,
    secret_key: &[u8; SECRET_KEY_SIZE],
    message: &[u8],
) -> Result<Vec<u8>> {
    let result = call_pe(
        device,
        pe_name,
        vec![
            // crypto_sign takes five arguments:
            // 1. output signature `sm`
            vec_transfer_alloc(
                device,
                &vec![0_u8; message.len() + SIGNATURE_SIZE],
                false,
                true,
            ),
            // 2. output signature length `smlen`
            // Use vec_transfer_alloc instead of PEParameter::Single64 to get the modified
            // variable back which is in fact a Vec<u64> with length 1
            vec_transfer_alloc(device, &[0_u8; 8], false, true),
            // 3. message to be signed `m`
            vec_transfer_alloc(device, message, true, false),
            // 4. length of message `mlen`
            PEParameter::Single64(message.len() as u64),
            // 5. bit-packed secret key `sk`
            vec_transfer_alloc(device, secret_key, true, false),
        ],
    )?;

    // Check if the signature has the length as indicated by smlen
    let signed_message = result
        .get(0)
        .expect("I expect to get a signed message back from the PE")
        .to_vec();
    let smlen = u64::from_le_bytes(
        result
            .get(1)
            .expect("I expect to get the signature length back from the PE")
            .to_vec()
            .try_into()
            .expect("This should be a u64 consisting of 8 bytes"),
    );

    if signed_message.len() as u64 != smlen {
        return InvalidSignatureSizeSnafu {
            signed_message_size: signed_message.len(),
        }
        .fail();
    }

    Ok(signed_message)
}

/// Generic function for the Verification PE
pub fn dsa_verify<const SIGNATURE_SIZE: usize, const PUBLIC_KEY_SIZE: usize>(
    device: &Device,
    pe_name: &str,
    public_key: &[u8; PUBLIC_KEY_SIZE],
    signed_message: &[u8],
) -> Result<Vec<u8>> {
    if signed_message.len() <= SIGNATURE_SIZE {
        return InvalidSignatureSizeSnafu {
            signed_message_size: signed_message.len(),
        }
        .fail();
    }

    let result = call_pe(
        device,
        pe_name,
        vec![
            // crypto_sign_open takes five arguments:
            // 1. output message `m`
            vec_transfer_alloc(
                device,
                &vec![0_u8; signed_message.len() - SIGNATURE_SIZE],
                false,
                true,
            ),
            // 2. output length of message `mlen`
            // Use vec_transfer_alloc instead of PEParameter::Single64 to get the modified
            // variable back which is in fact a Vec<u64> with length 1
            vec_transfer_alloc(device, &[0_u8; 8], false, true),
            // 3. signed message `sm`
            vec_transfer_alloc(device, signed_message, true, false),
            // 4. length of signed message `smlen`
            PEParameter::Single64(signed_message.len() as u64),
            // 5. bit-packed public key `pk`
            vec_transfer_alloc(device, public_key, true, false),
        ],
    )?;

    // Check if the signature has the length as indicated by smlen
    let verified_message = result
        .get(0)
        .expect("I expect to get a verified message back from the PE")
        .to_vec();
    let mlen = u64::from_le_bytes(
        result
            .get(1)
            .expect("I expect to get the message length back from the PE")
            .to_vec()
            .try_into()
            .expect("This should be a u64 consisting of 8 bytes"),
    );

    if verified_message.len() as u64 != mlen {
        return InvalidSignatureSizeSnafu {
            signed_message_size: signed_message.len(),
        }
        .fail();
    }

    Ok(verified_message)
}

pub fn dsa_test<const SIG: usize, const P: usize, const S: usize>(
    device: &Device,
    pe_name_sign: &str,
    pe_name_verify: &str,
    test_cases: &[DsaTestCase<P, S>],
    test_sign: bool,
    test_verify: bool,
) -> String {
    let mut test_results = Vec::new();

    for t in test_cases {
        // Generate a Signature with the Signature PE
        let result_sign = if test_sign {
            dsa_sign::<SIG, S>(device, pe_name_sign, &t.secret_key, &t.message)
                .map_or_else(|_| Vec::new(), |r| r)
        } else {
            info!("Skipping Signing!");

            t.signed_message.clone()
        };

        // Verify the Signature with the Verification PE
        let result_verify = if test_verify {
            dsa_verify::<SIG, P>(device, pe_name_verify, &t.public_key, &result_sign)
                .map_or_else(|_| Vec::new(), |r| r)
        } else {
            info!("Skipping Verfication!");

            t.message.clone()
        };

        info!(
            "T#{:02}: Signature verified: {}, Signed Message equals KAT: {}",
            t.count,
            t.message == result_verify,
            t.signed_message == result_sign,
        );

        let test_result = DsaTestCase {
            count: t.count,
            seed: t.seed,
            message: result_verify,
            public_key: t.public_key,
            secret_key: t.secret_key,
            signed_message: result_sign,
        };

        test_results.push(test_result);
    }

    // Count how many test results match the KAT response file
    let count_signed_message_equals_kat = test_cases
        .iter()
        .zip(test_results.iter())
        .filter(|(c, r)| c.signed_message == r.signed_message)
        .count();
    let count_message_recovered = test_cases
        .iter()
        .zip(test_results.iter())
        .filter(|(c, r)| c.message == r.message)
        .count();

    println!(
        "Tests: {}, Signature verified: {}, Signed Message equals KAT: {}.",
        test_results.len(),
        count_message_recovered,
        count_signed_message_equals_kat,
    );

    if test_sign {
        if count_signed_message_equals_kat == test_results.len() {
            println!("Sign PE is working.");
        } else {
            println!("Sign PE is broken!");
        }
    } else {
        println!("Signing has been skipped.");
    }

    if test_verify {
        if count_message_recovered == test_results.len() {
            println!("Verification PE is working.");
        } else {
            println!("Verification PE is broken!");
        }
    } else {
        println!("Verification has been skipped.");
    }

    format!("{}", DsaTestCases(test_results))
}
