// Based on tapasco/runtime/examples/Rust/libtapasco_tests

// Import the things from our library:
use tapasco_pqc_runtime::{Drng, PqcAlgorithm};

use std::{
    collections::HashMap,
    fs::{read_to_string, write, File},
    io::prelude::*,
    path::PathBuf,
};

use tapasco::device::Device;
use tapasco::tlkm::TLKM;

use clap::Parser;

use hex::{decode, encode_upper, FromHex, FromHexError};

use log::{info, trace};

use serde_json::json;

use snafu::{Backtrace, ErrorCompat, ResultExt, Snafu};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("Failed to initialize TLKM object: {source}"))]
    TLKMInit {
        #[snafu(backtrace)]
        source: tapasco::tlkm::Error,
    },

    #[snafu(display("Failed to decode TLKM device: {source}"))]
    DeviceInit {
        #[snafu(backtrace)]
        source: tapasco::device::Error,
    },

    #[snafu(display("While in PQC algorithm: {source}"))]
    Pqc {
        #[snafu(backtrace)]
        source: tapasco_pqc_runtime::Error,
    },

    #[snafu(display("Error using Known Answer Test file: {source}"))]
    KatFile {
        source: std::io::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Cannot read from file: {path}. Reason: {source}"))]
    ReadFile {
        source: std::io::Error,
        backtrace: Backtrace,
        path: String,
    },

    #[snafu(display("Cannot write to file: {path}. Reason: {source}"))]
    WriteFile {
        source: std::io::Error,
        backtrace: Backtrace,
        path: String,
    },

    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(Box<dyn std::error::Error>, Some)))]
        source: Option<Box<dyn std::error::Error>>,
    },

    #[snafu(display("Serialization failed: {source}"))]
    Serialize {
        source: serde_json::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display("Deserialization failed: {source}"))]
    Deserialize {
        source: serde_json::error::Error,
        backtrace: Backtrace,
    },

    #[snafu(display(
        "Length mismatch in {what} for {algorithm}! Expecting size of {expected_length} bytes."
    ))]
    ArgumentLength {
        source: std::array::TryFromSliceError,
        what: &'static str,
        algorithm: &'static str,
        expected_length: u32,
        backtrace: Backtrace,
    },

    #[snafu(display("Cannot parse hex-encoded string! {source}"))]
    ParseHex {
        source: FromHexError,
        backtrace: Backtrace,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

fn try_initialize_tapasco(device_id: u32) -> Result<Device> {
    let tlkm = TLKM::new().context(TLKMInitSnafu {})?;

    let mut device = tlkm
        .device_alloc(device_id, &HashMap::new())
        .context(TLKMInitSnafu {})?;

    device
        .change_access(tapasco::tlkm::tlkm_access::TlkmAccessExclusive)
        .context(DeviceInitSnafu {})?;

    Ok(device)
}

fn subcommand_status() -> Result<()> {
    TLKM::new()
        .context(TLKMInitSnafu {})?
        .device_enum(&HashMap::new())
        .context(TLKMInitSnafu {})?
        .into_iter()
        .for_each(|x| println!("Device {} {:#?}", x.id(), x.status()));

    Ok(())
}

fn subcommand_keypair(
    device: Option<&Device>,
    algorithm: &(impl PqcAlgorithm + ?Sized),
    keyfile_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    mut json: bool,
) -> Result<()> {
    if keyfile_path.is_some() && output_path.is_some() {
        eprintln!("Warning: `--keyfile` takes precedence over `--output`!");
    }

    let output_path = keyfile_path.or(output_path);

    // If the output path has a `.json` extension, set output format to json
    if let Some(ref path) = output_path {
        if let Some(e) = path.extension() {
            if e == "json" {
                json = true;
            }
        }
    }

    // Generate a keypair
    let result = algorithm.keypair(device).context(PqcSnafu {})?;

    // Serialize
    let output = if json {
        serde_json::to_string_pretty(&result).context(SerializeSnafu {})?
    } else {
        result.to_string()
    };

    if let Some(mut path) = output_path {
        if json {
            path.set_extension("json");
        }

        write(&path, &output).context(WriteFileSnafu {
            path: path.to_string_lossy(),
        })?;
    } else {
        println!("{output}");
    }

    Ok(())
}

fn subcommand_apply(
    device: Option<&Device>,
    algorithm: &(impl PqcAlgorithm + ?Sized),
    key: Option<String>,
    data: Option<String>,
    is_hex: bool,
    keyfile_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    // `key` takes precedence over `keypair`
    let keypair = if let Some(key) = key {
        Some(key.try_into().context(ParseHexSnafu {})?)
    } else if let Some(path) = keyfile_path {
        // Try to deserialize a keypair from the given file
        Some(
            serde_json::from_str(&read_to_string(&path).context(ReadFileSnafu {
                path: path.display().to_string(),
            })?)
            .context(DeserializeSnafu {})?,
        )
    } else {
        None
    };

    // Parse `data` cli argument
    let data = if let Some(data) = data {
        if is_hex {
            Some(decode(data).context(ParseHexSnafu {})?)
        } else {
            Some(data.as_bytes().to_vec())
        }
    } else {
        None
    };

    let result = algorithm
        .apply(device, keypair.as_ref(), data.as_deref())
        .context(PqcSnafu {})?;

    let output = if json {
        serde_json::to_string_pretty(&result).context(SerializeSnafu {})?
    } else {
        result.to_string()
    };

    if let Some(mut path) = output_path {
        if json {
            path.set_extension("json");
        }

        write(&path, &output).context(WriteFileSnafu {
            path: path.to_string_lossy(),
        })?;
    } else {
        println!("{output}");
    }

    Ok(())
}

fn subcommand_verify(
    device: Option<&Device>,
    algorithm: &(impl PqcAlgorithm + ?Sized),
    key: Option<String>,
    data: Option<String>,
    is_hex: bool,
    keyfile_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    // `key` takes precedence over `keypair`
    let keypair = if let Some(key) = key {
        Some(key.try_into().context(ParseHexSnafu {})?)
    } else if let Some(path) = keyfile_path {
        // Try to deserialize a keypair from the given file
        Some(
            serde_json::from_str(&read_to_string(&path).context(ReadFileSnafu {
                path: path.display().to_string(),
            })?)
            .context(DeserializeSnafu {})?,
        )
    } else {
        None
    };

    // Parse `data` cli argument
    let data = if let Some(data) = data {
        if is_hex {
            Some(decode(data).context(ParseHexSnafu {})?)
        } else {
            Some(data.as_bytes().to_vec())
        }
    } else {
        None
    };

    let result = algorithm
        .verify(device, keypair.as_ref(), data.as_deref())
        .context(PqcSnafu {})?;

    let output = if json {
        serde_json::to_string_pretty(&result).context(SerializeSnafu {})?
    } else {
        result.to_string()
    };

    if let Some(mut path) = output_path {
        if json {
            path.set_extension("json");
        }

        write(&path, &output).context(WriteFileSnafu {
            path: path.to_string_lossy(),
        })?;
    } else {
        println!("{output}");
    }

    Ok(())
}

fn subcommand_kat(
    device: Option<&Device>,
    algorithm: &(impl PqcAlgorithm + ?Sized),
    mut kat_filename: Option<String>,
    test_apply: bool,
    test_verify: bool,
    output_path: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    if json {
        eprintln!("The Known Answer Test cases cannot be serialized as JSON!");
        eprintln!("Output will be a single JSON object containing just one string.");
    }

    let mut output_path_str = output_path.as_ref().map(|p| p.display().to_string());
    let kat_filename = output_path_str.get_or_insert(
        (*kat_filename.get_or_insert(algorithm.default_kat_filename().to_string())).to_string(),
    );
    let known_answer_tests = read_to_string(&kat_filename).context(KatFileSnafu {})?;

    // Instantiate Deterministic "Random" Number Generator
    let mut drng = Drng::new();

    info!(
        "Writing Known Answer Test file to verify the hardware implementation: {kat_filename}.tapasco",
    );

    let mut tapasco_file_contents = String::new();

    // Write Algorithm name to the top of the file
    tapasco_file_contents.push_str(&format!("# {}\n\n", algorithm.kat_name()));

    let test_results = algorithm
        .test_kat(
            device,
            &known_answer_tests,
            &mut drng,
            test_apply,
            test_verify,
        )
        .context(PqcSnafu {})?;

    tapasco_file_contents.push_str(&test_results);

    // Print test results into Tapasco file
    let mut tapasco_file =
        File::create(format!("{kat_filename}.tapasco")).context(KatFileSnafu {})?;

    tapasco_file
        .write_all(tapasco_file_contents.as_bytes())
        .context(KatFileSnafu {})?;

    let output = if json {
        serde_json::to_string_pretty(&test_results).context(SerializeSnafu {})?
    } else {
        test_results
    };

    if let Some(mut path) = output_path {
        if json {
            path.set_extension("json");
        }

        write(&path, &output).context(WriteFileSnafu {
            path: path.display().to_string(),
        })?;
    } else {
        println!("{output}");
    }

    Ok(())
}

const DEFAULT_SEED: &str = "2A6F7386B815366F572AEB6C79E272CC21B7095FE09575F18072C9D677DA23BC9C8A4BC393B7524604D299BEDD260C8B";

/// Expand the given `seed` into three outputs of the `randombytes` function
///
/// which is useful for testing the DRBG (deterministic random bytes generator)
fn subcommand_rng(
    mut seed: Option<String>,
    output_path: Option<PathBuf>,
    json: bool,
) -> Result<()> {
    // Supply a default seed for easier testing
    let seed: [u8; 48] = Vec::from_hex(seed.get_or_insert(DEFAULT_SEED.to_string()))
        .context(ParseHexSnafu {})?
        .as_slice()
        .try_into()
        .context(ArgumentLengthSnafu {
            what: "seed",
            algorithm: "DRNG",
            expected_length: 48_u32,
        })?;

    let mut output = String::new();
    if json {
        output.push_str(
            &serde_json::to_string_pretty(&json!({
                "seed": seed.as_slice(),
            }))
            .context(SerializeSnafu {})?,
        );
    } else {
        output.push_str(&format!("Seed: {}\n", encode_upper(seed)));
    }

    let mut drng = Drng::new();
    drng.randombytes_init(&seed);

    trace!("Generating randombytes");

    let mut randombytes: Vec<[u8; 32]> = Vec::new();

    // Get 2 * 32 bytes from randombytes for keypair generation
    // and 1 * 32 bytes from randombytes for encapsulation
    for _ in 0..3 {
        randombytes.push(drng.randombytes());
    }

    if json {
        output.push_str(
            &serde_json::to_string_pretty(&json!({
                "random_bytes": randombytes
            }))
            .context(SerializeSnafu {})?,
        );
    } else {
        output.push_str(&format!(
            "Output from `randombytes`: {:?}",
            randombytes
                .iter()
                .map(encode_upper)
                .collect::<Vec<String>>()
        ));
    }

    if let Some(mut path) = output_path {
        if json {
            path.set_extension("json");
        }

        write(&path, &output).context(WriteFileSnafu {
            path: path.to_string_lossy(),
        })?;
    } else {
        println!("{output}");
    }

    Ok(())
}

#[derive(clap::Parser, Debug)]
/// `TaPaSCo` Runtime for NIST PQC Algorithms
#[command(rename_all = "kebab-case", version, about)]
struct Opt {
    /// Device ID of the FPGA you want to use (if you got more than one)
    #[arg(short = 'd', long = "device", default_value = "0")]
    device_id: u32,

    /// Implementation name of a supported NIST PQC algorithm. Possible values: [kyber_hls, dilithium_hls, kyber_sw, dilithium_sw]
    #[arg(short = 'n', long = "name", value_name = "IMPLEMENTATION_NAME")]
    name: String,

    /// NIST Security Level. Possible Values depend on the selected algorithm
    #[arg(short = 'l', long = "level", default_value = "3")]
    level: u8,

    /// Print out JSON instead of an undefined plain text format
    #[arg(short = 'j', long = "json")]
    json: bool,

    /// Path for output file. If left out, print to `stdout`
    #[arg(short = 'o', long = "output")]
    output_path: Option<PathBuf>,

    #[clap(subcommand)]
    pub subcommand: Command,
}
#[derive(clap::Parser, Debug)]
enum Command {
    /// Print status core information of all devices
    Status {},
    /// KEM / DSA Keypair Generation
    Keypair {
        /// Path to a file, where keys are stored as hex-encoded key-value or JSON
        #[arg(short = 'f', long = "keyfile", value_name = "PATH")]
        keyfile_path: Option<PathBuf>,
    },
    /// KEM Encapsulation / DSA Signature generation
    Apply {
        /// Public key for KEM or secret key for DSA as hex-encoded string.
        #[arg(short = 'k', long = "key", conflicts_with = "keyfile_path")]
        key: Option<String>,
        /// Random data for KEM as hex-encoded string or message for DSA as string
        #[arg(short = 'd', long = "data")]
        data: Option<String>,
        /// Decode random data for KEM or message for DSA as hex-encoded string
        #[arg(short = 'x', long = "hex")]
        is_hex: bool,
        /// Path to a file, where keys are stored as JSON (as by `keypair` command)
        #[arg(
            short = 'f',
            long = "keyfile",
            value_name = "PATH",
            conflicts_with = "key"
        )]
        keyfile_path: Option<PathBuf>,
    },
    /// KEM Decapsulation / DSA Signature verification
    Verify {
        /// Secret key for KEM or public key for DSA as hex-encoded string
        #[arg(short = 'k', long = "key", conflicts_with = "keyfile_path")]
        key: Option<String>,
        /// Ciphertext for KEM or signed message for DSA as hex-encoded string
        #[arg(short = 'd', long = "data")]
        data: Option<String>,
        /// Decode random data for KEM or message for DSA as hex-encoded string
        #[arg(short = 'x', long = "hex")]
        is_hex: bool,
        /// Path to a file, where keys are stored as JSON (as by `keypair` command)
        #[arg(
            short = 'f',
            long = "keyfile",
            value_name = "PATH",
            conflicts_with = "key"
        )]
        keyfile_path: Option<PathBuf>,
    },
    /// Verify Known Answer Tests from a `PQC{kem,sign}KAT_*` file
    Kat {
        /// Skip invokation of the KEM Encapsulation / DSA Signing PE
        #[arg(long, default_value_t = false)]
        skip_apply: bool,
        /// Skip invokation of the KEM Decapsulation / DSA Verification PE
        #[arg(long, default_value_t = false)]
        skip_verify: bool,
        /// The `*.rsp` file containing the Known Answer Tests
        kat_filename: Option<String>,
    },
    Rng {
        /// Seed of the Random Number Generator used by `randombytes_init`
        seed: Option<String>,
    },
}

fn parse_args_and_run_command() -> Result<()> {
    let Opt {
        device_id,
        name,
        level,
        output_path,
        mut json,
        subcommand,
    } = Opt::parse();

    // Initialize TLKM
    let device_result = try_initialize_tapasco(device_id);
    // Postpone Tapasco error handling for later
    let device = device_result.as_ref().ok();

    // Get an implementation trait object from name and level cli parameters
    let algorithm = <dyn PqcAlgorithm>::new(&name, level).context(PqcSnafu {})?;

    // If the output path has a `.json` extension, set output format to json
    if let Some(ref path) = output_path {
        if let Some(e) = path.extension() {
            if e == "json" {
                json = true;
            }
        }
    }

    // Run the requested subcommand
    let res = match subcommand {
        Command::Status {} => subcommand_status(),

        Command::Keypair { keyfile_path } => {
            subcommand_keypair(device, &algorithm, keyfile_path, output_path, json)
        }
        Command::Apply {
            key,
            data,
            is_hex,
            keyfile_path,
        } => subcommand_apply(
            device,
            &algorithm,
            key,
            data,
            is_hex,
            keyfile_path,
            output_path,
            json,
        ),
        Command::Verify {
            key,
            data,
            is_hex,
            keyfile_path,
        } => subcommand_verify(
            device,
            &algorithm,
            key,
            data,
            is_hex,
            keyfile_path,
            output_path,
            json,
        ),

        // The `subcommand_kat` takes a true boolean value if the respective operation should be tested
        Command::Kat {
            kat_filename,
            skip_apply,
            skip_verify,
        } => subcommand_kat(
            device,
            &algorithm,
            kat_filename,
            !skip_apply,
            !skip_verify,
            output_path,
            json,
        ),

        Command::Rng { seed } => subcommand_rng(seed, output_path, json),
    };

    // Now handle TLKM error if there is one
    if let Err(t) = device_result {
        // Append the TaPaSCo error message to the ImplementationNeedsTapasco error, otherwise we
        // just ignore the TaPaSCo error, as it shouldn't be needed.
        match res {
            Ok(()) => Ok(()),
            Err(ref e) => match e {
                Error::Pqc {
                    source: tapasco_pqc_runtime::Error::ImplementationNeedsTapasco { .. },
                } => res.with_whatever_context(|e| format!("{e} {t}")),
                //Error::Pqc { source: tapasco_pqc_runtime::Error::ImplementationNeedsTapasco {} } => res.context(TLKMInitSnafu { source }),
                _ => res,
            },
        }
    } else {
        Ok(())
    }
}

fn main() {
    env_logger::init();

    match parse_args_and_run_command() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("error: {e}");

            if let Some(backtrace) = ErrorCompat::backtrace(&e) {
                eprintln!("{backtrace}");
            }

            std::process::exit(1);
        }
    };
}
