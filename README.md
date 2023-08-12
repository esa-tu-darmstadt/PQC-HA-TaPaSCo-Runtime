# TaPaSCo Post-Quantum Cryptography Runtime

A CLI  TaPaSCo runtime for Post-Quantum Cryptography PEs using `libtapasco` and
the NIST PQC Program interface.

## Building

The PQC Software Reference Implementations require a recent GCC version (4.8.5
is not recent enough). This application was tested with GCC 10.3.0.

With stable Rust installed, running `cargo build` should be all (verified with
Rust 1.56.1). Newer stable Rust versions _should_ work but nightly builds are
currently not possible due to a dependency of `libtapasco` failing to compile.

## Usage

See the other repos in this group and their pipelines to download a bitstream.

Setup TaPaSCo and load the bitstream with your PEs, i.e. for testing Kyber on all levels:

```
tapasco-load-bitstream --reload-driver axi4mm-vc709--kyber2_enc_1_kyber2_dec_1_kyber3_enc_1_kyber3_dec_1_kyber4_enc_1_kyber4_dec_1--100.0.bit
```

This has been tested with Vivado 2020.2 and TaPaSCo 2021.1. If you cannot
load a bitstream for the AU280, try Tapasco's `develop` branch that should
contain fixes for the changed device name in Vivado 2020.2.

Then run the application with:

```
cargo run --release -- --name kyber_hls --level 1 kat
```

which should result in the following output:

```
Tests: 100, Ciphertext equals KAT: 100, Shared Secret equals KAT: 100.
```

This uses the verified NIST Known Answer Test Response (.rsp) files created
with the reference _software_ implementation and creates a file with the same
name plus the `.tapasco` suffix that contains the outputs from the PEs and
should be equal to the original file.

Verify this with i.e. `diff` which should output nothing and return `0` exit code:

```
$ diff PQCkemKAT_1632.rsp{,.tapasco}
$ echo $?
0
```

Additional details can be shown with a higher log level by setting the
`RUST_LOG` environment variable to one of `error`, `warn` (default), `info`,
`debug` and `trace`. The `debug` and `trace` levels are only available in debug
builds (default for `cargo build` without `--release`).
The individual test case results can be show with the `info` level:

```
RUST_LOG=info cargo run --release -- --name kyber_hls --level 1 kat
```


## Troubleshooting

### GCC on CentOS 7

If the compilation fails because your GCC version is too old, install the
`devtools-10` with `yum` and `source /opt/rh/devtoolset-10/enable` and retry
compilation with `cargo build`.


### Tests fail

First make sure that you have loaded the correct bitstream successfully. Check
`dmesg` for errors.

Then you can try the subcommands `apply` and `verify` to test a single PE where
`apply` is the `encapsulation` for KEMs and `sign` for DSAs and `verify` is the
`decapsulation` and `verification` respectively.


### Slow performance results

Make sure to run the application in release mode with `cargo run --release ...`.
