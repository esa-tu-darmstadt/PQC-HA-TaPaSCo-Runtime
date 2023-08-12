#!/usr/bin/env python3

# Measure the latency/execution time of each PE in the bitstreams in the
# extracted dse_results using the `extract_dse_results.py` script.
# Important: Execute this in the Tapasco runtime directory!
# Arguments: <dir_containing_extracted_dse_results> <algorithm> <platform>
# Example: ../kyber/dse_results kyber vc709

import os
import sys
import json
import pathlib
import subprocess

tapasco_workspace_path = pathlib.Path("~/ws").expanduser()
sudo_password = "Nah, I won't commit my password.." # Everything is insecure.
vivado_settings = "/opt/cad/xilinx/vitis/Vivado/2020.2/settings64.sh"

runs = 1000
dse_dir = pathlib.Path(sys.argv[1])
algorithm = sys.argv[2]
platform = sys.argv[3]
#runs = int(sys.argv[4])

# Tapsco Workspace Setup: Source Vivado's `settings.sh`
print(f"Sourcing Vivado settings: {vivado_settings}")
pipe = subprocess.Popen(f". {vivado_settings}; env -0", stdout=subprocess.PIPE, shell=True)
output = pipe.communicate()[0].decode("utf-8")
env = dict((line.split('=', 1) for line in output.split('\x00')[:-1]))
os.environ.update(env)

# Tapsco Workspace Setup: Source `tapasco-setup.sh`
tapasco_setup = tapasco_workspace_path.joinpath('tapasco-setup.sh')
print(f"Sourcing Tapasco Setup: {tapasco_setup}")
pipe = subprocess.Popen(f". {tapasco_setup}; env -0", stdout=subprocess.PIPE, shell=True)
output = pipe.communicate()[0].decode("utf-8")
env = dict((line.split('=', 1) for line in output.split('\x00')[:-1]))
os.environ.update(env)

# Build runtime release binary with Cargo
cargo_build = subprocess.run(["cargo", "build", "--release"], check=True)

# Check for binary at expected location
runtime = pathlib.Path(".").joinpath("target/release/tapasco_pqc_runtime")
assert(runtime.exists())
print("Runtime built successfully in release mode.")

# Set RUST_LOG environment variable to "info" for Performance log ouput
os.environ['RUST_LOG'] = "info"

# Glob all DSE directories in the directory given on CLI
dses = dse_dir.glob(f"DSE_axi4mm-{platform}-*")

# Create report as list of dicts with all necessary info
report = list()

for dse in dses:
    print(f"Running PE from DSE: {dse}")

    # Open Tapasco Status Core information
    with open(dse.joinpath('tapasco_status.json')) as tapasco_status_json:
        tapasco_status = json.load(tapasco_status_json)
        # Get (first and only) PE Name
        vlnv = tapasco_status['Architecture']['Composition'][0]['VLNV']
        pe_name = vlnv.split(":")[2]
        print(f"PE Name: {pe_name}")

        # Determine runtime algorithm, level and operation from PE Name
        pe_op = pe_name.split("_")[-1]
        runtime_op = ""
        if pe_op == "enc" or pe_op == "sign":
            runtime_op = "apply"
        elif pe_op == "dec" or pe_op == "verify":
            runtime_op = "verify"
        else:
            raise f"Unknown PE Operation: {pe_op}"

        level = pe_name.split("_")[0].split(algorithm)[1]
        # Fix level for Kyber [2,3,4] -> [1,3,5]
        if algorithm == "kyber":
            if level == "2":
                level = "1"
            elif level == "4":
                level = "5"

        print(f"Operation: {pe_op}, Level: {level}")

        # Determine path to bitstream to load
        bitstream_path = next(dse.glob('*.bit'))
        print(f"Loading Bitstream from Path: {bitstream_path}")

        # Unlock sudo to run `tapasco-load-bitstream` within sudo timeout
        # This line needs to use Popen directly for the sudo stdin to work:
        print("Activating sudo..")
        echo = subprocess.Popen(["echo", f"{sudo_password}"], stdout=subprocess.PIPE)
        sudo = subprocess.run(["sudo", "-S", "echo", "Ok"], capture_output=True, stdin=echo.stdout, check=True)
        assert(sudo.stdout == b"Ok\n")

        # Load Bitstream
        print("Programming FPGA..")
        tapasco_load_bitstream = subprocess.run(
                f"tapasco-load-bitstream --verbose --reload-driver {bitstream_path}",
                #["tapasco-load-bitstream", "--verbose", "--reload-driver", f"{bitstream_path}"],
                #stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, check=True)
                capture_output=True, shell=True, check=True)
        print(tapasco_load_bitstream.stdout)
        print(tapasco_load_bitstream.stderr)
        assert(b"tlkm loaded successfully" in tapasco_load_bitstream.stdout)
        print("FPGA programmed and TLKM loaded successfully.")

        # Run the PE Operation a few times to sort out statistical outliers
        stats = { 'Run': [], 'PE Start': [], 'PE Wait': [], 'PE Release': [] }
        #print(f"Stats: {stats}")
        command = [runtime, "-n", f"{algorithm}_hls", f"-l{level}", runtime_op]
        print(f"Running runtime command `{str(command)}` with {runs} runs.")

        for i in range(runs):
            # Call runtime and capture RUST_LOG in stderr
            pe_run = subprocess.run(command, capture_output=True, check=True)
            #print(f"PE Run stderr: {pe_run.stderr}")

            # Grep through RUST_LOG for Performance
            performance_log = [line for line in pe_run.stderr.decode("utf-8").splitlines() if "Performance:" in line]
            #print(f"Performance log lines: {performance_log}")

            # Parse PE Start, Wait and Release time
            pe_lines = [line[-24:] for line in performance_log]
            pe_result = dict((line.split(':', 1) for line in pe_lines))
            #print(f"PE Result: {pe_result}")

            # Save result of this PE Operation as dict with keys (PE Start, PE Wait, PE Release) and the time in ns as value
            pe_stats = { key:value.split("ns")[0].strip(" ") for (key, value) in pe_result.items() }
            # Set an index for this run
            pe_stats['Run'] = i
            #print(f"Run Result: {pe_stats}")

            # Append to stats
            for key in stats.keys():
                stats[key].append(pe_stats[key])


        result = {
            'Platform': platform,
            'DSE Path': str(dse),
            'Algorithm': algorithm,
            'PE Name': pe_name,
            'Runs': runs,
            'Stats': stats
        }

        report.append(result)

# Export report as JSON
with open(f"runtime_report_hls_{platform}_{algorithm}.json", 'w', encoding='utf-8') as output_json:
    json.dump(report, output_json)

print("Finished.")

