#!/usr/bin/env python3

# Measure the execution time of each Software Implementation.
# Important: Execute this in the Tapasco runtime directory!

import os
import sys
import json
import pathlib
import subprocess

runs = 1000
platform = "avx2"
software_impls = [
        { 'Name': "kyber", 'Operations': ["Encapsulate", "Decapsulate"], 'Levels': [1, 3, 5] },
        { 'Name': "dilithium", 'Operations': ["Sign", "Verify"], 'Levels': [2, 3, 5] },
]

# Build runtime release binary with Cargo
cargo_build = subprocess.run(["cargo", "build", "--release"], check=True)

# Check for binary at expected location
runtime = pathlib.Path(".").joinpath("target/release/tapasco_pqc_runtime")
assert(runtime.exists())
print("Runtime built successfully in release mode.")

# Set RUST_LOG environment variable to "info" for Performance log ouput
os.environ['RUST_LOG'] = "info"

# Create report as list of dicts with all necessary info
report = list()

for impl in software_impls:
    algorithm = impl['Name']

    for level in impl['Levels']:
        for operation in impl['Operations']:
            runtime_op = "apply" if operation == "Encapsulate" or operation == "Sign" else "verify"
            print(f"Running Software Implementation for: {algorithm}, operation: {operation} on level: {level}")

            # Run the Software Operation a few times to sort out statistical outliers
            stats = { 'Run': [], 'Software': [] }
            #print(f"Stats: {stats}")
            command = [runtime, "-n", f"{algorithm}_sw", f"-l{level}", runtime_op]
            print(f"Running runtime command `{str(command)}` with {runs} runs.")

            for i in range(runs):
                # Call runtime and capture RUST_LOG in stderr
                run = subprocess.run(command, capture_output=True, check=True)
                #print(f"Run stderr: {run.stderr}")

                # Grep through RUST_LOG for Performance
                performance_log = [line for line in run.stderr.decode("utf-8").splitlines() if "Performance:" in line]
                #print(f"Performance log lines: {performance_log}")

                # Parse PE Start, Wait and Release time
                lines = [line[-24:] for line in performance_log]
                result = dict((line.split(':', 1) for line in lines))
                #print(f"Result: {result}")

                # Save result of this Software Operation as dict with key Software and the time in ns as value
                stat = { key:value.split("ns")[0].strip(" ") for (key, value) in result.items() }
                # Set an index for this run
                stat['Run'] = i
                #print(f"Run Result: {stat}")

                # Append to stats
                for key in stats.keys():
                    stats[key].append(stat[key])


            result = {
                'Algorithm': algorithm,
                'Level': level,
                'Operation': operation,
                'Runs': runs,
                'Stats': stats
            }

            report.append(result)

# Export report as JSON
with open(f"runtime_report_sw_{platform}.json", 'w', encoding='utf-8') as output_json:
    json.dump(report, output_json)

print("Finished.")

