# EvtxECmd: Parses the EVTX file and outputs the results in CSV format.
# Volatility: Analyzes the memory image and outputs the process list in JSON format.
# RECmd: Parses the Registry hive and outputs the results in CSV format.

import subprocess
import os
import sys
import pandas as pd
from fpdf import FPDF
import json
from datetime import datetime
import os

def run_evtxecmd(evtx_file, output_dir):
    """
    Run EvtxECmd to parse EVTX files.
    """
    print("[*] Running EvtxECmd...")
    cmd = [
        "EvtxECmd\EvtxECmd.exe",
        "-d", evtx_file,
        "--csv", output_dir
    ]
    try:
        subprocess.run(cmd, check=True)
        print("[+] EvtxECmd completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] EvtxECmd failed: {e}")
        sys.exit(1)

def run_volatility(memory_image, output_dir):
    """
    Run Volatility to analyze memory.
    """
    print("[*] Running Volatility...")
    cmd = [
        "vol",
        "-f", memory_image,
        "windows.pslist.PsList",
        '-o', output_dir,
    ]
    try:
        # Redirect output to a file
        # with open(os.path.join(output_dir, "volatility_output.txt"), "w") as output_file:
        #     subprocess.run(cmd, stdout=output_file, stderr=subprocess.PIPE)
        subprocess.run(cmd, stderr=subprocess.PIPE)

        print("[+] Volatility completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] Volatility failed: {e}")
        sys.exit(1)

def run_recmd(registry_hive, output_dir):
    """
    Run RECmd to parse Registry hives.
    """
    print("[*] Running RECmd...")
    cmd = [
        "RECmd\RECmd.exe",
        "-d", registry_hive,
        "--csv", output_dir
        # One of the following switches is required: --sk | --sv | --sd | --ss | --kn | --Base64 | --MinSize | --bn
        # Need to identify what is needed above
    ]
    try:
        subprocess.run(cmd, check=True)
        print("[+] RECmd completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] RECmd failed: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 5:
        print("\nUsage: python combine_tools.py <evtx_file> <memory_image> <registry_hive> <output_dir>\n")
        print("<evtx_file>: Path to the EVTX file you want to analyze.",
              "<memory_image>: Path to the memory image file for Volatility.",
              "<registry_hive>: Path to the Registry hive file for RECmd.",
              "<output_dir>: Directory where the output files will be saved.\n", sep="\n")
        sys.exit(1)

    evtx_file = sys.argv[1]
    memory_image = sys.argv[2]
    registry_hive = sys.argv[3]
    output_dir = sys.argv[4]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Run EvtxECmd
    # run_evtxecmd(evtx_file, output_dir)

    # Run Volatility
    run_volatility(memory_image, output_dir)

    # Run RECmd
    run_recmd(registry_hive, output_dir)

    print("[+] All tools executed successfully.")

if __name__ == "__main__":
    main()