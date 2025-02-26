# EvtxECmd: Parses the EVTX file and outputs the results in CSV format.
# Volatility: Analyzes the memory image and dumps the evtx logs and registry artifacts.
# RECmd: Parses the Registry hive and outputs the results in CSV format.

import time
import subprocess
import os
import sys
from datetime import datetime
import pandas as pd
import json
import glob

def run_evtxecmd(evtx_file, output_dir):
    """
    Run EvtxECmd to parse EVTX files.
    """
    print("[*] Running EvtxECmd...")
    cmd = [
        "EvtxECmd\\EvtxECmd.exe",
        "-d", evtx_file,
        "--csv", output_dir
    ]
    try:
        subprocess.run(cmd, check=True)
        print("[+] EvtxECmd completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] EvtxECmd failed: {e}")
        sys.exit(1)

def run_volatility(memory_image, output_dir, profile="Win7SP1x64"):
    """
    Run Volatility to analyze memory and save output in CSV format.
    """

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs("artifacts/dumpfiles", exist_ok=True)

    filescan_path = "artifacts/filescan.json"

    # Check if the file exists and remove it
    if os.path.exists(filescan_path):
        os.remove(filescan_path)
    
    print("[*] Running Volatility 2.6 Memory Analysis...")

    plugins = {
        "Image Information": ["imageinfo"],
        "Registry Hives": ["hivelist"],
        "Dump Registry": ["dumpregistry", "-D", "artifacts"],
        # "Dump EVTX Files": ["dumpfiles", "-r", "\\.evtx", "-D", "artifacts"],
        "File Scan": ["filescan", "--output=json", "--output-file=artifacts/filescan.json"],
    }
    
    for desc, plugin in plugins.items():
        output_txt_file = os.path.join(output_dir, f"{plugin[0]}.txt")
        cmd = ["volatility_2.6\\volatility_2.6.exe", "-f", memory_image, "--profile=" + profile] + plugin
        
        try:
            print(f"[*] Running {desc} Analysis...")
            with open(output_txt_file, "w") as out:
                subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, check=True)
            print(f"[+] {desc} Analysis Completed. Output saved to {output_txt_file}")

            if desc == "File Scan":
                offsets = extract_evtx_offsets(filescan_path)

                for offset in offsets:
                    cmd = [
                        "volatility_2.6/volatility_2.6.exe",  
                        "-f", memory_image,
                        "--profile=" + profile,
                        "dumpfiles",
                        "-Q", hex(offset),  # Specify the offset of the .evtx file
                        "-D", "artifacts/dumpfiles",  # Output directory for dumped files
                    ]
                    try:
                        print(f"[*] Dumping EVTX file at offset {offset}...")
                        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
                        print(f"[+] Successfully dumped EVTX file at offset {offset}.")
                    except subprocess.CalledProcessError as e:
                        print(f"[-] Failed to dump EVTX file at offset {offset}: {e.stderr.decode()}")
                                
        except subprocess.CalledProcessError as e:
            print(f"[-] {desc} Analysis Failed: {e.stderr.decode()}")


def extract_evtx_offsets(json_file):
    """
    Extracts offsets of .evtx files from a Volatility JSON output.
    """
    evtx_offsets = []

    # Load the JSON file
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    # Iterate over the parsed JSON data
    for row in data["rows"]:
        offset = row[0]  # Offset is the first element
        file_path = row[4]  # File path is the last element

        # Check if the file path contains ".evtx"
        if ".evtx" in file_path.lower():
            evtx_offsets.append(offset)

    return evtx_offsets


def rename_and_move_evtx_files():
    """Rename valid EVTX files and move them to a separate directory."""

    for filename in os.listdir("artifacts/dumpfiles"):
        if filename.startswith("file.None.") and (filename.endswith(".dat") or filename.endswith(".vacb")):
            filepath = os.path.join("artifacts/dumpfiles", filename)
            
            new_filename = filename + ".evtx"
            new_filepath = os.path.join("artifacts", new_filename)
            
            os.rename(filepath, new_filepath)
            # os.remove(filepath)
            # print(f"[+] Renamed and moved: {filename} -> {new_filepath}")
           

def run_recmd(registry_hive, output_dir):
    """
    Run RECmd to parse Registry hives.
    """
    print("[*] Running RECmd...")
    cmd = [
        "RECmd\\RECmd.exe",
        "-d", registry_hive,
        "--bn", "DFIRBatch.reb",
        "--csv", output_dir
    ]
    try:
        subprocess.run(cmd, shell=True, check=True)
        print("[+] RECmd completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[-] RECmd failed: {e}")
        sys.exit(1)

def rename_and_move_evtx_files():
    """Rename valid EVTX files and move them to a separate directory."""
    evtx_dir = "artifacts"
    dump_dir = "artifacts/dumpfiles"

    os.makedirs(evtx_dir, exist_ok=True)  # Ensure destination directory exists

    for filename in os.listdir(dump_dir):
        if filename.startswith("file.None.") and (filename.endswith(".dat") or filename.endswith(".vacb")):
            filepath = os.path.join(dump_dir, filename)
            new_filename = filename + ".evtx"
            new_filepath = os.path.join(evtx_dir, new_filename)

            # If the destination file already exists, rename it or delete it before moving
            if os.path.exists(new_filepath):
                print(f"[!] File {new_filepath} already exists. Deleting and replacing it.")
                os.remove(new_filepath)  # Remove the existing file

            os.rename(filepath, new_filepath)
            print(f"[+] Renamed and moved: {filename} -> {new_filepath}")


def merge_forensic_data(output_dir):
    """
    Merges outputs from all tools into a single CSV file with flexible column handling.
    """
    print("[*] Merging forensic data outputs...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_csv_path = os.path.join(output_dir, f"forensic_analysis_{timestamp}.csv")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Find all relevant CSV files
        csv_files = glob.glob(os.path.join(output_dir, "*.csv"))
        all_dfs = []
        
        for file in csv_files:
            try:
                df = pd.read_csv(file)
                df['Source_File'] = os.path.basename(file)  # Track source of data
                all_dfs.append(df)
                print(f"[+] Loaded {file} with columns: {df.columns.tolist()}")
            except Exception as e:
                print(f"[-] Error loading {file}: {e}")
        
        if not all_dfs:
            print("[-] No data found to merge")
            return False
        
        # Merge all data into one DataFrame
        merged_df = pd.concat(all_dfs, ignore_index=True, sort=False)
        
        # Save merged data to a single CSV file
        merged_df.to_csv(output_csv_path, index=False)
        print(f"[+] Merged forensic data saved to {output_csv_path}")
        return True
    
    except Exception as e:
        print(f"[-] Error merging data: {str(e)}")
        return False



def main():
    if len(sys.argv) != 5:
        print("\nUsage: python combine_tools.py <evtx_file> <memory_image> <registry_hive> <output_dir>\n")
        print("<evtx_file>: Path to the EVTX file you want to analyze.",
              "<memory_image>: Path to the memory image file for Volatility.",
              "<registry_hive>: Path to the Registry hive file for RECmd.",
              "<output_dir>: Directory where the output files will be saved.\n", sep="\n")
        sys.exit(1)

    start_time = time.time()  # Start time

    evtx_file = sys.argv[1]
    memory_image = sys.argv[2]
    registry_hive = sys.argv[3]
    output_dir = sys.argv[4]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Run Volatility
    run_volatility(memory_image, output_dir)
    rename_and_move_evtx_files()

    # Run EvtxECmd
    run_evtxecmd(evtx_file, output_dir)

    # Run RECmd
    run_recmd(registry_hive, output_dir)

    # Merge the results
    merge_forensic_data(output_dir)

    end_time = time.time()  # End time
    elapsed_time = end_time - start_time

    print(f"[+] All tools executed successfully in {elapsed_time:.2f} seconds.")

if __name__ == "__main__":
    main()