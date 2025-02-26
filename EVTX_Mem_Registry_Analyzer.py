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

def merge_forensic_data(output_dir):
    """
    Merges outputs from all tools into organized Excel and CSV files with flexible column handling.
    """
    print("[*] Merging forensic data outputs...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        # Find relevant files
        evtx_files = glob.glob(os.path.join(output_dir, "*EvtxECmd*.csv"))
        reg_files = glob.glob(os.path.join(output_dir, "*RECmd*.csv"))
        
        all_dfs = []
        
        # Load EVTX data if available
        if evtx_files:
            try:
                evtx_df = pd.read_csv(evtx_files[0])
                evtx_df['Data_Source'] = 'EVTX'
                all_dfs.append(evtx_df)
                print(f"[+] Loaded EVTX data with columns: {evtx_df.columns.tolist()}")
            except Exception as e:
                print(f"[-] Error loading EVTX data: {e}")
        
        # Load Registry data if available
        if reg_files:
            try:
                reg_df = pd.read_csv(reg_files[0])
                reg_df['Data_Source'] = 'Registry'
                all_dfs.append(reg_df)
                print(f"[+] Loaded Registry data with columns: {reg_df.columns.tolist()}")
            except Exception as e:
                print(f"[-] Error loading Registry data: {e}")
        
        if not all_dfs:
            print("[-] No data found to merge")
            return False
        
        # Create outputs directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Save individual sheets
        excel_output = os.path.join(output_dir, f"forensic_analysis_{timestamp}.xlsx")
        with pd.ExcelWriter(excel_output) as writer:
            for i, df in enumerate(all_dfs):
                sheet_name = f"Data_Source_{i}"
                try:
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                    print(f"[+] Saved sheet {sheet_name}")
                except Exception as e:
                    print(f"[-] Error saving sheet {sheet_name}: {e}")

            # Save forensic timeline as a new sheet
            if timeline_entries:
                try:
                    combined_timeline.to_excel(writer, sheet_name="Forensic_Timeline", index=False)
                    print("[+] Saved forensic timeline as 'Forensic_Timeline' sheet")
                except Exception as e:
                    print(f"[-] Error saving forensic timeline: {e}")

        
        # Create combined timeline based on available columns
        try:
            # Initialize empty lists for timeline entries
            timeline_entries = []
            
            for df in all_dfs:
                # Create a copy of the dataframe for timeline
                timeline_df = df.copy()
                
                # Try to identify time-related columns
                time_columns = [col for col in df.columns if any(time_word in col.lower() 
                    for time_word in ['time', 'date', 'created', 'modified', 'accessed'])]
                
                # Try to identify description or message columns
                desc_columns = [col for col in df.columns if any(desc_word in col.lower() 
                    for desc_word in ['message', 'description', 'details', 'data', 'value', 'path'])]
                
                if time_columns:
                    # Use the first time column found
                    timeline_df['Timestamp'] = timeline_df[time_columns[0]]
                else:
                    timeline_df['Timestamp'] = pd.Timestamp.now()
                
                if desc_columns:
                    # Use the first description column found
                    timeline_df['Description'] = timeline_df[desc_columns[0]]
                else:
                    # Create a description from all available columns
                    timeline_df['Description'] = timeline_df.apply(
                        lambda x: ' | '.join(f"{k}: {v}" for k, v in x.items() if k != 'Data_Source'), 
                        axis=1
                    )
                
                # Select only necessary columns for timeline
                timeline_df = timeline_df[['Timestamp', 'Description', 'Data_Source']]
                timeline_entries.append(timeline_df)
            
            # Combine all timeline entries
            if timeline_entries:
                combined_timeline = pd.concat(timeline_entries, ignore_index=True)
                # Try to convert timestamp to datetime if it's not already
                try:
                    combined_timeline['Timestamp'] = pd.to_datetime(combined_timeline['Timestamp'])
                    combined_timeline = combined_timeline.sort_values('Timestamp')
                except Exception as e:
                    print(f"[-] Error converting timestamps: {e}")
                
                timeline_output = os.path.join(output_dir, f"forensic_timeline_{timestamp}.csv")
                combined_timeline.to_csv(timeline_output, index=False)
                print(f"[+] Created combined timeline at {timeline_output}")
        
        except Exception as e:
            print(f"[-] Error creating timeline: {e}")
        
        print(f"[+] Data merger completed. Outputs saved to {output_dir}")
        return True
    
    except Exception as e:
        print(f"[-] Error merging data: {str(e)}")
        return False




def main():
    if len(sys.argv) != 5:
        print("\nUsage: python EVTX_Mem_Registry_Analyzer.py <evtx_artifacts> <memory_image> <registry_artifacts> <output_dir>\n")
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