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
    os.makedirs(output_dir, exist_ok=True)
    print("[*] Running Volatility 2.6 Memory Analysis...")

    plugins = {
        "Image Information": ["imageinfo"],
        "Registry Hives": ["hivelist"],
        "Dump Registry": ["dumpregistry", "-D", "artifacts"],
        "Dump Files": ["dumpfiles", "-r=.extx", "-D", "artifacts"],
    }
    
    for desc, plugin in plugins.items():
        output_txt_file = os.path.join(output_dir, f"{plugin[0]}.txt")
        cmd = ["volatility_2.6\\volatility_2.6.exe", "-f", memory_image, "--profile=" + profile] + plugin
        
        try:
            print(f"[*] Running {desc} Analysis...")
            with open(output_txt_file, "w") as out:
                subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, check=True)
            print(f"[+] {desc} Analysis Completed. Output saved to {output_txt_file}")
        except subprocess.CalledProcessError as e:
            print(f"[-] {desc} Analysis Failed: {e.stderr.decode()}")

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
    Merges outputs from all tools into organized Excel and CSV files.
    """
    print("[*] Merging forensic data outputs...")
    
    try:
        # Find the most recent CSV files for each tool
        evtx_files = glob.glob(os.path.join(output_dir, "*EvtxECmd*.csv"))
        vol_files = glob.glob(os.path.join(output_dir, "imageinfo.txt"))  # Adjust based on actual output
        reg_files = glob.glob(os.path.join(output_dir, "*RECmd*.csv"))
        
        # Load EVTX data
        evtx_df = pd.DataFrame()
        if evtx_files:
            evtx_df = pd.read_csv(evtx_files[0])
            evtx_df['Data_Source'] = 'EVTX'
        
        # Load Volatility data (adjust parsing based on actual output format)
        vol_df = pd.DataFrame()
        if vol_files:
            with open(vol_files[0], 'r') as f:
                # Parse the text file into a structured format
                # This will need to be adjusted based on actual output format
                vol_data = f.readlines()
                # Add basic parsing logic here
                vol_df = pd.DataFrame(vol_data, columns=['Raw_Data'])
                vol_df['Data_Source'] = 'Memory'
        
        # Load Registry data
        reg_df = pd.DataFrame()
        if reg_files:
            reg_df = pd.read_csv(reg_files[0])
            reg_df['Data_Source'] = 'Registry'
        
        # Create multi-sheet Excel output
        output_xlsx = os.path.join(output_dir, "forensic_analysis_combined.xlsx")
        with pd.ExcelWriter(output_xlsx) as writer:
            if not evtx_df.empty:
                evtx_df.to_excel(writer, sheet_name='EVTX_Events', index=False)
            if not vol_df.empty:
                vol_df.to_excel(writer, sheet_name='Memory_Analysis', index=False)
            if not reg_df.empty:
                reg_df.to_excel(writer, sheet_name='Registry_Data', index=False)
        
        # Create unified timeline CSV
        # Select and standardize relevant columns from each source
        timeline_entries = []
        
        if not evtx_df.empty:
            evtx_selected = evtx_df[['TimeCreated', 'EventID', 'Message']].copy()
            evtx_selected['Source'] = 'EVTX'
            timeline_entries.append(evtx_selected)
        
        if not vol_df.empty:
            # Adjust column selection based on actual Volatility output
            vol_selected = vol_df[['Raw_Data']].copy()
            vol_selected['Source'] = 'Memory'
            timeline_entries.append(vol_selected)
        
        if not reg_df.empty:
            reg_selected = reg_df[['LastWriteTime', 'KeyPath', 'ValueName']].copy()
            reg_selected['Source'] = 'Registry'
            timeline_entries.append(reg_selected)
        
        if timeline_entries:
            combined_timeline = pd.concat(timeline_entries, ignore_index=True)
            combined_timeline.to_csv(os.path.join(output_dir, "forensic_timeline.csv"), index=False)
        
        print(f"[+] Data merger completed. Outputs saved to {output_dir}")
        return True
    
    except Exception as e:
        print(f"[-] Error merging data: {str(e)}")
        return False

def main():
    if len(sys.argv) != 5:
        print("\nUsage: python forensics_analyzer.py <evtx_file> <memory_image> <registry_hive> <output_dir>\n")
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

    # Run analysis tools
    run_volatility(memory_image, output_dir)
    run_evtxecmd(evtx_file, output_dir)
    run_recmd(registry_hive, output_dir)

    # Merge the results
    merge_forensic_data(output_dir)

    print("[+] Analysis and merger completed successfully.")

if __name__ == "__main__":
    main()