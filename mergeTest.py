import subprocess
import os
import sys
from datetime import datetime
import pandas as pd
import json
import glob

def run_evtxecmd(evtx_file, output_dir):
    """
    Run EvtxECmd to parse EVTX files and capture output.
    """
    print("[*] Running EvtxECmd...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"evtx_output_{timestamp}.csv")
    
    cmd = [
        "EvtxECmd\\EvtxECmd.exe",
        "-f", evtx_file,
        "--csv", output_file
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open(os.path.join(output_dir, f"evtx_log_{timestamp}.txt"), 'w') as f:
            f.write(result.stdout)
        print(f"[+] EvtxECmd completed successfully. Output saved to {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"[-] EvtxECmd failed: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)

def run_volatility(memory_image, output_dir, profile="Win7SP1x64"):
    """
    Run Volatility to analyze memory and capture output.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    print("[*] Running Volatility 2.6 Memory Analysis...")

    outputs = {}
    plugins = {
        "imageinfo": [],
        "pslist": [],
        "hivelist": [],
        "filescan": []
    }
    
    for plugin_name, plugin_args in plugins.items():
        output_file = os.path.join(output_dir, f"vol_{plugin_name}_{timestamp}.json")
        cmd = ["volatility_2.6\\volatility_2.6.exe", 
               "-f", memory_image, 
               "--profile=" + profile,
               plugin_name,
               "--output=json",
               "--output-file=" + output_file] + plugin_args
        
        try:
            print(f"[*] Running {plugin_name} analysis...")
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            outputs[plugin_name] = output_file
            print(f"[+] {plugin_name} completed. Output saved to {output_file}")
        except subprocess.CalledProcessError as e:
            print(f"[-] {plugin_name} failed: {e.stderr}")
            continue
    
    return outputs

def run_recmd(registry_hive, output_dir):
    """
    Run RECmd to parse Registry hives and capture output.
    """
    print("[*] Running RECmd...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"registry_output_{timestamp}.csv")
    
    cmd = [
        "RECmd\\RECmd.exe",
        "-f", registry_hive,
        "--bn", "DFIRBatch.reb",
        "--csv", output_file
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open(os.path.join(output_dir, f"recmd_log_{timestamp}.txt"), 'w') as f:
            f.write(result.stdout)
        print(f"[+] RECmd completed successfully. Output saved to {output_file}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"[-] RECmd failed: {e}")
        print(f"Error output: {e.stderr}")
        sys.exit(1)

def merge_forensic_data(evtx_output, vol_outputs, reg_output, output_dir):
    """
    Merges outputs from all tools into organized Excel and CSV files.
    """
    print("[*] Merging forensic data outputs...")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        # Load EVTX data
        evtx_df = pd.read_csv(evtx_output) if evtx_output else pd.DataFrame()
        if not evtx_df.empty:
            evtx_df['Data_Source'] = 'EVTX'
        
        # Load Volatility data
        vol_dfs = {}
        for plugin_name, output_file in vol_outputs.items():
            try:
                with open(output_file, 'r') as f:
                    vol_data = json.load(f)
                vol_dfs[plugin_name] = pd.DataFrame(vol_data)
                vol_dfs[plugin_name]['Data_Source'] = f'Memory_{plugin_name}'
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Warning: Could not load Volatility {plugin_name} data: {e}")
        
        # Load Registry data
        reg_df = pd.read_csv(reg_output) if reg_output else pd.DataFrame()
        if not reg_df.empty:
            reg_df['Data_Source'] = 'Registry'
        
        # Create multi-sheet Excel output
        excel_output = os.path.join(output_dir, f"forensic_analysis_{timestamp}.xlsx")
        with pd.ExcelWriter(excel_output) as writer:
            if not evtx_df.empty:
                evtx_df.to_excel(writer, sheet_name='EVTX_Events', index=False)
            
            for plugin_name, df in vol_dfs.items():
                if not df.empty:
                    df.to_excel(writer, sheet_name=f'Memory_{plugin_name}', index=False)
            
            if not reg_df.empty:
                reg_df.to_excel(writer, sheet_name='Registry_Data', index=False)
        
        # Create timeline CSV
        timeline_entries = []
        
        # Add EVTX events
        if not evtx_df.empty:
            evtx_timeline = evtx_df[['TimeCreated', 'EventID', 'Message']].copy()
            evtx_timeline['Source'] = 'EVTX'
            timeline_entries.append(evtx_timeline)
        
        # Add Volatility process data
        if 'pslist' in vol_dfs and not vol_dfs['pslist'].empty:
            vol_timeline = vol_dfs['pslist'][['start_time', 'process_name', 'pid']].copy()
            vol_timeline['Source'] = 'Memory_Process'
            timeline_entries.append(vol_timeline)
        
        # Add Registry data
        if not reg_df.empty:
            reg_timeline = reg_df[['LastWriteTime', 'KeyPath', 'ValueName']].copy()
            reg_timeline['Source'] = 'Registry'
            timeline_entries.append(reg_timeline)
        
        if timeline_entries:
            timeline_output = os.path.join(output_dir, f"forensic_timeline_{timestamp}.csv")
            combined_timeline = pd.concat(timeline_entries, ignore_index=True)
            combined_timeline.to_csv(timeline_output, index=False)
        
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

    # Run tools and capture their outputs
    evtx_output = run_evtxecmd(evtx_file, output_dir)
    vol_outputs = run_volatility(memory_image, output_dir)
    reg_output = run_recmd(registry_hive, output_dir)

    # Merge the results
    merge_forensic_data(evtx_output, vol_outputs, reg_output, output_dir)

    print("[+] Analysis and merger completed successfully.")

if __name__ == "__main__":
    main()