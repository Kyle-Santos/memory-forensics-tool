# EvtxECmd: Parses the EVTX file and outputs the results in CSV format.
# Volatility: Analyzes the memory image and outputs the process list in JSON format.
# RECmd: Parses the Registry hive and outputs the results in CSV format.

import subprocess
import os
import sys
import pandas as pd
from datetime import datetime

def run_as_admin(cmd):
    """
    Run a command with administrator privileges
    """
    import ctypes
    import sys
    import subprocess

    if sys.platform != 'win32':
        raise OSError("This function is only supported on Windows")

    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    if is_admin():
        # Already running as admin, run command directly
        return subprocess.run(cmd, check=True)
    else:
        # Re-run the command with elevated privileges
        ctypes.windll.shell32.ShellExecuteW(
            None,           # handle to parent window
            "runas",       # operation to perform
            sys.executable,  # program to run
            ' '.join(cmd), # parameters
            None,          # default directory
            1              # show window normally
        )

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

def run_volatility(memory_image, output_dir, profile="Win7SP1x64"):
    """
    Run Volatility to analyze memory.
    """

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    print("[*] Running Volatility 2.6 Memory Analysis...")
    
    plugins = {
        "Process List": ["pslist"],
        "Process Tree": ["pstree"],
        "Process Scanning": ["psscan"],
        "Network Connections": ["connections"],
        "Open Sockets": ["sockets"],
        "Registry Hives": ["hivelist"],
        "Registry Key - Terminal Server": ["printkey", "-K", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"],
        "Registry Key - Run Persistence": ["printkey", "-K", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
        "Command History": ["cmdscan"],
        "Console Output": ["consoles"],
        "File Scan": ["filescan"],
    }
    
    for desc, plugin in plugins.items():
        output_file = os.path.join(output_dir, f"{plugin[0]}.txt")
        cmd = [".\volatility_2.6_win64_standalone\volatility_2.6_win64_standalone.exe", "-f", memory_image, "--profile=" + profile] + plugin
        
        try:
            print(f"[*] Running {desc} Analysis...")
            with open(output_file, "w") as out:
                subprocess.run(cmd, stdout=out, stderr=subprocess.PIPE, check=True)
            print(f"[+] {desc} Analysis Completed. Output saved to {output_file}")
        
        except subprocess.CalledProcessError as e:
            print(f"[-] {desc} Analysis Failed: {e.stderr.decode()}")

def run_recmd(registry_hive, output_dir):
    """
    Run RECmd to parse Registry hives with elevated privileges.
    """
    print("[*] Running RECmd...")
    
    # Create the individual folder path inside output directory
    individual_path = os.path.join(output_dir, "Individual")
    os.makedirs(individual_path, exist_ok=True)
    
    # Construct the command
    cmd = [
        r"RECmd\\RECmd.exe",
        "-d", registry_hive,
        "--bn", r"RECmd\BatchExamples\UserActivity.reb",
        "--csv", individual_path,
        "--csvf", "recmd.csv"
    ]
    
    try:
        print(f"[*] Attempting to run RECmd with elevated privileges...")
        run_as_admin(cmd)
        print("[+] RECmd completed successfully.")
    except Exception as e:
        print(f"[-] RECmd failed: {e}")
        print("    If prompted, please allow the program to run with administrative privileges")
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
    # run_volatility(memory_image, output_dir)

    # Run RECmd
    run_recmd(registry_hive, output_dir)

    print("[+] All tools executed successfully.")

if __name__ == "__main__":
    main()