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


def export_to_pdf(output_dir, report_name="forensic_analysis_report.pdf"):
    """
    Export analysis results from CSV and JSON files to a structured PDF report.
    
    Args:
        output_dir (str): Directory containing the analysis output files
        report_name (str): Name of the output PDF file
    """
    class PDF(FPDF):
        def header(self):
            # Header with logo and title
            self.set_font('Arial', 'B', 15)
            self.cell(0, 10, 'Forensic Analysis Report', 0, 1, 'C')
            self.ln(10)
            
        def footer(self):
            # Footer with page number
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_section_header(pdf, title):
        pdf.set_font('Arial', 'B', 12)
        pdf.set_fill_color(200, 200, 200)
        pdf.cell(0, 10, title, 0, 1, 'L', fill=True)
        pdf.ln(5)

    def add_table(pdf, data, headers):
        # Configure table settings
        pdf.set_font('Arial', 'B', 9)
        col_width = pdf.w / len(headers) - 10
        row_height = 6
        
        # Add headers
        for header in headers:
            pdf.cell(col_width, row_height, str(header), 1)
        pdf.ln(row_height)
        
        # Add data
        pdf.set_font('Arial', '', 8)
        for row in data:
            for item in row:
                pdf.cell(col_width, row_height, str(item)[:30], 1)
            pdf.ln(row_height)

    # Create PDF object
    pdf = PDF()
    pdf.add_page()
    
    # Add report metadata
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
    pdf.cell(0, 10, f'Source Directory: {output_dir}', 0, 1)
    pdf.ln(10)

    # Process EvtxECmd CSV output
    evtx_files = [f for f in os.listdir(output_dir) if f.endswith('_EvtxECmd.csv')]
    if evtx_files:
        add_section_header(pdf, 'Windows Event Log Analysis')
        for file in evtx_files:
            try:
                df = pd.read_csv(os.path.join(output_dir, file))
                # Select important columns
                important_cols = ['TimeCreated', 'EventId', 'Channel', 'Computer', 'Message']
                display_df = df[important_cols].head(20)  # Limit to first 20 entries
                
                pdf.set_font('Arial', '', 10)
                pdf.cell(0, 10, f'Source: {file}', 0, 1)
                add_table(pdf, display_df.values.tolist(), important_cols)
                pdf.ln(10)
            except Exception as e:
                pdf.cell(0, 10, f'Error processing {file}: {str(e)}', 0, 1)

    # Process Volatility JSON output
    volatility_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]
    if volatility_files:
        add_section_header(pdf, 'Memory Analysis')
        for file in volatility_files:
            try:
                with open(os.path.join(output_dir, file), 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        # Extract process information
                        process_data = [[p.get('PID', ''), p.get('PPID', ''), 
                                       p.get('ImageFileName', ''), p.get('CreateTime', '')] 
                                      for p in data]
                        headers = ['PID', 'PPID', 'Process Name', 'Create Time']
                        add_table(pdf, process_data[:20], headers)  # Limit to first 20 processes
                pdf.ln(10)
            except Exception as e:
                pdf.cell(0, 10, f'Error processing {file}: {str(e)}', 0, 1)

    # Process RECmd CSV output
    recmd_files = [f for f in os.listdir(output_dir) if f.endswith('_RECmd.csv')]
    if recmd_files:
        add_section_header(pdf, 'Registry Analysis')
        for file in recmd_files:
            try:
                df = pd.read_csv(os.path.join(output_dir, file))
                # Select important columns
                important_cols = ['KeyPath', 'ValueName', 'ValueData', 'LastWriteTimestamp']
                display_df = df[important_cols].head(20)  # Limit to first 20 entries
                
                pdf.set_font('Arial', '', 10)
                pdf.cell(0, 10, f'Source: {file}', 0, 1)
                add_table(pdf, display_df.values.tolist(), important_cols)
                pdf.ln(10)
            except Exception as e:
                pdf.cell(0, 10, f'Error processing {file}: {str(e)}', 0, 1)

    # Save the PDF
    output_path = os.path.join(output_dir, report_name)
    pdf.output(output_path)
    print(f"[+] PDF report generated successfully: {output_path}")

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
    try:
        export_to_pdf(output_dir)
    except Exception as e:
        print(f"An error occurec: {e}")

    print("[+] All tools executed successfully.")

if __name__ == "__main__":
    main()