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



def export_to_pdf(output_dir, report_name="forensic_analysis_report.pdf", entries_per_section=None, page_width=None):
    """
    Export analysis results from CSV and JSON files to a structured PDF report.
    
    Args:
        output_dir (str): Directory containing the analysis output files
        report_name (str): Name of the output PDF file
        entries_per_section (int): Number of entries to show per section. None for all entries.
        page_width (float): Custom page width in mm. None for default A4.
    """
    class PDF(FPDF):
        def header(self):
            self.set_font('Arial', 'B', 15)
            self.cell(0, 10, 'Forensic Analysis Report', 0, 1, 'C')
            self.ln(10)
            
        def footer(self):
            self.set_y(-15)
            self.set_font('Arial', 'I', 8)
            self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def add_section_header(pdf, title, total_entries=None, displayed_entries=None):
        pdf.set_font('Arial', 'B', 12)
        pdf.set_fill_color(200, 200, 200)
        header_text = title
        if total_entries is not None:
            header_text += f" (Showing {displayed_entries} of {total_entries} entries)"
        pdf.cell(0, 10, header_text, 0, 1, 'L', fill=True)
        pdf.ln(5)

    def add_table(pdf, data, headers):
        if not data:
            pdf.set_font('Arial', 'I', 10)
            pdf.cell(0, 10, "No data available for this section", 0, 1)
            return

        # Calculate column widths based on content
        pdf.set_font('Arial', '', 8)
        col_widths = []
        for i in range(len(headers)):
            header_width = pdf.get_string_width(str(headers[i])) + 4
            max_data_width = max(pdf.get_string_width(str(row[i]))+ 4 for row in data[:5])
            col_widths.append(min(max(header_width, max_data_width), 50))  # Cap at 50mm
            
        # Scale widths if they exceed page width
        available_width = pdf.w - 20  # 10mm margin on each side
        total_width = sum(col_widths)
        if total_width > available_width:
            scale_factor = available_width / total_width
            col_widths = [w * scale_factor for w in col_widths]

        # Headers
        pdf.set_font('Arial', 'B', 9)
        for i, header in enumerate(headers):
            pdf.cell(col_widths[i], 6, str(header), 1)
        pdf.ln()

        # Data
        pdf.set_font('Arial', '', 8)
        for row in data:
            # Check if we need to add a new page
            if pdf.get_y() + 6 > pdf.page_break_trigger:
                pdf.add_page()
                # Repeat headers
                pdf.set_font('Arial', 'B', 9)
                for i, header in enumerate(headers):
                    pdf.cell(col_widths[i], 6, str(header), 1)
                pdf.ln()
                pdf.set_font('Arial', '', 8)
            
            for i, item in enumerate(row):
                # Truncate long strings with ellipsis
                content = str(item)
                if pdf.get_string_width(content) > col_widths[i]:
                    while pdf.get_string_width(content + "...") > col_widths[i]:
                        content = content[:-1]
                    content += "..."
                pdf.cell(col_widths[i], 6, content, 1)
            pdf.ln()

    # Create PDF object
    pdf = PDF()
    if page_width:
        pdf = PDF('L') if page_width > 297 else PDF('P')  # Landscape if very wide
    pdf.add_page()
    
    # Add report metadata
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
    pdf.cell(0, 10, f'Source Directory: {output_dir}', 0, 1)
    if entries_per_section:
        pdf.cell(0, 10, f'Entries per section: {entries_per_section}', 0, 1)
    pdf.ln(10)

    # Process EvtxECmd CSV output
    evtx_files = [f for f in os.listdir(output_dir) if f.endswith('_EvtxECmd.csv')]
    if evtx_files:
        for file in evtx_files:
            try:
                df = pd.read_csv(os.path.join(output_dir, file))
                total_entries = len(df)
                important_cols = ['TimeCreated', 'EventId', 'Channel', 'Computer', 'Message']
                display_df = df[important_cols]
                if entries_per_section:
                    display_df = display_df.head(entries_per_section)
                
                add_section_header(pdf, 'Windows Event Log Analysis', total_entries, 
                                 len(display_df) if entries_per_section else total_entries)
                pdf.set_font('Arial', '', 10)
                pdf.cell(0, 10, f'Source: {file}', 0, 1)
                add_table(pdf, display_df.values.tolist(), important_cols)
                pdf.ln(10)
            except Exception as e:
                pdf.cell(0, 10, f'Error processing {file}: {str(e)}', 0, 1)

    # Process Volatility JSON output
    volatility_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]
    if volatility_files:
        for file in volatility_files:
            try:
                with open(os.path.join(output_dir, file), 'r') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        process_data = [[p.get('PID', ''), p.get('PPID', ''), 
                                       p.get('ImageFileName', ''), p.get('CreateTime', '')] 
                                      for p in data]
                        total_entries = len(process_data)
                        if entries_per_section:
                            process_data = process_data[:entries_per_section]
                        
                        add_section_header(pdf, 'Memory Analysis', total_entries,
                                         len(process_data))
                        headers = ['PID', 'PPID', 'Process Name', 'Create Time']
                        add_table(pdf, process_data, headers)
                pdf.ln(10)
            except Exception as e:
                pdf.cell(0, 10, f'Error processing {file}: {str(e)}', 0, 1)

    # Process RECmd CSV output
    recmd_files = [f for f in os.listdir(output_dir) if f.endswith('_RECmd.csv')]
    if recmd_files:
        for file in recmd_files:
            try:
                df = pd.read_csv(os.path.join(output_dir, file))
                total_entries = len(df)
                important_cols = ['KeyPath', 'ValueName', 'ValueData', 'LastWriteTimestamp']
                display_df = df[important_cols]
                if entries_per_section:
                    display_df = display_df.head(entries_per_section)
                
                add_section_header(pdf, 'Registry Analysis', total_entries,
                                 len(display_df) if entries_per_section else total_entries)
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