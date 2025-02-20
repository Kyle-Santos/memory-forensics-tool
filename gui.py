import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

class ForensicsAnalysisTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Forensync")
        self.root.geometry("800x600")
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=5, pady=5)
        
        self.home_tab = ttk.Frame(self.notebook)
        self.evtx_tab = ttk.Frame(self.notebook)
        self.memory_tab = ttk.Frame(self.notebook)
        self.registry_tab = ttk.Frame(self.notebook)
        self.report_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.home_tab, text='Home')
        self.notebook.add(self.evtx_tab, text='Event Logs')
        self.notebook.add(self.memory_tab, text='Memory Analysis')
        self.notebook.add(self.registry_tab, text='Registry Analysis')
        self.notebook.add(self.report_tab, text='Report')
        
        self.setup_home_tab()
        self.setup_evtx_tab()
        self.setup_memory_tab()
        self.setup_registry_tab()
        self.setup_report_tab()

    def setup_home_tab(self):
        welcome_label = ttk.Label(
            self.home_tab, 
            text="Forensync", 
            font=('Helvetica', 16, 'bold')
        )
        welcome_label.pack(pady=20)
        
        case_frame = ttk.LabelFrame(self.home_tab, text="Case Information", padding=10)
        case_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(case_frame, text="Case Name:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(case_frame).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(case_frame, text="Case Number:").grid(row=1, column=0, padx=5, pady=5)
        ttk.Entry(case_frame).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(case_frame, text="Examiner:").grid(row=2, column=0, padx=5, pady=5)
        ttk.Entry(case_frame).grid(row=2, column=1, padx=5, pady=5)

    def setup_evtx_tab(self):
        file_frame = ttk.LabelFrame(self.evtx_tab, text="Event Log Analysis", padding=10)
        file_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(
            file_frame, 
            text="Select .evtx File",
            command=lambda: self.select_file('.evtx')
        ).pack(pady=5)
        
        filter_frame = ttk.LabelFrame(self.evtx_tab, text="Filters", padding=10)
        filter_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(filter_frame, text="Security Events").pack()
        ttk.Checkbutton(filter_frame, text="RDP Access").pack()
        ttk.Checkbutton(filter_frame, text="Service Installations").pack()
        
        results_frame = ttk.LabelFrame(self.evtx_tab, text="Results", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.evtx_results = ScrolledText(results_frame)
        self.evtx_results.pack(fill='both', expand=True)

    def setup_memory_tab(self):
        dump_frame = ttk.LabelFrame(self.memory_tab, text="Memory Dump Analysis", padding=10)
        dump_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(
            dump_frame, 
            text="Select Memory Dump",
            command=lambda: self.select_file('.dmp')
        ).pack(pady=5)
        
        process_frame = ttk.LabelFrame(self.memory_tab, text="Process List", padding=10)
        process_frame.pack(fill='both', expand=True, padx=10, pady=5)

        ttk.Entry(process_frame).pack(fill='x', padx=5, pady=5)
        ttk.Button(process_frame, text="Search Process").pack(pady=5)

        self.process_tree = ttk.Treeview(process_frame, columns=('PID', 'Name', 'Status'))
        self.process_tree.heading('PID', text='PID')
        self.process_tree.heading('Name', text='Process Name')
        self.process_tree.heading('Status', text='Status')
        self.process_tree.pack(fill='both', expand=True)

    def setup_registry_tab(self):
        reg_frame = ttk.LabelFrame(self.registry_tab, text="Registry Analysis", padding=10)
        reg_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Button(
            reg_frame, 
            text="Select Registry Hive",
            command=lambda: self.select_file('.dat')
        ).pack(pady=5)
        
        options_frame = ttk.LabelFrame(self.registry_tab, text="Analysis Options", padding=10)
        options_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Checkbutton(options_frame, text="Scan Startup Entries").pack()
        ttk.Checkbutton(options_frame, text="Detect Modifications").pack()
        ttk.Checkbutton(options_frame, text="Find Malicious Keys").pack()
        
        reg_results_frame = ttk.LabelFrame(self.registry_tab, text="Findings", padding=10)
        reg_results_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.reg_results = ScrolledText(reg_results_frame)
        self.reg_results.pack(fill='both', expand=True)

    def setup_report_tab(self):
        report_frame = ttk.LabelFrame(self.report_tab, text="Report Generation", padding=10)
        report_frame.pack(fill='x', padx=10, pady=5)
        
        ttk.Label(report_frame, text="Export Format:").pack()
        format_var = tk.StringVar(value="CSV")
        ttk.Radiobutton(report_frame, text="CSV", variable=format_var, value="CSV").pack()
        ttk.Radiobutton(report_frame, text="JSON", variable=format_var, value="JSON").pack()
        ttk.Radiobutton(report_frame, text="PDF", variable=format_var, value="PDF").pack()
        
        ttk.Button(report_frame, text="Generate Report").pack(pady=10)
        
        preview_frame = ttk.LabelFrame(self.report_tab, text="Report Preview", padding=10)
        preview_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.report_preview = ScrolledText(preview_frame)
        self.report_preview.pack(fill='both', expand=True)

    def select_file(self, file_type):
        filetypes = [("All files", "*.*")]
        if file_type == '.evtx':
            filetypes = [("Event Log files", "*.evtx"), ("All files", "*.*")]
        elif file_type == '.dmp':
            filetypes = [("Memory Dump files", "*.dmp"), ("All files", "*.*")]
        elif file_type == '.dat':
            filetypes = [("Registry files", "*.dat"), ("All files", "*.*")]
            
        filename = filedialog.askopenfilename(
            title=f"Select {file_type} file",
            filetypes=filetypes
        )
        if filename:
            messagebox.showinfo("File Selected", f"Selected file: {filename}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ForensicsAnalysisTool(root)
    root.mainloop()