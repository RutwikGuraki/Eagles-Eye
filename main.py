import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import os
import socket
from datetime import datetime
import time
from urllib.parse import quote
import ssl
import requests
import re
from bs4 import BeautifulSoup
import dns.resolver
import whois
import subprocess
import platform
import pyshark
from scapy.all import *
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from fpdf import FPDF
from PIL import Image, ImageTk
import yara

class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Web Application Penetration Testing Report', 0, 1, 'C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')


class WebAppPenTestTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Web Application Penetration Testing Tool")
        self.root.geometry("1000x700")
        self.root.configure(bg='#f0f0f0')

        # Set window icon
        try:
            self.root.iconbitmap('icon.ico')  # You can provide an icon file
        except:
            pass

        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TButton', font=('Helvetica', 12), padding=10)
        self.style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 12))
        self.style.configure('Header.TLabel', font=('Helvetica', 16, 'bold'))
        self.style.map('Accent.TButton',
                       foreground=[('active', 'black'), ('!active', 'black')],
                       background=[('active', '#45a049'), ('!active', '#4CAF50')])

        self.project_name = None
        self.project_dir = "projects"
        self.ids_rules = []
        self.ids_alerts = []
        self.scan_results = ""

        # Create main menu
        self.main_menu()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def main_menu(self):
        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="Web Application Penetration Testing Tool",
                  style='Header.TLabel').pack(pady=20)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)

        # Menu buttons with consistent styling
        buttons = [
            ("Web App Vulnerability Scanning", self.web_app_scanning_menu),
            ("Network Security Auditing", self.network_security_auditing_menu),
            ("System Security Check", self.system_security_check_menu),
            ("Exit", self.root.quit)
        ]

        for text, command in buttons:
            btn = ttk.Button(btn_frame, text=text, command=command, style='Accent.TButton')
            btn.pack(pady=10, fill='x')
    def system_security_check_menu(self):
        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="System Security Check",
                 style='Header.TLabel').pack(pady=20)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)

        buttons = [
            ("Scan System for Malware", self.scan_system),
            ("Scan File for Malware", self.scan_file),
            ("Scan Folder for Malware", self.scan_folder),
            ("Manage Detection Rules", self.manage_rules),
            ("Back to Main Menu", self.main_menu)
        ]

        for text, command in buttons:
            btn = ttk.Button(btn_frame, text=text, command=command, style='Accent.TButton')
            btn.pack(pady=10, fill='x')

    def manage_rules(self):
        rules_window = tk.Toplevel(self.root)
        rules_window.title("Manage Detection Rules")
        rules_window.geometry("800x600")

        main_frame = ttk.Frame(rules_window, padding="10")
        main_frame.pack(expand=True, fill='both')

        # Load existing rules
        self.load_rules()

        # Rule list
        ttk.Label(main_frame, text="Current Detection Rules:").pack(anchor='w')

        rule_list_frame = ttk.Frame(main_frame)
        rule_list_frame.pack(fill='both', expand=True, pady=10)

        scrollbar = ttk.Scrollbar(rule_list_frame)
        scrollbar.pack(side='right', fill='y')

        self.rule_listbox = tk.Listbox(rule_list_frame, yscrollcommand=scrollbar.set,
                                      font=('Courier', 10))
        self.rule_listbox.pack(fill='both', expand=True)
        scrollbar.config(command=self.rule_listbox.yview)

        for rule in self.rules:
            self.rule_listbox.insert(tk.END, f"{rule['name']}: {rule['description']}")

        # Rule management buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(btn_frame, text="Add Rule", command=self.add_rule,
                  style='Accent.TButton').pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Edit Rule", command=self.edit_rule).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Delete Rule", command=self.delete_rule).pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Close", command=rules_window.destroy).pack(side='right', padx=5)

    def load_rules(self):
        """Load detection rules from file or use defaults"""
        self.rules = []
        rules_file = os.path.join(self.project_dir, "detection_rules.yar")

        if os.path.exists(rules_file):
            try:
                # Load rules from file
                with open(rules_file, 'r') as f:
                    rule_content = f.read()
                self.rules = self.parse_rules(rule_content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load rules: {str(e)}")
                self.rules = self.get_default_rules()
        else:
            self.rules = self.get_default_rules()

    def get_default_rules(self):
        """Return default set of detection rules"""
        return [
            {
                'name': 'SUSPICIOUS_SCRIPT',
                'description': 'Detects common script patterns in executable files',
                'rule': '''
                    rule suspicious_script {
                        strings:
                            $script1 = "eval(" nocase
                            $script2 = "exec(" nocase
                            $script3 = "<script>" nocase
                            
                        condition:
                            any of them
                    }
                '''
            },
            {
                'name': 'POWERSHELL_MALWARE',
                'description': 'Detects common PowerShell malware patterns',
                'rule': '''
                    rule powershell_malware {
                        strings:
                            $ps1 = "powershell" nocase
                            $ps2 = "-enc" nocase
                            $ps3 = "Invoke-Expression" nocase
                            
                        condition:
                            all of them
                    }
                '''
            },
            {
                'name': 'BINARY_SUSPICIOUS_IMPORTS',
                'description': 'Detects suspicious imports in binary files',
                'rule': '''
                    rule binary_suspicious_imports {
                        strings:
                            $import1 = "CreateRemoteThread"
                            $import2 = "VirtualAllocEx"
                            $import3 = "WriteProcessMemory"
                            
                        condition:
                            any of them
                    }
                '''
            }
        ]

    def parse_rules(self, rule_content):
        """Parse YARA rules from content"""
        rules = []
        current_rule = None

        for line in rule_content.split('\n'):
            line = line.strip()

            if line.startswith('rule '):
                if current_rule:
                    rules.append(current_rule)
                current_rule = {
                    'name': line.split()[1].strip('{').strip(),
                    'description': '',
                    'rule': line + '\n'
                }
            elif current_rule:
                current_rule['rule'] += line + '\n'
                if 'description' in line.lower():
                    current_rule['description'] = line.split(':', 1)[1].strip().strip('"')

        if current_rule:
            rules.append(current_rule)

        return rules

    def add_rule(self):
        """Add a new detection rule"""
        rule_window = tk.Toplevel(self.root)
        rule_window.title("Add Detection Rule")
        rule_window.geometry("800x600")

        main_frame = ttk.Frame(rule_window, padding="10")
        main_frame.pack(expand=True, fill='both')

        # Rule name
        ttk.Label(main_frame, text="Rule Name:").pack(anchor='w')
        name_entry = ttk.Entry(main_frame, font=('Helvetica', 12))
        name_entry.pack(fill='x', pady=5)

        # Rule description
        ttk.Label(main_frame, text="Description:").pack(anchor='w')
        desc_entry = ttk.Entry(main_frame, font=('Helvetica', 12))
        desc_entry.pack(fill='x', pady=5)

        # Rule content
        ttk.Label(main_frame, text="YARA Rule Content:").pack(anchor='w')
        rule_text = tk.Text(main_frame, wrap='word', font=('Courier', 10))
        rule_text.pack(fill='both', expand=True, pady=5)

        # Add default template
        rule_text.insert(tk.END, '''rule RULE_NAME {
    meta:
        description = "DESCRIPTION"
    
    strings:
        $s1 = "PATTERN" nocase
        
    condition:
        any of them
}''')

        def save_rule():
            name = name_entry.get().strip()
            description = desc_entry.get().strip()
            content = rule_text.get("1.0", tk.END).strip()

            if not name or not description or not content:
                messagebox.showerror("Error", "All fields are required")
                return

            try:
                # Validate the rule by compiling it
                yara.compile(source=content)

                self.rules.append({
                    'name': name,
                    'description': description,
                    'rule': content
                })

                # Update listbox
                self.rule_listbox.insert(tk.END, f"{name}: {description}")
                messagebox.showinfo("Success", "Rule added successfully")
                rule_window.destroy()

            except yara.SyntaxError as e:
                messagebox.showerror("Error", f"Invalid YARA rule: {str(e)}")

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(btn_frame, text="Save Rule", command=save_rule,
                  style='Accent.TButton').pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Cancel", command=rule_window.destroy).pack(side='right', padx=5)

    def edit_rule(self):
        """Edit an existing rule"""
        selection = self.rule_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a rule to edit")
            return

        index = selection[0]
        rule = self.rules[index]

        rule_window = tk.Toplevel(self.root)
        rule_window.title("Edit Detection Rule")
        rule_window.geometry("800x600")

        main_frame = ttk.Frame(rule_window, padding="10")
        main_frame.pack(expand=True, fill='both')

        # Rule name
        ttk.Label(main_frame, text="Rule Name:").pack(anchor='w')
        name_entry = ttk.Entry(main_frame, font=('Helvetica', 12))
        name_entry.insert(0, rule['name'])
        name_entry.pack(fill='x', pady=5)

        # Rule description
        ttk.Label(main_frame, text="Description:").pack(anchor='w')
        desc_entry = ttk.Entry(main_frame, font=('Helvetica', 12))
        desc_entry.insert(0, rule['description'])
        desc_entry.pack(fill='x', pady=5)

        # Rule content
        ttk.Label(main_frame, text="YARA Rule Content:").pack(anchor='w')
        rule_text = tk.Text(main_frame, wrap='word', font=('Courier', 10))
        rule_text.insert(tk.END, rule['rule'])
        rule_text.pack(fill='both', expand=True, pady=5)

        def save_rule():
            name = name_entry.get().strip()
            description = desc_entry.get().strip()
            content = rule_text.get("1.0", tk.END).strip()

            if not name or not description or not content:
                messagebox.showerror("Error", "All fields are required")
                return

            try:
                # Validate the rule by compiling it
                yara.compile(source=content)

                self.rules[index] = {
                    'name': name,
                    'description': description,
                    'rule': content
                }

                # Update listbox
                self.rule_listbox.delete(index)
                self.rule_listbox.insert(index, f"{name}: {description}")
                messagebox.showinfo("Success", "Rule updated successfully")
                rule_window.destroy()

            except yara.SyntaxError as e:
                messagebox.showerror("Error", f"Invalid YARA rule: {str(e)}")

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(btn_frame, text="Save Changes", command=save_rule,
                  style='Accent.TButton').pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Cancel", command=rule_window.destroy).pack(side='right', padx=5)

    def delete_rule(self):
        """Delete a rule"""
        selection = self.rule_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Please select a rule to delete")
            return

        index = selection[0]
        rule = self.rules[index]

        if messagebox.askyesno("Confirm", f"Delete rule '{rule['name']}'?"):
            self.rules.pop(index)
            self.rule_listbox.delete(index)
            messagebox.showinfo("Success", "Rule deleted successfully")

    def save_rules(self):
        """Save rules to file"""
        if not hasattr(self, 'rules'):
            return

        rules_file = os.path.join(self.project_dir, "detection_rules.yar")

        try:
            with open(rules_file, 'w') as f:
                for rule in self.rules:
                    f.write(rule['rule'] + '\n\n')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save rules: {str(e)}")

    def scan_system(self):
        """Scan the entire system using YARA rules"""
        if not hasattr(self, 'rules') or not self.rules:
            messagebox.showerror("Error", "No detection rules loaded")
            return

        # Ask for confirmation since system scan can take time
        if not messagebox.askyesno("Confirm", "System scan may take a long time. Continue?"):
            return

        # Compile rules
        try:
            rules_content = '\n'.join(rule['rule'] for rule in self.rules)
            rules = yara.compile(source=rules_content)
        except yara.SyntaxError as e:
            messagebox.showerror("Error", f"Invalid YARA rule: {str(e)}")
            return

        # Start scanning
        results = []
        start_time = time.time()

        # Scan common system directories
        scan_dirs = [
            '/usr/bin', '/usr/sbin', '/bin', '/sbin',  # Unix/Linux
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64'  # Windows
        ]

        for directory in scan_dirs:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            matches = rules.match(file_path)
                            if matches:
                                results.append(f"{file_path}: {[m.rule for m in matches]}")
                        except Exception as e:
                            results.append(f"Error scanning {file_path}: {str(e)}")

        scan_time = time.time() - start_time
        results.insert(0, f"System scan completed in {scan_time:.2f} seconds")

        self.display_scan_results('\n'.join(results), "")

    def scan_file(self):
        """Scan a single file using YARA rules"""
        if not hasattr(self, 'rules') or not self.rules:
            messagebox.showerror("Error", "No detection rules loaded")
            return

        file_path = filedialog.askopenfilename(title="Select a file to scan")
        if not file_path:
            return

        # Compile rules
        try:
            rules_content = '\n'.join(rule['rule'] for rule in self.rules)
            rules = yara.compile(source=rules_content)
        except yara.SyntaxError as e:
            messagebox.showerror("Error", f"Invalid YARA rule: {str(e)}")
            return

        # Scan the file
        try:
            matches = rules.match(file_path)
            if matches:
                result = f"File: {file_path}\n"
                result += "Matches found:\n"
                for match in matches:
                    result += f"- {match.rule}\n"
                    for string in match.strings:
                        result += f"  Found '{string[2].decode('utf-8', errors='replace')}' at 0x{string[0]:X}\n"
            else:
                result = f"No matches found in {file_path}"

            self.display_scan_results(result, "")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan file: {str(e)}")

    def scan_folder(self):
        """Scan a folder recursively using YARA rules"""
        if not hasattr(self, 'rules') or not self.rules:
            messagebox.showerror("Error", "No detection rules loaded")
            return

        folder_path = filedialog.askdirectory(title="Select a folder to scan")
        if not folder_path:
            return

        # Ask for confirmation since folder scan can take time
        if not messagebox.askyesno("Confirm", "Folder scan may take a long time. Continue?"):
            return

        # Compile rules
        try:
            rules_content = '\n'.join(rule['rule'] for rule in self.rules)
            rules = yara.compile(source=rules_content)
        except yara.SyntaxError as e:
            messagebox.showerror("Error", f"Invalid YARA rule: {str(e)}")
            return

        # Start scanning
        results = []
        start_time = time.time()
        file_count = 0
        match_count = 0

        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_count += 1
                try:
                    matches = rules.match(file_path)
                    if matches:
                        match_count += 1
                        results.append(f"{file_path}: {[m.rule for m in matches]}")
                except Exception as e:
                    results.append(f"Error scanning {file_path}: {str(e)}")

        scan_time = time.time() - start_time
        summary = (
            f"Folder scan completed in {scan_time:.2f} seconds\n"
            f"Files scanned: {file_count}\n"
            f"Files with matches: {match_count}\n\n"
            "Detailed results:"
        )
        results.insert(0, summary)

        self.display_scan_results('\n'.join(results), "")

    # ... (rest of the code remains the same)
    def is_clamav_installed(self):
        try:
            subprocess.run(["clamscan", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def display_scan_results(self, stdout, stderr):
        result_window = tk.Toplevel(self.root)
        result_window.title("Scan Results")
        result_window.geometry("800x600")

        main_frame = ttk.Frame(result_window, padding="10")
        main_frame.pack(expand=True, fill='both')

        text_frame = ttk.Frame(main_frame)
        text_frame.pack(expand=True, fill='both')

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')

        result_text = tk.Text(text_frame, wrap='word', font=('Courier', 10), yscrollcommand=scrollbar.set)
        result_text.pack(expand=True, fill='both')
        scrollbar.config(command=result_text.yview)

        result_text.insert(tk.END, stdout)
        if stderr:
            result_text.insert(tk.END, "\n\nErrors:\n")
            result_text.insert(tk.END, stderr)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        save_btn = ttk.Button(btn_frame, text="Save to PDF",
                              command=lambda: self.save_to_pdf(stdout + "\n" + stderr, "scan_results.pdf"),
                              style='Accent.TButton')
        save_btn.pack(side='left', padx=5)

        close_btn = ttk.Button(btn_frame, text="Close", command=result_window.destroy)
        close_btn.pack(side='right', padx=5)

    def web_app_scanning_menu(self):
        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="Web App Vulnerability Scanning",
                  style='Header.TLabel').pack(pady=10)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(pady=10)

        ttk.Label(input_frame, text="Enter Project Name:").pack(side='left', padx=5)
        self.project_name_entry = ttk.Entry(input_frame, font=('Helvetica', 12))
        self.project_name_entry.pack(side='left', padx=5)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Continue", command=self.setup_project,
                   style='Accent.TButton').pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Back", command=self.main_menu).pack(side='right', padx=10)

    def network_security_auditing_menu(self):
        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="Network Security Auditing",
                  style='Header.TLabel').pack(pady=10)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(pady=10)

        ttk.Label(input_frame, text="Enter Project Name:").pack(side='left', padx=5)
        self.project_name_entry = ttk.Entry(input_frame, font=('Helvetica', 12))
        self.project_name_entry.pack(side='left', padx=5)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=20)

        ttk.Button(btn_frame, text="Continue", command=self.setup_network_audit_project,
                   style='Accent.TButton').pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Back", command=self.main_menu).pack(side='right', padx=10)

    def setup_project(self):
        self.project_name = self.project_name_entry.get()
        if not self.project_name:
            messagebox.showerror("Error", "Project name cannot be empty")
            return

        project_path = os.path.join(self.project_dir, self.project_name)
        if not os.path.exists(project_path):
            os.makedirs(project_path)

        self.scanning_options()

    def setup_network_audit_project(self):
        self.project_name = self.project_name_entry.get()
        if not self.project_name:
            messagebox.showerror("Error", "Project name cannot be empty")
            return

        project_path = os.path.join(self.project_dir, self.project_name)
        if not os.path.exists(project_path):
            os.makedirs(project_path)

        self.ids_options()

    def scanning_options(self):
        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="Scanning Options",
                  style='Header.TLabel').pack(pady=10)

        input_frame = ttk.Frame(main_frame)
        input_frame.pack(pady=10, fill='x')

        ttk.Label(input_frame, text="Enter Domain Name:").pack(side='left', padx=5)
        self.domain_entry = ttk.Entry(input_frame, font=('Helvetica', 12))
        self.domain_entry.pack(side='left', padx=5, expand=True, fill='x')

        # Create a canvas and scrollbar for the checkboxes
        canvas = tk.Canvas(main_frame, borderwidth=0, background="#ffffff")
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.scan_options = {
            "IP Lookup": self.ip_lookup,
            "SSL Inspection": self.ssl_inspection,
            "Subdomain Enumeration": self.subdomain_enumeration,
            "Web Crawling": self.web_crawling,
            "Wayback URL": self.wayback_machine,
            "Social Media Links": self.social_media_links,
            "WHOIS lookup": self.whois_lookup,
            "DNS Enumeration": self.dns_enumeration,
            "Port Scanning": self.port_scanning,
            "Technology Analysis": self.technology_analysis,
            "Admin Panel": self.admin_panel,
            "XSS Finding": self.xss_finding,
            "Directory Search": self.directory_search
        }

        self.selected_options = {}

        for option in self.scan_options:
            var = tk.BooleanVar()
            cb = ttk.Checkbutton(scrollable_frame, text=option, variable=var)
            cb.pack(anchor='w', pady=2)
            self.selected_options[option] = var

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(btn_frame, text="Start Scan", command=self.start_scan,
                   style='Accent.TButton').pack(side='left', padx=10)
        ttk.Button(btn_frame, text="Back", command=self.web_app_scanning_menu).pack(side='right', padx=10)

    def ids_options(self):
        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="Intrusion Detection System",
                  style='Header.TLabel').pack(pady=20)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)

        buttons = [
            ("Start IDS Monitoring", self.start_ids_monitoring),
            ("View IDS Rules", self.view_ids_rules),
            ("Add Custom IDS Rule", self.add_custom_ids_rule),
            ("View Alerts", self.view_ids_alerts),
            ("Generate Report", self.generate_ids_report),
            ("Back to Main Menu", self.main_menu)
        ]

        for text, command in buttons:
            btn = ttk.Button(btn_frame, text=text, command=command, style='Accent.TButton')
            btn.pack(pady=5, fill='x')

    def start_ids_monitoring(self):
        self.ids_alerts = []
        if not self.ids_rules:
            self.load_default_ids_rules()

        interface = filedialog.askstring("Network Interface", "Enter network interface to monitor (e.g., eth0, wlan0):")
        if not interface:
            return

        duration = filedialog.askinteger("Monitoring Duration", "Enter monitoring duration in seconds:", minvalue=1,
                                         maxvalue=3600)
        if not duration:
            return

        import threading
        monitoring_thread = threading.Thread(target=self.run_ids_monitoring, args=(interface, duration))
        monitoring_thread.start()

        messagebox.showinfo("Info", f"IDS monitoring started on interface {interface} for {duration} seconds")

    def run_ids_monitoring(self, interface, duration):
        try:
            capture = pyshark.LiveCapture(interface=interface)
            end_time = time.time() + duration

            for packet in capture.sniff_continuously():
                if time.time() > end_time:
                    break
                self.analyze_packet(packet)

        except Exception as e:
            self.ids_alerts.append(f"Error in IDS monitoring: {str(e)}")

    def analyze_packet(self, packet):
        try:
            packet_dict = {}
            if hasattr(packet, 'ip'):
                packet_dict['src_ip'] = packet.ip.src
                packet_dict['dst_ip'] = packet.ip.dst

            if hasattr(packet, 'tcp'):
                packet_dict['src_port'] = packet.tcp.srcport
                packet_dict['dst_port'] = packet.tcp.dstport
                packet_dict['flags'] = getattr(packet.tcp, 'flags', '')
            elif hasattr(packet, 'udp'):
                packet_dict['src_port'] = packet.udp.srcport
                packet_dict['dst_port'] = packet.udp.dstport

            for rule in self.ids_rules:
                if self.match_rule(packet_dict, rule):
                    alert_msg = f"ALERT: {rule['description']} - SRC: {packet_dict.get('src_ip', 'N/A')}:{packet_dict.get('src_port', 'N/A')} " \
                                f"DST: {packet_dict.get('dst_ip', 'N/A')}:{packet_dict.get('dst_port', 'N/A')}"
                    self.ids_alerts.append(alert_msg)

        except Exception as e:
            self.ids_alerts.append(f"Error analyzing packet: {str(e)}")

    def match_rule(self, packet, rule):
        try:
            for condition in rule['conditions']:
                field = condition['field']
                operator = condition['operator']
                value = condition['value']

                packet_value = packet.get(field, None)
                if packet_value is None:
                    return False

                if operator == '==' and str(packet_value) != str(value):
                    return False
                elif operator == '!=' and str(packet_value) == str(value):
                    return False
                elif operator == 'contains' and str(value) not in str(packet_value):
                    return False
                elif operator == 'not contains' and str(value) in str(packet_value):
                    return False
                elif operator == '>' and float(packet_value) <= float(value):
                    return False
                elif operator == '<' and float(packet_value) >= float(value):
                    return False

            return True
        except:
            return False

    def load_default_ids_rules(self):
        self.ids_rules = [
            {
                'id': 1,
                'description': "Possible port scan detected (multiple SYN packets to different ports)",
                'conditions': [
                    {'field': 'flags', 'operator': '==', 'value': '0x002'}  # SYN flag set
                ]
            },
            {
                'id': 2,
                'description': "Possible XSS attack detected",
                'conditions': [
                    {'field': 'payload', 'operator': 'contains', 'value': '<script>'}
                ]
            },
            {
                'id': 3,
                'description': "Possible SQL injection attempt detected",
                'conditions': [
                    {'field': 'payload', 'operator': 'contains', 'value': "' OR '1'='1"}
                ]
            },
            {
                'id': 4,
                'description': "HTTP request to known malicious domain",
                'conditions': [
                    {'field': 'dst_ip', 'operator': '==', 'value': '1.2.3.4'}  # Example malicious IP
                ]
            },
            {
                'id': 5,
                'description': "Unusual large ICMP packet (possible ping flood)",
                'conditions': [
                    {'field': 'protocol', 'operator': '==', 'value': 'ICMP'},
                    {'field': 'length', 'operator': '>', 'value': '1000'}
                ]
            }
        ]

    def view_ids_rules(self):
        rules_window = tk.Toplevel(self.root)
        rules_window.title("IDS Rules")
        rules_window.geometry("800x600")

        main_frame = ttk.Frame(rules_window, padding="10")
        main_frame.pack(expand=True, fill='both')

        text_frame = ttk.Frame(main_frame)
        text_frame.pack(expand=True, fill='both')

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')

        rules_text = tk.Text(text_frame, wrap='word', font=('Courier', 10), yscrollcommand=scrollbar.set)
        rules_text.pack(expand=True, fill='both')
        scrollbar.config(command=rules_text.yview)

        if not self.ids_rules:
            rules_text.insert(tk.END, "No IDS rules loaded. Loading default rules...\n")
            self.load_default_ids_rules()

        for rule in self.ids_rules:
            rules_text.insert(tk.END, f"Rule ID: {rule['id']}\n")
            rules_text.insert(tk.END, f"Description: {rule['description']}\n")
            rules_text.insert(tk.END, "Conditions:\n")
            for condition in rule['conditions']:
                rules_text.insert(tk.END, f"  {condition['field']} {condition['operator']} {condition['value']}\n")
            rules_text.insert(tk.END, "\n")

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        save_btn = ttk.Button(btn_frame, text="Save to PDF",
                              command=lambda: self.save_to_pdf(rules_text.get("1.0", tk.END), "ids_rules.pdf"),
                              style='Accent.TButton')
        save_btn.pack(side='left', padx=5)

        close_btn = ttk.Button(btn_frame, text="Close", command=rules_window.destroy)
        close_btn.pack(side='right', padx=5)

    def add_custom_ids_rule(self):
        rule_window = tk.Toplevel(self.root)
        rule_window.title("Add Custom IDS Rule")
        rule_window.geometry("600x400")

        main_frame = ttk.Frame(rule_window, padding="20")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="Rule Description:").pack(anchor='w', pady=5)
        desc_entry = ttk.Entry(main_frame, font=('Helvetica', 12))
        desc_entry.pack(fill='x', pady=5)

        conditions_frame = ttk.LabelFrame(main_frame, text="Conditions", padding=10)
        conditions_frame.pack(fill='both', expand=True, pady=10)

        condition_entries = []

        def add_condition():
            condition_frame = ttk.Frame(conditions_frame)
            condition_frame.pack(fill='x', pady=5)

            field_var = tk.StringVar(value="src_ip")
            field_menu = ttk.OptionMenu(condition_frame, field_var,
                                        "src_ip", "dst_ip", "src_port", "dst_port",
                                        "protocol", "flags", "payload")
            field_menu.pack(side='left', padx=5)

            operator_var = tk.StringVar(value="==")
            operator_menu = ttk.OptionMenu(condition_frame, operator_var,
                                           "==", "!=", "contains", "not contains", ">", "<")
            operator_menu.pack(side='left', padx=5)

            value_entry = ttk.Entry(condition_frame, font=('Helvetica', 12))
            value_entry.pack(side='left', padx=5, expand=True, fill='x')

            condition_entries.append({
                'frame': condition_frame,
                'field': field_var,
                'operator': operator_var,
                'value': value_entry
            })

        add_condition()

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(btn_frame, text="Add Condition", command=add_condition).pack(side='left', padx=5)

        def save_rule():
            description = desc_entry.get()
            if not description:
                messagebox.showerror("Error", "Rule description cannot be empty")
                return

            conditions = []
            for entry in condition_entries:
                field = entry['field'].get()
                operator = entry['operator'].get()
                value = entry['value'].get()

                if not field or not operator or not value:
                    messagebox.showerror("Error", "All condition fields must be filled")
                    return

                conditions.append({
                    'field': field,
                    'operator': operator,
                    'value': value
                })

            new_rule = {
                'id': len(self.ids_rules) + 1,
                'description': description,
                'conditions': conditions
            }

            self.ids_rules.append(new_rule)
            messagebox.showinfo("Success", "Custom rule added successfully")
            rule_window.destroy()

        ttk.Button(btn_frame, text="Save Rule", command=save_rule,
                   style='Accent.TButton').pack(side='right', padx=5)

    def view_ids_alerts(self):
        alerts_window = tk.Toplevel(self.root)
        alerts_window.title("IDS Alerts")
        alerts_window.geometry("800x600")

        main_frame = ttk.Frame(alerts_window, padding="10")
        main_frame.pack(expand=True, fill='both')

        text_frame = ttk.Frame(main_frame)
        text_frame.pack(expand=True, fill='both')

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')

        alerts_text = tk.Text(text_frame, wrap='word', font=('Courier', 10), yscrollcommand=scrollbar.set)
        alerts_text.pack(expand=True, fill='both')
        scrollbar.config(command=alerts_text.yview)

        if not self.ids_alerts:
            alerts_text.insert(tk.END, "No alerts detected yet.\n")
        else:
            for alert in self.ids_alerts:
                alerts_text.insert(tk.END, alert + "\n\n")

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        save_btn = ttk.Button(btn_frame, text="Save to PDF",
                              command=lambda: self.save_to_pdf(alerts_text.get("1.0", tk.END), "ids_alerts.pdf"),
                              style='Accent.TButton')
        save_btn.pack(side='left', padx=5)

        close_btn = ttk.Button(btn_frame, text="Close", command=alerts_window.destroy)
        close_btn.pack(side='right', padx=5)

    def generate_ids_report(self):
        if not self.project_name:
            messagebox.showerror("Error", "No project is loaded")
            return

        project_path = os.path.join(self.project_dir, self.project_name)
        if not os.path.exists(project_path):
            os.makedirs(project_path)

        report_file = os.path.join(project_path, "ids_report.pdf")

        # Create PDF
        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Add title and date
        pdf.cell(0, 10, f"Intrusion Detection System Report for Project: {self.project_name}", ln=1)
        pdf.cell(0, 10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=2)

        # Add IDS Rules section
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "IDS Rules", ln=1)
        pdf.set_font("Arial", size=12)

        for rule in self.ids_rules:
            pdf.multi_cell(0, 10, f"Rule ID: {rule['id']}\nDescription: {rule['description']}")
            pdf.cell(0, 5, "Conditions:", ln=1)
            for condition in rule['conditions']:
                pdf.cell(0, 5, f"  {condition['field']} {condition['operator']} {condition['value']}", ln=1)
            pdf.ln(5)

        # Add IDS Alerts section
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "IDS Alerts", ln=1)
        pdf.set_font("Arial", size=12)

        if not self.ids_alerts:
            pdf.cell(0, 10, "No alerts detected.", ln=1)
        else:
            for alert in self.ids_alerts:
                pdf.multi_cell(0, 10, alert)
                pdf.ln(2)

        # Save the PDF
        pdf.output(report_file)
        messagebox.showinfo("Info", f"IDS report saved to {report_file}")

    def start_scan(self):
        domain = self.domain_entry.get()
        if not domain:
            messagebox.showerror("Error", "Domain name cannot be empty")
            return

        self.clear_screen()

        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(expand=True, fill='both')

        ttk.Label(main_frame, text="Scan Results",
                  style='Header.TLabel').pack(pady=10)

        text_frame = ttk.Frame(main_frame)
        text_frame.pack(expand=True, fill='both')

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side='right', fill='y')

        self.results_text = tk.Text(text_frame, wrap='word', font=('Courier', 10), yscrollcommand=scrollbar.set)
        self.results_text.pack(expand=True, fill='both')
        scrollbar.config(command=self.results_text.yview)

        self.scan_results = ""  # Reset scan results

        for option, var in self.selected_options.items():
            if var.get():
                scan_function = self.scan_options[option]
                result = scan_function(domain)
                self.results_text.insert(tk.END, f"=== {option} Results ===\n{result}\n\n")
                self.scan_results += f"=== {option} Results ===\n{result}\n\n"

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill='x', pady=10)

        ttk.Button(btn_frame, text="Save to PDF",
                   command=lambda: self.save_to_pdf(self.scan_results, "scan_results.pdf"),
                   style='Accent.TButton').pack(side='left', padx=5)
        ttk.Button(btn_frame, text="Back", command=self.scanning_options).pack(side='right', padx=5)

    def save_to_pdf(self, content, filename):
        if not self.project_name:
            messagebox.showerror("Error", "No project is loaded")
            return

        project_path = os.path.join(self.project_dir, self.project_name)
        if not os.path.exists(project_path):
            os.makedirs(project_path)

        report_file = os.path.join(project_path, filename)

        pdf = PDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)

        # Split content into lines and add to PDF
        for line in content.split('\n'):
            pdf.cell(0, 10, line, ln=1)

        pdf.output(report_file)
        messagebox.showinfo("Info", f"Report saved to {report_file}")

    # All the scanning methods remain the same as in your original code
    # (ip_lookup, ssl_inspection, subdomain_enumeration, etc.)
    # I've kept them out for brevity, but they should be included in the actual implementation




    def ip_lookup(self, domain):
        try:
            # Get IP address
            ip_address = socket.gethostbyname(domain)

            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip_address)[0]
            except socket.herror:
                hostname = "Not found"

            # IP Geolocation using an API (for example, ipinfo.io)
            try:
                response = requests.get(f"https://ipinfo.io/{ip_address}/json")
                geolocation_data = response.json()
                city = geolocation_data.get("city", "Unknown")
                region = geolocation_data.get("region", "Unknown")
                country = geolocation_data.get("country", "Unknown")
                org = geolocation_data.get("org", "Unknown")
                asn = org.split()[0] if "AS" in org else "Unknown"
                ip_range = geolocation_data.get("network", "Unknown")  # Check if network info is available
            except Exception as e:
                city, region, country, org, asn, ip_range = "Unknown", "Unknown", "Unknown", "Unknown", "Unknown", "Unknown"

            # Prepare result string
            result = (
                f"IP Address: {ip_address}\n"
                f"Hostname: {hostname}\n"
                f"Location: {city}, {region}, {country}\n"
                f"Organization: {org}\n"
                f"ASN: {asn}\n"
                f"IP Range: {ip_range}\n"
            )

            return result

        except socket.gaierror:
            return f"Error: Unable to resolve {domain}"

    def ssl_inspection(self, domain):
        context = ssl.create_default_context()
        try:
            # Step 1: DNS resolution check
            try:
                ip = socket.gethostbyname(domain)
                print(f"[INFO] {domain} resolved to {ip}")
            except socket.gaierror:
                return f"❌ DNS Error: Cannot resolve hostname “{domain}”. Please check the domain name or your network settings."

            # Step 2: Establish SSL connection
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    ssl_version = ssock.version()

                    subject_raw = cert.get('subject', [])
                    issuer_raw = cert.get('issuer', [])

                    subject = dict(x[0] for x in subject_raw) if subject_raw else {}
                    issuer = dict(x[0] for x in issuer_raw) if issuer_raw else {}

                    not_before = cert.get('notBefore', '')
                    not_after = cert.get('notAfter', '')

                    try:
                        valid_from = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                        valid_to = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    except ValueError:
                        return f"⚠️ Error parsing certificate validity dates. Raw: From '{not_before}' to '{not_after}'"

                    current_date = datetime.utcnow()
                    if current_date > valid_to:
                        cert_status = "Expired"
                    elif (valid_to - current_date).days < 30:
                        cert_status = "Expiring soon"
                    else:
                        cert_status = "Valid"

                    cipher_suite_name = cipher[0]
                    key_length = cipher[2]
                    protocol_version = ssl_version

                    result = (
                        f"✅ SSL Certificate Details for {domain}:\n"
                        f"Subject: {subject}\n"
                        f"Issuer: {issuer}\n"
                        f"Valid From: {valid_from}\n"
                        f"Valid To: {valid_to} ({cert_status})\n"
                        f"Cipher Suite: {cipher_suite_name}\n"
                        f"Key Length: {key_length} bits\n"
                        f"SSL/TLS Version: {protocol_version}\n"
                        f"OCSP Check: Not implemented.\n"
                    )
                    return result

        except socket.timeout:
            return f"⏱️ Timeout Error: Connection to {domain}:443 timed out."
        except ssl.SSLError as e:
            return f"🔐 SSL Error: {e}"
        except Exception as e:
            return f"❌ Unexpected Error: {e}"

    def subdomain_enumeration(self, domain):
        results = []
        try:
            # Using crt.sh to find subdomains
            url = f"https://crt.sh/?q={quote(f'%.{domain}')}&output=json"

            # Retry logic for network reliability
            def fetch_with_retries(url, retries=3, delay=5):
                for attempt in range(retries):
                    try:
                        response = requests.get(url)
                        response.raise_for_status()
                        return response
                    except requests.RequestException as e:
                        if attempt < retries - 1:
                            time.sleep(delay)
                        else:
                            raise e

            response = fetch_with_retries(url)
            data = response.json()

            subdomains = set()

            # Regular expression to match subdomains
            subdomain_pattern = re.compile(rf"([a-zA-Z0-9-]+\.)*{domain}")

            for entry in data:
                subdomain = entry.get('name_value')
                if subdomain:
                    for sub in subdomain.split('\n'):
                        match = subdomain_pattern.match(sub)
                        if match:
                            subdomains.add(sub)

            # If we found subdomains, add them to the result
            if subdomains:
                results.append(f"Subdomains for {domain}:\n")
                for subdomain in sorted(subdomains):
                    results.append(f"- {subdomain}\n")
            else:
                results.append(f"No subdomains found for {domain}\n")

        except requests.RequestException as e:
            results.append(f"Error fetching subdomains: {e}\n")

        return ''.join(results)

    def web_crawling(self, domain):
        try:
            url = f"http://{domain}"
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            links = [a['href'] for a in soup.find_all('a', href=True)]
            result = "Found Links:\n" + "\n".join(links)
            return result
        except Exception as e:
            return f"Error: Unable to crawl {domain}. {e}"

    def wayback_machine(self, domain):
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
            response = requests.get(url)
            if response.status_code == 200:
                snapshots = response.json()
                result = "Wayback Machine Snapshots:\n"
                result += "\n".join([f"Snapshot: {snapshot[1]} on {snapshot[2]}" for snapshot in snapshots[1:]])
                return result
            else:
                return f"Error: Unable to retrieve Wayback Machine snapshots for {domain}."
        except Exception as e:
            return f"Error: Unable to retrieve Wayback Machine snapshots for {domain}. {e}"

    def social_media_links(self, domain):
        try:
            url = f"http://{domain}"
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            social_media = []
            for a in soup.find_all('a', href=True):
                href = a['href']
                if "facebook.com" in href or "twitter.com" in href or "linkedin.com" in href:
                    social_media.append(href)
            if social_media:
                result = "Social Media Links:\n" + "\n".join(social_media)
            else:
                result = "No Social Media Links found."
            return result
        except Exception as e:
            return f"Error: Unable to retrieve Social Media Links for {domain}. {e}"

    def whois_lookup(self, domain):
        try:
            # Perform WHOIS lookup using the python-whois library
            domain_info = whois.whois(domain)

            # Extract relevant information from the WHOIS result
            if domain_info:
                results = [
                    f"WHOIS lookup for {domain}:\n",
                    f"Domain Name: {domain_info.get('domain_name', 'Not available')}\n",
                    f"Registrar: {domain_info.get('registrar', 'Not available')}\n",
                    f"Creation Date: {domain_info.get('creation_date', 'Not available')}\n",
                    f"Expiration Date: {domain_info.get('expiration_date', 'Not available')}\n",
                    f"Name Servers: {', '.join(domain_info.get('name_servers', ['Not available']))}\n",
                    f"Status: {', '.join(domain_info.get('status', ['Not available']))}\n",
                    f"Updated Date: {domain_info.get('updated_date', 'Not available')}\n"
                ]
                return ''.join(results)
            else:
                return f"Error: No WHOIS data found for {domain}.\n"

        except Exception as e:
            return f"Error: Unable to perform WHOIS lookup for {domain}. {e}\n"

    def dns_enumeration(self, domain):
        results = []

        try:
            # A records (IPv4 addresses)
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                for ip in a_records:
                    results.append(f"A record: {ip.to_text()}")
            except dns.exception.DNSException:
                results.append("No A records found.")

            # MX records (Mail servers)
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                for mx in mx_records:
                    results.append(f"MX record: {mx.exchange.to_text()} with priority {mx.preference}")
            except dns.exception.DNSException:
                results.append("No MX records found.")

            # NS records (Name servers)
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                for ns in ns_records:
                    results.append(f"NS record: {ns.target.to_text()}")
            except dns.exception.DNSException:
                results.append("No NS records found.")

            # TXT records (Text records)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for txt in txt_records:
                    results.append(f"TXT record: {txt.to_text()}")
            except dns.exception.DNSException:
                results.append("No TXT records found.")

            # Add other types of DNS records as needed (e.g., CNAME, SOA)

            if not results:
                results.append(f"No DNS records found for {domain}")

        except Exception as e:
            results.append(f"Error: Unable to perform DNS enumeration for {domain}. {e}")

        return "\n".join(results)

    def port_scanning(self, domain):
        try:
            ip_address = socket.gethostbyname(domain)
            common_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                67: "DHCP (Server)",
                68: "DHCP (Client)",
                80: "HTTP",
                110: "POP3",
                115: "SFTP",
                143: "IMAP",
                161: "SNMP",
                162: "SNMP Trap",
                194: "IRC",
                443: "HTTPS",
                445: "SMB",
                465: "SMTP over SSL",
                514: "Syslog",
                587: "SMTP (Submission)",
                631: "IPP",
                993: "IMAPS",
                995: "POP3S",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                5900: "VNC",
                6379: "Redis",
                8080: "HTTP (Alternate)",
                8443: "HTTPS (Alternate)",

            }

            port_statuses = []

            for port, service in common_ports.items():
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_address, port))

                    if result == 0:
                        port_statuses.append(f"Port {port} ({service}) is open")
                    elif result == 10061:  # Connection refused
                        port_statuses.append(f"Port {port} ({service}) is closed")
                    else:
                        # Assume any other result means the port is filtered
                        port_statuses.append(f"Port {port} ({service}) is filtered or inaccessible")

            if port_statuses:
                return "\n".join(port_statuses)
            else:
                return "No common ports scanned."

        except socket.gaierror:
            return f"Error: Unable to resolve {domain}"
        except Exception as e:
            return f"Error: Unable to perform port scanning for {domain}. {e}"

    def technology_analysis(self, domain):
        try:
            # Send an HTTP request to the domain
            url = f"http://{domain}"
            response = requests.get(url, timeout=10)  # Added timeout for better error handling

            # Check if the response is successful
            if response.status_code != 200:
                return f"Error: Unable to access {domain}. HTTP Status code: {response.status_code}"

            headers = response.headers
            server = headers.get('Server', 'Unknown')
            x_powered_by = headers.get('X-Powered-By', 'Unknown')

            technologies = f"Server: {server}\nX-Powered-By: {x_powered_by}\n"

            # Parsing HTML for generator/meta tags
            soup = BeautifulSoup(response.text, 'html.parser')

            # Look for 'generator' meta tag which can tell you the CMS or technology used
            meta_generator = soup.find('meta', {'name': 'generator'})
            if meta_generator:
                technologies += f"Generator: {meta_generator['content']}\n"

            # Optionally, you can check for other common identifiers like frameworks in comments or other meta tags
            # For example, detecting WordPress based on meta tag
            if 'wp-content' in response.text:
                technologies += "Technology: WordPress\n"

            # Additional checks for specific technologies (e.g., React, Angular)
            if 'React' in response.text:
                technologies += "Technology: React\n"
            if 'Angular' in response.text:
                technologies += "Technology: Angular\n"

            # Return the technologies string if anything was found, otherwise indicate no technologies were detected
            return technologies if technologies.strip() else "No technology information found."

        except requests.exceptions.Timeout:
            return f"Error: Timeout occurred while trying to access {domain}."
        except requests.exceptions.RequestException as e:
            return f"Error: Unable to connect to {domain}. {e}"
        except Exception as e:
            return f"Error: Unable to perform technology analysis for {domain}. {e}"

    def admin_panel(self, domain):
        common_admin_paths = [
            "admin", "admin/login", "admin/index", "admin/admin", "admin_area/admin", "admin1", "admin2", "admin3",
            "administrator", "administrator/login", "administrator/index", "cpanel", "cpanel/login", "cpanel/index",
            "controlpanel", "controlpanel/login", "controlpanel/index", "login", "login/admin"
        ]
        found_panels = []

        # Adding headers to simulate a real user agent and prevent blocks
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        session = requests.Session()  # Using a session object to maintain cookies between requests

        for path in common_admin_paths:
            # Try both HTTP and HTTPS
            for protocol in ['http', 'https']:
                url = f"{protocol}://{domain}/{path}"
                try:
                    response = session.get(url, headers=headers, timeout=5)  # Added timeout to avoid hanging

                    if response.status_code == 200:  # Admin panel found
                        found_panels.append(f"Found: {url} (Status Code: {response.status_code})")
                    elif response.status_code == 403:  # Forbidden but may exist
                        found_panels.append(f"Possible Admin Panel (403): {url}")
                    elif response.status_code == 401:  # Unauthorized but may exist
                        found_panels.append(f"Possible Admin Panel (401): {url}")
                    else:
                        # Log non-200, non-403, non-401 status codes
                        print(f"Checked URL: {url} - Status Code: {response.status_code}")
                except requests.RequestException as e:
                    # Log any request exceptions (e.g., connection errors, timeouts)
                    print(f"Error with URL: {url} - {str(e)}")

        if found_panels:
            return "Found Admin Panels:\n" + "\n".join(found_panels)
        else:
            return "No Admin Panels found"

    def xss_finding(self, domain):
        # Example payloads for XSS testing
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>"
        ]
        test_urls = [
            f"http://{domain}/",  # Test base URL
            f"http://{domain}/index.php",  # You can customize this list based on known paths
            f"http://{domain}/login",  # Login pages often have forms
            f"http://{domain}/search",  # Search functionality might reflect input
            f"http://{domain}/profile",  # Profile pages can reflect data
        ]

        results = []

        for test_url in test_urls:
            for payload in payloads:
                try:
                    # Test both GET (URL params) and POST (form data) methods
                    # Testing GET method (URL parameter)
                    response = requests.get(test_url, params={'input': payload})
                    if payload in response.text:
                        results.append(f"Potential XSS found with payload: {payload} on GET method at {test_url}")

                    # Testing POST method (form field)
                    response = requests.post(test_url, data={'input': payload})
                    if payload in response.text:
                        results.append(f"Potential XSS found with payload: {payload} on POST method at {test_url}")

                except requests.RequestException as e:
                    results.append(f"Error during XSS test at {test_url}: {e}")

        if results:
            return "\n".join(results)
        else:
            return "No XSS vulnerabilities found."

    def directory_search(self, domain):
        common_paths = [
            "admin", "login", "uploads", "images", "css", "js", "scripts", "assets",
            "backup", "temp", "test", "docs", "config", "api", "cgi-bin", "downloads",
            "filemanager", "includes", "content", "static", "private"
        ]
        found_directories = []

        for path in common_paths:
            # Try both with and without a trailing slash
            for check_path in [f"{path}", f"{path}/"]:
                url = f"http://{domain}/{check_path}"

                try:
                    response = requests.get(url, timeout=5)  # Added timeout for better performance
                    if response.status_code in [200, 301, 302]:  # Check for successful or redirect status codes
                        found_directories.append(url)
                except requests.RequestException as e:
                    # Handle any network-related errors here (e.g., timeout, DNS error)
                    continue

        if found_directories:
            return "Found Directories:\n" + "\n".join(found_directories)
        else:
            return "No directories found."

if __name__ == "__main__":
    root = tk.Tk()
    app = WebAppPenTestTool(root)
    root.mainloop()