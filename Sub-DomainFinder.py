import sys
import csv
import json
import threading
import time
import dns.resolver
import requests
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QLabel, QLineEdit, QPushButton, QTextEdit, QTableWidget, 
                             QTableWidgetItem, QProgressBar, QComboBox, QSpinBox, 
                             QFileDialog, QMessageBox, QSplitter, QTabWidget, QCheckBox,
                             QGroupBox, QFormLayout, QHeaderView, QToolButton, QMenu, QAction)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon

class ScanThread(QThread):
    update_progress = pyqtSignal(int, int, str)
    found_subdomain = pyqtSignal(str, str, str, str)
    scan_finished = pyqtSignal()
    
    def __init__(self, target_domain, wordlist_path, dns_servers, threads, use_ct_logs, 
                 validate_http, check_common_ports, parent=None):
        super().__init__(parent)
        self.target_domain = target_domain
        self.wordlist_path = wordlist_path
        self.dns_servers = dns_servers
        self.threads = threads
        self.use_ct_logs = use_ct_logs
        self.validate_http = validate_http
        self.check_common_ports = check_common_ports
        self.is_running = True
        
    def run(self):
        # Read wordlist
        try:
            with open(self.wordlist_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.update_progress.emit(0, 0, f"Error reading wordlist: {str(e)}")
            return
            
        total = len(wordlist)
        found_count = 0
        
        # Configure DNS resolver
        resolver = dns.resolver.Resolver()
        if self.dns_servers:
            resolver.nameservers = self.dns_servers.split(',')
        
        # Process wordlist
        for i, word in enumerate(wordlist):
            if not self.is_running:
                break
                
            subdomain = f"{word}.{self.target_domain}"
            self.update_progress.emit(i+1, total, f"Testing: {subdomain}")
            
            try:
                answers = resolver.resolve(subdomain, 'A')
                for answer in answers:
                    ip = answer.to_text()
                    status = "DNS Found"
                    
                    # HTTP validation if enabled
                    if self.validate_http:
                        try:
                            response = requests.get(f"http://{subdomain}", timeout=5)
                            status = f"HTTP {response.status_code}"
                        except:
                            try:
                                response = requests.get(f"https://{subdomain}", timeout=5)
                                status = f"HTTPS {response.status_code}"
                            except:
                                status = "DNS Found (No HTTP)"
                    
                    self.found_subdomain.emit(subdomain, ip, status, "Active")
                    found_count += 1
            except:
                pass
                
            # Small delay to avoid rate limiting
            time.sleep(0.05)
            
        self.scan_finished.emit()
        
    def stop(self):
        self.is_running = False


class SubdomainFinderGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Subdomain Finder")
        self.setGeometry(100, 100, 1200, 800)
        
        # Initialize variables
        self.scan_thread = None
        self.results = []
        self.dark_mode = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Create tabs
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Scan tab
        scan_tab = QWidget()
        scan_layout = QVBoxLayout(scan_tab)
        tabs.addTab(scan_tab, "Scan")
        
        # Settings tab
        settings_tab = QWidget()
        settings_layout = QVBoxLayout(settings_tab)
        tabs.addTab(settings_tab, "Settings")
        
        # Setup scan tab
        self.setup_scan_tab(scan_layout)
        
        # Setup settings tab
        self.setup_settings_tab(settings_layout)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
    def setup_scan_tab(self, layout):
        # Target input
        target_group = QGroupBox("Target Domain")
        target_layout = QHBoxLayout(target_group)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com")
        target_layout.addWidget(QLabel("Domain:"))
        target_layout.addWidget(self.target_input)
        layout.addWidget(target_group)
        
        # Options group
        options_group = QGroupBox("Scan Options")
        options_layout = QFormLayout(options_group)
        
        # Wordlist selection
        wordlist_layout = QHBoxLayout()
        self.wordlist_combo = QComboBox()
        self.wordlist_combo.addItems(["common.txt", "subdomains-top1million.txt", "custom.txt"])
        self.wordlist_button = QPushButton("Browse...")
        self.wordlist_button.clicked.connect(self.browse_wordlist)
        wordlist_layout.addWidget(self.wordlist_combo)
        wordlist_layout.addWidget(self.wordlist_button)
        options_layout.addRow("Wordlist:", wordlist_layout)
        
        # DNS servers
        self.dns_input = QLineEdit()
        self.dns_input.setPlaceholderText("8.8.8.8,1.1.1.1")
        options_layout.addRow("DNS Servers:", self.dns_input)
        
        # Threads
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 100)
        self.threads_spin.setValue(20)
        options_layout.addRow("Threads:", self.threads_spin)
        
        # Checkboxes
        self.ct_logs_check = QCheckBox("Use Certificate Transparency Logs")
        self.http_check = QCheckBox("Validate HTTP/HTTPS")
        self.ports_check = QCheckBox("Check Common Ports")
        options_layout.addRow("", self.ct_logs_check)
        options_layout.addRow("", self.http_check)
        options_layout.addRow("", self.ports_check)
        
        layout.addWidget(options_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.clear_button)
        layout.addLayout(button_layout)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Subdomain", "IP Address", "Status", "Type"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.results_table)
        
    def setup_settings_tab(self, layout):
        # Theme selection
        theme_group = QGroupBox("Appearance")
        theme_layout = QVBoxLayout(theme_group)
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light Theme", "Dark Theme"])
        self.theme_combo.currentTextChanged.connect(self.change_theme)
        theme_layout.addWidget(QLabel("Theme:"))
        theme_layout.addWidget(self.theme_combo)
        layout.addWidget(theme_group)
        
        # Other settings can be added here
        layout.addStretch()
        
    def browse_wordlist(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.wordlist_combo.addItem(file_path)
            self.wordlist_combo.setCurrentText(file_path)
            
    def start_scan(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a target domain")
            return
            
        wordlist_path = self.wordlist_combo.currentText()
        dns_servers = self.dns_input.text().strip()
        threads = self.threads_spin.value()
        use_ct_logs = self.ct_logs_check.isChecked()
        validate_http = self.http_check.isChecked()
        check_ports = self.ports_check.isChecked()
        
        # Disable UI elements during scan
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Create and start scan thread
        self.scan_thread = ScanThread(
            target, wordlist_path, dns_servers, threads, 
            use_ct_logs, validate_http, check_ports, self
        )
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.found_subdomain.connect(self.add_subdomain)
        self.scan_thread.scan_finished.connect(self.scan_finished)
        self.scan_thread.start()
        
        self.status_bar.showMessage(f"Scanning {target}...")
        
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.stop()
            self.scan_thread.wait()
            self.status_bar.showMessage("Scan stopped")
            
    def scan_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("Scan completed")
        
    def update_progress(self, current, total, message):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.status_bar.showMessage(message)
        
    def add_subdomain(self, subdomain, ip, status, type_):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        self.results_table.setItem(row, 0, QTableWidgetItem(subdomain))
        self.results_table.setItem(row, 1, QTableWidgetItem(ip))
        self.results_table.setItem(row, 2, QTableWidgetItem(status))
        self.results_table.setItem(row, 3, QTableWidgetItem(type_))
        
        # Add to results list for export
        self.results.append({
            "subdomain": subdomain,
            "ip": ip,
            "status": status,
            "type": type_
        })
        
    def export_results(self):
        if not self.results:
            QMessageBox.warning(self, "Export Error", "No results to export")
            return
            
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Export Results", "", 
            "CSV Files (*.csv);;Text Files (*.txt);;JSON Files (*.json)"
        )
        
        if not file_path:
            return
            
        try:
            if selected_filter == "CSV Files (*.csv)" or file_path.endswith('.csv'):
                with open(file_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["subdomain", "ip", "status", "type"])
                    writer.writeheader()
                    writer.writerows(self.results)
                    
            elif selected_filter == "JSON Files (*.json)" or file_path.endswith('.json'):
                with open(file_path, 'w') as f:
                    json.dump(self.results, f, indent=2)
                    
            else:  # Text file
                with open(file_path, 'w') as f:
                    for result in self.results:
                        f.write(f"{result['subdomain']} | {result['ip']} | {result['status']} | {result['type']}\n")
                        
            QMessageBox.information(self, "Export Successful", f"Results exported to {file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")
            
    def clear_results(self):
        self.results_table.setRowCount(0)
        self.results = []
        self.status_bar.showMessage("Results cleared")
        
    def change_theme(self, theme_name):
        if theme_name == "Dark Theme":
            self.apply_dark_theme()
        else:
            self.apply_light_theme()
            
    def apply_dark_theme(self):
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(53, 53, 53))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(25, 25, 25))
        palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        palette.setColor(QPalette.ToolTipBase, Qt.white)
        palette.setColor(QPalette.ToolTipText, Qt.white)
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(53, 53, 53))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.BrightText, Qt.red)
        palette.setColor(QPalette.Link, QColor(42, 130, 218))
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        palette.setColor(QPalette.HighlightedText, Qt.black)
        
        self.setPalette(palette)
        self.dark_mode = True
        
    def apply_light_theme(self):
        self.setPalette(QApplication.style().standardPalette())
        self.dark_mode = False


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SubdomainFinderGUI()
    window.show()
    sys.exit(app.exec_())