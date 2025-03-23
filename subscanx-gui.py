#!/usr/bin/env python3

import sys
import requests
import json
import threading
import time
import os
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget, 
                            QCheckBox, QProgressBar, QFileDialog, QMessageBox, QGroupBox, 
                            QComboBox, QSplitter, QTableWidget, QTableWidgetItem, QHeaderView,
                            QToolButton, QStatusBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QSize
from PyQt5.QtGui import QFont, QIcon, QDesktopServices, QPixmap, QPalette, QColor
from PyQt5.QtSvg import QSvgWidget

# Use dnspython for DNS resolution
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

requests.packages.urllib3.disable_warnings()

class ScanThread(QThread):
    update_progress = pyqtSignal(int)
    update_status = pyqtSignal(str)
    finished_scan = pyqtSignal(dict, dict, list)
    
    def __init__(self, domain):
        super().__init__()
        self.domain = domain
        
    def run(self):
        domainsFound = {}
        domainsNotFound = {}
        
        try:
            # Try multiple sources to find subdomains
            all_domains = set()
            sources_tried = 0
            sources_successful = 0
            
            # First source: crt.sh
            self.update_status.emit("Trying crt.sh certificate database...")
            crt_domains = self.get_domains_from_crtsh()
            sources_tried += 1
            if crt_domains:
                all_domains.update(crt_domains)
                sources_successful += 1
                self.update_status.emit(f"Found {len(crt_domains)} domains from crt.sh")
            
            # Second source: Alternative sources
            self.update_status.emit("Trying alternative sources...")
            alt_domains = self.get_domains_from_alternative_sources()
            sources_tried += 1
            if alt_domains:
                all_domains.update(alt_domains)
                sources_successful += 1
                self.update_status.emit(f"Found {len(alt_domains)} domains from alternative sources")
            
            # Third source: Common subdomain wordlist
            # Only try common subdomains if we found less than 10 domains or no successful sources
            if len(all_domains) < 10 or sources_successful == 0:
                self.update_status.emit("Trying common subdomain list...")
                common_domains = self.get_domains_from_common_list()
                sources_tried += 1
                if common_domains:
                    all_domains.update(common_domains)
                    sources_successful += 1
                    self.update_status.emit(f"Found {len(common_domains)} domains from common subdomain list")
            
            if len(all_domains) == 0:
                self.update_status.emit("No domains found from any source!")
                self.finished_scan.emit({}, {}, [])
                return
                
            self.update_status.emit(f"Found {len(all_domains)} unique domains from {sources_successful}/{sources_tried} sources. Resolving DNS records...")
            
            # Resolve domains and update progress
            domain_list = sorted(all_domains)  # Sort for consistent results
            total_domains = len(domain_list)
            
            # Optimize batch size based on total domains
            batch_size = min(max(5, total_domains // 20), 20)  # Between 5 and 20
            batches = [domain_list[i:i + batch_size] for i in range(0, total_domains, batch_size)]
            
            for batch_idx, batch in enumerate(batches):
                batch_results = {}
                batch_errors = {}
                
                for domain in batch:
                    result = self.resolve(domain)
                    if result:
                        domain_name = list(result.keys())[0]
                        ip = result[domain_name]
                        if ip != 'none':
                            domainsFound.update(result)
                        else:
                            domainsNotFound.update(result)
                
                # Update progress after each batch
                progress = int((batch_idx + 1) / len(batches) * 100)
                self.update_progress.emit(progress)
                
                # Provide periodic updates for long scans
                if (batch_idx + 1) % 5 == 0 or batch_idx == len(batches) - 1:
                    self.update_status.emit(f"Resolved {min((batch_idx + 1) * batch_size, total_domains)}/{total_domains} domains... Found {len(domainsFound)} valid records so far.")
            
            self.update_status.emit(f"Scan completed! Found {len(domainsFound)} resolved domains out of {total_domains} total domains.")
            
        except Exception as e:
            self.update_status.emit(f"Error during scan: {str(e)}")
        finally:
            # Always emit results, even if there was an error
            self.finished_scan.emit(domainsFound, domainsNotFound, domain_list if 'domain_list' in locals() else [])
    
    def resolve(self, domain):
        """Resolve domain to IP address using system's resolver or dnspython if available"""
        try:
            if HAS_DNSPYTHON:
                try:
                    # Set a shorter timeout for faster resolution
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 2.0  # 2 seconds timeout
                    resolver.lifetime = 4.0  # 4 seconds total lifetime
                    
                    answers = resolver.resolve(domain, 'A')
                    # Return the first IP address
                    return {domain: str(answers[0])}
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    # Common DNS errors: Domain doesn't exist, No A record, Timeout
                    return {domain: "none"}
                except Exception as e:
                    # Other DNS errors
                    return {domain: "none"}
            else:
                # Fallback to socket with timeout
                import socket
                socket.setdefaulttimeout(2.0)  # 2 seconds timeout
                return {domain: socket.gethostbyname(domain)}
        except Exception as e:
            # Don't log every resolution error to avoid flooding the log
            # Only log every 10th error or unusual errors
            if hash(domain) % 10 == 0:
                self.update_status.emit(f"DNS resolution issues continue - {domain}: {str(e)[:50]}")
            return {domain: "none"}
    
    def get_domains_from_crtsh(self):
        """Get domains from crt.sh certificate database"""
        domains = set()
        
        # Define a helper function to process JSON data and extract domains
        def process_crtsh_data(data):
            extracted_domains = set()
            for entry in data:
                # Process name_value field
                if 'name_value' in entry:
                    domain_names = entry['name_value'].split('\n')
                    for name in domain_names:
                        if name.endswith(self.domain) and '*' not in name:
                            extracted_domains.add(name)
                
                # Process common_name field
                if 'common_name' in entry and entry['common_name'].endswith(self.domain) and '*' not in entry['common_name']:
                    extracted_domains.add(entry['common_name'])
            return extracted_domains
        
        # Try queries with different formats
        queries = [
            f'https://crt.sh/?q=%.{self.domain}&output=json',  # Wildcard query
            f'https://crt.sh/?q={self.domain}&output=json'      # Direct query
        ]
        
        for query_url in queries:
            if domains:  # If we already found domains, no need to try other queries
                break
                
            try:
                response = requests.get(query_url, verify=False, timeout=10)
                query_type = "wildcard" if "%" in query_url else "direct"
                self.update_status.emit(f"crt.sh {query_type} query response: HTTP {response.status_code}")
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        new_domains = process_crtsh_data(data)
                        domains.update(new_domains)
                        if new_domains:
                            self.update_status.emit(f"Found {len(new_domains)} domains from crt.sh {query_type} query")
                    except json.JSONDecodeError:
                        self.update_status.emit(f"Invalid JSON from crt.sh {query_type} query")
            except requests.exceptions.RequestException as e:
                self.update_status.emit(f"crt.sh {query_type} query error: {str(e)}")
        
        return domains
    
    def get_domains_from_alternative_sources(self):
        """Get domains from alternative sources"""
        domains = set()
        
        # Define sources with their configurations
        sources = [
            {
                'name': 'Alienvault OTX',
                'url': f'https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns',
                'headers': {},
                'parser': lambda data: [
                    entry['hostname'] for entry in data.get('passive_dns', [])
                    if 'hostname' in entry and entry['hostname'].endswith(self.domain)
                ]
            },
            {
                'name': 'VirusTotal',
                'url': f'https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40',
                'headers': {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                },
                'parser': lambda data: [
                    entry['id'] for entry in data.get('data', [])
                    if 'id' in entry and entry['id'].endswith(self.domain)
                ]
            }
        ]
        
        # Query each source
        for source in sources:
            try:
                self.update_status.emit(f"Querying {source['name']}...")
                response = requests.get(
                    source['url'],
                    headers=source['headers'],
                    timeout=10
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        new_domains = source['parser'](data)
                        if new_domains:
                            domains.update(new_domains)
                            self.update_status.emit(f"Found {len(new_domains)} domains from {source['name']}")
                    except json.JSONDecodeError:
                        self.update_status.emit(f"Invalid JSON from {source['name']}")
                else:
                    self.update_status.emit(f"{source['name']} returned status code {response.status_code}")
            except requests.exceptions.RequestException as e:
                self.update_status.emit(f"{source['name']} connection error: {str(e)[:50]}")
        
        return domains
    
    def get_domains_from_common_list(self):
        """Try common subdomains via brute force"""
        # Expanded list of common subdomains, organized by category
        common_subdomains = [
            # Basic services
            "www", "mail", "webmail", "smtp", "pop", "pop3", "imap", "ftp", "sftp",
            
            # Network infrastructure
            "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "mx", "mx1", "mx2",
            "autodiscover", "autoconfig", "ipv6", "ipv4", "gateway", "router", "vpn",
            "proxy", "firewall", "nat", "dhcp", "ldap", "remote", "ssh", "sip",
            
            # Web services
            "web", "www2", "portal", "api", "api-docs", "developer", "developers",
            "dev", "app", "apps", "mobile", "m", "wap", "cdn", "static", "assets",
            "images", "img", "css", "js", "media", "download", "downloads", "upload",
            
            # Business functions
            "admin", "administrator", "webadmin", "admins", "cpanel", "cp", "whm",
            "dashboard", "manage", "management", "manager", "client", "clients",
            "customer", "customers", "user", "users", "partner", "partners", "reseller",
            "store", "shop", "cart", "checkout", "payment", "pay", "billing", "bill",
            "secure", "support", "help", "faq", "ticket", "tickets", "kb", "knowledgebase",
            
            # Collaboration and content
            "blog", "forum", "community", "chat", "discuss", "wiki", "docs", "documentation",
            "news", "events", "calendar", "mail2", "webmail2", "email", "newsletter",
            
            # Development and operations
            "test", "testing", "staging", "stage", "demo", "beta", "alpha", "sandbox",
            "dev-api", "qa", "uat", "build", "jenkins", "ci", "gitlab", "git", "svn",
            "jira", "confluence", "status", "monitor", "monitoring", "analytics", "stats",
            "metrics", "graphite", "grafana", "kibana", "elasticsearch", "logging",
            
            # Internal systems
            "intranet", "internal", "inside", "local", "private", "corp", "corporate",
            "backup", "backups", "archive", "db", "database", "sql", "mysql", "postgres",
            "oracle", "server", "host", "cloud", "exchange", "sharepoint", "office"
        ]
        
        # Create a set for faster lookups and to avoid duplicates
        domains = set()
        
        # Add the base domain itself
        domains.add(self.domain)
        
        # Add common subdomains
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.domain}"
            domains.add(full_domain)
        
        # Add some common patterns with numbers
        for i in range(1, 6):  # 1 through 5
            domains.add(f"server{i}.{self.domain}")
            domains.add(f"s{i}.{self.domain}")
            domains.add(f"vps{i}.{self.domain}")
            
        self.update_status.emit(f"Generated {len(domains)} potential common subdomains")
        return domains


class SubScanXGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        
        # Store scan results
        self.domains_found = {}
        self.domains_not_found = {}
        self.all_domains = []
        
        # Load stylesheet
        self.load_stylesheet()
    
    def open_github(self):
        """Open GitHub page in default browser"""
        QDesktopServices.openUrl(QUrl("https://github.com/captainmgc"))
        
    def load_stylesheet(self):
        """Load the QSS stylesheet"""
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'styles.qss'), 'r') as f:
                self.setStyleSheet(f.read())
        except Exception as e:
            print(f"Error loading stylesheet: {str(e)}")
            
    def center_on_screen(self):
        """Center the window on the screen"""
        # Get screen geometry
        screen = QApplication.desktop().screenGeometry()
        # Calculate center position
        x = (screen.width() - self.width()) // 2
        y = (screen.height() - self.height()) // 2
        # Move window to center
        self.move(x, y)
        
    def initUI(self):
        self.setWindowTitle('SubScanX - Certificate Transparency Subdomain Finder')
        # Set window size
        self.resize(1000, 700)
        # Center window on screen
        self.center_on_screen()
        
        # Set application icon
        self.setWindowIcon(self.load_svg_icon('logo'))
        
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Header with logo
        header_layout = QHBoxLayout()
        # Use PNG logo instead of SVG
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', 'logo.png')
        logo_pixmap = QPixmap(logo_path)
        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap.scaled(96, 96, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setFixedSize(96, 96)
        header_layout.addWidget(logo_label)
        
        header_text = QLabel("<h1>SubScanX</h1><p>Certificate Transparency Subdomain Finder</p>")
        header_text.setTextFormat(Qt.RichText)
        header_layout.addWidget(header_text)
        header_layout.addStretch()
        
        # Add info button that links to GitHub
        info_button = QPushButton()
        info_button.setIcon(self.load_svg_icon('info'))
        info_button.setToolTip("Visit GitHub Page")
        info_button.setFixedSize(32, 32)
        info_button.clicked.connect(self.open_github)
        header_layout.addWidget(info_button)
        main_layout.addLayout(header_layout)
        
        # Input section
        input_group = QGroupBox("Domain Search")
        input_layout = QVBoxLayout()
        
        search_layout = QHBoxLayout()
        domain_label = QLabel("Domain:")
        domain_label.setFixedWidth(60)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain to query (e.g., example.com)")
        
        # Search button with icon
        self.scan_button = QPushButton("Scan")
        self.scan_button.setIcon(self.load_svg_icon('search'))
        self.scan_button.setIconSize(QSize(18, 18))
        self.scan_button.clicked.connect(self.start_scan)
        
        search_layout.addWidget(domain_label)
        search_layout.addWidget(self.domain_input)
        search_layout.addWidget(self.scan_button)
        
        # Progress section
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        # Add status log text box
        log_layout = QHBoxLayout()
        log_label = QLabel("Status Log:")
        log_label.setFixedWidth(80)
        self.status_log = QTextEdit()
        self.status_log.setReadOnly(True)
        self.status_log.setMaximumHeight(100)
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.status_log)
        
        input_layout.addLayout(search_layout)
        input_layout.addLayout(progress_layout)
        input_layout.addLayout(log_layout)
        input_group.setLayout(input_layout)
        
    def load_svg_icon(self, icon_name):
        """Load an SVG icon from the icons directory"""
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', f'{icon_name}.svg')
        return QIcon(icon_path)
    
    def initUI(self):
        self.setWindowTitle('SubScanX - Certificate Transparency Subdomain Finder')
        # Set window size
        self.resize(1000, 700)
        # Center window on screen
        self.center_on_screen()
        
        # Set application icon
        self.setWindowIcon(self.load_svg_icon('logo'))
        
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(15, 15, 15, 15)
        
        # Header with logo
        header_layout = QHBoxLayout()
        # Use PNG logo instead of SVG
        logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icons', 'logo.png')
        logo_pixmap = QPixmap(logo_path)
        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap.scaled(96, 96, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo_label.setFixedSize(96, 96)
        header_layout.addWidget(logo_label)
        
        header_text = QLabel("<h1>SubScanX</h1><p>Certificate Transparency Subdomain Finder</p>")
        header_text.setTextFormat(Qt.RichText)
        header_layout.addWidget(header_text)
        header_layout.addStretch()
        
        # Add info button that links to GitHub
        info_button = QPushButton()
        info_button.setIcon(self.load_svg_icon('info'))
        info_button.setToolTip("Visit GitHub Page")
        info_button.setFixedSize(32, 32)
        info_button.clicked.connect(self.open_github)
        header_layout.addWidget(info_button)
        main_layout.addLayout(header_layout)
        
        # Input section
        input_group = QGroupBox("Domain Search")
        input_layout = QVBoxLayout()
        
        search_layout = QHBoxLayout()
        domain_label = QLabel("Domain:")
        domain_label.setFixedWidth(60)
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain to query (e.g., example.com)")
        
        # Search button with icon
        self.scan_button = QPushButton("Scan")
        self.scan_button.setIcon(self.load_svg_icon('search'))
        self.scan_button.setIconSize(QSize(18, 18))
        self.scan_button.clicked.connect(self.start_scan)
        
        search_layout.addWidget(domain_label)
        search_layout.addWidget(self.domain_input)
        search_layout.addWidget(self.scan_button)
        
        # Progress section
        progress_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.status_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.status_label)
        
        # Add status log text box
        log_layout = QHBoxLayout()
        log_label = QLabel("Status Log:")
        log_label.setFixedWidth(80)
        self.status_log = QTextEdit()
        self.status_log.setReadOnly(True)
        self.status_log.setMaximumHeight(100)
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.status_log)
        
        input_layout.addLayout(search_layout)
        input_layout.addLayout(progress_layout)
        input_layout.addLayout(log_layout)
        input_group.setLayout(input_layout)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        
        # Found domains tab
        self.found_tab = QWidget()
        found_layout = QVBoxLayout()
        
        # Table for found domains
        self.found_table = QTableWidget()
        self.found_table.setColumnCount(2)
        self.found_table.setHorizontalHeaderLabels(["IP Address", "Domain"])
        self.found_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        found_layout.addWidget(self.found_table)
        
        # Export options for found domains
        export_found_layout = QHBoxLayout()
        self.export_found_button = QPushButton("Export Results")
        self.export_found_button.setIcon(self.load_svg_icon('export'))
        self.export_found_button.clicked.connect(lambda: self.export_results("found"))
        self.export_format_found = QComboBox()
        self.export_format_found.addItems(["CSV", "Text", "URLs List", "IP List"])
        export_found_layout.addWidget(self.export_found_button)
        export_found_layout.addWidget(self.export_format_found)
        found_layout.addLayout(export_found_layout)
        
        self.found_tab.setLayout(found_layout)
        
        # Not found domains tab
        self.not_found_tab = QWidget()
        not_found_layout = QVBoxLayout()
        
        # Table for not found domains
        self.not_found_table = QTableWidget()
        self.not_found_table.setColumnCount(2)
        self.not_found_table.setHorizontalHeaderLabels(["Status", "Domain"])
        self.not_found_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        not_found_layout.addWidget(self.not_found_table)
        
        # Export options for not found domains
        export_not_found_layout = QHBoxLayout()
        self.export_not_found_button = QPushButton("Export Results")
        self.export_not_found_button.setIcon(self.load_svg_icon('export'))
        self.export_not_found_button.clicked.connect(lambda: self.export_results("not_found"))
        self.export_format_not_found = QComboBox()
        self.export_format_not_found.addItems(["CSV", "Text", "Domain List"])
        export_not_found_layout.addWidget(self.export_not_found_button)
        export_not_found_layout.addWidget(self.export_format_not_found)
        not_found_layout.addLayout(export_not_found_layout)
        
        self.not_found_tab.setLayout(not_found_layout)
        
        # All domains tab
        self.all_domains_tab = QWidget()
        all_domains_layout = QVBoxLayout()
        
        # Table for all domains
        self.all_domains_table = QTableWidget()
        self.all_domains_table.setColumnCount(1)
        self.all_domains_table.setHorizontalHeaderLabels(["Domain"])
        self.all_domains_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        all_domains_layout.addWidget(self.all_domains_table)
        
        # Export options for all domains
        export_all_layout = QHBoxLayout()
        self.export_all_button = QPushButton("Export Results")
        self.export_all_button.setIcon(self.load_svg_icon('export'))
        self.export_all_button.clicked.connect(lambda: self.export_results("all"))
        self.export_format_all = QComboBox()
        self.export_format_all.addItems(["CSV", "Text", "URLs List"])
        export_all_layout.addWidget(self.export_all_button)
        export_all_layout.addWidget(self.export_format_all)
        all_domains_layout.addLayout(export_all_layout)
        
        self.all_domains_tab.setLayout(all_domains_layout)
        
        # Add tabs to tab widget
        self.results_tabs.addTab(self.found_tab, "Domains Found")
        self.results_tabs.addTab(self.not_found_tab, "Domains Not Found")
        self.results_tabs.addTab(self.all_domains_tab, "All Domains")
        
        # Add custom icons to tabs
        self.results_tabs.setTabIcon(0, self.load_svg_icon('found'))
        self.results_tabs.setTabIcon(1, self.load_svg_icon('not-found'))
        self.results_tabs.setTabIcon(2, self.load_svg_icon('domain'))
        
        # Add stats section
        stats_group = QGroupBox("Statistics")
        stats_layout = QHBoxLayout()
        
        self.stats_total_label = QLabel("Total domains: 0")
        self.stats_found_label = QLabel("Resolved domains: 0")
        self.stats_not_found_label = QLabel("Unresolved domains: 0")
        
        stats_layout.addWidget(self.stats_total_label)
        stats_layout.addWidget(self.stats_found_label)
        stats_layout.addWidget(self.stats_not_found_label)
        
        stats_group.setLayout(stats_layout)
        
        # Add widgets to main layout
        main_layout.addWidget(input_group)
        main_layout.addWidget(self.results_tabs)
        main_layout.addWidget(stats_group)
        
        # Add status bar
        self.statusBar = QStatusBar()
        self.setStatusBar(self.statusBar)
        self.statusBar.showMessage("Ready to scan domains")
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
    
    def start_scan(self):
        """Start the domain scanning process"""
        # Validate domain input
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain to scan.")
            return
            
        # Basic domain format validation
        if not self.is_valid_domain(domain):
            QMessageBox.warning(self, "Input Error", 
                               f"'{domain}' does not appear to be a valid domain.\n"
                               "Please enter a domain in the format: example.com")
            return
        
        # Clear previous results
        self.found_table.setRowCount(0)
        self.not_found_table.setRowCount(0)
        self.all_domains_table.setRowCount(0)
        self.status_log.clear()
        
        # Reset progress bar and statistics
        self.progress_bar.setValue(0)
        self.stats_total_label.setText("Total domains: 0")
        self.stats_found_label.setText("Resolved domains: 0")
        self.stats_not_found_label.setText("Unresolved domains: 0")
        
        # Update UI to show scanning is in progress
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning...")
        self.scan_button.setIcon(self.load_svg_icon('refresh'))
        self.domain_input.setReadOnly(True)  # Prevent editing during scan
        
        # Update status
        scan_message = f"Scanning {domain}..."
        self.statusBar.showMessage(scan_message)
        self.update_status(scan_message)
        
        # Start scan thread
        self.scan_thread = ScanThread(domain)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.update_status.connect(self.update_status)
        self.scan_thread.finished_scan.connect(self.scan_completed)
        self.scan_thread.start()
        
    def is_valid_domain(self, domain):
        """Basic validation for domain format"""
        # Simple check for domain format
        import re
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def update_status(self, status):
        self.status_label.setText(status)
        self.status_log.append(status)
        self.statusBar.showMessage(status)
    
    def scan_completed(self, domains_found, domains_not_found, all_domains):
        """Process and display scan results"""
        # Store results
        self.domains_found = domains_found
        self.domains_not_found = domains_not_found
        self.all_domains = all_domains
        
        try:
            # Update found domains table
            self.found_table.setSortingEnabled(False)  # Disable sorting during update
            self.found_table.setRowCount(len(domains_found))
            for idx, domain in enumerate(sorted(domains_found.keys())):
                ip_item = QTableWidgetItem(domains_found[domain])
                domain_item = QTableWidgetItem(domain)
                self.found_table.setItem(idx, 0, ip_item)
                self.found_table.setItem(idx, 1, domain_item)
            self.found_table.setSortingEnabled(True)  # Re-enable sorting
            
            # Update not found domains table
            self.not_found_table.setSortingEnabled(False)  # Disable sorting during update
            self.not_found_table.setRowCount(len(domains_not_found))
            for idx, domain in enumerate(sorted(domains_not_found.keys())):
                status_item = QTableWidgetItem("No DNS Record")
                domain_item = QTableWidgetItem(domain)
                self.not_found_table.setItem(idx, 0, status_item)
                self.not_found_table.setItem(idx, 1, domain_item)
            self.not_found_table.setSortingEnabled(True)  # Re-enable sorting
            
            # Update all domains table
            self.all_domains_table.setSortingEnabled(False)  # Disable sorting during update
            self.all_domains_table.setRowCount(len(all_domains))
            for idx, domain in enumerate(sorted(all_domains)):
                domain_item = QTableWidgetItem(domain)
                self.all_domains_table.setItem(idx, 0, domain_item)
            self.all_domains_table.setSortingEnabled(True)  # Re-enable sorting
            
            # Update statistics
            self.stats_total_label.setText(f"Total domains: {len(all_domains)}")
            self.stats_found_label.setText(f"Resolved domains: {len(domains_found)}")
            self.stats_not_found_label.setText(f"Unresolved domains: {len(domains_not_found)}")
            
            # Select appropriate tab based on results
            if domains_found:
                self.results_tabs.setCurrentIndex(0)  # Show found domains tab
            elif domains_not_found:
                self.results_tabs.setCurrentIndex(1)  # Show not found domains tab
            else:
                self.results_tabs.setCurrentIndex(2)  # Show all domains tab
            
            # Show completion message with more details
            completion_message = f"Scan completed! Found {len(all_domains)} domains, {len(domains_found)} resolved."
            self.update_status(completion_message)
            self.statusBar.showMessage(f"Ready - Last scan: {len(all_domains)} domains found, {len(domains_found)} resolved")
            
        except Exception as e:
            error_message = f"Error processing scan results: {str(e)}"
            self.update_status(error_message)
            self.statusBar.showMessage("Error processing results")
        
        finally:
            # Always re-enable UI elements
            self.scan_button.setEnabled(True)
            self.scan_button.setText("Scan")
            self.scan_button.setIcon(self.load_svg_icon('search'))
            self.domain_input.setReadOnly(False)  # Re-enable domain input
    
    def export_results(self, result_type):
        """Export scan results in various formats"""
        # Define data sources based on result type
        data_sources = {
            "found": (self.domains_found, self.export_format_found),
            "not_found": (self.domains_not_found, self.export_format_not_found),
            "all": (self.all_domains, self.export_format_all)
        }
        
        # Check if we have data to export
        data, format_combo = data_sources.get(result_type, (None, None))
        if not data:
            QMessageBox.warning(self, "Export Error", f"No {result_type} domains to export.")
            return
        
        # Get export format
        export_format = format_combo.currentText()
        
        # Set file extension based on export format
        file_extension = ".txt"  # Default extension
        if export_format == "CSV":
            file_extension = ".csv"
        
        # Get domain name from input for file naming
        domain = self.domain_input.text().strip()
        default_filename = f"{domain}_{result_type}_results{file_extension}"
        
        # Get file path with appropriate filter based on format
        filter_text = "Text Files (*.txt)" if file_extension == ".txt" else "CSV Files (*.csv)"
        file_path, _ = QFileDialog.getSaveFileName(self, "Save File", default_filename, filter_text)
        if not file_path:
            return
            
        # Ensure file has the correct extension
        if not file_path.endswith(file_extension):
            file_path += file_extension
        
        try:
            with open(file_path, "w") as f:
                # Define export formatters as functions
                if result_type == "found":
                    if export_format == "CSV":
                        f.write("IP,Domain\n")
                        for domain in sorted(data.keys()):
                            f.write(f"{data[domain]},{domain}\n")
                    elif export_format == "Text":
                        for domain in sorted(data.keys()):
                            f.write(f"{data[domain]}\t{domain}\n")
                    elif export_format == "URLs List":
                        for domain in sorted(data.keys()):
                            f.write(f"https://{domain}\n")
                    elif export_format == "IP List":
                        # Create unique IP list for masscan
                        ip_list = sorted(set(data.values()))
                        for ip in ip_list:
                            f.write(f"{ip}\n")
                
                elif result_type == "not_found":
                    if export_format == "CSV":
                        f.write("Status,Domain\n")
                        for domain in sorted(data.keys()):
                            f.write(f"No DNS Record,{domain}\n")
                    elif export_format == "Text":
                        for domain in sorted(data.keys()):
                            f.write(f"none\t{domain}\n")
                    elif export_format == "Domain List":
                        for domain in sorted(data.keys()):
                            f.write(f"{domain}\n")
                
                else:  # All domains
                    if export_format == "CSV":
                        f.write("Domain\n")
                        for domain in sorted(data):
                            f.write(f"{domain}\n")
                    elif export_format == "Text":
                        for domain in sorted(data):
                            f.write(f"{domain}\n")
                    elif export_format == "URLs List":
                        for domain in sorted(data):
                            f.write(f"https://{domain}\n")
            
            self.statusBar.showMessage(f"Exported {len(data)} domains to {file_path}", 5000)
            QMessageBox.information(self, "Export Successful", f"Results successfully exported to {file_path}")
        
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {str(e)}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for a more modern look
    window = SubScanXGUI()
    window.show()
    sys.exit(app.exec_())