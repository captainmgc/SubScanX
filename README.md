# SubScanx GUI

Modern PyQt5-based GUI for SubScanx, a powerful tool that discovers subdomains by querying Certificate Transparency (CT) logs. With a sleek and responsive design, SubScanx GUI makes it easier than ever to uncover hidden subdomains.

![SubScanx GUI Screenshot](https://via.placeholder.com/800x500?text=SubScanx+GUI)

---

## 🚀 Features

### 🔍 Subdomain Discovery
- **Certificate Transparency Log Scanning**: Identify subdomains using CT logs
- **Multi-source Queries**: Fetch data from:
  - [crt.sh](https://crt.sh/)
  - [AlienVault OTX](https://otx.alienvault.com/)
  - [VirusTotal](https://www.virustotal.com/)
  - Common subdomain wordlists

### 🌐 DNS Resolution
- Automatically resolve discovered domains to IP addresses
- Categorization into:
  - **Resolved Domains** (with IPs)
  - **Unresolved Domains**
  - **Complete Domain List**

### 📊 Real-time Progress & Statistics
- Live scanning updates with progress indicators
- **Statistics Dashboard** for a quick overview of scan results

### 📁 Multiple Export Formats
- **CSV Export**
- **Text Export**
- **URLs List**
- **IP List (for masscan)**

### 🎨 Modern UI & User Experience
- **Beautiful PyQt5 Interface** with tabbed navigation
- **Custom SVG Icons** for a polished look
- **Dark & Light Themes**
- **Multi-threaded architecture** ensuring a smooth experience

---

## 📥 Installation

### Prerequisites
- Python 3.6 or higher

### Setup
```bash
# Clone the repository
git clone https://github.com/captainmgc/subscanx-gui.git
cd subscanx-gui

# Install dependencies
pip install -r requirements.txt
```

---

## 🛠 Usage

1. **Run the application:**
```bash
python subscanx-gui.py
```
2. **Enter a domain to scan** (e.g., `example.com`)
3. **Click "Scan"** and monitor the real-time progress
4. **View categorized results** in the tabbed interface:
   - **Domains Found**: Resolved domains with their IP addresses
   - **Domains Not Found**: Unresolved domains
   - **All Domains**: Complete list of discovered subdomains
5. **Export results** in your preferred format

---

## 🖼 Screenshots

![Main Interface](https://via.placeholder.com/800x200?text=Main+Interface)
![Results View](https://via.placeholder.com/800x200?text=Results+View)
![Export Options](https://via.placeholder.com/800x200?text=Export+Options)

---

## ⚙️ Technical Details

- **Built with:** PyQt5 for a responsive and modern UI
- **Uses:** `dnspython` & `gevent` for efficient DNS resolution
- **Multi-threaded scanning:** Ensures a smooth experience without UI freezing
- **Customizable stylesheet** for consistent UI appearance

---

## 📜 License
This project is licensed under the **MIT License** - see the LICENSE file for details.

---

## 👨‍💻 Author
Developed by **[Captain MGC](https://github.com/captainmgc)**.

For contributions, feel free to submit a pull request or report issues in the repository!

