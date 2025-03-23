# SubScanx GUI

![SubScanx Logo](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhfaYeg38h2SPabwL7mqV1WV7vNIVLLIID35UZa7D_88EIVdSUpD0zvVuLC-9osQzshs9sQh_carpBbsazerRjHa5rxX-wqmi3VoYT4uq86hvkDgz9-_-5eKMXdo-zh5Z3vnPhAi1oFtGB7zjS2EzjexSVBRU4Tw9AaeCEDWGes6UPYCZabRcDxlwOQf0o/s16000/Gemini_Generated_Image_ln2g0eln2g0eln2g.jpg)

Modern PyQt5-based GUI for SubScanx, a powerful tool that discovers subdomains by querying Certificate Transparency (CT) logs. With a sleek and responsive design, SubScanx GUI makes it easier than ever to uncover hidden subdomains.

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
git clone https://github.com/captainmgc/SubScanX.git
cd SubScanX

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

![Main Interface](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEhPWDqCs4hZ5l-4KNR7iMU8_A20_E3X2EZwZY10HCf1Z8QhMP-i5bPOzXEc0XphYnyidEI9E8NFk4I4brnEFGssgOCQSWP8oLzc0smVuEmwiMZtkJpmVKr0KmxVkrQdSJfE8S2zeF2OEkjekoQJqB76pmgcCUtAOePMKgGpLGYGqL5wgHbQp0Jdg8X3Ynk/s16000/Ekran%20g%C3%B6r%C3%BCnt%C3%BCs%C3%BC%202025-03-23%20154515.png)

![Results View](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEidrpoNr7ImRCjM4AvDdPlXQj9IpLALHTLfpsTCZwIKxcmKkR5w1Ye6pKEwjsKNDqSYECRCBseAjwNdocPk74I4BQG2-VLR8tfzi8ok_J8W9FRfV-Ksug9TVqJ4tLVp72R1l0AtZ66gcVpeARpaXfi57YUWWJOo6WuVdNtMUjix3NGr24g6xfqMODjYngo/s16000/Ekran%20g%C3%B6r%C3%BCnt%C3%BCs%C3%BC%202025-03-23%20154552.png)

![Export Options](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEiM2EwDVnoceNGkdxwyTRMaVd_OQvGPTL1eBv6-x3yZZSg_E-eId4h1V3TatmkImwUD2hSv3ZV8QMdN8gmUpCys9aB0cy7CvAKZFzYCjvMiePVHol6RPNcl2nC__lLvDNr4QwuguRIMQgCRyQYAYuYNsanN9tpOww9jKSFjfZQeg4llawp2hvrWNWuG3AY/s16000/Ekran%20g%C3%B6r%C3%BCnt%C3%BCs%C3%BC%202025-03-23%20154628.png)

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

