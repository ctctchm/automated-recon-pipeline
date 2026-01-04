# 🔍 Automated Recon Pipeline - Kali Native

> Professional reconnaissance automation using native Kali Linux tools
> 
> **By ctctchm** | [GitHub](https://github.com/ctctchm) | [Portfolio](https://github.com/ctctchm?tab=repositories)

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## ✨ Features

- 🌐 **Subdomain Enumeration** - DNS brute force, zone transfer, certificate transparency
- 🔌 **Port Scanning** - Fast Nmap scanning with service detection
- 🚀 **HTTP Service Detection** - Live web service enumeration
- ⚠️ **Vulnerability Scanning** - Nikto-based security assessment
- 📊 **Beautiful Reports** - HTML + JSON output
- 🎨 **Stylish Terminal UI** - Colored logs and ASCII art
- 💾 **No Go Required** - Pure Kali native tools

## 🚀 Installation
```bash
# Clone the repository
git clone https://github.com/ctctchm/automated-recon-pipeline.git
cd automated-recon-pipeline

# Install dependencies (native Kali tools)
sudo apt update
sudo apt install nmap bind9-host dnsutils nikto curl -y

# Make executable
chmod +x recon_pipeline.py
```

## 📖 Usage
```bash
# Basic scan
python3 recon_pipeline.py -t example.com

# Custom output directory
python3 recon_pipeline.py -t example.com -o my_results

# Help menu
python3 recon_pipeline.py -h
```

## 📂 Output Structure
```
recon_example_com_20260104_153000/
├── report.html          # Beautiful visual report
├── results.json         # Machine-readable data
├── subdomains.txt       # List of discovered subdomains
└── raw_output/          # Raw tool outputs
    ├── nmap_*.txt
    ├── nikto_*.txt
    └── ...
```

## 🛠️ Tools Used

| Tool | Purpose |
|------|---------|
| **Nmap** | Port scanning & service detection |
| **Host/Dig** | DNS enumeration & zone transfers |
| **Curl** | HTTP service probing |
| **Nikto** | Web vulnerability scanning |
| **crt.sh** | Certificate transparency lookup |

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for security professionals conducting authorized security assessments. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before testing any systems you do not own.

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details

## 👨‍💻 Author

**ctctchm**
- GitHub: [@ctctchm](https://github.com/ctctchm)
- Portfolio: [View Projects](https://github.com/ctctchm?tab=repositories)

## 🌟 Support

If you find this tool useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs via Issues
- 🔀 Contributing via Pull Requests

---
