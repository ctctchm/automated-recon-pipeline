# Automated Recon Pipeline

Reconnaissance automation for penetration testing. Built with native Kali tools.

**ctctchm** | [github.com/ctctchm](https://github.com/ctctchm)

---

## What it does

Automates the boring parts of recon: subdomain discovery, port scanning, service detection, basic vulnerability checks. Saves time, generates reports.

## Features

- Subdomain enumeration (DNS brute force, zone transfers, cert transparency)
- Port scanning with Nmap
- HTTP service probing
- Nikto vulnerability assessment
- HTML and JSON reports
- No Go dependencies, just standard Kali tools

## Setup

```bash
git clone https://github.com/ctctchm/automated-recon-pipeline.git
cd automated-recon-pipeline
sudo apt install nmap bind9-host dnsutils nikto curl
chmod +x recon_pipeline.py
```

## Usage

```bash
python3 recon_pipeline.py -t example.com
python3 recon_pipeline.py -t example.com -o results
```

## Output

Creates a timestamped directory with:
- `report.html` - visual summary
- `results.json` - structured data
- `subdomains.txt` - discovered hosts
- `raw_output/` - complete tool logs

## How it works

1. Enumerates subdomains using multiple methods
2. Scans ports with Nmap (top 1000)
3. Probes HTTP/HTTPS services
4. Runs Nikto on live web services
5. Aggregates everything into reports

## Tools used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning |
| host/dig | DNS queries |
| curl | HTTP detection |
| Nikto | Web scanning |
| crt.sh | Certificate logs |

## Legal

For authorized testing only. Get permission in writing before scanning anything. Unauthorized access is illegal.

## Notes

Built this for my cybersecurity portfolio at IPSSI Paris. It's practical, it works, and it demonstrates understanding of recon workflows without overcomplicating things.

Code is straightforward Python that orchestrates system tools. Nothing fancy, just effective automation.

## Contributing

Issues and PRs welcome if you find bugs or have improvements.

## License

MIT

---

**ctctchm** • 2026