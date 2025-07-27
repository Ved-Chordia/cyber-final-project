
# Cybersecurity Final Project – Ved Chordia

Welcome to my final cybersecurity project submission for Elevate Labs Internship. This repository contains **two complete mini-projects** that showcase my understanding of **web application security** and **network packet filtering** using Python.

---

## Project Structure

```
cyber-final-project/
├── web-vuln-scanner/
│   ├── scanner.py
│   ├── README.md
│   └── screenshots/
├── personal-firewall/
│   ├── firewall.py
│   ├── rules.json
│   ├── README.md
│   └── screenshots/
├── final_report.docx  
```

---

## Project 1: Web Application Vulnerability Scanner

### Features:
- Automatically detects common web vulnerabilities (XSS and SQL Injection)
- Parses forms using BeautifulSoup
- Submits malicious payloads to test sanitization
- Supports URL scanning and basic route testing

### Usage:
```bash
python scanner.py http://example.com
```

### Tested On:
- http://testphp.vulnweb.com (a known vulnerable test site)

---

## Project 2: Personal Firewall using Packet Filtering

### Features:
- Uses Scapy to sniff real-time packets
- Matches against custom rules from `rules.json`
- Logs dropped packets in `logs/firewall_log.txt`
- Lightweight and terminal-based

### Example Rule:
```json
{
  "protocol": "TCP",
  "port": 23,
  "action": "block"
}
```

### Usage:
```bash
python firewall.py
```

---

## Final Report
A detailed report explaining the objectives, implementation, tools, and outcomes for both projects is included as `final_report.docx`.

---

## Author

**Ved Chordia**  
Cybersecurity Intern – Elevate Labs  
GitHub: [Ved-Chordia](https://github.com/Ved-Chordia)

---

## License

This project is for educational purposes only. Use responsibly.
