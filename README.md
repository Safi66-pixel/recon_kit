# 🔍 OSINT Investigator Tool

> **By Hafiz Muhammad Safiullah Baig**  
> Senior Cyber Auditor | Network Manager | BS-CS Student @ NIIT University

A Python-based Open Source Intelligence (OSINT) tool that investigates **email addresses**, **phone numbers**, **usernames**, and **IP/domain names** using public data sources — no paid APIs required (except optional HIBP breach check).

---

## ✨ Features

| Module | Capabilities |
|--------|-------------|
| **Email** | Domain categorization, Gravatar hash, social guesses, HaveIBeenPwned breach check |
| **Phone** | Country detection, Pakistan carrier detection, reverse lookup links, Google dorks |
|  **Username** | 20+ platform existence check (HTTP probe), variations, Google dorks |
|  **IP/Domain** | Geolocation (ip-api.com), reverse DNS, Shodan/Censys/VirusTotal links |
|  **Auto-Detect** | Automatically classifies any input and routes to the right module |

---

##  Installation & Usage

### Requirements
- Python 3.6+
- No external packages needed (uses only Python stdlib)

### Run the tool
```bash
git clone https://github.com/yourusername/osint-tool.git
cd osint-tool
python3 osint_tool.py
```

### Example
```
Select option: 5
Enter target: test@gmail.com

[*] Auto-detected input type: EMAIL
[+] Email Category     FREE EMAIL PROVIDER
[+] Gravatar Hash      55502f40dc8b7c769880b10874abc9d0
[+] Domain IP          142.250.64.5
...
```

---

##  Output

Every scan generates a timestamped JSON report:
```
osint_report_test_gmail_com_1719000000.json
```

---

## ️ Legal Disclaimer

This tool is for **educational purposes and authorized security research only**.  
Never use it against targets without explicit written permission.  
The author is not responsible for any misuse.

---

## Built With

- Python 3 (stdlib only: `socket`, `hashlib`, `urllib`, `re`, `json`)
- ip-api.com (free geolocation API)
- HaveIBeenPwned API (optional)

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

## Author

**Hafiz Muhammad Safiullah Baig**  
 NIIT University, Pakistan  
 Cybersecurity Researcher | Penetration Tester  
