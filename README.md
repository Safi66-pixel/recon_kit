#!/usr/bin/env python3
"""
=============================================================
  OSINT Investigator Tool - By Hafiz Muhammad Safiullah Baig
  GitHub: https://github.com/yourusername/osint-tool
  For educational and authorized use only.
=============================================================
"""

import re
import json
import time
import socket
import hashlib
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────
#  ANSI Color Codes for Terminal Output
# ─────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
  ██████╗ ███████╗██╗███╗   ██╗████████╗    ████████╗ ██████╗  ██████╗ ██╗     
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
 ██║   ██║███████╗██║██╔██╗ ██║   ██║          ██║   ██║   ██║██║   ██║██║     
 ██║   ██║╚════██║██║██║╚██╗██║   ██║          ██║   ██║   ██║██║   ██║██║     
 ╚██████╔╝███████║██║██║ ╚████║   ██║          ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝          ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{RESET}
{YELLOW}  [*] OSINT Investigator v1.0  |  By Safiullah Baig  |  Ethical Use Only{RESET}
{RED}  [!] Only investigate targets you have explicit permission to investigate.{RESET}
"""


# ─────────────────────────────────────────────
#  UTILITY FUNCTIONS
# ─────────────────────────────────────────────

def print_section(title):
    """Print a styled section header."""
    print(f"\n{CYAN}{BOLD}{'─'*55}")
    print(f"  {title}")
    print(f"{'─'*55}{RESET}")


def print_result(label, value, color=WHITE):
    """Print a key-value result line."""
    print(f"  {YELLOW}[+]{RESET} {label:<25} {color}{value}{RESET}")


def print_error(msg):
    print(f"  {RED}[!] {msg}{RESET}")


def print_info(msg):
    print(f"  {CYAN}[*] {msg}{RESET}")


def save_report(data: dict, target: str):
    """Save all results to a JSON report file."""
    filename = f"osint_report_{target.replace('@','_').replace('.','_')}_{int(time.time())}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\n{GREEN}[✓] Report saved to: {filename}{RESET}")
    return filename


# ─────────────────────────────────────────────
#  INPUT DETECTION MODULE
# ─────────────────────────────────────────────

def detect_input_type(target: str) -> str:
    """
    Automatically detects whether the input is:
    - email
    - phone number
    - IP address
    - domain/URL
    - username (fallback)
    
    Uses regex pattern matching on the input string.
    """
    target = target.strip()

    # Email pattern: word@word.word
    if re.match(r'^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$', target):
        return "email"

    # Phone: starts with +, or digits with dashes/spaces, 7-15 digits total
    if re.match(r'^\+?[\d\s\-\(\)]{7,15}$', target):
        return "phone"

    # IPv4 address
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
        return "ip"

    # Domain or URL
    if re.match(r'^(https?://)?([\w\-]+\.)+[a-zA-Z]{2,}(/.*)?$', target):
        return "domain"

    # Default: treat as username
    return "username"


# ─────────────────────────────────────────────
#  EMAIL OSINT MODULE
# ─────────────────────────────────────────────

def investigate_email(email: str) -> dict:
    """
    Email OSINT:
    1. Validates email format
    2. Extracts username + domain
    3. Checks email format patterns (disposable, corporate, edu)
    4. Generates Gravatar hash to check profile picture
    5. DNS MX record lookup for mail server info
    6. Checks breach databases (HaveIBeenPwned public API)
    7. Generates social media guesses from email username
    """
    print_section("EMAIL INVESTIGATION")
    results = {"target": email, "type": "email"}

    # Step 1: Basic parsing
    parts = email.split("@")
    username = parts[0]
    domain = parts[1]
    results["username"] = username
    results["domain"] = domain
    print_result("Email", email, GREEN)
    print_result("Username Part", username)
    print_result("Domain Part", domain)

    # Step 2: Domain category detection
    disposable_domains = ["mailinator.com", "guerrillamail.com", "tempmail.com",
                          "throwam.com", "yopmail.com", "10minutemail.com"]
    edu_keywords = [".edu", ".ac.", "university", "college", "school"]
    gov_keywords = [".gov", ".mil", ".govt"]

    if domain in disposable_domains:
        category = "DISPOSABLE / TEMPORARY EMAIL"
        cat_color = RED
    elif any(k in domain for k in edu_keywords):
        category = "EDUCATIONAL INSTITUTION"
        cat_color = CYAN
    elif any(k in domain for k in gov_keywords):
        category = "GOVERNMENT / MILITARY"
        cat_color = YELLOW
    elif domain in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"]:
        category = "FREE EMAIL PROVIDER"
        cat_color = WHITE
    else:
        category = "LIKELY CORPORATE / CUSTOM DOMAIN"
        cat_color = GREEN

    results["email_category"] = category
    print_result("Email Category", category, cat_color)

    # Step 3: Gravatar MD5 hash
    # Gravatar uses MD5 of lowercased, trimmed email to store profile pictures
    gravatar_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"
    results["gravatar_hash"] = gravatar_hash
    results["gravatar_url"] = gravatar_url
    print_result("Gravatar Hash", gravatar_hash, CYAN)
    print_result("Gravatar URL", gravatar_url, CYAN)

    # Step 4: MX Record lookup (mail server)
    try:
        mx = socket.getaddrinfo(domain, None)
        ip = mx[0][4][0]
        results["domain_ip"] = ip
        print_result("Domain IP", ip, GREEN)
    except Exception:
        results["domain_ip"] = "Could not resolve"
        print_error(f"Could not resolve domain: {domain}")

    # Step 5: Social media username guesses based on email username
    social_platforms = {
        "GitHub":    f"https://github.com/{username}",
        "Twitter/X": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "LinkedIn":  f"https://linkedin.com/in/{username}",
        "Reddit":    f"https://reddit.com/user/{username}",
        "TryHackMe": f"https://tryhackme.com/p/{username}",
    }
    results["social_guesses"] = social_platforms
    print_section("POSSIBLE SOCIAL PROFILES (from email username)")
    for platform, url in social_platforms.items():
        print_result(platform, url, CYAN)

    # Step 6: HaveIBeenPwned check
    print_section("BREACH CHECK (HaveIBeenPwned)")
    try:
        encoded = urllib.parse.quote(email)
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "OSINT-Tool-Educational",
            "hibp-api-key": "YOUR_API_KEY_HERE"  # Replace with your API key
        })
        response = urllib.request.urlopen(req, timeout=5)
        breaches = json.loads(response.read().decode())
        breach_names = [b["Name"] for b in breaches]
        results["breaches"] = breach_names
        print_result("Breaches Found", str(len(breach_names)), RED)
        for b in breach_names:
            print(f"       {RED}• {b}{RESET}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            results["breaches"] = []
            print_result("Breaches", "No breaches found (Good!)", GREEN)
        elif e.code == 401:
            results["breaches"] = "API key required"
            print_info("HIBP requires a paid API key. Visit https://haveibeenpwned.com/API/Key")
        else:
            results["breaches"] = f"HTTP Error {e.code}"
            print_error(f"HTTP Error: {e.code}")
    except Exception as e:
        results["breaches"] = str(e)
        print_error(f"Breach check failed: {e}")

    return results


# ─────────────────────────────────────────────
#  PHONE NUMBER OSINT MODULE
# ─────────────────────────────────────────────

def investigate_phone(phone: str) -> dict:
    """
    Phone OSINT:
    1. Cleans and normalizes the number
    2. Detects country code from prefix
    3. Identifies Pakistan mobile carrier from prefix
    4. Generates search dorks for the number
    5. Provides reverse lookup suggestions
    """
    print_section("PHONE NUMBER INVESTIGATION")
    results = {"target": phone, "type": "phone"}

    # Step 1: Strip all non-digit characters except leading +
    cleaned = re.sub(r'[^\d+]', '', phone)
    results["cleaned_number"] = cleaned
    print_result("Raw Input", phone)
    print_result("Cleaned Number", cleaned, GREEN)

    # Step 2: Country code detection (common codes)
    country_codes = {
        "+1":   "USA / Canada",
        "+44":  "United Kingdom",
        "+92":  "Pakistan",
        "+91":  "India",
        "+86":  "China",
        "+49":  "Germany",
        "+33":  "France",
        "+61":  "Australia",
        "+971": "UAE",
        "+966": "Saudi Arabia",
        "+880": "Bangladesh",
        "+93":  "Afghanistan",
    }

    detected_country = "Unknown"
    for code, country in country_codes.items():
        if cleaned.startswith(code):
            detected_country = country
            break

    results["country"] = detected_country
    print_result("Country", detected_country, YELLOW)

    # Step 3: Pakistan carrier detection (if Pakistani number)
    if cleaned.startswith("+92") or cleaned.startswith("0"):
        local = cleaned.replace("+92", "0") if cleaned.startswith("+92") else cleaned
        pk_carriers = {
            "030": "Jazz / Warid",
            "031": "Jazz / Warid",
            "032": "Jazz / Warid",
            "033": "Jazz / Warid",
            "034": "Jazz (M2M SIM)",
            "035": "Jazz (M2M SIM)",
            "036": "Jazz",
            "037": "Jazz",
            "038": "Jazz",
            "041": "Jazz",
            "045": "Jazz",
            "070": "Warid",
            "030": "Jazz",
            "031": "Jazz",
            "032": "Jazz",
            "033": "Jazz",
            "034": "Jazz",
            "0300": "Jazz",
            "0301": "Jazz",
            "0302": "Jazz",
            "0303": "Jazz",
            "0304": "Jazz",
            "0305": "Jazz",
            "0306": "Jazz",
            "0307": "Jazz",
            "0308": "Jazz",
            "0309": "Jazz",
            "0310": "Jazz",
            "0311": "Jazz",
            "0312": "Jazz",
            "0313": "Jazz",
            "0314": "Jazz",
            "0315": "Jazz",
            "0316": "Jazz",
            "0317": "Jazz",
            "0318": "Jazz",
            "0319": "Jazz",
            "032": "Jazz/Warid",
            "033": "Ufone",
            "0330": "Ufone",
            "0331": "Ufone",
            "0332": "Ufone",
            "0333": "Ufone",
            "0334": "Ufone",
            "0335": "Ufone",
            "0336": "Ufone",
            "0337": "Ufone",
            "0338": "Ufone",
            "0339": "Ufone",
            "034": "Zong",
            "0340": "Zong",
            "0341": "Zong",
            "0342": "Zong",
            "0343": "Zong",
            "0344": "Zong",
            "0345": "Zong",
            "0346": "Zong",
            "0347": "Zong",
            "0348": "Zong",
            "0349": "Zong",
            "035": "Telenor",
            "0350": "Telenor",
            "0351": "Telenor",
            "0352": "Telenor",
            "0353": "Telenor",
            "0354": "Telenor",
            "0355": "Telenor",
            "0356": "Telenor",
            "0357": "Telenor",
            "0358": "Telenor",
            "0359": "Telenor",
            "036": "Telenor",
            "0360": "Telenor",
            "0361": "Telenor",
            "0362": "Telenor",
            "0363": "Telenor",
            "0364": "Telenor",
            "0365": "Telenor",
            "0366": "Telenor",
            "0367": "Telenor",
            "0368": "Telenor",
            "0369": "Telenor",
        }
        prefix4 = local[:4]
        carrier = pk_carriers.get(prefix4, "Unknown PK Carrier")
        results["carrier"] = carrier
        print_result("PK Carrier (est.)", carrier, CYAN)

    # Step 4: Generate Google dorks for the phone number
    digits_only = re.sub(r'\D', '', cleaned)
    dorks = [
        f'"{phone}" site:truecaller.com',
        f'"{phone}" site:whitepages.com',
        f'"{phone}" site:facebook.com',
        f'"{digits_only}" inurl:profile',
        f'"{phone}" linkedin',
    ]
    results["google_dorks"] = dorks
    print_section("GOOGLE DORKS (paste into Google)")
    for dork in dorks:
        print(f"  {YELLOW}→{RESET} {dork}")

    # Step 5: Reverse lookup platforms
    lookup_sites = {
        "Truecaller":  f"https://www.truecaller.com/search/pk/{digits_only}",
        "NumLookup":   f"https://www.numlookup.com/{phone}",
        "PhoneInfoga": "https://github.com/sundowndev/phoneinfoga (CLI tool)",
    }
    results["lookup_sites"] = lookup_sites
    print_section("REVERSE LOOKUP PLATFORMS")
    for site, url in lookup_sites.items():
        print_result(site, url, CYAN)

    return results


# ─────────────────────────────────────────────
#  USERNAME OSINT MODULE
# ─────────────────────────────────────────────

def investigate_username(username: str) -> dict:
    """
    Username OSINT:
    1. Generates profile URLs for 20+ platforms
    2. Attempts HTTP check (200 = likely exists, 404 = not found)
    3. Generates Google dorks
    4. Checks username variations
    """
    print_section("USERNAME INVESTIGATION")
    results = {"target": username, "type": "username"}
    print_result("Username", username, GREEN)

    # Platforms to check
    platforms = {
        "GitHub":         f"https://github.com/{username}",
        "Twitter/X":      f"https://twitter.com/{username}",
        "Instagram":      f"https://instagram.com/{username}",
        "Reddit":         f"https://reddit.com/user/{username}",
        "LinkedIn":       f"https://linkedin.com/in/{username}",
        "TikTok":         f"https://tiktok.com/@{username}",
        "YouTube":        f"https://youtube.com/@{username}",
        "Pinterest":      f"https://pinterest.com/{username}",
        "Tumblr":         f"https://{username}.tumblr.com",
        "Medium":         f"https://medium.com/@{username}",
        "DevTo":          f"https://dev.to/{username}",
        "HackerNews":     f"https://news.ycombinator.com/user?id={username}",
        "GitLab":         f"https://gitlab.com/{username}",
        "Keybase":        f"https://keybase.io/{username}",
        "Pastebin":       f"https://pastebin.com/u/{username}",
        "TryHackMe":      f"https://tryhackme.com/p/{username}",
        "HackTheBox":     f"https://app.hackthebox.com/profile/search?name={username}",
        "Replit":         f"https://replit.com/@{username}",
        "Twitch":         f"https://twitch.tv/{username}",
        "Steam":          f"https://steamcommunity.com/id/{username}",
        "About.me":       f"https://about.me/{username}",
        "Gravatar":       f"https://en.gravatar.com/{username}",
    }

    found = {}
    not_found = {}
    errors = {}

    print_section("PLATFORM EXISTENCE CHECK")
    print_info("Checking platforms (this may take a moment)...")

    for platform, url in platforms.items():
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            })
            resp = urllib.request.urlopen(req, timeout=4)
            code = resp.getcode()
            if code == 200:
                found[platform] = url
                print(f"  {GREEN}[✓] FOUND{RESET}    {platform:<15} {CYAN}{url}{RESET}")
            else:
                not_found[platform] = url
                print(f"  {YELLOW}[?] UNKNOWN{RESET}  {platform:<15} (Status: {code})")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                not_found[platform] = url
                print(f"  {RED}[✗] NOT FOUND{RESET} {platform}")
            else:
                errors[platform] = str(e.code)
                print(f"  {YELLOW}[?] ERROR {e.code}{RESET}  {platform}")
        except Exception:
            errors[platform] = "timeout/network"
            print(f"  {YELLOW}[?] TIMEOUT{RESET}   {platform}")
        time.sleep(0.3)  # Polite delay between requests

    results["found_on"] = found
    results["not_found"] = not_found
    results["errors"] = errors

    # Google dorks
    dorks = [
        f'"{username}" site:github.com',
        f'"{username}" site:linkedin.com',
        f'"{username}" intitle:profile',
        f'"{username}" site:reddit.com',
        f'"{username}" "about me"',
        f'"{username}" filetype:pdf',
    ]
    results["google_dorks"] = dorks
    print_section("GOOGLE DORKS")
    for d in dorks:
        print(f"  {YELLOW}→{RESET} {d}")

    # Username variations
    variations = [
        username + "1", username + "123",
        username + "_", "_" + username,
        username + "official", "the" + username,
        username.replace(" ", "_"), username.lower(), username.upper()
    ]
    results["variations"] = variations
    print_section("USERNAME VARIATIONS TO TRY")
    for v in variations:
        print(f"  {CYAN}•{RESET} {v}")

    return results


# ─────────────────────────────────────────────
#  IP / DOMAIN OSINT MODULE
# ─────────────────────────────────────────────

def investigate_ip_or_domain(target: str) -> dict:
    """
    IP/Domain OSINT:
    1. Resolves domain to IP (or uses IP directly)
    2. Reverse DNS lookup
    3. Queries ip-api.com for geolocation (free, no key needed)
    4. Generates Shodan / Censys links
    5. Generates WHOIS lookup links
    """
    print_section("IP / DOMAIN INVESTIGATION")
    results = {"target": target, "type": "ip_domain"}

    # Step 1: Resolve to IP
    clean = target.replace("http://", "").replace("https://", "").split("/")[0]
    results["cleaned_target"] = clean

    try:
        ip = socket.gethostbyname(clean)
        results["resolved_ip"] = ip
        print_result("Target", clean, GREEN)
        print_result("Resolved IP", ip, YELLOW)
    except Exception as e:
        ip = clean  # treat as raw IP
        results["resolved_ip"] = ip
        print_result("Target (IP)", ip, GREEN)

    # Step 2: Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        results["reverse_dns"] = hostname
        print_result("Reverse DNS", hostname, CYAN)
    except Exception:
        results["reverse_dns"] = "No reverse DNS found"
        print_result("Reverse DNS", "Not found", YELLOW)

    # Step 3: Geolocation via ip-api.com (free, no key needed)
    try:
        geo_url = f"http://ip-api.com/json/{ip}"
        req = urllib.request.Request(geo_url, headers={"User-Agent": "OSINT-Tool"})
        resp = urllib.request.urlopen(req, timeout=6)
        geo = json.loads(resp.read().decode())

        if geo.get("status") == "success":
            fields = {
                "Country":    geo.get("country", "N/A"),
                "Region":     geo.get("regionName", "N/A"),
                "City":       geo.get("city", "N/A"),
                "ZIP":        geo.get("zip", "N/A"),
                "Latitude":   str(geo.get("lat", "N/A")),
                "Longitude":  str(geo.get("lon", "N/A")),
                "ISP":        geo.get("isp", "N/A"),
                "Org":        geo.get("org", "N/A"),
                "AS":         geo.get("as", "N/A"),
                "Timezone":   geo.get("timezone", "N/A"),
            }
            results["geolocation"] = fields
            print_section("GEOLOCATION DATA")
            for k, v in fields.items():
                print_result(k, v, GREEN)
        else:
            print_error("Geolocation failed (private/reserved IP?)")
            results["geolocation"] = {"error": "private IP or API limit"}
    except Exception as e:
        print_error(f"Geo lookup failed: {e}")
        results["geolocation"] = {"error": str(e)}

    # Step 4: Recon tool links (Shodan, Censys, VirusTotal, etc.)
    recon_links = {
        "Shodan":       f"https://www.shodan.io/host/{ip}",
        "Censys":       f"https://search.censys.io/hosts/{ip}",
        "VirusTotal":   f"https://www.virustotal.com/gui/ip-address/{ip}",
        "AbuseIPDB":    f"https://www.abuseipdb.com/check/{ip}",
        "IPInfo":       f"https://ipinfo.io/{ip}",
        "WHOIS":        f"https://who.is/whois-ip/ip-address/{ip}",
        "MXToolbox":    f"https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a{ip}",
    }
    results["recon_links"] = recon_links
    print_section("RECON / INTEL PLATFORMS")
    for name, url in recon_links.items():
        print_result(name, url, CYAN)

    # Step 5: Port scan note
    print_section("SUGGESTED NEXT STEPS")
    print(f"  {CYAN}→{RESET} Run: nmap -sV -sC {ip}")
    print(f"  {CYAN}→{RESET} Run: nmap --script vuln {ip}")
    print(f"  {CYAN}→{RESET} Check Shodan link above for open ports & banners")

    return results


# ─────────────────────────────────────────────
#  MAIN MENU
# ─────────────────────────────────────────────

def main():
    print(BANNER)
    print(f"{BOLD}  What do you want to investigate?{RESET}")
    print(f"""
  {CYAN}[1]{RESET} Email Address
  {CYAN}[2]{RESET} Phone Number
  {CYAN}[3]{RESET} Username
  {CYAN}[4]{RESET} IP Address / Domain
  {CYAN}[5]{RESET} Auto-Detect (enter anything)
  {CYAN}[0]{RESET} Exit
""")

    choice = input(f"  {YELLOW}Select option:{RESET} ").strip()
    if choice == "0":
        print(f"\n{GREEN}Goodbye!{RESET}\n")
        return

    target = input(f"  {YELLOW}Enter target:{RESET} ").strip()
    if not target:
        print_error("No target entered.")
        return

    report_data = {}
    start_time = datetime.now()

    if choice == "1":
        report_data = investigate_email(target)
    elif choice == "2":
        report_data = investigate_phone(target)
    elif choice == "3":
        report_data = investigate_username(target)
    elif choice == "4":
        report_data = investigate_ip_or_domain(target)
    elif choice == "5":
        itype = detect_input_type(target)
        print_info(f"Auto-detected input type: {itype.upper()}")
        if itype == "email":
            report_data = investigate_email(target)
        elif itype == "phone":
            report_data = investigate_phone(target)
        elif itype == "ip":
            report_data = investigate_ip_or_domain(target)
        elif itype == "domain":
            report_data = investigate_ip_or_domain(target)
        else:
            report_data = investigate_username(target)
    else:
        print_error("Invalid choice.")
        return

    # Add metadata
    end_time = datetime.now()
    report_data["scan_timestamp"] = str(start_time)
    report_data["scan_duration_seconds"] = (end_time - start_time).seconds

    # Save report
    print_section("SAVING REPORT")
    save_report(report_data, target)
    print(f"\n{CYAN}{'═'*55}{RESET}")
    print(f"{GREEN}  Scan complete. Use findings responsibly.{RESET}")
    print(f"{CYAN}{'═'*55}{RESET}\n")


if __name__ == "__main__":
    main()
