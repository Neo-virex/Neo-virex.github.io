---
title: "TryHackMe: OWASP Juice Shop"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_owasp_juice_shop
image:
  path: room_img.png
description: "This room uses the Juice Shop vulnerable web application to learn how to identify and exploit common web application vulnerabilities."
---
# OWASP Juice Shop

Created: April 16, 2025 9:24 PM
Finishing Date: April 17, 2025 → April 17, 2025
Status: Done

# **Learning objective**

[**Injection**](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A1-Injection)

[**Broken Authentication**](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A2-Broken_Authentication)

[**Sensitive Data Exposure**](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A3-Sensitive_Data_Exposure)

[**Broken Access Control**](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A5-Broken_Access_Control)

[**Cross-Site Scripting XSS**](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A7-Cross-Site_Scripting_(XSS))

## Reconnaissance && Service Enumeration

### Rustscan >> open port’s

```jsx
└─$ rustscan -a 10.10.1.230  
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.1.230:80
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-16 21:30 EDT
Initiating Ping Scan at 21:30
Scanning 10.10.1.230 [4 ports]
Completed Ping Scan at 21:30, 0.15s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:30
Completed Parallel DNS resolution of 1 host. at 21:30, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 21:30
Scanning 10.10.1.230 [1 port]
Discovered open port 80/tcp on 10.10.1.230
Completed SYN Stealth Scan at 21:30, 0.14s elapsed (1 total ports)
Nmap scan report for 10.10.1.230
Host is up, received echo-reply ttl 63 (0.13s latency).
Scanned at 2025-04-16 21:30:19 EDT for 0s

PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
           Raw packets sent: 5 (196B) | Rcvd: 2 (72B)

                   
```

### nmap >> versions , server running

```jsx
$ nmap -p80 -A -sC -sV -T4 -O 10.10.1.230 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-16 21:31 EDT
Nmap scan report for 10.10.1.230
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http
|_http-title: OWASP Juice Shop
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-robots.txt: 1 disallowed entry 
|_/ftp
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     Feature-Policy: payment 'self'
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Thu, 17 Apr 2025 01:27:37 GMT
|     ETag: W/"786-196415bccac"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 1926
|     Vary: Accept-Encoding
|     Date: Thu, 17 Apr 2025 01:31:47 GMT
|     Connection: close
|     <!--
|     Copyright (c) 2014-2020 Bjoern Kimminich.
|     SPDX-License-Identifier: MIT
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>OWASP Juice Shop</title>
|     <meta name="description" content="Probably the most modern and sophisticated insecure web application">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/favicon_ctf.ico">
|     <link rel="stylesheet" typ
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Origin: *
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: SAMEORIGIN
|     Feature-Policy: payment 'self'
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Thu, 17 Apr 2025 01:27:37 GMT
|     ETag: W/"786-196415bccac"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 1926
|     Vary: Accept-Encoding
|     Date: Thu, 17 Apr 2025 01:31:46 GMT
|     Connection: close
|     <!--
|     Copyright (c) 2014-2020 Bjoern Kimminich.
|     SPDX-License-Identifier: MIT
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>OWASP Juice Shop</title>
|     <meta name="description" content="Probably the most modern and sophisticated insecure web application">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link id="favicon" rel="icon" type="image/x-icon" href="assets/public/favicon_ctf.ico">
|     <link rel="stylesheet" typ
|   HTTPOptions: 
|     HTTP/1.1 204 No Content
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: GET,HEAD,PUT,PATCH,POST,DELETE
|     Vary: Access-Control-Request-Headers
|     Content-Length: 0
|     Date: Thu, 17 Apr 2025 01:31:46 GMT
|     Connection: close
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.95%I=7%D=4/16%Time=68005A03%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,925,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allow-Origin:\x20\
SF:*\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20SAMEORIG
SF:IN\r\nFeature-Policy:\x20payment\x20'self'\r\nAccept-Ranges:\x20bytes\r
SF:\nCache-Control:\x20public,\x20max-age=0\r\nLast-Modified:\x20Thu,\x201
SF:7\x20Apr\x202025\x2001:27:37\x20GMT\r\nETag:\x20W/\"786-196415bccac\"\r
SF:\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2019
SF:26\r\nVary:\x20Accept-Encoding\r\nDate:\x20Thu,\x2017\x20Apr\x202025\x2
SF:001:31:46\x20GMT\r\nConnection:\x20close\r\n\r\n<!--\n\x20\x20~\x20Copy
SF:right\x20\(c\)\x202014-2020\x20Bjoern\x20Kimminich\.\n\x20\x20~\x20SPDX
SF:-License-Identifier:\x20MIT\n\x20\x20-->\n\n<!doctype\x20html>\n<html\x
SF:20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20<t
SF:itle>OWASP\x20Juice\x20Shop</title>\n\x20\x20<meta\x20name=\"descriptio
SF:n\"\x20content=\"Probably\x20the\x20most\x20modern\x20and\x20sophistica
SF:ted\x20insecure\x20web\x20application\">\n\x20\x20<meta\x20name=\"viewp
SF:ort\"\x20content=\"width=device-width,\x20initial-scale=1\">\n\x20\x20<
SF:link\x20id=\"favicon\"\x20rel=\"icon\"\x20type=\"image/x-icon\"\x20href
SF:=\"assets/public/favicon_ctf\.ico\">\n\x20\x20<link\x20rel=\"stylesheet
SF:\"\x20typ")%r(HTTPOptions,EA,"HTTP/1\.1\x20204\x20No\x20Content\r\nAcce
SF:ss-Control-Allow-Origin:\x20\*\r\nAccess-Control-Allow-Methods:\x20GET,
SF:HEAD,PUT,PATCH,POST,DELETE\r\nVary:\x20Access-Control-Request-Headers\r
SF:\nContent-Length:\x200\r\nDate:\x20Thu,\x2017\x20Apr\x202025\x2001:31:4
SF:6\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,2F,"HTTP/1\.1\
SF:x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(X11Probe,2
SF:F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")
SF:%r(FourOhFourRequest,925,"HTTP/1\.1\x20200\x20OK\r\nAccess-Control-Allo
SF:w-Origin:\x20\*\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Option
SF:s:\x20SAMEORIGIN\r\nFeature-Policy:\x20payment\x20'self'\r\nAccept-Rang
SF:es:\x20bytes\r\nCache-Control:\x20public,\x20max-age=0\r\nLast-Modified
SF::\x20Thu,\x2017\x20Apr\x202025\x2001:27:37\x20GMT\r\nETag:\x20W/\"786-1
SF:96415bccac\"\r\nContent-Type:\x20text/html;\x20charset=UTF-8\r\nContent
SF:-Length:\x201926\r\nVary:\x20Accept-Encoding\r\nDate:\x20Thu,\x2017\x20
SF:Apr\x202025\x2001:31:47\x20GMT\r\nConnection:\x20close\r\n\r\n<!--\n\x2
SF:0\x20~\x20Copyright\x20\(c\)\x202014-2020\x20Bjoern\x20Kimminich\.\n\x2
SF:0\x20~\x20SPDX-License-Identifier:\x20MIT\n\x20\x20-->\n\n<!doctype\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20<meta\x20charset=\"utf-8\
SF:">\n\x20\x20<title>OWASP\x20Juice\x20Shop</title>\n\x20\x20<meta\x20nam
SF:e=\"description\"\x20content=\"Probably\x20the\x20most\x20modern\x20and
SF:\x20sophisticated\x20insecure\x20web\x20application\">\n\x20\x20<meta\x
SF:20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1
SF:\">\n\x20\x20<link\x20id=\"favicon\"\x20rel=\"icon\"\x20type=\"image/x-
SF:icon\"\x20href=\"assets/public/favicon_ctf\.ico\">\n\x20\x20<link\x20re
SF:l=\"stylesheet\"\x20typ");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   135.25 ms 10.23.0.1
2   130.01 ms 10.10.1.230

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.02 seconds

```

## Web Application Analysis

**Burp Suite,  OWASP ZAP,   Nikto,   Wapiti,    Dirbuster**

![Screenshot From 2025-04-16 21-28-14.png](img1.png)

![Screenshot From 2025-04-16 21-29-22.png](img2.png)

- FFUF  writeups
    
    ```jsx
    gobuster dir -u http://10.10.57.123/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 200
    
    ffuf -u http://10.10.57.123/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt -t 500 -c -recursion
    
    dirsearch -u http://10.10.57.123/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-big.txt -e php,html,js,zip,sql -t 200
    
    # Directory brute-force with FFUF using a common wordlist
    $ ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt
    # Fuzz for common directories like /admin/, /login/, /uploads/
    
    # File extension fuzzing (PHP, TXT) using FFUF
    $ ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .php,.txt,.bak
    # Find hidden files with specific extensions
    
    # Recursive directory fuzzing with FFUF
    $ ffuf -u http://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -recursion
    # Scan deeper into discovered directories
    
    # Subdomain fuzzing (vhost discovery) with FFUF
    $ ffuf -u http://target.com -H "Host: FUZZ.target.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    # Discover hidden vhosts served by the same IP
    
    # POST data parameter fuzzing with FFUF
    $ ffuf -u http://target.com/login -X POST -d "username=FUZZ&password=pass" -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt
    # Test for valid usernames
    
    ```
    

- GOBUSTER writeups
    
    ```jsx
    # Directory brute-force with Gobuster using a common Kali wordlist
    $ gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt
    # Most common directory enumeration scan
    
    # Gobuster with file extension support
    $ gobuster dir -u http://target.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak
    # Try to find /admin.php, /config.bak, etc.
    
    # DNS subdomain brute-forcing with Gobuster
    $ gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
    # Discover subdomains like api.target.com, dev.target.com
    
    # Vhost (virtual host) fuzzing with Gobuster
    $ gobuster vhost -u http://target.com -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt
    # Check for hidden vhosts served by same IP
    
    # HTTPS fuzzing with Gobuster
    $ gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
    # Same as HTTP, but over TLS
    ```
    

```jsx

```

## Vulnerability Scanning

[Exploit-DB,](https://www.exploit-db.com/)        [CVE Details,](https://www.cvedetails.com/)    [ZeroDay Initiative (ZDI),](https://www.zerodayinitiative.com/)           [Exploit Tracker,](https://www.exploittracker.net/)          [Metasploit Exploit Database](https://docs.metasploit.com/docs/using-metasploit/interfacing/metasploit-module-library.html)

### **SQL Injection**

SQL Injection is when an attacker enters a malicious or malformed query to either retrieve or tamper data from a database. And in some cases, log into accounts.

![tPFJnmC.png](img3.png)

This injection login as admin

![1F1ufc3.png](img4.png)

login in as bender email

![Screenshot From 2025-04-16 21-49-33.png](img5.png)

### **Command Injection**

Command Injection is when web applications take input or user-controlled data and run them as system commands. An attacker may tamper with this data to execute their own system commands. This can be seen in applications that perform misconfigured ping tests.

**Email Injection**

Email injection is a security vulnerability that allows malicious users to send email messages without prior authorization by the email server. These occur when the attacker adds extra data to fields, which are not interpreted by the server correctly.

## Exploit & Initial Access

### Reverse Shell Generators writeup

### 🐚 **Reverse Shell Generators**

- [**Reverse Shell Generator**](https://www.revshells.com/) – Quick reverse shell one-liner generator.
- [**Pentestmonkey Reverse Shell Cheatsheet**](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) – Classic shell one-liners for various languages.
- [**Nishang Shell Generator**](https://github.com/samratashok/nishang) – PowerShell reverse shells (see `Invoke-PowerShellTcp`).
- [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings) – Collection of useful payloads and bypasses.
- [**Shells.cloud**](https://shells.cloud/) *(if available)* – Online reverse shell generator (mirror of revshells sometimes).

### Privilege Escalation

### tools writups

### 🐧 **Linux Privilege Escalation Tools**

1. [**LinPEAS**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) – Bash script for Linux privilege escalation enumeration.
2. [**Linux Exploit Suggester 2**](https://github.com/jondonas/linux-exploit-suggester-2) – Bash script that suggests exploits based on kernel version.
3. [**LES - Linux Exploit Suggester**](https://github.com/mzet-/linux-exploit-suggester) – Older but still useful version written in Perl.
4. [**BeRoot (Linux)**](https://github.com/AlessandroZ/BeRoot) – Linux local privilege escalation checks in Python.
5. [**LinEnum**](https://github.com/rebootuser/LinEnum) – Bash script for enumerating privilege escalation vectors.
6. [**GTFOBins**](https://gtfobins.github.io/) – Not a tool, but a searchable database of Unix binaries that can be exploited for privilege escalation.

---

### 🪟 **Windows Privilege Escalation Tools**

1. [**WinPEAS**](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS) – Powerful enumeration tool for Windows (exe and bat versions).
2. [**PowerUp**](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) – PowerShell-based tool for privilege escalation checks.
3. [**Windows Exploit Suggester - NextGen (WES-NG)**](https://github.com/bitsadmin/wesng) – Python-based local exploit suggester.
4. [**BeRoot (Windows)**](https://github.com/AlessandroZ/BeRoot) – Local privilege escalation checker (Python-based, requires pywin32).
5. [**Seatbelt**](https://github.com/GhostPack/Seatbelt) – C# tool that grabs a wide range of security-relevant Windows data.
6. [**Sherlock**](https://github.com/rasta-mouse/Sherlock) – PowerShell script to find missing patches that allow local privilege escalation.

---

### 💡 **Bonus - Cross-Platform / Language-Specific Scripts**

- [**PEASS-ng**](https://github.com/carlospolop/PEASS-ng) – Central repo that includes linPEAS, winPEAS, and other helpers.
- [**PrivescCheck**](https://github.com/itm4n/PrivescCheck) – Windows privilege escalation checker using PowerShell.
- [**Privilege-Escalation-Awesome-Scripts-Suite (P.E.A.S.S)**](https://github.com/carlospolop/PEASS-ng) – Massive collection of PE tools.

## Lateral Movement

### writeups

### **Windows Lateral Movement Tools & Techniques**

1. [**Impacket**](https://github.com/fortra/impacket) – Python collection of tools for remote execution, pass-the-hash, WMI, SMB, etc.
    - Tools include: `wmiexec.py`, `psexec.py`, `smbexec.py`, `atexec.py`
2. [**PsExec**](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) – Microsoft's Sysinternals tool to execute processes remotely.
3. [**CrackMapExec**](https://github.com/Porchetta-Industries/CrackMapExec) – Swiss army knife for network pentesting; supports SMB, WinRM, RDP, etc.
4. [**WinRM / Evil-WinRM**](https://github.com/Hackplayers/evil-winrm) – Ruby tool for remote shell access over Windows Remote Management.
5. **[WMI (Windows Management Instrumentation)]** – Allows remote command execution using built-in Windows features (`wmic` or scripts).
6. **[RDP (Remote Desktop Protocol)]** – Often used post-authentication with credentials or tokens.
7. [**Token Impersonation & Pass-the-Token**](https://github.com/SkelSec/PyWhisker) – Move laterally without re-authentication using stolen tokens.
8. [**Mimikatz**](https://github.com/gentilkiwi/mimikatz) – Extracts credentials and enables pass-the-hash/ticket capabilities.

---

### 🐧 **Linux Lateral Movement Tools & Techniques**

1. **[SSH (with harvested keys/passwords)]** – Most common method for lateral movement in Unix-like systems.
2. [**SSH Agent Hijacking**](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/ssh-agent-hijacking) – Abuse SSH agent sockets for key reuse.
3. [**Fabric / Paramiko (Python)**](https://github.com/paramiko/paramiko) – Python libraries to automate SSH lateral movement.
4. [**Ansible Misuse**](https://book.hacktricks.xyz/pentesting-web/ansible) – Misconfigured automation can lead to lateral code execution.
5. **[scp/rsync with authorized_keys planting]** – Transfer payloads or enable backdoor access on other systems.

---

### 🧠 **General Techniques**

- **Pass-the-Hash / Pass-the-Ticket (PtH / PtT)** – Use hashed or ticket-based credentials to authenticate without knowing passwords.
- **Kerberoasting** – Extract and crack service tickets to impersonate accounts.
- **Remote Service Creation** – Create and execute services on remote machines (via `sc`, `schtasks`, or similar tools).
- **DLL Injection & WMI Scripts** – Inject malicious DLLs into remote processes or run WMI event consumers.

---

### 🔧 **Automation / Toolkits**

- [**BloodHound**](https://github.com/BloodHoundAD/BloodHound) – Maps out Active Directory attack paths.
- [**SharpHound**](https://github.com/BloodHoundAD/SharpHound) – Data collector for BloodHound (used for lateral movement path discovery).
- [**LaZagne**](https://github.com/AlessandroZ/LaZagne) – Credential dumper that helps fuel lateral moves.

---
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
