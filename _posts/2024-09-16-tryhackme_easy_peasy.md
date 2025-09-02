---
title: "TryHackMe: Easy Peasy"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_easy_peasy/
image:
  path: room_img.png
description: "Practice using tools such as Nmap and GoBuster to locate a hidden directory to get initial access to a vulnerable machine. Then escalate your privileges through a vulnerable cronjob."
---
# Easy Peasy

Created: April 11, 2025 2:03 PM
Finishing Date: April 12, 2025
Status: Done

## Reconnaissance

```jsx
└─$ rustscan -a 10.10.194.238
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.194.238:80
Open 10.10.194.238:6498
Open 10.10.194.238:65524
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 13:59 EDT
Initiating Ping Scan at 13:59
Scanning 10.10.194.238 [4 ports]
Completed Ping Scan at 13:59, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:59
Completed Parallel DNS resolution of 1 host. at 13:59, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 13:59
Scanning 10.10.194.238 [3 ports]
Discovered open port 80/tcp on 10.10.194.238
Discovered open port 65524/tcp on 10.10.194.238
Discovered open port 6498/tcp on 10.10.194.238
Completed SYN Stealth Scan at 13:59, 0.16s elapsed (3 total ports)
Nmap scan report for 10.10.194.238
Host is up, received echo-reply ttl 63 (0.13s latency).
Scanned at 2025-04-11 13:59:43 EDT for 1s

PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 63
6498/tcp  open  unknown syn-ack ttl 63
65524/tcp open  unknown syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (160B)

```

## Service Enumeration

```jsx
└─$ nmap -p80,6498,65524 -A 10.10.194.238
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 14:00 EDT
Nmap scan report for 10.10.194.238
Host is up (0.14s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to nginx!
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   140.38 ms 10.23.0.1
2   136.41 ms 10.10.194.238

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.78 seconds
                                                                      
┌──(neo㉿neo)-[~]
└─$ 
                    
```

## Web Application Analysis

![Screenshot From 2025-04-11 14-37-52.png](img1.png)

| 9fdafbd64c47471a8f54cd3fc64cd312 | md5 | candeger |
| --- | --- | --- |

## Vulnerability Scanning

![Screenshot From 2025-04-11 15-08-01.png](img2.png)

![Screenshot From 2025-04-11 15-08-17.png](img3.png)

![Screenshot From 2025-04-11 15-09-32.png](img4.png)

![Screenshot From 2025-04-11 15-21-49.png](img5.png)

![Screenshot From 2025-04-11 15-59-13.png](img6.png)

![Screenshot From 2025-04-11 15-59-22.png](img7.png)

### terminal

```jsx
─(neo㉿neo)-[~]
└─$ nmap -p80,6498,65524 10.10.194.238
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 14:00 EDT
Nmap scan report for 10.10.194.238
Host is up (0.14s latency).

PORT      STATE SERVICE
80/tcp    open  http
6498/tcp  open  unknown
65524/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 0.46 seconds
                                                                      
┌──(neo㉿neo)-[~]
└─$ nmap -p80,6498,65524 -v 10.10.194.238
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 14:00 EDT
Initiating Ping Scan at 14:00
Scanning 10.10.194.238 [4 ports]
Completed Ping Scan at 14:00, 0.18s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:00
Completed Parallel DNS resolution of 1 host. at 14:00, 0.03s elapsed
Initiating SYN Stealth Scan at 14:00
Scanning 10.10.194.238 [3 ports]
Discovered open port 80/tcp on 10.10.194.238
Discovered open port 6498/tcp on 10.10.194.238
Discovered open port 65524/tcp on 10.10.194.238
Completed SYN Stealth Scan at 14:00, 0.18s elapsed (3 total ports)
Nmap scan report for 10.10.194.238
Host is up (0.15s latency).

PORT      STATE SERVICE
80/tcp    open  http
6498/tcp  open  unknown
65524/tcp open  unknown

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
           Raw packets sent: 7 (284B) | Rcvd: 4 (160B)
                                                                      
┌──(neo㉿neo)-[~]
└─$ nmap -p80,6498,65524 -A 10.10.194.238
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 14:00 EDT
Nmap scan report for 10.10.194.238
Host is up (0.14s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Welcome to nginx!
6498/tcp  open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
|_  256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
65524/tcp open  http    Apache httpd 2.4.43 ((Ubuntu))
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
| http-robots.txt: 1 disallowed entry 
|_/
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   140.38 ms 10.23.0.1
2   136.41 ms 10.10.194.238

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.78 seconds
                                                                      
┌──(neo㉿neo)-[~]
└─$ 
                                                                      
┌──(neo㉿neo)-[~]
└─$ Nmap done: 1 IP address (1 host up) scanned in 21.78 seconds
zsh: unknown file attribute: 1
                                                                      
┌──(neo㉿neo)-[~]
└─$                                                                       
                                                                      
┌──(neo㉿neo)-[~]
└─$ ┌──(neo㉿neo)-[~]
┌──(neo㉿neo)-[~]: command not found
                                                                      
┌──(neo㉿neo)-[~]
└─$ └─$ 
└─$: command not found
                                                                      
┌──(neo㉿neo)-[~]
└─$ gobuster dir -u http://10.10.194.238 -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.238
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/hidden               (Status: 301) [Size: 169] [--> http://10.10.194.238/hidden/]
/index.html           (Status: 200) [Size: 612]
/index.html           (Status: 200) [Size: 612]
/robots.txt           (Status: 200) [Size: 43]
/robots.txt           (Status: 200) [Size: 43]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ gobuster dir -u http://10.10.194.238:65524 -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.238:65524
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd.php        (Status: 403) [Size: 281]
/.htpasswd.html       (Status: 403) [Size: 281]
/.html                (Status: 403) [Size: 281]
/.htaccess.php        (Status: 403) [Size: 281]
/.hta                 (Status: 403) [Size: 281]
/.hta.html            (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/.htaccess.txt        (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/.htaccess.html       (Status: 403) [Size: 281]
/.hta.php             (Status: 403) [Size: 281]
/.hta.txt             (Status: 403) [Size: 281]
/.htpasswd.txt        (Status: 403) [Size: 281]
/index.html           (Status: 200) [Size: 10818]
/index.html           (Status: 200) [Size: 10818]
/robots.txt           (Status: 200) [Size: 153]
/robots.txt           (Status: 200) [Size: 153]
/server-status        (Status: 403) [Size: 281]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ gobuster dir -u http://10.10.194.238:65524 -w /home/neo/Downloads/easypeasy_1596838725703.txt -t 50 -x php,html,txt 

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.238:65524
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/neo/Downloads/easypeasy_1596838725703.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 20564 / 20564 (100.00%)
===============================================================
Finished
===============================================================
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ gobuster dir -e -u http://10.10.194.238:80/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.238:80/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,php,html
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.10.194.238:80/hidden               (Status: 301) [Size: 169] [--> http://10.10.194.238/hidden/]                                                                                                       
http://10.10.194.238:80/index.html           (Status: 200) [Size: 612]
http://10.10.194.238:80/index.html           (Status: 200) [Size: 612]
http://10.10.194.238:80/robots.txt           (Status: 200) [Size: 43]
http://10.10.194.238:80/robots.txt           (Status: 200) [Size: 43]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ gobuster dir -e -u http://10.10.194.238:65524/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.238:65524/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,txt,php
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.10.194.238:65524/.htpasswd.php        (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htpasswd.html       (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta.txt             (Status: 403) [Size: 281]
http://10.10.194.238:65524/.html                (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta.php             (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta                 (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess            (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess.txt        (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess.php        (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess.html       (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta.html            (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htpasswd            (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htpasswd.txt        (Status: 403) [Size: 281]
http://10.10.194.238:65524/index.html           (Status: 200) [Size: 10818]
http://10.10.194.238:65524/index.html           (Status: 200) [Size: 10818]
http://10.10.194.238:65524/robots.txt           (Status: 200) [Size: 153]
http://10.10.194.238:65524/robots.txt           (Status: 200) [Size: 153]
http://10.10.194.238:65524/server-status        (Status: 403) [Size: 281]
Progress: 18456 / 18460 (99.98%)
===============================================================
Finished
===============================================================
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ gobuster dir -e -u http://10.10.194.238:65524/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt
SD
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.238:65524/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Expanded:                true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
http://10.10.194.238:65524/.html                (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htpasswd.php        (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta                 (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta.php             (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta.txt             (Status: 403) [Size: 281]
http://10.10.194.238:65524/.hta.html            (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess            (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess.html       (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htpasswd            (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess.txt        (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htpasswd.html       (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htpasswd.txt        (Status: 403) [Size: 281]
http://10.10.194.238:65524/.htaccess.php        (Status: 403) [Size: 281]
Progress: 406 / 18460 (2.20%)^Z
zsh: suspended  gobuster dir -e -u http://10.10.194.238:65524/ -w  -t 50 -x php,html,txt
SD: command not found
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ kgobuster dir -e -u http://10.10.194.238:65524/ -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt
SD
Command 'kgobuster' not found, did you mean:
  command 'gobuster' from deb gobuster
Try: sudo apt install <deb name>
SD: command not found
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ gobuster dir -u http://10.10.196.238:65524/ -w /usr/share/wordlists/dirb/common.txt -o dirs6.log
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.196.238:65524/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

Error: error on running gobuster: unable to connect to http://10.10.196.238:65524/: Get "http://10.10.196.238:65524/": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
                                                                                                        
┌──(neo㉿neo)-[~]
└─$ pro                                                                                               
                                                                                                        
┌──(neo㉿neo)-[~/pro]
└─$ ls
Chankro  ftp.txt  l               PUBLIC_NOTICE.txt  wget-log
fo       id_rsa   output.txt.txt  vpn                WindowsXP_1551719014755.jpg
                                                                                                        
┌──(neo㉿neo)-[~/pro]
└─$ mkdir s   
                                                                                                        
┌──(neo㉿neo)-[~/pro]
└─$ s              
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ sudo nano hash.txt                     
[sudo] password for neo: 
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --wordlist=easypeasy.txt --format=gost hash.txt
Created directory: /home/neo/.john
Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ ls
easypeasy_1596838725703.txt  hash.txt
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --wordlist=easypeasy_1596838725703.txt --format=gost hash.txt 
Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ hashid hash.txt

--File 'hash.txt'--
Analyzing '9fdafbd64c47471a8f54cd3fc64cd312'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x 
--End of file 'hash.txt'--                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=gost --wordlist=easypeasy_1596838725703.txt hash.txt

Using default input encoding: UTF-8
No password hashes loaded (see FAQ)
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ cat hash.txt      
9fdafbd64c47471a8f54cd3fc64cd312
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=raw-md5 --wordlist=easypeasy_1596838725703.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2025-04-11 14:52) 0g/s 128525p/s 128525c/s 128525C/s yoly200..sunshine
Session completed. 
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ ssh -p 6498 boring@10.10.194.238
The authenticity of host '[10.10.194.238]:6498 ([10.10.194.238]:6498)' can't be established.
ED25519 key fingerprint is SHA256:6XHUSqR7Smm/Z9qPOQEMkXuhmxFm+McHTLbLqKoNL/Q.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.194.238]:6498' (ED25519) to the list of known hosts.
*************************************************************************
**        This connection are monitored by government offical          **
**            Please disconnect if you are not authorized              **
** A lawsuit will be filed against you if the law is not followed      **
*************************************************************************
boring@10.10.194.238's password: 
Permission denied, please try again.
boring@10.10.194.238's password: 
Permission denied, please try again.
boring@10.10.194.238's password: 

                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=raw-SHA-256 --wordlist=easypeasy_1596838725703.txt hash.txt

Unknown ciphertext format name requested
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=SHA-256 --wordlist=easypeasy_1596838725703.txt hash.txt 

Unknown ciphertext format name requested
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ cat hash.txt
9fdafbd64c47471a8f54cd3fc64cd312
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=raw-md5 --wordlist=easypeasy_1596838725703.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2025-04-11 14:57) 0g/s 102820p/s 102820c/s 102820C/s yoly200..sunshine
Session completed. 
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ sudo nano hash.txt                                                       
[sudo] password for neo: 
Sorry, try again.
[sudo] password for neo: 
                                                                                                        
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=gost --wordlist=easypeasy_1596838725703.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mypasswordforthatjob (?)     
1g 0:00:00:00 DONE (2025-04-11 15:06) 16.66g/s 68266p/s 68266c/s 68266C/s vgazoom4x..flash88
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                       
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=gost --wordlist=easypeasy_1596838725703.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
No password hashes left to crack (see FAQ)
                                                                                                            
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=gost --wordlist=easypeasy_1596838725703.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
No password hashes left to crack (see FAQ)
                                                                                                            
┌──(neo㉿neo)-[~/pro/s]
└─$ john --format=gost --wordlist=easypeasy_1596838725703.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (gost, GOST R 34.11-94 [64/64])
No password hashes left to crack (see FAQ)
                                                                                                            
┌──(neo㉿neo)-[~/pro/s]
└─$ gobuster dir -u http://10.10.194.238:65524/n0th1ng3ls3m4tt3r/ -w /usr/share/wordlists/dirb/common.txt -o dirs6.log
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.194.238:65524/n0th1ng3ls3m4tt3r/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 281]
/.htaccess            (Status: 403) [Size: 281]
/.htpasswd            (Status: 403) [Size: 281]
/index.html           (Status: 200) [Size: 384]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
                         
```

### terminal

```jsx
                                                                      

                                                                                        
┌──(neo㉿neo)-[/home]
└─$ pro
Command 'pro' not found, did you mean:
  command 'pry' from deb pry
  command 'prr' from deb prr
  command 'pr' from deb coreutils
  command 'proj' from deb proj-bin
  command 'prt' from deb prt
  command 'ro' from deb golang-redoctober
  command 'prs' from deb prs
Try: sudo apt install <deb name>
                                                                                                            
┌──(neo㉿neo)-[/home]
└─$ neo          
                                                                               
┌──(neo㉿neo)-[~]
└─$ pro
                                                                               
┌──(neo㉿neo)-[~/pro]
└─$ s              
                                                                               
┌──(neo㉿neo)-[~/pro/s]
└─$ ls
 binarycodepixabay.jpg                                      dirs6.log          
'data:image-jpeg;base64,-9j-4AAQSkZJRgABAQAAAQABAAD-.txt'   easypeasy_159683872
                                                                               
┌──(neo㉿neo)-[~/pro/s]
└─$ steghide extract -sf binarycodepixabay.jpg      
Enter passphrase: 
wrote extracted data to "secrettext.txt".
                                                                               
┌──(neo㉿neo)-[~/pro/s]
└─$ 

```
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
