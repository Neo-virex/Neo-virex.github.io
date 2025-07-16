---
title: "TryHackme: Pickle Rick"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_pickle_rick/
image:
  path: room_img.jpeg
description: "Pickle Rick is a fun beginner-level TryHackMe room where you help Rick gain access to a server and find ingredients to turn himself back into a human. It teaches basic Linux enumeration, file permissions, and simple privilege escalation techniques."
---

Created: April 11, 2025 1:00 PM
Finishing Date: April 10, 2025
Status: Done

## Reconnaissance && Service Enumeration

```jsx
└─$ rustscan -a 10.10.146.130
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Because guessing isn't hacking.

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.146.130:22
Open 10.10.146.130:80
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 13:03 EDT
Initiating Ping Scan at 13:03
Scanning 10.10.146.130 [4 ports]
Completed Ping Scan at 13:03, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:03
Completed Parallel DNS resolution of 1 host. at 13:03, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 13:03
Scanning 10.10.146.130 [2 ports]
Discovered open port 22/tcp on 10.10.146.130
Discovered open port 80/tcp on 10.10.146.130
Completed SYN Stealth Scan at 13:03, 0.15s elapsed (2 total ports)
Nmap scan report for 10.10.146.130
Host is up, received echo-reply ttl 63 (0.13s latency).
Scanned at 2025-04-11 13:03:37 EDT for 0s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (
```

![Screenshot From 2025-04-11 13-06-07.png](img1.png)

![Screenshot From 2025-04-11 13-07-50.png](img2.png)

```jsx
$ ffuf -u http://10.10.146.130/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.146.130/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 1062, Words: 148, Lines: 38, Duration: 146ms]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 342ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 1335ms]
.hta                    [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 3355ms]
assets                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 240ms]
index.html              [Status: 200, Size: 1062, Words: 148, Lines: 38, Duration: 150ms]
robots.txt              [Status: 200, Size: 17, Words: 1, Lines: 2, Duration: 188ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 138ms]
:: Progress: [4614/4614] :: Job [1/1] :: 256 req/sec :: Duration: [0:00:20] :: Errors: 0 ::
             
```

![Screenshot From 2025-04-11 13-14-40.png](img3.png)

the password is the robots.txt 

`Wubbalubbadubdub`

## Lateral Movement

1 in the var/www/html

2 in /home/rick

3 in /root

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
