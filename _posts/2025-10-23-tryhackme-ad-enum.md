---
title: "Tryhackme: AD: Basic Enumeration"
author: NeoVirex
categories: [thm]
tags: [CTF, thm, AD, enum, Window]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_ad-enum
image:
  path: room-img.png
description: Learning Active Directory reconnaissance on a Windows DC (TryHackMe-style)
---

# AD: Basic Enumeration

*Learning Active Directory reconnaissance on a Windows DC (TryHackMe-style)*

---

### Neo-Virex

I attacked a small AD lab to practice enumeration. After discovering three live hosts I focused on the Domain Controller (DC). Using basic network scanning and unauthenticated SMB/LDAP queries I was able to: enumerate shares, download readable files (including a small flag), enumerate 30+ domain users and groups, and extract password policy details — all without valid credentials. This is a classic reminder: misconfigured shares and overly-informative services make AD environments easy to map. 

---

## Why this lab matters

Active Directory is the backbone of many corporate Windows environments. Attackers spend a lot of time in the reconnaissance phase: mapping services, finding shares and files, and collecting usernames before trying credential-based attacks. This lab demonstrates how much information you can get *without authenticating at all*, and why preventing trivial information leakage is critical.

---

## Lab overview — what I attacked

- **Target:** Windows domain controller (identified as `DC.tryhackme.loc`) on `10.211.11.10`.
- **Key services discovered:** Kerberos (88), LDAP (389), SMB (445), RPC/NetBIOS, RDP (3389).
- **Goal:** Practice enumeration: list shares, retrieve readable files, enumerate domain users/groups and extract password policy — all unauthenticated.

---

## Lab setup & connectivity

From the attacker machine I confirmed network routes and discovered live hosts on the target subnet using `fping`:

```bash
# quickly list live hosts
fping -agq 10.211.11.0/24
# -> 10.211.11.10, 10.211.11.20, 10.211.11.250
```

I focused on `10.211.11.10` — it returned many AD-related services (Kerberos, LDAP, SMB, RPC, RDP) in an `nmap` service scan. Key ports: `88, 135, 139, 389, 445, 3389, 5985` (Windows DC fingerprint). 
 

---

## High-level methodology

1. Quick host discovery (fping).
2. Service discovery (`nmap -sV -sC` on interesting ports).
3. SMB exploration (`smbclient`, `smbmap`) to check anonymous access and list shares.
4. Run AD-focused enumeration tools (`enum4linux`, `enum4linux-ng`, `rpcclient`) to gather domain users, groups, policy and share mapping.
5. Read accessible files from shares (flag, stories) and collect usernames for further attacks (password spraying, Kerberoasting, brute force, etc.).  

---

## Important findings (what I actually discovered)

- **Open AD services:** LDAP (`389`), LDAPS (`636`), Kerberos (`88`), SMB (`445`), RPC/NetBIOS. Nmap identified the host as *Windows Server 2019 Datacenter* with FQDN `DC.tryhackme.loc`.
- **Anonymous SMB allowed (null session):** `smbclient -L //10.211.11.10 -N` and `smbmap -H 10.211.11.10` showed several shares and allowed anonymous listing of `SharedFiles`, `AnonShare`, and `UserBackups`.
- **Files retrieved:** `Mouse_and_Malware.txt` from `SharedFiles` and a small `flag.txt` plus `story.txt` from `UserBackups`. The flag file was downloadable via anonymous SMB.
- **Domain/user enumeration (unauthenticated):** `enum4linux` / `enum4linux-ng` / `rpcclient` revealed ~32 domain users (e.g., `administrator`, `krbtgt`, `sshd`, `gerald.burgess`, `katie.thomas`, etc.) and many domain groups including `Domain Admins`, `Enterprise Admins`, `Domain Users`. This was all visible without a valid domain credential. cite
- **Password policy:** Minimum length 7, complexity enabled, password history 24 — captured with `rpcclient` / `crackmapexec`. This helps tailor password spraying wordlists and timing to avoid lockouts.

---

## Key commands (cheat-sheet)

Run these to reproduce the main discovery steps:

```bash
# find live hosts
fping -agq 10.211.11.0/24

# quick service scan on a host
nmap -p 1-65535 -sV -sC 10.211.11.10

# targeted nmap on AD ports
nmap -p 88,135,139,389,445 -sV -sC 10.211.11.10

# check smb shares anonymously
smbclient -L //10.211.11.10 -N
smbmap -H 10.211.11.10

# connect to readable share and download
smbclient //10.211.11.10/SharedFiles -N
# then "ls" and "get Mouse_and_Malware.txt" inside smbclient

# domain enumeration without creds
enum4linux -a 10.211.11.10
enum4linux-ng -A 10.211.11.10 -oA enum4linux-ng

# rpcclient for scripted queries
rpcclient -U "" 10.211.11.10 -N -c "enumdomusers"
```

All of the above (output and examples) were taken from the lab notes. 
 

---

## What this teaches — blue team & red team takeaways

### Red team (learners)

- **Unauthenticated enumeration is powerful.** Many AD misconfigurations leak user and group data over SMB/RPC/LDAP even without credentials. This is low-hanging fruit to map a domain.
- **Enumerate everything early.** Users, groups, shares, and password policy all inform your next moves (which accounts to target, password spray windows, likely service misconfigs).
- **Read any readable files.** Simple texts often contain interesting hints or flags — don’t skip shares like `UserBackups` or `SharedFiles`.

### Blue team (defenders)

- **Disable anonymous/null SMB sessions** unless strictly required. Null sessions allow attackers to enumerate users and shares.
- **Lock down shares and apply least privilege.** Shares like `UserBackups` should not allow anonymous listing.
- **Harden LDAP/LDAPS & Kerberos exposure.** Prevent excessive information leakage (domain/forest names, time sync that helps Kerberos attacks).
- **Monitor for enumeration patterns.** Unusual `rpcclient`, `enum4linux`, `smbclient` activities should alert defenders to early-stage recon.

---

## Next steps (if you were doing the full CTF)

From the enumerated info you can pivot to higher-value actions (only in authorised labs!):

- Use the harvested **username list** for targeted **password spraying** (respecting the domain’s lockout policy).
- Attempt **Kerberoasting** on service accounts (if any SPNs are exposed).
- Investigate writable shares for credential files, scripts, backup archives (often contain plaintext or weakly-protected secrets).
- If you obtain credentials, plan lateral movement (PSExec, RDP, WinRM) and privilege escalation along AD attack paths.

---

## Full writeup-style narrative (short)

I found live hosts on the target subnet, then used `nmap` to fingerprint services. The presence of Kerberos, LDAP and SMB flagged this as an AD environment, so I focused on SMB and RPC enumeration. Using `smbclient`/`smbmap` I listed shares and downloaded a `flag.txt` from a backup share. `enum4linux` and `rpcclient` returned ~32 domain users and password policy details — all unauthenticated. With a username list and policy details in hand, the stage was set for offline/online password attacks, Kerberoasting, and targeted exploitation (in an authorized lab). This demonstrates how minor misconfigurations turn into major reconnaissance wins for attackers.

---