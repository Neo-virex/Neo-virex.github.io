---
title: "TryHackMe: Biohazard"
author: NeoVirex
categories: [CTF, TryHackMe]
tags: [base64, web, ctf]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_biohazard/
image:
  path: room_img.png

description: "This write-up documents a complete walkthrough of the Biohazard CTF challenge. It integrates the detailed steps from the reference HTML write-up (originally from the Bio-hazard TryHackMe page) with my own investigation, notes, and captured artifacts. It explores each phase in sequence reconnaissance, enumeration, exploitation, and **privilege escalation alongside captured flags, passwords, tools, and decryption paths."
---

# 🕯️ The Biohazard – CTF Write-up
Created: August 3, 2025 3:27 AM
Status: Done


## 1. Reconnaissance & Initial Access

### 1.1. Nmap Scan

```bash
nmap -sC -sV -p- ctf.thm

```

- **Ports**:
    - `21/tcp` - FTP (Login required)
    - `80/tcp` - HTTP (Web application)

### 1.2. Web Enumeration

- Navigated to `http://ctf.thm` and found a mansion-themed homepage.
- Page source revealed several accessible room paths:
    
    ```
    /diningRoom/
    /teaRoom/
    /artRoom/
    /barRoom/
    /diningRoom2F/
    /tigerStatusRoom/
    /galleryRoom/
    /studyRoom/
    /armorRoom/
    /attic/
    
    ```
    
- A clue from `Look like a map.txt` pointed toward `/teaRoom/`.

---

## 2. Exploring Rooms and Gathering Flags

### 2.1. Tea Room Clue

The file provided the following encoded text:

```
SG93IGFib3V0IHRoZSAvdGVhUm9vbS8=

```

Decoding via `base64`:

```bash
echo "SG93IGFib3V0IHRoZSAvdGVhUm9vbS8=" | base64 -d
# How about the /teaRoom/

```

### 2.2. `/teaRoom/` Flags

Visiting `http://ctf.thm/teaRoom/` revealed several in-game items/flags:

- `emblem{fec832623[REDACTED]4fe1821d58727}`
- `lock_pick{037b3[REDACTED]916a9abf99129c8e1837}`
- `blue_jewel{e1d457e9[REDACTED]3ec7bc475d48aa}`
- `music_sheet{362d7[REDACTED]c63daece6a1f676e}`
- `gold_emblem{58a8[REDACTED]a4e38d02a4d7ff4843}`
- `shield_key{48a7[REDACTED]7eb89f0a062590798cbac}`

---

## 3. Puzzle in Dining Room

Visiting `/diningRoom/emblem_slot.php`, a message was presented:

```
klfvg ks r wimgnd biz mpuiui ulg fiemok tqod. Xii jvmc tbkg ks tempgf tyi_hvgct_jljinf_kvc

```

This is a Caesar cipher (ROT13). Decrypting it:

```
xysit xf e jvzqat ovm zchvhf hytr svrzbx gd bqd

```

The message instructs collecting four “crests,” each encoded differently.

---

## 4. Crest Collection and Decoding

### Crest 1 (Base64)

```
S0pXRkVVS0pKQkxIVVdTWUpFM0VTUlk9

```

Decoded twice:

```
KJWFUEKJBLHUWSYJE3ESRY=

```

### Crest 2 (Base32)

```
GVFW[REDACTED]TCILE4DKY3DNN4GQQRTM5AVCTKE

```

Double-decoded → usable key string.

### Crest 3 (Binary)

A long binary string was found and converted using:

```bash
echo "<binary>" | perl -lpe '$_=pack"B*",$_'

```

Resulting Base64 then decoded to obtain a string.

### Crest 4 (Base62)

```
gSUE[REDACTED]yPpuYz66JDmRTbJubaoArM6CAQsnVwte6zF9J4GGYyun3k5qM9ma4s

```

Double-decoded to reveal login credentials (FTP).

### Combined Result:

```
RlRQIHVzZXI6IGh1bnRlciw[REDACTED]M6IHlvdV9jYW50X2hpZGVfZm9yZV9mb3JldmVy

```

Base64 decoded:

```
FTP user: hunter
FTP pass: you_ca[REDACTED]_forever

```

---

## 5. FTP Enumeration

Used the credentials:

```bash
ftp ctf.thm
Name: hunter
Password: you_ca[REDACTED]de_forever

```

### Files Found:

- `001-key.jpg`
- `002-key.jpg`
- `003-key.jpg`
- `helmet_key.txt.gpg`
- `important.txt`

All were downloaded for local analysis.

---

## 6. Steganography & Image Metadata

Analyzed JPGs using `exiftool`:

### `002-key.jpg`:

- Comment: `5fYmVfZGVzdHJveV9` → `_be_destroy_`

### Combined from all images:

```
plant42_can_be_d[REDACTED]y_with_vjolt

```

This is later used as the key for Vigenère cipher.

---

## 7. GPG Decryption

Decrypted:

```bash
gpg -d helmet_key.txt.gpg

```

Result:

```
helmet_key{458493193501d[REDACTED]e727f8db4b}

```

---

## 8. Vigenère Cipher Decryption

Used provided script (`vigenere_decrypt.py`) and content in `important.txt`.

- Key: `plant42_can_be_destroy_with_vjolt`
- Resulted in path to:

```
/hiddenCloset8997e740cb7f5cece994381b9477ec38/MO_DISK1.txt

```

Navigated and retrieved MO Disk 1.

---

## 9. Access via SSH

Disks (MO_DISK1.txt, etc.) hinted toward:

```
SSH user: umbrella_guest
Password: T_virus_rules

```

Logged in:

```bash
ssh umbrella_guest@ctf.thm

```

### `~/.jailcell/chris.txt`:

Found hint: "albert" — used as password for `su`.

---

## 10. Privilege Escalation

Switched to user:

```bash
su weasker
Password: stars_mem[REDACTED]re_my_guinea_pig

```

Checked permissions:

```bash
sudo -l
# (ALL : ALL) ALL

```

Escalated to root:

```bash
sudo su

```

---

## 11. Final Flag

Accessed root flag at `/root/root.txt`:

```
flag: 3c5794a00dc[REDACTED]6571edf3bf

```

---

## 🎯 Summary of Captured Flags

| Area | Flag/Item |
| --- | --- |
| Tea Room Items | emblem{fec8326`[REDACTED]`20bf4fe1821d58727} |
|  | lock_pick{037b35`[REDACTED]`abf99129c8e1837} |
|  | blue_jewel{e1d457e96cac`[REDACTED]`63ec7bc475d48aa} |
|  | music_sheet{362d72de`[REDACTED]`3daece6a1f676e} |
|  | gold_emblem{58a8c41a9d08`[REDACTED]`02a4d7ff4843} |
|  | shield_key{48a7a9227cd7eb`[REDACTED]`0798cbac} |
| GPG Decryption | helmet_key{458493193501d`[REDACTED]`27f8db4b} |
| FTP Credentials | hunter / you_c`[REDACTED]`t_hide_forever |
| Vigenère Key | plant42_can_be_d`[REDACTED]`y_with_vjolt |
| SSH Credentials | umbrella_guest / T_virus_rules |
| Root Password Hint | su weasker (password: albert) |
| Final Root Flag | 3c5794a00`[REDACTED]`96571edf3bf |

---

## Conclusion

The “Nightmare” CTF was an immersive and well-crafted multi-stage challenge, combining:

- Web enumeration
- Cipher puzzles
- Steganography
- Realistic filesystem interaction
- FTP & SSH access chaining
- Root privilege escalation