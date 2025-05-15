#### pre-requests:
>`user credntial` domain joined 

#### goal :
> 1-`domain users`
> 2-`computer attributes`
> 3-`group membership`
> 4-`Group Policy Objects` >
> 5- `permissions, ACLs, trusts`

![[Pasted image 20250307213831.png]]

`User=`forend` and password=`Klmcargo2

---
# check-list
1- `crackmapexec`
```bash
1- Domain User Enumeration
2- Domain Group Enumeration
3- Logged On Users
4- Share Searching  `Domain Controller` >  -Spider_plus
5- 
```
---

2- `SMBMap`
```bash
1- Check Access
2- Recursive List Of All Directories
```

3- `rpcclient`
```bash
1-#### NULL Session
2-#### User Enumeration By RID
```

4- `Impacket Toolkit`
```bash
psexec
wmexec
```

5- `Windapsearch`
```bash
1-  Domain Admins
2-  Privileged Users
```

6- `Bloodhound.py`

---

# Enumeration

## CrackMapExec
`Be sure to review the entire help menu and all possible options.`
`Bad-Pwd-Count attribute`
The number of times the user tried to log on to the account using an incorrect password. A value of 0 indicates that the value is unknown.

```
We should save all of our output to files to easily access it again later for reporting or use with other tools.
```


#### CME - Domain User Enumeration
```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
#### CME - Domain Group Enumeration
```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups

crackmapexec ldap <target_ip> -u <username> -p <password> --group "Domain Admins"

```

```
built-in groups on the Domain Controller, such as `Backup Operators`. We can begin to note down groups of interest. Take note of key groups like `Administrators`, `Domain Admins`, `Executives`, any groups that may contain privileged IT admins, etc. These groups will likely contain users with elevated privileges worth targeting during our assessment.
```

#### CME - Logged On Users
```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users

`(Pwn3d!)` appears after the tool successfully authenticates to the target host. A host like this may be used as a jump host or similar by administrative users
```

#### Share Enumeration - Domain Controller
`spider_plus`
```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares

AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```
```shell-session
OUTPUT: /tmp/cme_spider_plus
```
JSON output. We could dig around for interesting files such as `web.config` files or scripts that may contain passwords. If we wanted to dig further, we could pull those files to see what all resides within, perhaps finding some hardcoded credentials or other sensitive information.

## SMBMap
#### Recursive List Of All Directories
```bash
AhmaDb0x@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```
`try it without --dir-only`

## rpcclient
--user=[DOMAIN\]USERNAME[%PASSWORD]
```bash
rpcclient -U "" -N 172.16.5.5
```
```shell-session
rpcclient $> queryuser 0x457
```
```shell-session
rpcclient $> enumdomusers
```
-enum SID
- The [SID](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) for the INLANEFREIGHT.LOCAL domain is: `S-1-5-21-3842939050-3880317879-2865463114`.
- When an object is created within a domain, the number above (SID) will be combined with a RID to make a unique value used to represent the object.
- So the domain user `htb-student` with a RID:[0x457] Hex 0x457 would = decimal `1111`, will have a full user SID of: `S-1-5-21-3842939050-3880317879-2865463114-1111`.
- This is unique to the `htb-student` object in the INLANEFREIGHT.LOCAL domain and you will never see this paired value tied to another object in this domain or any other
Standard **SID structure** in AD:
```bash
S-1-5-21-[DOMAIN_IDENTIFIER]-[RID]
```
- **500** – Administrator
- **512** – Domain Admins
- **518** – Schema Admins
- **519** – Enterprise Admins

## psexec wmexec
obsidian://open?vault=Enumeration%20%26%20Attack%20Planning&file=Impacket%20Toolkit


## Windapsearch
#### Windapsearch - Domain Admins
```bash
AhmaDb0x@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 --da
```
#### Windapsearch - Privileged Users
```bash
AhmaDb0x@htb[/htb]$ python3 windapsearch.py --dc-ip 172.16.5.5 -u forend@inlanefreight.local -p Klmcargo2 -PU
```

## Bloodhound.py
https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/
`Raw Query` box at the bottom, and hitting enter
#### Executing BloodHound.py
```bash
AhmaDb0x@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 
```

```bash
sudo neo4j start
`user == neo4j` / `pass == HTB_@cademy_stdnt!`

bloodhound gui


```

1- `Find Shortest Paths To Domain Admins`
2- `Database Info` <> `Domain Users`

Keep in mind as we go through the engagement, we should be documenting every file that is transferred to and from hosts in the domain and where they were placed on disk. This is good practice if we have to deconflict our actions with the customer. Also, depending on the scope of the engagement, you want to ensure you cover your tracks and clean up anything you put in the environment at the conclusion of the engagement.