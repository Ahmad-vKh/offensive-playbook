# Windows attack host

`SharpHound/BloodHound, PowerView/SharpView, Grouper2, Snaffler`
```
client may be interested in all possible findings, so even issues like the ability to run BloodHound freely or certain user account attributes may be worth including in our report as either medium-risk findings or a separate appendix section. Not every issue we uncover has to be geared towards forwarding our attacks. Some of the results may be informational in nature but useful to the customer to help improve their security posture.
```

---
the goal:
```
misconfigurations and permission issues that could lead to lateral and vertical movement.
```

## TTPs
https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

## ActiveDirectory PowerShell Module
#### Discover Modules
```bash
PS C:\htb> Get-Module
```
```powershell-session
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```

### Get Domain Info
```powershell-session
PS C:\htb> Get-ADDomain
check :
sid
```

#### Get-ADUser
`ServicePrincipalName`
```powershell-session
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

#### Checking For Trust Relationships
`domain trust relationships`
```powershell-session
PS C:\htb> Get-ADTrust -Filter *
```
goal:
`with domains in other forests, the type of trust, the direction of the trust, and the name of the domain the relationship is with.`
#### Group Enumeration
```powershell-session
PS C:\htb> Get-ADGroup -Filter * | select name
```
#### Detailed Group Info
```powershell-session
PS C:\htb> Get-ADGroup -Identity "Backup Operators"
```

### Group Membership
```powershell
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"

distinguishedName : CN=BACKUPAGENT,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
name              : BACKUPAGENT
objectClass       : user
objectGUID        : 2ec53e98-3a64-4706-be23-1d824ff61bed
SamAccountName    : backupagent
SID               : S-1-5-21-3842939050-3880317879-2865463114-5220
```
take over this service account through some attack, we could use its membership in the Backup Operators group to take over the domain.
key success:`repeating the process with a few different groups.`
```
Utilizing the ActiveDirectory module on a host can be a stealthier way of performing actions than dropping a tool onto a host or loading it into memory and attempting to use it.
```

---

## PowerView
obsidian://open?vault=Enumeration%20%26%20Attack%20Planning&file=PowerView.PS1

https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon
---
## SharpView
`Get-NetGmsa`, used to hunt for [Group Managed Service Accounts](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
`SharpView can be useful when a client has hardened against PowerShell usage`

---

## Shares

Shares allow users on a domain to quickly access information relevant to their daily roles and share content with their organization. When set up correctly, domain shares will require a user to be domain joined and required to authenticate when accessing the system. Permissions will also be in place to ensure users can only access and see what is necessary for their daily role. Overly permissive shares can potentially cause accidental disclosure of sensitive information, especially those containing medical, legal, personnel, HR, data, etc. In an attack, gaining control over a standard domain user who can access shares such as the IT/infrastructure shares could lead to the disclosure of sensitive data such as configuration files or authentication files like SSH keys or passwords stored insecurely. We want to identify any issues like these to ensure the customer is not exposing any data to users who do not need to access it for their daily jobs and that they are meeting any legal/regulatory requirements they are subject to (HIPAA, PCI, etc.). We can use PowerView to hunt for shares and then help us dig through them or use various manual commands to hunt for common strings such as files with `pass` in the name. This can be a tedious process, and we may miss things, especially in large environments. Now, let's take some time to explore the tool `Snaffler` and see how it can aid us in identifying these issues more accurately and efficiently.

----
## Snaffler
[Snaffler](https://github.com/SnaffCon/Snaffler) 
goal :may find passwords, SSH keys, configuration files, or other data that can be used to further our access
```
is a tool that can help us acquire credentials or other sensitive data in an Active Directory environment. Snaffler works by obtaining a list of hosts within the domain and then enumerating those hosts for shares and readable directories. Once that is done, it iterates through any directories readable by our user and hunts for files that could serve to better our position within the assessment. Snaffler requires that it be run from a domain-joined host or in a domain-user context 
```

#### Snaffler Execution
```bash
Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data
```



### SharpHound
```powershell-session
PS C:\htb> .\SharpHound.exe -c All --zipfilename ILFREIGHT
```

typing `bloodhound` into a CMD or PowerShell console. The credentials should be saved, but enter `neo4j: HTB_@cademy_stdnt!`

TRAGETS:
1- ``Analysis` tab. The query `Find Computers with Unsupported Operating Systems` is great for finding outdated and unsupported operating systems running legacy software.`
Keeping these hosts around may save money, but they also can add unnecessary vulnerabilities to the network. Older hosts may be susceptible to older remote code execution vulnerabilities like [MS08-067](https://support.microsoft.com/en-us/topic/ms08-067-vulnerability-in-server-service-could-allow-remote-code-execution-ac7878fc-be69-7143-472d-2507a179cd15)

---

Keep in mind as we go through the engagement, we should be documenting every file that is transferred to and from hosts in the domain and where they were placed on disk. This is good practice if we have to deconflict our actions with the customer. Also, depending on the scope of the engagement, you want to ensure you cover your tracks and clean up anything you put in the environment at the conclusion of the engagement.