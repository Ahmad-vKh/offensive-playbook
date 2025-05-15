## Enumerating ACLs with PowerView

#### 1- Using Find-InterestingDomainAcl
```powershell-session
PS C:\htb> Find-InterestingDomainAcl
```
-avoid because its time consuming

wley <> transporter@4
```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
powershell -ep bypass -File .\PowerView.ps1
powershell -ep bypass
. .\PowerView.ps1

```
#### 2- Using Get-DomainObjectACL
```powershell-session
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```
>`welly user sid maping to ACL FOR OBJECTS IN THE DOMAIN THAT HE HAS ACCESS TO`



>USE `ResolveGUIDs`
>GUID value `00299570-246d-11d0-a768-00aa006e0529` <> go search what is this

Alternatively, we could do a reverse search using PowerShell to map the right name back to the GUID value.

----

#### Performing a Reverse Search & Mapping to a GUID Value

This gave us our answer, but would be highly inefficient during an assessment
```python
PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

---

#### Using the -ResolveGUIDs Flag
```python
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
```

---

`Why did we walk through this example when we could have just searched using ResolveGUIDs first?`
[^1]: 
!!!
	in case a tool fails or is blocked. Before moving on, let's take a quick look at how we could do this using the [Get-Acl](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-acl?view=powershell-7.2) and [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps) cmdlets which we may find available to us on a client system. Knowing how to perform this type of search without using a tool such as PowerView is greatly beneficial and could set us apart from our peers. We may be able to use this knowledge to achieve results when a client has us work from one of their systems, and we are restricted down to what tools are readily available on the system without the ability to pull in any of our own.
	This example is not very efficient, and the command can take a long time to run,

---

#### Creating a List of Domain Users

```python
PS C:\htb> Get-ADUser -Filter * | Select-Object -ExpandProperty SamAccountName > ad_users.txt
```

`foreach` loop, and use the `Get-Acl` cmdlet to retrieve ACL information for each domain user by feeding each line of the `ad_users.txt` file to the `Get-ADUser` cmdlet. We then select just the `Access property`, which will give us information about access rights. Finally, we set the `IdentityReference` property to the user we are in control of (or looking to see what rights they have), in our case, `wley`.

```powershell-session
PS C:\htb> foreach($line in [System.IO.File]::ReadLines("C:\Users\htb-student\Desktop\ad_users.txt")) {get-acl  "AD:\$(Get-ADUser $line)" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\wley'}}
```

convert the GUID to a human-readable


#### Further Enumeration of Rights Using damundsen

```powershell-session
S C:\htb> $sid2 = Convert-NameToSid dpayne
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid2} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Help Desk Level 1,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```
```powershell-session
ActiveDirectoryRights : ListChildren, ReadProperty, GenericWrite
```

`damundsen` has `GenericWrite` privileges over the `Help Desk Level 1` group
we can add any user (or ourselves) to this group and inherit any rights that this group has applied to it.

#### Investigating the Help Desk Level 1 Group with Get-DomainGroup
```powershell-session
PS C:\htb> Get-DomainGroup -Identity "Help Desk Level 1" | select memberof

Get-DomainGroup -Identity *gpo*

memberof                                                                      
--------                                                                      
CN=Information Technology,OU=Security Groups,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
```

---

- We have control over the user `wley` whose hash we retrieved earlier in the module (assessment) using Responder and cracked offline using Hashcat to reveal the cleartext password value
- We enumerated objects that the user `wley` has control over and found that we could force change the password of the user `damundsen`
- From here, we found that the `damundsen` user can add a member to the `Help Desk Level 1` group using `GenericWrite` privileges
- The `Help Desk Level 1` group is nested into the `Information Technology` group, which grants members of that group any rights provisioned to the `Information Technology` group

---


#### Investigating the Information Technology Group

```powershell-session
PS C:\htb> $itgroupsid = Convert-NameToSid "GPO Management"
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $itgroupsid} -Verbose

AceType               : AccessAllowed
ObjectDN              : CN=Angela Dunn,OU=Server Admin,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights : GenericAll
```

- Modify group membership
- Force change a password
- Perform a targeted Kerberoasting attack and attempt to crack the user's password if it is weak


Finally, let's see if the `adunn` user has any type of interesting access that we may be able to leverage to get closer to our goal.

#### Looking for Interesting Access `adunn`
```powershell-session
PS C:\htb> $adunnsid = Convert-NameToSid adunn 
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $adunnsid} -Verbose

AceQualifier           : AccessAllowed
ObjectDN               : DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
```

```powershell-session
ObjectAceType          : DS-Replication-Get-Changes-In-Filtered-Set
```

This means that this user can be leveraged to perform a DCSync attack

# Enumerating ACLs with BloodHound

checklist:
```
1- run sharphound
2- set pwned user as start node `Node Info` tab and scroll down to `Outbound Control Rights`.
3-

```

![image](https://academy.hackthebox.com/storage/modules/143/wley_damundsen.png)
```
3- run help


```
`16` next to `Transitive Object Control`:
![image](https://academy.hackthebox.com/storage/modules/143/wley_path.png)

