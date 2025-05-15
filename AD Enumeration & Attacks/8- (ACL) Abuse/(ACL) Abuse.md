
OBJECT > any resource can be secured or managed 
example :
1- user account !
2- groups (department)
3- computers , shared folders , printers .... etc

---
>`every object in AD has its own` ACL assigned to (who can access ?)

what is ACE : ACEES CONTROL ENTRIES:
>`THE RULES IT SELF ASSINED IN ACL FOR THE` object 
>who can access + what they can do (read  or  write or modify or delete )

#two-types-of-ACLs:
1- `Discretionary Access Control List` (`DACL`):
>DACLs are made up of ACEs
>It contains **ACEs**, which are individual **access rules**
>If an object **does not have a DACL**, it means **everyone** has full access. If an object has a **blank DACL**, **nobody** (not even the owner) can access it.
>**(ACE)** is a **single entry** in a DACL
>

2- `System Access Control Lists` (`SACL`):
>allow administrators to log access attempts made to secured objects.

---
#three-main-types-of-ACEs

| **ACE**              | **Description**                                                                                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Access denied ACE`  | Used within a DACL to show that a user or group is explicitly denied access to an object                                                                                   |
| `Access allowed ACE` | Used within a DACL to show that a user or group is explicitly granted access to an object                                                                                  |
| `System audit ACE`   | Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred |

#ACE-four-components
>SID
>FLAG = DENY , ALLOW , AUDIT
>SET OF FLAGS = whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
>An [access mask](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) which is a 32-bit value that defines the rights granted to an object

---
## Why are ACEs Important?
>object > ACL > DACL > ACE > ADD ENRTIES (for grant access + persistence)
>organizations are unaware of the ACEs applied to each object or the impact of it
>cannot be detected by vulnerability scanning tools

---

#abuse-ACE
>- `ForceChangePassword` abused with `Set-DomainUserPassword`
>- - `Add Members` abused with `Add-DomainGroupMember`
>- - `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
>- - `GenericWrite` abused with `Set-DomainObject`
>- - `WriteOwner` abused with `Set-DomainObjectOwner`
>- - `WriteDACL` abused with `Add-DomainObjectACL`
>- - `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
>- - `Addself` abused with `Add-DomainGroupMember`


## enumerating  ACEs
[^1]


[^1]: - [ForceChangePassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
	- [GenericWrite](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
	- `AddSelf` - shows security groups that a user can add themselves to.
	- [GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access
	-
![image](https://academy.hackthebox.com/storage/modules/143/ACL_attacks_graphic.png)

---


For example, we may import data into BloodHound and see that a user we have control over (or can potentially take over) has the rights to read the password for a Group Managed Service Account (gMSA) through the [ReadGMSAPassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#readgmsapassword) edge. In this case, there are tools such as [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader) that we could use, along with other methods, to obtain the password for the service account in question. Other times we may come across extended rights such as [Unexpire-Password](https://learn.microsoft.com/en-us/windows/win32/adschema/r-unexpire-password) or [Reanimate-Tombstones](https://learn.microsoft.com/en-us/windows/win32/adschema/r-reanimate-tombstones) using PowerView and have to do a bit of research to figure out how to exploit these for our benefit. It's worth familiarizing yourself with all of the [BloodHound edges](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html) and as many Active Directory [Extended Rights](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) as possible as you never know when you may encounter a less common one during an assessment.

---

# scenarios

|Attack|Description|
|---|---|
|`Abusing forgot password permissions`|Help Desk and other IT users are often granted permissions to perform password resets and other privileged tasks. If we can take over an account with these privileges (or an account in a group that confers these privileges on its users), we may be able to perform a password reset for a more privileged account in the domain.|
|`Abusing group membership management`|It's also common to see Help Desk and other staff that have the right to add/remove users from a given group. It is always worth enumerating this further, as sometimes we may be able to add an account that we control into a privileged built-in AD group or a group that grants us some sort of interesting privilege.|
|`Excessive user rights`|We also commonly see user, computer, and group objects with excessive rights that a client is likely unaware of. This could occur after some sort of software install (Exchange, for example, adds many ACL changes into the environment at install time) or some kind of legacy or accidental configuration that gives a user unintended rights. Sometimes we may take over an account that was given certain rights out of convenience or to solve a nagging problem more quickly.|

**Note:** Some ACL attacks can be considered "destructive," such as changing a user's password or performing other modifications within a client's AD domain. If in doubt, it's always best to run a given attack by our client before performing it to have written documentation of their approval in case an issue arises. We should always carefully document our attacks from start to finish and revert any changes. This data should be included in our report, but we should also highlight any changes we make clearly so that the client can go back and verify that our changes were indeed reverted properly.


