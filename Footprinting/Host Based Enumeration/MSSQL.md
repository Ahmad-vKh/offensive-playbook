
`1433`
what dbo.devsacc do ??
(`MSSQL`) is Microsoft's SQL-based relational database management system. Unlike MySQL, which we discussed in the last section, MSSQL is closed source and was initially written to run on Windows operating systems.

closed ,source for WINDOWS OS (on .NET framework).
There are versions of MSSQL that will run on Linux and MacOS, but we will more likely come across MSSQL instances on targets running Windows.


#### MSSQL Clients

`SSMS` == `SQL server management system`
we could come across a vulnerable system with SSMS with saved credentials that allow us to connect to the database.

MSSQL
Many other clients can be used to access a database running on MSSQL. Including but not limited to:
`mssql-cli` 	
`SQL Server PowerShell`	
`HeidiSQL` 	
`SQLPro` 	
#### **`Impacket's mssqlclient.py`**

Of the MSSQL clients listed above, pentesters may find Impacket's `mssqlclient.py` to be the most useful due to SecureAuthCorp's Impacket project being present on many pen-testing distributions at install. To find if and where the client is located on our host, we can use the following command

#### MSSQL Databases

| Default System Database | Description                                                                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `master`                | Tracks all system information for an SQL server instance                                                                                                                                               |
| `model`                 | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| `msdb`                  | The SQL Server Agent uses this database to schedule jobs & alerts                                                                                                                                      |
| `tempdb`                | Stores temporary objects                                                                                                                                                                               |
| `resource`              | Read-only database containing system objects included with SQL server                                                                                                                                  |
- MSSQL clients not using encryption to connect to the MSSQL server
    
- The use of self-signed certificates when encryption is being used. It is possible to spoof self-signed certificates
    
- The use of [named pipes](https://docs.microsoft.com/en-us/sql/tools/configuration-manager/named-pipes-properties?view=sql-server-ver15)
    
- Weak & default `sa` credentials. Admins may forget to disable this account


## Foot-printing the Service

```shell
AhmaDb0x@htb[/htb]$ sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.201.248
```

```shell
$ msf6 auxiliary(scanner/mssql/mssql_ping) > set rhosts 10.129.201.248
```

```shell
AhmaDb0x@htb[/htb]$ python3 mssqlclient.py Administrator@10.129.201.248 -windows-auth
```

