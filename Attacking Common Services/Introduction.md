## File Share Services
mixture of internal and external file-sharing services,
SMB, NFS, FTP, TFTP, SFTP
cloud services such:
Dropbox, Google Drive, OneDrive, SharePoint
AWS S3, Azure Blob Storage, or Google Cloud Storage.

## Server Message Block (SMB)
file sharing protocol in windows env
1-`[WINKEY] + [R]` to open the Run
2-`\\192.168.220.129\Finance\`
cmd or powershell they are software to interact with underlaying os
#### Windows CMD - DIR

```cmd-session
dir \\192.168.220.129\Finance\
```
#### Windows CMD - Net Use
```cmd-session
C:\htb> net use n: \\192.168.220.129\Finance
```
map its content to the drive letter `n`
```cmd-session
C:\htb> net use n: \\192.168.220.129\Finance /user:plaintext Password123
```
`assume share folder have thousends of files`
- cred
- password
- users
- secrets
- key
- Common File Extensions for source code such as: .cs, .c, .go, .java, .php, .asp, .aspx, .html.

```cmd-session
C:\htb>dir n:\*cred* /s /b
```

| **Syntax** | **Description**                                                |
| ---------- | -------------------------------------------------------------- |
| `dir`      | Application                                                    |
| `n:`       | Directory or drive to search                                   |
| `/a-d`     | `/a` is the attribute and `-d` means not directories           |
| `/s`       | Displays files in a specified directory and all subdirectories |
| `/b`       | Uses bare format (no heading information or summary)           |

```cmd-session
c:\htb>findstr /s /i cred n:\*.*
```

#### Windows PowerShell
scripting language , extend of cmd with scripts

```powershell-session
PS C:\htb> Get-ChildItem \\192.168.220.129\Finance\

    Directory: \\192.168.220.129\Finance
```

```powershell-session
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"
```

#### Windows PowerShell - PSCredential Object
```powershell-session
PS C:\htb> $username = 'plaintext'
PS C:\htb> $password = 'Password123'
PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred

Name           Used (GB)     Free (GB) Provider      Root                                                              CurrentLocation
----           ---------     --------- --------      ----                                                              ---------------
N                                      FileSystem    \\192.168.220.129\Finance
```

```powershell-session
PS C:\htb> Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

    Directory: N:\Contracts\private

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/23/2022   4:36 PM             25 credentials.txt
```
`Select-String` similar to `grep` in UNIX or `findstr.exe` in Windows.

```powershell-session
PS C:\htb> Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List

N:\Contracts\private\secret.txt:1:file with all credentials
N:\Contracts\private\credentials.txt:1:admin:SecureCredentials!
```

#### Linux
```shell-session
AhmaDb0x@htb[/htb]$ sudo mkdir /mnt/Finance
AhmaDb0x@htb[/htb]$ sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
```
As an alternative, we can use a credential file.
#### CredentialFile
```txt
username=plaintext
password=Password123
domain=.
```
---
```shell-session
AhmaDb0x@htb[/htb]$ mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
```
---
Note: We need to install `cifs-utils` to connect to an SMB share folder. To install it we can execute from the command line `sudo apt install cifs-utils`.

---
```shell-session
AhmaDb0x@htb[/htb]$ find /mnt/Finance/ -name *cred*

/mnt/Finance/Contracts/private/credentials.txt
```

```shell-session
AhmaDb0x@htb[/htb]$ grep -rn /mnt/Finance/ -ie cred

/mnt/Finance/Contracts/private/credentials.txt:1:admin:SecureCredentials!
/mnt/Finance/Contracts/private/secret.txt:1:file with all credentials
```


## Email

1-We typically need two protocols to send and receive messages(SMTP) 
2-email delivery protocol used to send mail over the internet. 
3-to retrieve an email from a service. There are two main protocols we can use POP3 and IMAP.
```shell-session
AhmaDb0x@htb[/htb]$ sudo apt-get install evolution
```
Note: If an error appears when starting evolution indicating "bwrap: Can't create file at ...", use this command to start evolution `export WEBKIT_FORCE_SANDBOX=0 && evolution`.




## Databases
common relational databases called MySQL & MSSQL
three common ways to interact with databases:

|`1.`|Command Line Utilities (`mysql` or `sqsh`)|
|`2.`|Programming Languages|
|`3.`|A GUI application to interact with databases such as HeidiSQL, MySQL      Workbench, or SQL Server Management Studio.|

### mysql and mssql

#### mssql
linux
```shell-session
AhmaDb0x@htb[/htb]$ sqsh -S 10.129.20.13 -U username -P Password123
```
windows
```cmd-session
C:\htb> sqlcmd -S 10.129.20.13 -U username -P Password123
```

#### MySQL
```shell-session
AhmaDb0x@htb[/htb]$ mysql -u username -pPassword123 -h 10.129.20.13
```
```cmd-session
C:\htb> mysql.exe -u username -pPassword123 -h 10.129.20.13
```

#### Tools to Interact with Common Services

|**SMB**|**FTP**|**Email**|**Databases**|
|---|---|---|---|
|[smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)|[ftp](https://linux.die.net/man/1/ftp)|[Thunderbird](https://www.thunderbird.net/en-US/)|[mssql-cli](https://github.com/dbcli/mssql-cli)|
|[CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)|[lftp](https://lftp.yar.ru/)|[Claws](https://www.claws-mail.org/)|[mycli](https://github.com/dbcli/mycli)|
|[SMBMap](https://github.com/ShawnDEvans/smbmap)|[ncftp](https://www.ncftp.com/)|[Geary](https://wiki.gnome.org/Apps/Geary)|[mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)|
|[Impacket](https://github.com/SecureAuthCorp/impacket)|[filezilla](https://filezilla-project.org/)|[MailSpring](https://getmailspring.com)|[dbeaver](https://github.com/dbeaver/dbeaver)|
|[psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)|[crossftp](http://www.crossftp.com/)|[mutt](http://www.mutt.org/)|[MySQL Workbench](https://dev.mysql.com/downloads/workbench/)|
|[smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py)||[mailutils](https://mailutils.org/)|[SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms)|
|||[sendEmail](https://github.com/mogaal/sendemail)||
|||[swaks](http://www.jetmore.org/john/code/swaks/)||
|||[sendmail](https://en.wikipedia.org/wiki/Sendmail)||
Some reasons why we may not have access to a resource:

- Authentication
- Privileges
- Network Connection
- Firewall Rules
- Protocol Support


