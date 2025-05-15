8-digit password that consists only of upper case letters and numbers, we would get a total of `36⁸` (`208,827,064,576`) different combinations of passwords.

`24% of Americans` have used passwords like `password`, `Qwerty`, or `123456`. So, in theory, we could successfully compromise systems using these three passwords at many different organizations due to their widespread use

`22%` used their `name`, and `33%` used the name of their `pet` or `children`. Another critical statistic for us is the `password re-use` of an already used password for more than one account, `66%`. This means that 66% of all Americans, according to this statistic, have used the same password for multiple platforms. Therefore, once we have obtained or guessed a password, there is a 66% chance that we could use it to authenticate ourselves on other platforms with the user's ID (username or email address). This would, of course, require that we are able to guess the user's user ID, which, in many cases, is not difficult to do.

We can also check if one of our email addresses is affected by various data breaches. One of the best-known sources for this is [HaveIBeenPwned](https://haveibeenpwned.com/). We enter an email address in the HaveIBeenPwned website, and it checks in its database if the email address has already been affected by any reported data breaches. If this is the case, we will see a list of all of the breaches in which our email address appears.

# linux
|**ID**|**Cryptographic Hash Algorithm**|
|---|---|
|`$1$`|[MD5](https://en.wikipedia.org/wiki/MD5)|
|`$2a$`|[Blowfish](https://en.wikipedia.org/wiki/Blowfish_\(cipher\))|
|`$5$`|[SHA-256](https://en.wikipedia.org/wiki/SHA-2)|
|`$6$`|[SHA-512](https://en.wikipedia.org/wiki/SHA-2)|
|`$sha1$`|[SHA1crypt](https://en.wikipedia.org/wiki/SHA-1)|
|`$y$`|[Yescrypt](https://github.com/openwall/yescrypt)|
|`$gy$`|[Gost-yescrypt](https://www.openwall.com/lists/yescrypt/2019/06/30/1)|
|`$7$`|[Scrypt](https://en.wikipedia.org/wiki/Scrypt)|
# Credential Storage



![[geuizoqp.bmp]]`lsass` It verifies users logging on to a Windows computer or server, handles password changes, and creates access tokens. It also writes to the Windows Security Log.

Credential providers are COM objects that are located in DLLs. ??

**Component Object Model (COM) objects** that reside in **Dynamic Link Library (DLL) files**. They are responsible for handling user authentication by capturing and processing credentials during logon, unlock, and other authentication scenarios.


Winlogon is the only process that intercepts login requests from the keyboard sent via an RPC message from Win32k.sys. Winlogon immediately launches the LogonUI application at logon to display the user interface for logon. After Winlogon obtains a user name and password from the credential providers, it calls LSASS to authenticate the user attempting to log in.

#### LSASS

[Local Security Authority Subsystem Service](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service) (`LSASS`) is a collection of many modules and has access to all authentication processes that can be found in `%SystemRoot%\System32\Lsass.exe`. This service is responsible for the local system security policy, user authentication, and sending security audit logs to the `Event log`. In other words, it is the vault for Windows-based operating systems, and we can find



| **Authentication Packages** | **Description**                                                                                                                                                                                                                                                |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Lsasrv.dll`                | The LSA Server service both enforces security policies and acts as the security package manager for the LSA. The LSA contains the Negotiate function, which selects either the NTLM or Kerberos protocol after determining which protocol is to be successful. |
| `Msv1_0.dll`                | Authentication package for local machine logons that don't require custom authentication.                                                                                                                                                                      |
| `Samsrv.dll`                | The Security Accounts Manager (SAM) stores local security accounts, enforces locally stored policies, and supports APIs.                                                                                                                                       |
| `Kerberos.dll`              | Security package loaded by the LSA for Kerberos-based authentication on a machine.                                                                                                                                                                             |
| `Netlogon.dll`              | Network-based logon service.                                                                                                                                                                                                                                   |
| `Ntdsa.dll`                 | This library is used to create new records and folders in the Windows registry.                                                                                                                                                                                |
#### SAM Database

[Security Account Manager](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc756748\(v=ws.10\)?redirectedfrom=MSDN) (`SAM`) is a database file in Windows operating systems that stores users' passwords. It can be used to authenticate local and remote users. SAM uses cryptographic measures to prevent unauthenticated users from accessing the system. User passwords are stored in a hash format in a registry structure as `HASH` either an:
1- `LM`
2- `NTLM`


If the system has been assigned to a workgroup, it handles the SAM database locally and stores all existing users locally in this database. However, if the system has been joined to a domain, the Domain Controller (`DC`) must validate the credentials from the Active Directory database (`ntds.dit`), which is stored in `%SystemRoot%\ntds.dit`.

Credential Manager is a feature built-in to all Windows operating systems that allows users to save the credentials they use to access various network resources and websites. Saved credentials are stored based on user profiles in each user's `Credential Locker`. Credentials are encrypted and stored at the following location:


```powershell-session
PS C:\Users\[Username]\AppData\Local\Microsoft\[Vault/Credentials]\
```

#### NTDS

NTDS.dit is a database file that stores the data in Active Directory, including but not limited to:

- User accounts (username & password hash)
- Group accounts
- Computer accounts
- Group policy objects

-----



login: mike   password: 7777777

Destiny2022!

987654321
jason:C4mNKjAtL2dydsYa6

dennis             | 7AUgWWQEiMPdqx

P@ssw0rd12020!



```
johanna 1231234!
```


10.129.86.230
evil-winrm -i 10.129.86.230 -u johanna -p 1231234!
evil-winrm -i 10.129.86.230 -u administrator -p Liverp00l8!