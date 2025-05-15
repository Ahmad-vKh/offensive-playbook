check-list:
## 1-Windows Defender
check real time protection
```powershell-session
PS C:\htb> Get-MpComputerStatus

-----
`RealTimeProtectionEnabled` parameter is set to `True`
```

## 2- AppLocker
app white list powershell.exe blocked
```powershell-session
PS C:\htb> Get-MpComputerStatus

----PATH
`%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe`

```

## 3-PowerShell Constrained mode
blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes
like `juicypotato` problem


```powershell-session
PS C:\htb> $ExecutionContext.SessionState.LanguageMode

ConstrainedLanguage

---
we need <> Full Language Mode

```

## 4- LAPS
1- used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement
2- enumerate what domain users can read the LAPS password set
3- machines with LAPS installed and what machines do not have LAPS installed
4- [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) > parsing `ExtendedRights` for all computers with LAPS enabled. it show s groups that can read LAPS passwords, which are often users in protected groups.


#### Using Find-LAPSDelegatedGroups
```powershell-session
PS C:\htb> Find-LAPSDelegatedGroups

OrgUnit                                             Delegated Groups
-------                                             ----------------
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\Domain Admins
OU=Servers,DC=INLANEFREIGHT,DC=LOCAL                INLANEFREIGHT\LAPS Admins
```


#### Using Find-AdmPwdExtendedRights
1- checks the rights on each computer with LAPS enabled
2- any groups with read access and users with "All Extended Rights." ??
3- target == Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups

```powershell-session
PS C:\htb> Find-AdmPwdExtendedRights

ComputerName                Identity                    Reason
------------                --------                    ------
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\Domain Admins Delegated
EXCHG01.INLANEFREIGHT.LOCAL INLANEFREIGHT\LAPS Admins   Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\Domain Admins Delegated
SQL01.INLANEFREIGHT.LOCAL   INLANEFREIGHT\LAPS Admins   Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\Domain Admins Delegated
WS01.INLANEFREIGHT.LOCAL    INLANEFREIGHT\LAPS Admins   Delegated
```


#### Using Get-LAPSComputers
We can use the `Get-LAPSComputers` function to search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has acces
```powershell-session
PS C:\htb> Get-LAPSComputers

ComputerName                Password       Expiration
------------                --------       ----------
DC01.INLANEFREIGHT.LOCAL    6DZ[+A/[]19d$F 08/26/2020 23:29:45
EXCHG01.INLANEFREIGHT.LOCAL oj+2A+[hHMMtj, 09/26/2020 00:51:30
SQL01.INLANEFREIGHT.LOCAL   9G#f;p41dcAe,s 09/26/2020 00:30:09
WS01.INLANEFREIGHT.LOCAL    TCaG-F)3No;l8C 09/26/2020 00:46:04
```

