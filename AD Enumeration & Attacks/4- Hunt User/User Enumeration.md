# Detailed User Enumeration no creds
checklist:
```markdown

1-smb null session , cme , enum4linux , rpclient
2- ldap anonymous bind <> dc
3- Kerbrute with common list ? metadata ? jsmith
4- responder
```

## SMB NULL Session to Pull User List
twoways:
```markdown
1- valid domain user
2- system access to windows host part of domain
```

```bash
AhmaDb0x@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

```bash
AhmaDb0x@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
```

```bash
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.10.10.161 --users
```


## Gathering Users with LDAP Anonymous
```bash
┌──(pwn㉿kali)-[~/AD-TOOLS-LINUX/windapsearch]
└─$ ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb,DC=local" -s sub "(&(objectclass=*))" | grep sAMAccountName: | cut -f2 -d" "
```

```bash
AhmaDb0x@htb[/htb]$ ./windapsearch.py --dc-ip 10.10.10.161 -u "" -U
```


## Enumerating Users with Kerbrute
This method does not generate Windows event ID [4625: An account failed to log on],  or a logon failure which is often monitored for.

[jsmith.txt](https://github.com/insidetrust/statistically-likely-usernames/blob/master/jsmith.txt) wordlist of 48,705 possible common usernames in the format `flast`. The [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo is an excellent resource for this type of attack and contains a variety of different username lists that we can use to enumerate valid usernames using `Kerbrute`.

#### Kerbrute User Enumeration
```bash
AhmaDb0x@htb[/htb]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack. If we are successful with this method during a penetration test, this can be an excellent recommendation to add to our report.


----
If we are unable to create a valid username list using any of the methods highlighted above, we could turn back to external information gathering and search for company email addresses or use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to mash up possible usernames from a company's LinkedIn page

---

# Credentialed Enumeration

```bash
AhmaDb0x@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users
```

