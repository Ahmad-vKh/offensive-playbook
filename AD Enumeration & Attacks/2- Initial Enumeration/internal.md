https://academy.hackthebox.com/module/143/section/1265
please check the setting up
## Setting Up
1- ssh to kali vm inside internal vpn
2- ssh to physical deviice vpn 
3-direct physical access ethernet
4-ssh to cloud vm that has access to internal

---
- A custom pentest VM within their internal network that calls back to our jump host, and we can SSH into it to perform testing.
- They've also given us a Windows host that we can load tools onto if need be.
- They've asked us to start from an unauthenticated standpoint but have also given us a standard domain user account (`htb-student`) which can be used to access the Windows attack host.
- "Grey box" testing. They have given us the network range 172.16.5.0/23 and no other information about the network.
- Non-evasive testing.
---
-no creds

---

## TTP - CHECKLIST

### 1- Identifying Hosts
#### Start Wireshark on ea-attack01
```shell-session
┌─[htb-student@ea-attack01]─[~]
└──╼ $sudo -E wireshark
```
`172.16.5.5, 172.16.5.25 172.16.5.50, 172.16.5.100,  172.16.5.125.`
`ACADEMY-EA-WEB01 host`
#### Tcpdump + `pktmon.exe`
```shell-session
AhmaDb0x@htb[/htb]$ sudo tcpdump -i ens224 
```
#### Responder
```bash
sudo responder -I ens224 -A 

posions trafic llmnr + nbt-ns old resolver+ mdns

build HOST LIST + DNS LIST
```
#### FPing Active Checks
```shell-session
AhmaDb0x@htb[/htb]$ fping -asgq 172.16.5.0/23
`a` to show targets that are alive
`s` to print stats at the end of the scan
`g` to generate a target list from the CIDR network
`q` to not show per-target results.
```
#### Nmap Scanning
```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
`-oA` flag 
```

```shell-session
AhmaDb0x@htb[/htb]$ nmap -A 172.16.5.100
```
findings:
ARP packets make us aware of the hosts: 172.16.5.5, 172.16.5.25 172.16.5.50, 172.16.5.100, and 172.16.5.125.



## 2- Identifying Users
https://github.com/insidetrust/statistically-likely-usernames
`jsmith.txt` or `jsmith2.txt`

### Kerbrute -

#### Cloning Kerbrute GitHub Repo
```shell-session
AhmaDb0x@htb[/htb]$ sudo git clone https://github.com/ropnop/kerbrute.git
```
```shell-session
AhmaDb0x@htb[/htb]$ sudo make all
```
#### Adding the Tool to our Path
```shell-session
AhmaDb0x@htb[/htb]$ echo $PATH
/home/htb-student/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/snap/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/htb-student/.dotnet/tools
```
#### Moving the Binary
```shell-session
AhmaDb0x@htb[/htb]$ sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```
#### Enumerating Users with Kerbrute
```shell-session
AhmaDb0x@htb[/htb]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```


## 3- Identifying Potential Vulnerabilities
gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions:

- Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
- Perform Kerberoasting / ASREPRoasting attacks within the same domain.
- Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
- Perform token impersonation to hijack a privileged domain user account.
- Carry out ACL attacks.



`stealth` is of concern. Throwing Nmap at an entire network is not exactly quiet, and many of the tools we commonly use on a penetration test will trigger alarms for an educated and prepared SOC or Blue Teamer. Always be sure to clarify the goal of your assessment with the client in writing before it begins.

172.16.5.130  Microsoft SQL Server 2019 15.00.2000.00

```

172.16.5.5
172.16.5.130
172.16.5.225

```