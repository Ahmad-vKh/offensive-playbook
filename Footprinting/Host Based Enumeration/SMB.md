
when we ever encounter SMB port open never-rely on one tool try different tool
# introduction

port 139
Samba can function as an Active Directory (AD) domain controller, enabling Linux servers to manage authentication, user accounts, group policies, and directory services just like a Windows-based AD controller. It supports features such as Kerberos authentication, LDAP directory services, and integration with Windows clients.


```shell
zonda00@htb[/htb]$ cat /etc/samba/smb.conf | grep -v "#\|\;" 
```

#### Restart Samba
```shell
root@samba: sudo systemctl restart smbd
```
```shell-session
zonda00@htb[/htb]$ smbclient -N -L //10.129.14.128
```
N > NULL
L > LIST

```shell
zonda00@htb[/htb]$ smbclient //10.129.14.128/notes
```

```shell
smb: \> help
smb: \> get file.txt
smb: \> !'command' == execute it == !cat file.txt

```
From the administrative point of view, we can check these connections using `smbstatus`. Apart from the Samba version, we can also see who, from which host, and which share the client is connected. This is especially important once we have entered a subnet (perhaps even an isolated one) that the others can still access.

```shell-session
root@samba:~# smbstatus
```

## Footprinting SMB

we should resort to other tools that allow us to interact manually with the SMB and send specific requests for the information.

#### RPCclient

```shell
zonda00@htb[/htb]$ rpcclient -U "" 10.129.14.128

rpcclient $> `srvinfo`
rpcclient $> `enumdomains`
rpcclient $> `querydominfo`
rpcclient $> `netshareenumall` Enumerates all available shares.
rpcclient $> `netsharegetinfo <share>` Provides information about a specific share.
rpcclient $> `enumdomusers`
rpcclient $> `queryuser`
rpcclient $> `querygroup`
```

` rpcclient $> queryuser 0x3e8 `
```shell-session
user_rid :      0x3e8
group_rid:      0x201
```
```shell-session
rpcclient $> querygroup 0x201

        Group Name:     None
        Description:    Ordinary Users
        Group Attribute:7
        Num Members:2
```

sometimes not all command allowed to us in the session > 
we need list users but we cant  use `queryuser 0x-- ` so we must do brute force
`manualy` vs `impacket-python`

#### Brute Forcing User RIDs

```shell
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

        User Name   :   sambauser
        user_rid :      0x1f5
        group_rid:      0x201
		
        User Name   :   mrb3n
        user_rid :      0x3e8
        group_rid:      0x201
		
        User Name   :   cry0l1t3
        user_rid :      0x3e9
        group_rid:      0x201
```

#### `Impacket` - Samrdump.py

```shell
zonda00@htb[/htb]$ samrdump.py 10.129.14.128
```

#### `SMBmap`

```shell
zonda00@htb[/htb]$ smbmap -H 10.129.14.128
```

#### `CrackMapExec`

```shell
zonda00@htb[/htb]$ crackmapexec smb 10.129.14.128 --shares -u '' -p ''
```

#### Enum4Linux-ng - Enumeration

```shell
zonda00@htb[/htb]$ ./enum4linux-ng.py 10.129.14.128 -A
```

