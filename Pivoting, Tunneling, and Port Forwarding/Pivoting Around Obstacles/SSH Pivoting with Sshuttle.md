
```shell-session
AhmaDb0x@htb[/htb]$ sudo apt-get install sshuttle
```

```shell-session
AhmaDb0x@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```


```shell-session
AhmaDb0x@htb[/htb]$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

