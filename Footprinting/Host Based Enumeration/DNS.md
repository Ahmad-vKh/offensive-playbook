port 53

DNS is mainly unencrypted.

IT security professionals apply `DNS over TLS` (`DoT`) or `DNS over HTTPS` (`DoH`) here. In addition, the network protocol `DNSCrypt` also encrypts the traffic between the computer and the name server.


| `SOA` | Provides information about <br>1-`the corresponding DNS zone`. <br>2-`email address of the administrative contact.` |
| ----- | ------------------------------------------------------------------------------------------------------------------- |
The dot (.) is replaced by an at sign (@) in the email address. In this example, the email address of the administrator is `awsdns-hostmaster@amazon.com`.

| `NS` | Returns the DNS servers (nameservers) of the domain. |
| ---- | ---------------------------------------------------- |

local configuration files are usually:

- `named.conf.local`
- `named.conf.options`
- `named.conf.log`

`Asynchronous Full Transfer Zone` (`AXFR`)

```shell
zonda00@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128
```

#### Subdomain Brute Forcing
```shell
zonda00@htb[/htb]$ for sub in $(cat /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

```shell
zonda00@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/seclists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb
```

