DNS is mostly `UDP/53`, but DNS will rely on `TCP/53` more heavily as time progresses. DNS has always been designed to use both UDP and TCP port 53 from the start, with UDP being the default, and falls back to using TCP when it cannot communicate on UDP, typically when the packet size is too large to push through in a single UDP packet. Since nearly all network applications use DNS, attacks against DNS servers represent one of the most prevalent and significant threats today.

## Enumeration
```shell-session
AhmaDb0x@htb[/htb]# nmap -p53 -Pn -sV -sC 10.10.110.213
```

## DNS Zone Transfer

DNS servers utilize DNS zone transfers to copy a portion of their database to another DNS server. Unless a DNS server is configured correctly (limiting which IPs can perform a DNS zone transfer), anyone can ask a DNS server for a copy of its zone information since `DNS zone transfers do not require any authentication`

-when performing DNS zone transfer, it uses a TCP port for reliable data transmission.

`dig` utility with DNS query type `AXFR` option to dump the entire DNS namespaces from a vulnerable DNS server

#### DIG - AXFR Zone Transfer
```shell-session
AhmaDb0x@htb[/htb]# dig AXFR @ns1.inlanefreight.htb inlanefreight.htb

; <<>> DiG 9.11.5-P1-1-Debian <<>> axfr inlanefrieght.htb @10.129.110.213
```

-enumerate all DNS servers of the root domain and scan for a DNS zone transfer
```shell-session
AhmaDb0x@htb[/htb]# fierce --domain zonetransfer.me
```


## Domain Takeovers & Subdomain Enumeration

`Domain takeover` is registering a non-existent domain name to gain control over another domain.

find an expired domain, they can claim that domain to perform further attacks such as hosting malicious content on a website or sending a phishing email leveraging the claimed domain.

`subdomain takeover`
DNS's canonical name (`CNAME`) record is used to map different domains to a parent domain.


Many organizations use third-party services like AWS, GitHub, Akamai, Fastly, and other content delivery networks (CDNs) to host their content. In this case, they usually create a subdomain and make it point to those services. For example,

Attacking DNS

```shell-session
sub.target.com.   60   IN   CNAME   anotherdomain.com
```

The domain name (e.g., `sub.target.com`) uses a CNAME record to another domain (e.g., `anotherdomain.com`). Suppose the `anotherdomain.com` expires and is available for anyone to claim the domain since the `target.com`'s DNS server has the `CNAME` record. In that case, anyone who registers `anotherdomain.com` will have complete control over `sub.target.com` until the DNS record is updated.

#### Subdomain Enumeration

```shell-session
AhmaDb0x@htb[/htb]# ./subfinder -d inlanefreight.com -v       
```

---
An excellent alternative is a tool called [Subbrute](https://github.com/TheRook/subbrute). This tool allows us to use self-defined resolvers and perform pure DNS brute-forcing attacks during internal penetration tests on hosts that do not have Internet access.

```shell-session
AhmaDb0x@htb[/htb]$ git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
AhmaDb0x@htb[/htb]$ cd subbrute
AhmaDb0x@htb[/htb]$ echo "ns1.inlanefreight.com" > ./resolvers.txt
AhmaDb0x@htb[/htb]$ ./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt
```
🔥 **What Would `resolvers.txt` Contain?**

```
8.8.8.8       # Google Public DNS
1.1.1.1       # Cloudflare DNS
9.9.9.9       # Quad9 DNS
208.67.222.222 # OpenDNS
8.8.4.4       # Google Backup DNS
1.0.0.1       # Cloudflare Secondary
```

we have reached an internal host through pivoting and want to work from there.

```shell-session
AhmaDb0x@htb[/htb]# host support.inlanefreight.com

support.inlanefreight.com is an alias for inlanefreight.s3.amazonaws.com
```

The `support` subdomain has an alias record pointing to an AWS S3 bucket. However, the URL `https://support.inlanefreight.com` shows a `NoSuchBucket` error indicating that the subdomain is potentially vulnerable to a subdomain takeover. Now, we can take over the subdomain by creating an AWS S3 bucket with the same subdomain name.

🔥 **Quick Takeover Testing**
```bash
subjack -w subdomains.txt -t 10 -o takeover_results.txt -ssl

```

---
https://github.com/EdOverflow/can-i-take-over-xyz

---



## DNS Spoofing

An attacker could intercept the communication between a user and a DNS server to route the user to a fraudulent destination instead of a legitimate one by performing a Man-in-the-Middle (`MITM`) attack

Exploiting a vulnerability found in a DNS server could yield control over the server by an attacker to modify the DNS records.

#### Local DNS Cache Poisoning
From a local network perspective, an attacker can also perform DNS Cache Poisoning using MITM tools like [Ettercap](https://www.ettercap-project.org/) or [Bettercap](https://www.bettercap.org/).

To exploit the DNS cache poisoning via `Ettercap`, we should first edit the `/etc/ettercap/etter.dns` file to map the target domain name (e.g., `inlanefreight.com`) that they want to spoof and the attacker's IP address (e.g., `192.168.225.110`) that they want to redirect a user to:

```shell-session
AhmaDb0x@htb[/htb]# cat /etc/ettercap/etter.dns

inlanefreight.com      A   192.168.225.110
*.inlanefreight.com    A   192.168.225.110
```

python3 suubrute.py -d inlanefreight.htb -r 10.129.49.1 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
