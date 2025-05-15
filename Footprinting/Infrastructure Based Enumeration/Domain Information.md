https://academy.hackthebox.com/module/112/section/1061

step-1 : scrutinize the company's `main website`.we should read through the texts, keeping in mind what technologies and structures are needed for these services.
Therefore, we take the developer's view and look at the whole thing from their point of view. This point of view allows us to gain many technical insights into the functionality.


## Online Presence

`SSL certificate` > secure sockets layer (SSL) certificate refers to **a file hosted within the webpage's origin server, which holds the data that browsers access when you are viewing and interacting with the page**.

`https://crt.sh/ `>find more subdomains  ,provides information about **Certificate Transparency logs**. 
- **crt.sh** collects and organizes the data from these **public logs**.
- It allows you to search for certificates issued for a domain name.
- If a certificate is issued for a **subdomain**, like `secure.example.com`, crt.sh can find it because this information is included in the certificate logs.

**What is Certificate Transparency?**
- When a website uses HTTPS (secure connection), it needs an **SSL/TLS certificate**.
- These certificates are issued by organizations called **Certificate Authorities (CAs)**.
- **Certificate Transparency (CT)** is a system where every SSL/TLS certificate issued is recorded in **public logs**. This helps ensure that no certificates are issued falsely or maliciously.

so every subdomain has its own certificate
These certificates are logged in Certificate Transparency logs.
Tools like crt.sh allow you to search these logs and find `sub.example.com` listed as a subdomain.

#### Certificate Transparency

```shell-session
zonda00@htb[/htb]$ curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .
```

Next, we can identify the hosts directly accessible from the Internet and not hosted by third-party providers. This is because we are not allowed to test the hosts without the permission of third-party providers.


```shell-session
zonda00@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done
```
**Output**: Subdomain names and their resolved IP addresses linked to `inlanefreight.com`.
```shell-session
blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```



Shodan scans the internet to find devices and systems that are **always connected** to the web.
It looks for **open ports** (communication channels) on devices using protocols like:
- **HTTP/HTTPS**: Websites or web servers.
- **FTP**: File servers.
- **SSH**: Remote login services.
- **SNMP, Telnet, RTSP, SIP**: Other common protocols.

```shell
zonda00@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done

zonda00@htb[/htb]$ for i in $(cat ip-addresses.txt);do shodan host $i;done
```

API interfaces that we can then test for various vulnerabilities such as IDOR, SSRF, POST, PUT requests,

Companies often use Office 365 with OneDrive and cloud resources such as Azure blob and file storage. 
`Azure file storage can be very interesting because it works with the SMB protocol.`



