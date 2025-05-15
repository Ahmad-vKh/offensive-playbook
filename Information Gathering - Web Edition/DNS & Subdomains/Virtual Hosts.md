Web servers like Apache, Nginx, or IIS are designed to host multiple websites or applications on a single server. They achieve this through virtual hosting, which allows them to differentiate between domains, subdomains, or even separate websites with distinct content.


## How Virtual Hosts Work: Understanding V-Hosts and Subdomains



The key difference between `VHosts` and `subdomains` is their relationship to the `Domain Name System (DNS)` and the web server's configuration.

`Subdomains` typically have their own `DNS records`, pointing to either the same IP address as the main domain or a different one.

`Virtual Hosts` (`VHosts`): Virtual hosts are configurations within a web server that allow multiple websites or applications to be hosted on a single server. They can be associated with top-level domains (e.g., `example.com`) or subdomains (e.g., `dev.example.com`). Each virtual host can have its own separate configuration, enabling precise control over how requests are handled.

If a virtual host does not have a DNS record, you can still access it by modifying the `hosts` file on your local machine. The `hosts` file allows you to map a domain name to an IP address manually, bypassing DNS resolution.

Websites often have subdomains that are not public and won't appear in DNS records. These `subdomains` are only accessible internally or through specific configurations. `VHost fuzzing` is a technique to discover public and non-public `subdomains` and `VHosts` by testing various hostnames against a known IP address.


Virtual hosts can also be configured to use different domains, not just subdomains. For example:
```apacheconf
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

![[Pasted image 20241230004848.png]]

```shell-session
AhmaDb0x@htb[/htb]$ gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain
```


```shell-session
AhmaDb0x@htb[/htb]$ gobuster vhost -u http://inlanefreight.htb:81 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

- Consider using the `-t` flag to increase the number of threads for faster scanning.
- The `-k` flag can ignore SSL/TLS certificate errors.
- You can use the `-o` flag to save the output to a file for later analysis
-
```bash
ffuf -u http://inlanefreight.htb -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt

ffuf -u http://inlanefreight.htb -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -o results.txt

```

```shell
ffuf -u http://inlanefreight.htb -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -o results.txt
```

```bash
gobuster vhost -u http://10.129.118.153 -w namelist.txt -p pattern --exclude-length 301 -t 10
```

wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.inlanefreight.htb" http://inlanefreight.htb:48214 | grep -oP '"\K[^"]+' > output.txt
status 200 , http
--- 
```shell

ffuf -u http://94.237.59.63:40817 -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 10198 -mc 200

ffuf -u http://94.237.59.63:40817 -H "Host: FUZZ.inlanefreight.htb" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -fs 116 -mc 200

```



### **What Happens Internally**

1. You access `http://app.inlanefreight.local`.
    
    - The system resolves `app.inlanefreight.local` to the IP (e.g., `192.168.1.10`) using `/etc/hosts`.
    - The HTTP request includes `Host: app.inlanefreight.local`.
2. You access `http://dev.inlanefreight.local`.
    
    - The system resolves `dev.inlanefreight.local` to the same IP (`192.168.1.10`).
    - The HTTP request includes `Host: dev.inlanefreight.local`.

The web server compares the `Host` header value to its virtual host configurations and responds accordingly.


