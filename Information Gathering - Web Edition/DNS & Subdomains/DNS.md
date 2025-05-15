
![[Pasted image 20241229185832.png]]

## How DNS Works

1- you type in the URL `www.example.com` , while the computer doesn't understand anything except numbers (#IP)

2- `(DNS Query)`: your computer first checks its memory (cache) to see if it remembers the IP address from a previous visit. If not, it reaches out to a DNS resolver, usually provided by your internet service provider (ISP).

3- `(DNS Resolver)` <> Map (Recursive Lookup) ,**recursive lookup**, the DNS resolver takes full responsibility for finding the final answer.
it starts a journey through the DNS hierarchy. It begins by asking a root name server, which is like the librarian of the internet.

4- `Root Name Server Points the Way`: The root server doesn't know the exact address but knows who does – the Top-Level Domain (TLD) name server responsible for the domain's ending (e.g., .com, .org). It points the resolver in the right direction.

5- `TLD Name Server Narrows It Down`: The TLD name server is like a regional map. It knows which authoritative name server is responsible for the specific domain you're looking for (e.g., `example.com`) and sends the resolver there.

6- `Authoritative Name Server Delivers the Address`: The authoritative name server is the final stop. It's like the street address of the website you want. It holds the correct IP address and sends it back to the resolver.

7- `The DNS Resolver Returns the Information`: The resolver receives the IP address and gives it to your computer. It also remembers it for a while (caches it), in case you want to revisit the website soon.


### The Hosts File

bypasses the DNS process.

---

The `hosts` file is located in `C:\Windows\System32\drivers\etc\hosts` on Windows and in `/etc/hosts` on Linux and MacOS.

---

Code: txt
```txt
127.0.0.1       localhost
192.168.1.10    devserver.local
```

blocking unwanted websites by redirecting their domains to a non-existent IP address:
Code: txt
```txt
0.0.0.0       unwanted-site.com
```

---

##### `example.com. IN NS ns1.example.com.`

**ns1.example.com.**: The authoritative name server for `example.com`.
When someone queries `example.com`, the DNS system will contact `ns1.example.com` to get further DNS records (like IP addresses) for that domain.

```shell
dig NS example.com
```

---
![[Pasted image 20241229191758.png]]

## Why DNS Matters for Web Recon

a `CNAME` record pointing to an outdated server:
(`dev.example.com` CNAME `oldserver.example.net`) could lead to a vulnerable system.

a `TXT` record containing a value like `_1password=...` strongly suggests the organization is using 1Password, which could be leveraged for social engineering attacks or targeted phishing campaigns.