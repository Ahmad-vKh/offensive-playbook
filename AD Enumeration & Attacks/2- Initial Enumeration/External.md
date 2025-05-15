https://academy.hackthebox.com/module/143/section/1264
why external:

- Validating information provided to you in the scoping document from the client
- Ensuring you are taking actions against the appropriate scope when working remotely
- Looking for any information that is publicly accessible that can affect the outcome of your test, such as leaked credentials

---
## Where Are We Looking?

|**Resource**|**Examples**|
|---|---|
|`ASN / IP registrars`|[IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/)|
|`Domain Registrars & DNS`|[Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/lookup), manual DNS record requests against the domain in question or against well known DNS servers, such as `8.8.8.8`.|
|`Social Media`|Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.|
|`Public-Facing Company Websites`|Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.|
|`Cloud & Dev Storage Spaces`|[GitHub](https://github.com/), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https://www.exploit-db.com/google-hacking-database)|
|`Breach Data Sources`|[HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication.|
#### `BGP-Toolkit` 
 [BGP Toolkit](https://bgp.he.net/)
 
#### `DNS`
[domaintools](https://whois.domaintools.com/), and [viewdns.info](https://viewdns.info/)

#### `public data`

Tools like [Trufflehog](https://github.com/trufflesecurity/truffleHog) and sites like [Greyhat Warfare](https://buckets.grayhatwarfare.com/) are fantastic resources for finding these breadcrumbs.

## check-list
1- [BGP Toolkit](https://bgp.he.net/)
2- [viewdns.info](https://viewdns.info/)
3- validate > nslookup
4- examining the website `inlanefreight.com`
5- check PDF == `filetype:pdf inurl:inlanefreight.com`
6- Hunting E-mail == `intext:"@inlanefreight.com" inurl:inlanefreight.com`
7- user list <> contacts 
8- [linkedin2username](https://github.com/initstring/linkedin2username)
9- check already breach data == [Dehashed](http://dehashed.com/)
```shell-session
AhmaDb0x@htb[/htb]$ sudo python3 dehashed.py -q inlanefreight.local -p
```
