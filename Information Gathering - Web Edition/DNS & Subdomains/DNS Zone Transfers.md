for uncovering subdomains – DNS zone transfers. This mechanism, designed for replicating DNS records between name servers, can inadvertently become a goldmine of information for prying eyes if misconfigured.

![[Pasted image 20241229225923.png]]

- `Zone Transfer Request (AXFR)`: The secondary DNS server initiates the process by sending a zone transfer request to the primary server. This request typically uses the AXFR (Full Zone Transfer) type.
- `SOA Record Transfer`: Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record. The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.



```shell
AhmaDb0x@htb[/htb]$ dig axfr @nsztm1.digi.ninja zonetransfer.me
```

```shell
dig axfr @<nameserver-ip> inlanefreight.htb
```

