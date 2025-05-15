UDP port `161`

1- was created to `monitor` network devices.
2- handle `configuration` tasks and change settings remotely
3- SNMP-enabled hardware can also be `queried and controlled` using this standard protocol.
4- SNMP also transmits control commands using agents over UDP port `161`
5-SNMP also enables the use of so-called `traps` over UDP port `162`.
6- an SNMP trap is sent to the client once a specific event occurs on the server-side.

7- `Management Information Base` (`MIB`) is a text file in which all queryable SNMP objects of a device are listed in a standardized tree hierarchy

8-It contains at least one `Object Identifier` (`OID`), for each object in this text file
9-MIB files are written in the `Abstract Syntax Notation One` (`ASN.1`) based ASCII text format.
10- The MIBs do not contain data, it explain where to find which information and what it looks like

11- OID > A sequence of numbers uniquely identifies each node, allowing the node's position in the tree to be determined

### **versions**

#### `SNMPv1` 
`no built-in authentication` == `does not support encryption`

####  `SNMPv2` 
the `community string` that provides security is only transmitted in plain text, meaning it has no built-in encryption.

#### `SNMPv3`
`authentication` == transmission `encryption` (via `pre-shared key`)

### Community Strings
1- passwords that are used to determine whether the requested information can be viewed or not
2- many organizations are still using `SNMPv2`, as the transition to `SNMPv3` can be very complex


## Dangerous Settings

_OID_, it's an address used to uniquely identify managed devices and their statuses.

| **Settings**                                     | **Description**                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `rwuser noauth`                                  | Provides access to the full OID tree without authentication.                          |
| `rwcommunity <community string> <IPv4 address>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6.                  |


## `Footprinting` the Service

SNMP service that does not require authentication (versions 1, 2c),
`snmpwalk`, `onesixtyone`, and `braa` 

1- `Snmpwalk` is used to query the OIDs with their information.
2- `Onesixtyone` can be used to brute-force the names of the community strings since they can be named arbitrarily by the administrator

these community strings can be bound to any source, identifying the existing community strings can take quite some time.


```shell
AhmaDb0x@htb[/htb]$ snmpwalk -v2c -c public 10.129.14.128
```

```shell
AhmaDb0x@htb[/htb]$ onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```


Often, when certain community strings are bound to specific IP addresses, so ??
	`answer:  community strings == named with the hostname of the host`
	`   or:  community strings == sometimes even symbols are added to these names                                 to make them more challenging to identify`

extensive network with over 100 different servers managed using SNMP, the labels, in that case, will have some pattern to them. Therefore, we can use different rules to guess them. We can use the tool [crunch](https://secf00tprint.github.io/blog/passwords/crunch/advanced/en) to create custom wordlists. Creating custom wordlists is not an essential part of this module, but more details can be found in the module [Cracking Passwords With Hashcat](https://academy.hackthebox.com/course/preview/cracking-passwords-with-hashcat).


[braa](https://github.com/mteg/braa) to brute-force the individual OIDs
```shell
AhmaDb0x@htb[/htb]$ braa public@10.129.14.128:.1.3.6.*
```

