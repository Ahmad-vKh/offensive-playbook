#### In Scope For Assessment

| **Range/Domain**                | **Description**                                                                           |
| ------------------------------- | ----------------------------------------------------------------------------------------- |
| `INLANEFREIGHT.LOCAL`           | Customer domain to include AD and web services.                                           |
| `LOGISTICS.INLANEFREIGHT.LOCAL` | Customer subdomain                                                                        |
| `FREIGHTLOGISTICS.LOCAL`        | Subsidiary company owned by Inlanefreight. External forest trust with INLANEFREIGHT.LOCAL |
| `172.16.5.0/23`                 | In-scope internal subnet.                                                                 |
|                                 |                                                                                           |

### External Information Gathering

target: https://www.inlanefreight.com
No active enumeration, port scans, or attacks will be performed against internet-facing "real-world" IP addresses or the website located at `https://www.inlanefreight.com`

### Internal Testing

Testing will start from an anonymous position on the internal network with the goal of obtaining domain user credentials, enumerating the internal domain, gaining a foothold, and moving laterally and vertically to achieve compromise of all in-scope internal domains. Computer systems and network operations will not be intentionally interrupted during the test.


### Password Testing
Password files captured from Inlanefreight devices, or provided by the organization, may be loaded onto offline workstations for decryption and utilized to gain further access and accomplish the assessment goals. At no time will a captured password file or the decrypted passwords be revealed to persons not officially participating in the assessment. All data will be stored securely on Cat-5 owned and approved systems and retained for a period of time defined in the official contract between Cat-5 and Inlanefreight

