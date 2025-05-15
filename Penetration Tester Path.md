| **`Introduction`**                                                                 |
| ---------------------------------------------------------------------------------- |
| 1. [Penetration Testing Process](https://academy.hackthebox.com/module/details/90) |
| 2. [Getting Started](https://academy.hackthebox.com/module/details/77)             |

| **`Reconnaissance, Enumeration & Attack Planning`**                                         |
| ------------------------------------------------------------------------------------------- |
| 3. [Network Enumeration with Nmap](https://academy.hackthebox.com/module/details/19)        |
| 4. [Footprinting](https://academy.hackthebox.com/module/details/112)                        |
| 5. [Information Gathering - Web Edition](https://academy.hackthebox.com/module/details/144) |
| 6. [Vulnerability Assessment](https://academy.hackthebox.com/module/details/108)            |
| 7. [File Transfers](https://academy.hackthebox.com/module/details/24)                       |
| 8. [Shells & Payloads](https://academy.hackthebox.com/module/details/115)                   |
| 9. [Using the Metasploit Framework](https://academy.hackthebox.com/module/details/39)       |

|**`Exploitation & Lateral Movement`**|
|---|
|10. [Password Attacks](https://academy.hackthebox.com/module/details/147)|
|11. [Attacking Common Services](https://academy.hackthebox.com/module/details/116)|
|12. [Pivoting, Tunneling, and Port Forwarding](https://academy.hackthebox.com/module/details/158)|
|13. [Active Directory Enumeration & Attacks](https://academy.hackthebox.com/module/details/143)|

|**`Web Exploitation`**|
|---|
|14. [Using Web Proxies](https://academy.hackthebox.com/module/details/110)|
|15. [Attacking Web Applications with Ffuf](https://academy.hackthebox.com/module/details/54)|
|16. [Login Brute Forcing](https://academy.hackthebox.com/module/details/57)|
|17. [SQL Injection Fundamentals](https://academy.hackthebox.com/module/details/33)|
|18. [SQLMap Essentials](https://academy.hackthebox.com/module/details/58)|
|19. [Cross-Site Scripting (XSS)](https://academy.hackthebox.com/module/details/103)|
|20. [File Inclusion](https://academy.hackthebox.com/module/details/23)|
|21. [File Upload Attacks](https://academy.hackthebox.com/module/details/136)|
|22. [Command Injections](https://academy.hackthebox.com/module/details/109)|
|23. [Web Attacks](https://academy.hackthebox.com/module/details/134)|
|24. [Attacking Common Applications](https://academy.hackthebox.com/module/details/113)|

| **`Post-Exploitation`**                                                              |
| ------------------------------------------------------------------------------------ |
| 25. [Linux Privilege Escalation](https://academy.hackthebox.com/module/details/51)   |
| 26. [Windows Privilege Escalation](https://academy.hackthebox.com/module/details/67) |

|**`Reporting & Capstone`**|
|---|
|27. [Documentation & Reporting](https://academy.hackthebox.com/module/details/162)|
|28. [Attacking Enterprise Networks](https://academy.hackthebox.com/module/details/163)|
![[0-PT-Process.webp]]

|**Path**|**Description**|
|---|---|
|`Vulnerability Assessment`|The next stop on our journey is `Vulnerability Assessment`, where we use the information found to identify potential weaknesses. We can use vulnerability scanners that will scan the target systems for known vulnerabilities and manual analysis where we try to look behind the scenes to discover where the potential vulnerabilities might lie.|
step2

|                         |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Exploitation`          | The first we can jump into is the `Exploitation` stage. This happens when we do not yet have access to a system or application. Of course, this assumes that we have already identified at least one gap and prepared everything necessary to attempt to exploit it.                                                                                                                                                                                                                                                   |
| `Post-Exploitation`     | The second way leads to the `Post-Exploitation` stage, where we escalate privileges on the target system. This assumes that we are already on the target system and can interact with it.                                                                                                                                                                                                                                                                                                                              |
| `Lateral Movement`      | Our third option is the `Lateral Movement` stage, where we move from the already exploited system through the network and attack other systems. Again, this assumes that we are already on a target system and can interact with it. However, privilege escalation is not strictly necessary because interacting with the system already allows us to move further in the network under certain circumstances. Other times we will need to escalate privileges before moving laterally. Every assessment is different. |
| `Information Gathering` | The last option is returning to the `Information Gathering` stage when we do not have enough information on hand. Here we can dig deeper to find more information that will give us a more accurate view.                                                                                                                                                                                                                                                                                                              |

`Exploitation `<> We use the information from the `Information Gathering` stage, analyze it in the `Vulnerability Assessment` stage, and prepare the potential attacks

step3
![[Pasted image 20241123103459.png]]
