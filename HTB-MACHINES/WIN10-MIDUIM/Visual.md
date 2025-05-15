## **Step 1: Initial Access via Git Repository Abuse**

The target machine runs a web service that accepts **.NET 6.0** project repositories, builds them, and returns the compiled executables. The key vulnerability here is that the build process executes a **PreBuild** event specified in the repository’s configuration.

### **Exploitation**

- Create a local Git repository containing a `.NET 6.0` project.
- Modify the project file (`.csproj`) to include a **PreBuild** event that executes a malicious payload.
- Push this project to the target machine via the web service.
- The server builds the project, triggering the **PreBuild** event and executing the payload.
- This results in a **reverse shell** as the **"enox"** user.

---

## **Step 2: File Write to Web Root for Privilege Escalation**

After obtaining access as **enox**, the next goal is to escalate privileges.

### **Exploitation**

- The user **enox** has write permissions to the **web root directory**.
- An attacker can drop a **malicious ASPX web shell** (e.g., **`revshell.aspx`**) into the web root directory.
- Accessing this file via the browser allows executing commands with the privileges of the web server.

### **Outcome**
- The web server runs under the **NT AUTHORITY\LOCAL SERVICE** account.
- The attacker gets a **reverse shell** as the **LOCAL SERVICE** user.
---
## **Step 3: Restoring Local Service Privileges**
At this stage, the **LOCAL SERVICE** account does **not** have its usual privileges. However, there is a way to restore them.
### **Exploitation**
- The **NT AUTHORITY\LOCAL SERVICE** account typically has **SeImpersonatePrivilege**, but it has been stripped.
- There exists a way to **recover** these missing privileges and **restore SeImpersonate**.
- This can be done using privilege recovery techniques (e.g., `Chimichurri` method or modifying tokens).
### **Outcome**
- Once **SeImpersonatePrivilege** is restored, the attacker can impersonate higher-privileged tokens.
---
## **Step 4: SYSTEM Privilege Escalation via Potato Exploit**
Since **SeImpersonatePrivilege** is now available, an **NTLM relay attack** can be used.
### **Exploitation**
- Use a **Potato attack** (e.g., **JuicyPotato, RoguePotato, PrintSpoofer**) to **escalate from LOCAL SERVICE to SYSTEM**.
- These exploits force **a privileged Windows process** to authenticate to the attacker, who relays the authentication and impersonates SYSTEM.

### **Outcome**
- The attacker gains a **SYSTEM shell** (`nt authority\system`).
- Full control over the machine is achieved.

---
## **Summary of Exploitation Flow**
1. **Abuse Git repository build process** → **Initial shell as `enox`**.
2. **Write to web root directory** → **Get a shell as `LOCAL SERVICE`**.
3. **Restore `SeImpersonatePrivilege`** → **Regain missing privileges**.
4. **Exploit Potato attack** → **Privilege escalation to SYSTEM**.

---
