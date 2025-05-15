![](https://academy.hackthebox.com/storage/modules/158/88.png)

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.42.198 connectport=3389 connectaddress=172.16.5.19
```

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```

```bash
xfreerdp /v:10.129.42.198:8080 /u:victor /p:pass@123
xfreerdp /v:10.129.42.198 /u:htb-student /p:HTB_@cademy_stdnt! 
```
