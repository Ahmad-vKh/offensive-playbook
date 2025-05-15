
https://academy.hackthebox.com/module/112/section/1240

ports `512`, `513`, and `514`
enable remote access or issue commands between Unix hosts over TCP/IP

##### R-COMMANDS
- rcp (`remote copy`)
- rexec (`remote execution`)
- rlogin (`remote login`)
- rsh (`remote shell`)
- rstat
- ruptime
- rwho (`remote who`)

|**Command**|**Service Daemon**|**Port**|**Transport Protocol**|**Description**|
|---|---|---|---|---|
|`rcp`|`rshd`|514|TCP|Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the `cp` command on Linux but provides `no warning to the user for overwriting existing files on a system`.|
|`rsh`|`rshd`|514|TCP|Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files for validation.|
|`rexec`|`rexecd`|512|TCP|Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
|`rlogin`|`rlogind`|513|TCP|Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|

#### /etc/hosts.equiv

```shell
AhmaDb0x@htb[/htb]$ cat /etc/hosts.equiv
```

#### `.rhosts`

```shell
AhmaDb0x@htb[/htb]$ sudo nmap -sV -p 512,513,514 10.0.17.2
```

The `hosts.equiv` and `.rhosts` files contain a list of hosts (`IPs` or `Hostnames`) and users that are `trusted` by the local host when a connection attempt is made using `r-commands`. Entries in either file can appear like the following:

--- 

**Note:** The `hosts.equiv` file is recognized as the global configuration regarding all users on a system, whereas `.rhosts` provides a per-user configuration

---

check `.rhost` in the module
The `+` symbol is a wildcard that lets **any** host log in without a password, which is an insecure configuration. This could be exploited by an attacker within the network.



However, the `rwho` daemon periodically broadcasts information about logged-on users, so it might be beneficial to watch the network traffic.

