
1- fast and efficient tool for locally and remotely copying files.
2- delta-transfer algorithm. This algorithm reduces the amount of data transmitted over the network
3- when a version of the file already exists on the destination host.
4- It does this by sending only the differences between the source files and the older version of the files that reside on the destination server.
5- used for backups and mirroring.
6- it uses port `873` and can be configured to use SSH for secure file transfers by piggybacking on top of an established SSH server connection.



# abusing RSYNC

`can be abused, most notably by listing the contents of a shared folder on a target server and retrieving files. This can sometimes be done without authentication. Other times we will need credentials. If you find credentials during a pentest and run into Rsync on an internal (or external) host, it is always worth checking for password re-use as you may be able to pull down some sensitive files that could be used to gain remote access to the target.`

```shell
AhmaDb0x@htb[/htb]$ sudo nmap -sV -p 873 127.0.0.1
```

#### Probing for Accessible Shares

```shell
AhmaDb0x@htb[/htb]$ nc -nv 127.0.0.1 873

dev            	Dev Tools

```

```shell
AhmaDb0x@htb[/htb]$ rsync -av --list-only rsync://127.0.0.1/dev
```

If Rsync is configured to use SSH to transfer files, we could modify our commands to include the `-e ssh` flag, or `-e "ssh -p2222"` if a non-standard port is in use for SSH. This [guide](https://phoenixnap.com/kb/how-to-rsync-over-ssh) is helpful for understanding the syntax for using Rsync over SSH.


