_Port_ `111` (TCP and UDP) and `2049` (TCP and UDP) for the _NFS_ server
`Network File System`
https://academy.hackthebox.com/module/112/section/1068


Authentication is handled by the RPC layer, typically using UNIX UID/GID, but NFS itself lacks built-in authentication and authorization mechanisms. This creates a risk of mismatched UID/GID mappings between clients and servers. Therefore, NFS with this method should only be used in trusted networks.

```shell-session
zonda00@htb[/htb]$ cat /etc/exports 
```

We can take a look at the `insecure` option. This is dangerous because users can use ports above 1024. The first 1024 ports can only be used by root. This prevents the fact that no users can use sockets above port 1024 for the NFS service and interact with it.



## Footprinting the Service

```shell
zonda00@htb[/htb]$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC
```

|`no_root_squash`|All files created by root are kept with the UID/GID 0.


```shell
zonda00@htb[/htb]$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049
```

#### Show Available NFS Shares
```shell
zonda00@htb[/htb]$ showmount -e 10.129.14.128
```

#### Mounting NFS Share
```shell
zonda00@htb[/htb]$ mkdir target-NFS
zonda00@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
zonda00@htb[/htb]$ cd target-NFS
zonda00@htb[/htb]$ tree .
```

It is important to note that if the `root_squash` option is set, we cannot edit the `backup.sh` file even as `root`.


#### Unmounting

NFS

```shell
zonda00@htb[/htb]$ cd ..
zonda00@htb[/htb]$ sudo umount ./target-NFS
```

We can also use NFS for further escalation. For example, if we have access to the system via SSH and want to read files from another folder that a specific user can read, we would need to upload a shell to the NFS share that has the `SUID` of that user and then run the shell via the SSH user.

mount