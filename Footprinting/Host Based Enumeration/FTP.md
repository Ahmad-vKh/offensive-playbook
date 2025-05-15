The FTP runs within the application layer of the TCP/IP protocol stack

Thus, it is on the same layer as `HTTP` or `POP`. These protocols also work with the support of `browsers` or `email` clients to perform their services. There are also special FTP programs for the File Transfer Protocol.


### **`active` and `passive` FTP. **
A distinction is made between `active` and `passive` FTP. In the active variant, the client establishes the connection as described via TCP port 21 and thus informs the server via which client-side port the server can transmit its responses. However, if a firewall protects the client, the server cannot reply because all external connections are blocked. For this purpose, the `passive mode` has been developed. Here, the server announces a port through which the client can establish the data channel. Since the client initiates the connection in this method, the firewall does not block the transfer.




FTP knows different [commands](https://web.archive.org/web/20230326204635/https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/) and status codes.

FTP is a `clear-text` protocol that can sometimes be sniffed if conditions on the network are right. However, there is also the possibility that a server offers `anonymous FTP`. 


```shell-session
zonda00@htb[/htb]$ sudo apt install vsftpd 
```
#### **`vsFTPd` Config File**

```shell-session
zonda00@htb[/htb]$ cat /etc/vsftpd.conf | grep -v "#"
```
Privileged access management (PAM)

| `rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem`          | The last three options specify the location of the RSA certificate to use for SSL encrypted connections. |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key` |                                                                                                          |
| `ssl_enable=NO`                                               |                                                                                                          |

In addition, there is a file called `/etc/ftpusers` that we also need to pay attention to, as this file is used to deny certain users access to the FTP service. In the following example, the users `guest`, `john`, and `kevin` are not permitted to log in to the FTP service, even if they exist on the Linux system.

```shell-session
zonda00@htb[/htb]$ cat /etc/ftpusers

guest
john
kevin
```
### post ftp connection
he `response code 220` is displayed with the banner of the FTP server. Often this banner contains the description of the `service` and even the `version` of it

```shell-session
ftp> status
ftp> debug
ftp> trace
```

| `hide_ids=YES` | All user and group information in directory listings will be displayed as "ftp". |
| -------------- | -------------------------------------------------------------------------------- |
if the `hide_ids=YES` setting is present, the UID and GUID representation of the service will be overwritten, making it more difficult for us to identify with which rights these files are written and uploaded.


```shell-session
Important Notes.txt
ftp> get Important\ Notes.txt
```

```shell-session
zonda00@htb[/htb]$ sudo nmap -sV -p21 -sC -A 10.129.14.136
```
```shell-session
zonda00@htb[/htb]$ find / -type f -name ftp* 2>/dev/null | grep scripts
```

```shell-session
zonda00@htb[/htb]$ nc -nv 10.129.14.136 21
```
```shell-session
zonda00@htb[/htb]$ telnet 10.129.14.136 21
```

It looks slightly different if the FTP server runs with TLS/SSL encryption. Because then we need a client that can handle TLS/SSL. For this, we can use the client `openssl` and communicate with the FTP server. The good thing about using `openssl` is that we can see the SSL certificate, which can also be helpful.


```shell-session
zonda00@htb[/htb]$ openssl s_client -connect 10.129.14.136:21 -starttls ftp
```



