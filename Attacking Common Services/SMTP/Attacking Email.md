![text](https://academy.hackthebox.com/storage/modules/116/SMTP-IMAP-1.png)

## Enumeration
We can use the `Mail eXchanger` (`MX`) DNS record to identify a mail server.
```shell-session
AhmaDb0x@htb[/htb]$ host -t MX hackthebox.eu
```

```shell-session
AhmaDb0x@htb[/htb]$ dig mx inlanefreight.com | grep "MX" | grep -v ";"
```

#### Host - A Records
```shell-session
AhmaDb0x@htb[/htb]$ host -t A mail1.inlanefreight.htb.
```

If we are targetting a custom mail server implementation such as `inlanefreight.htb`, we can enumerate the following ports:

|**Port**|**Service**|
|---|---|
|`TCP/25`|SMTP Unencrypted|
|`TCP/143`|IMAP4 Unencrypted|
|`TCP/110`|POP3 Unencrypted|
|`TCP/465`|SMTP Encrypted|
|`TCP/587`|SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS)|
|`TCP/993`|IMAP4 Encrypted|
|`TCP/995`|POP3 Encrypted|

We can use `Nmap`'s default script `-sC` option to enumerate those ports on the target system:

Attacking Email Services

```shell-session
AhmaDb0x@htb[/htb]$ sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128
```

## Misconfigurations
anonymous authentication
support protocols that can be used to enumerate valid usernames.

#### Authentication

The SMTP server has different commands that can be used to enumerate valid usernames `VRFY`, `EXPN`, and `RCPT TO`. If we successfully enumerate valid usernames, we can attempt to password spray, brute-forcing, or guess a valid password. So let's explore how those commands work.

```shell-session
AhmaDb0x@htb[/htb]$ telnet 10.10.110.20 25

Trying 10.10.110.20...
Connected to 10.10.110.20.
Escape character is '^]'.
220 parrot ESMTP Postfix (Debian/GNU)


VRFY root

252 2.0.0 root
```
```shell-session
EXPN john

250 2.1.0 john@inlanefreight.htb


EXPN support-team

250 2.0.0 carol@inlanefreight.htb
250 2.1.5 elisa@inlanefreight.htb
```


command `USER` followed by the username, and if the server responds `OK`. This means that the user exists on the server.


```shell-session
AhmaDb0x@htb[/htb]$ smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```

#### O365 Spray
-validate
```shell-session
msplaintext
```

```shell-session
AhmaDb0x@htb[/htb]$ python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz        
```

#### Hydra - Password Attack
```shell-session
AhmaDb0x@htb[/htb]$ hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3
```

s [o365spray](https://github.com/0xZDH/o365spray) or [MailSniper](https://github.com/dafthack/MailSniper) for Microsoft Office 365 or [CredKing](https://github.com/ustayready/CredKing) for Gmail or Okta.




#### O365 Spray - Password Spraying
```shell-session
AhmaDb0x@htb[/htb]$ python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz
```


## Protocol Specifics Attacks

An open relay is a Simple Mail Transfer Protocol (`SMTP`) server, which is improperly configured and allows an unauthenticated email relay. Messaging servers that are accidentally or intentionally configured as open relays allow mail from any source to be transparently re-routed through the open relay server. This behavior masks the source of the messages and makes it look like the mail originated from the open relay server.

```shell-session
AhmaDb0x@htb[/htb]# nmap -p25 -Pn --script smtp-open-relay 10.10.11.213
```

```shell-session
AhmaDb0x@htb[/htb]# swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: Company Notification' --body 'Hi All, we want to hear from you! Please complete the following survey. http://mycustomphishinglink.com/' --server 10.10.11.213
```



marlin@inlanefreight.htb   password: poohbear