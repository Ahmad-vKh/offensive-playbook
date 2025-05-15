port 25
https://academy.hackthebox.com/module/112/section/1072

By default, SMTP servers accept connection requests on port `25`. However, newer SMTP servers also use other ports such as TCP port `587`. This port is used to receive mail from authenticated users/servers, usually using the STARTTLS command to switch the existing plaintext connection to an encrypted connection. The authentication data is protected and no longer visible in plaintext over the network. At the beginning of the connection, authentication occurs when the client confirms its identity with a user name and password. The emails can then be transmitted. For this purpose, the client sends the server sender and recipient addresses, the email's content, and other information and parameters. After the email has been transmitted, the connection is terminated again. The email server then starts sending the email to another SMTP server.

SMTP works unencrypted without further measures and transmits all commands, data, or authentication information in plain text. To prevent unauthorized reading of data, the SMTP is used in conjunction with SSL/TLS encryption. Under certain circumstances, a server uses a port other than the standard TCP port `25` for the encrypted connection, for example, TCP port `465`.

An essential function of an SMTP server is preventing spam using authentication mechanisms that allow only authorized users to send e-mails. For this purpose, most modern SMTP servers support the protocol extension ESMTP with SMTP-Auth


`SMTP servers prevent spam by requiring user authentication, often using ESMTP with SMTP-Auth. Emails are sent from the client (Mail User Agent, MUA), converted into headers and body, and uploaded to the SMTP server, which uses a Mail Transfer Agent (MTA) to handle sending and receiving.`

#### Key Steps:

1. `**Mail Submission Agent (MSA)**`: Verifies email origin before passing it to the MTA. Misconfigured MSAs can lead to Open Relay Attacks.
2. `**Mail Transfer Agent (MTA)**:` Checks email size, spam, and looks up recipient server IP via DNS.
3. `**Mail Delivery Agent (MDA)**:` Delivers the email to the recipient's mailbox for access via POP3/IMAP.

The process ensures email integrity and delivery while protecting against spam and misuse.`


A list of all SMTP response codes can be found [here](https://serversmtp.com/smtp-error/).
```shell
┌──(kali㉿kali)-[~]
└─$ smtp-user-enum -t 10.129.44.240 -p 25 -w 10 -u robin -v -m 8 -d

┌──(kali㉿kali)-[~]
└─$ smtp-user-enum -t 10.129.44.240 -p 25 -w 5 -U /home/kali/footprinting-wordlist.txt -v
```

