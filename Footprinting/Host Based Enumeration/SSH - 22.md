`SSH` is a cryptographic network protocol that provides a secure channel for remote login, command execution, and file transfers over an unsecured network.

The SSH server can also be configured to only allow connections from specific clients. An advantage of SSH is that the protocol runs on all common operating systems.

two competing protocols: `SSH-1` and `SSH-2`.
`SSH-2`, also known as SSH version 2, is a more advanced protocol than SSH version 1 in encryption, speed, stability, and security. For example, `SSH-1` is vulnerable to `MITM` attacks, whereas SSH-2 is not.

OpenSSH has six different authentication methods:

1. Password authentication
2. Public-key authentication
3. Host-based authentication
4. Keyboard authentication
5. Challenge-response authentication
6. GSSAPI authentication


#### Public Key Authentication


The private key is created individually for the user's own computer and secured with a passphrase that should be longer than a typical password.

If we want to establish an SSH connection, we first enter the passphrase and thus open access to the private key.

Public keys are also stored on the server. The server creates a cryptographic problem with the client's public key and sends it to the client. The client, in turn, decrypts the problem with its own private key, sends back the solution, and thus informs the server that it may establish a legitimate connection. During a session, users only need to enter the passphrase once to connect to any number of servers. At the end of the session, users log out of their local machines, ensuring that no third party who gains physical access to the local machine can connect to the server.



## Dangerous Settings

```shell
cat /etc/ssh/sshd_config  | grep -v "#" | sed -r '/^\s*$/d'
```

| **Setting**                  | **Description**                             |
| ---------------------------- | ------------------------------------------- |
| `PasswordAuthentication yes` | Allows password-based authentication.       |
| `PermitEmptyPasswords yes`   | Allows the use of empty passwords.          |
| `PermitRootLogin yes`        | Allows to log in as the root user.          |
| `Protocol 1`                 | Uses an outdated version of encryption.     |
| `X11Forwarding yes`          | Allows X11 forwarding for GUI applications. |
| `AllowTcpForwarding yes`     | Allows forwarding of TCP ports.             |
| `PermitTunnel`               | Allows tunneling.                           |
| `DebianBanner yes`           | Displays a specific banner when logging in. |


```shell
AhmaDb0x@htb[/htb] git clone https://github.com/jtesta/ssh-audit.git && cd ssh-audit

AhmaDb0x@htb[/htb] ./ssh-audit.py 10.129.14.132
```


#### Change Authentication Method

```shell
AhmaDb0x@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132

OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config 
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
```

```shell
AhmaDb0x@htb[/htb]$ ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password

OpenSSH_8.2p1 Ubuntu-4ubuntu0.3, OpenSSL 1.1.1f  31 Mar 2020
debug1: Reading configuration data /etc/ssh/ssh_config
...SNIP...
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: password

cry0l1t3@10.129.14.132's password:
```

banner is important <> `SSH-1.99-OpenSSH_3.9p1`
				    `SSH-2.0-OpenSSH_8.2p1`

