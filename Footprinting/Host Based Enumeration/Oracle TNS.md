
https://academy.hackthebox.com/module/112/section/2117
`tcp _port_ 1521, by default`

1- `Transparent Network Substrate` (`TNS`) server

2-  communication protocol that facilitates communication between Oracle databases and applications over networks.

3- a preferred solution for managing large, complex databases in the healthcare, finance, and retail industries.

4- its built-in encryption mechanism ensures the security of data transmitted, making it an ideal solution for enterprise environments where data security is paramount.

5- Name resolution 	Connection management 	Load balancing 	Security <> features

6- encryption between client and server communication through an additional layer of security over the TCP/IP protocol layer.

7- `Oracle TNS can be remotely managed in `Oracle 8i`/`9i` but not in Oracle 10g/11g.`

##### 8- The configuration files for Oracle TNS are called `tnsnames.ora` and `listener.ora` and are typically located in the `$ORACLE_HOME/network/admin` directory.

9- TNS <> DBSNMP, Oracle Databases, Oracle Application Server, Oracle Enterprise Manager, Oracle Fusion Middleware, web servers, and many more.

10- `Oracle 9 has a default password, `CHANGE_ON_INSTALL

11- Oracle 10 has no default password set.

##### 12- Oracle DBSNMP service also uses a default password, `dbsnmp` that we should remember when we come across this one

13- many organizations still use the `finger` service together with Oracle, which can put Oracle's service at risk and make it vulnerable when we have the required knowledge of a home directory.
 14- (`SID`) is a unique name that identifies a particular database instance.
### `config`

1- Each database or service has a unique entry in the **`tnsnames.ora`** file,
containing the `necessary information` for clients to connect to the service. The entry consists of a `name` for the service, the `network location` of the service, and the `database or service name` that `clients should use when connecting to the service.`

include additional information, such as `authentication details`, `connection pooling settings`, and `load balancing configurations.`

https://academy.hackthebox.com/module/112/section/2117
```shell
${listener.ora} file is a server-side configuration file that defines the listener process's properties and parameters, which is responsible for receiving incoming client requests and forwarding them to the appropriate Oracle database instance.
```

```shell
${`tnsnames.ora`} client-side Oracle Net Services software uses the `tnsnames.ora` file to resolve service names to network addresses,
```

```shell
${``listener.ora``} listener process uses the `listener.ora` file to determine the services it should listen to and the behavior of the listener.
```

```shell
AhmaDb0x@htb[/htb]$ ./odat.py -h
alwaye check the version of the database
```

Oracle Database Attacking Tool (`ODAT`) is an open-source penetration testing tool written in Python and designed to enumerate and exploit vulnerabilities in Oracle databases. It can be used to identify and exploit various security flaws in Oracle databases, including SQL injection, remote code execution, and privilege escalation.


`no sid specify tnsnames.ra default value is used`

The SIDs are an essential part of the connection process, as it identifies the specific instance of the database the client wants to connect to. If the client specifies an incorrect SID, the connection attempt will fail. Database administrators can use the SID to monitor and manage the individual instances of a database. For example, they can start, stop, or restart an instance, adjust its memory allocation or other configuration parameters, and monitor its performance using tools like Oracle Enterprise Manager.


```shell
AhmaDb0x@htb[/htb]$ ./odat.py all -s 10.129.204.235
```


`sqlplus` used to connect to oracle database `it neeeeeeeeeeeeds credentials`

#### SQLplus - Log In

```shell
AhmaDb0x@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE

```

If you come across the following error `sqlplus: error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory`,

```shell
AhmaDb0x@htb[/htb]$ sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig
```
DBS

#### Oracle RDBMS - Interaction

```shell
$ SQL> select table_name from all_tables;
```

```shell
$ SQL> select * from user_role_privs;
```

Here, the user `scott` has no administrative privileges. However, we can try using this account to log in as the System Database Admin (`sysdba`), giving us higher privileges. This is possible when the user `scott` has the appropriate privileges typically granted by the database administrator or used by the administrator him/herself.

#### Oracle RDBMS - Database Enumeration

```shell
AhmaDb0x@htb[/htb]$ sqlplus scott/tiger@10.129.204.235/XE as sysdba
dbsnmp
**XE**:

- It stands for **Oracle Database Express Edition** (XE), which is a lightweight, free edition of Oracle Database.
- In this context, `XE` is the **Oracle System Identifier (SID)** or **service name** used to identify the specific database instance you're connecting to on the host `10.129.205.19`.
- 

```

```shell
SQL> select * from user_role_privs;
```

we could retrieve the password hashes from the `sys.user$` and try to crack them offline.

```shell
SQL> select name, password from sys.user$;
```

Another option is to upload a web shell to the target. However, this requires the server to run a web server, and we need to know the exact location of the root directory for the webserver. Nevertheless, if we know what type of system we are dealing with, we can try the default paths, which are:

|**OS**|**Path**|
|---|---|
|Linux|`/var/www/html`|
|Windows|`C:\inetpub\wwwroot`|

#### Oracle RDBMS - File Upload
```shell
AhmaDb0x@htb[/htb]$ echo "Oracle File Upload Test" > testing.txt

AhmaDb0x@htb[/htb]$ ./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

```shell
AhmaDb0x@htb[/htb]$ curl -X GET http://10.129.204.235/testing.txt
```

DBSNMP is **the account used by Oracle's intelligent agent to logon automatically to remote servers in order to provide information for presentation via Enterprise Manager**. DNSMP has the SELECT ANY DICTIONARY system privilege which can read the passwords from SYS.


**Try Default Users and Passwords:** Common Oracle default users include:

- `sys`
- `system`
- `scott`
- `admin` Check with tools or a wordlist if they have default or weak passwords.

SELECT * FROM v$pwfile_users;

USERNAME                       SYSDBA SYSOPER
------------------------------ ------ -------
SYS                            TRUE   TRUE
DBSNMP                         TRUE   FALSE




Try other default Oracle credentials to gain access. Common ones include:

- `sys/change_on_install as sysdba`
- `system/manager`
- `scott/tiger`
- `admin/admin`