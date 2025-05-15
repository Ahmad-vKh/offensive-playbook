MySQL server runs on `TCP port 3306`

1- `MySQL` is an open-source SQL relational database management system.
2- developed and supported by Oracle.
3- The database system can quickly process large amounts of data with high performance.
4- The database is controlled using the `[SQL database language].`
5- operate on `client-server principle`
6- consists of a MySQL server and one or more MySQL clients.
7- The data is stored in tables with different columns, rows, and data types.
8- databases are often stored in a single file with the file extension `.sql`
9- there are database structures that are distributed across multiple servers not single one.

#### MySQL Clients

1- access is possible via an internal network or the public Internet.
2- best examples of database usage is the CMS WordPress.
3- WordPress stores all created posts, usernames, and passwords in their own database.
4- only accessible from the localhost.(`wordpress`)


#### MySQL Databases

`[LAMP]`== (Linux, Apache, MySQL, PHP).
`[LEMP]` == (Linux, nginx, MySQL, PHP)


1-MySQL is ideally suited for applications such as `dynamic websites`
2- `dynamic websites`, where efficient syntax and high response speed are essential.
3- It is often combined with a Linux OS, PHP, and an Apache web server.
4- `[LAMP]`== (Linux, Apache, MySQL, PHP).
5- `[LEMP]` == (Linux, nginx, MySQL, PHP)

Sensitive data such as passwords can be stored in their plain-text form by MySQL; however, they are generally encrypted beforehand by the PHP scripts using secure methods such as [One-Way-Encryption](https://en.citizendium.org/wiki/One-way_encryption).

| stored                  |                  |                   |            |
| ----------------------- | ---------------- | ----------------- | ---------- |
| Headers                 | Texts            | Meta tags         | Forms      |
| Customers               | Usernames        | Administrators    | Moderators |
| Email addresses         | User information | Permissions       | Passwords  |
| External/Internal links | Links to Files   | Specific contents | Values     |

MariaDB was created to ensure an open, community-controlled alternative to MySQL after Oracle's acquisition.

## Dangerous Settings

|**Settings**|**Description**|
|---|---|
|`user`|Sets which user the MySQL service will run as.|
|`password`|Sets the password for the MySQL user.|
|`admin_address`|The IP address on which to listen for TCP/IP connections on the administrative network interface.|
|`debug`|This variable indicates the current debugging settings|
|`sql_warnings`|This variable controls whether single-row INSERT statements produce an information string if warnings occur.|
|`secure_file_priv`|This variable is used to limit the effect of data import and export operations.|

## Footprinting the Service

why a MySQL server could be accessed from an external network?
Nevertheless, it is far from being one of the best practices, and we can always find databases that we can reach. Often, these settings were only meant to be temporary but were forgotten by the administrators.

1- `The system schema (sys)` contains tables, information, and metadata necessary for management.
2- `information schema` (`information_schema`).


```shell
AhmaDb0x@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p3306 --script mysql*
```
`false-positive` !!

1- target MySQL server does not use an empty password for the user `root`, but a fixed password.

```shell
AhmaDb0x@htb[/htb]$ mysql -u root -h 10.129.14.132

Access denied for user 'root'@'10.129.14.1'
```


```shell
AhmaDb0x@htb[/htb]$ mysql -u root -pP4SSw0rd -h 10.129.14.128
```
The most important databases for the MySQL server are the `system schema` (`sys`) and `information schema` (`information_schema`).

[reference manual](https://dev.mysql.com/doc/refman/8.0/en/system-schema.html#:~:text=The%20mysql%20schema%20is%20the,used%20for%20other%20operational%20purposes)

| **Command**                                           | **Description**                                                                                       |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>`        | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;`                                     | Show all databases.                                                                                   |
| `use <database>;`                                     | Select one of the existing databases.                                                                 |
| `show tables;`                                        | Show all available tables in the selected database.                                                   |
| `show columns from <table>;`                          | Show all columns in the selected database.                                                            |
| `select * from <table>;`                              | Show everything in the desired table.                                                                 |
| `select * from <table> where <column> = "<string>";`  | Search for needed `string` in the desired table.                                                      |
| `SELECT email FROM myTable WHERE name = 'Otto Lang';` |                                                                                                       |

```shell
$ mysql -u robin -probin -h 10.129.173.199 --ssl-verify-server-cert=FALSE
```


SELECT email FROM myTable WHERE name = 'Otto Lang';
