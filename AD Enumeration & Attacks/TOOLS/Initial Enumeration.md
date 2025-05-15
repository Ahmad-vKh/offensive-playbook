```shell-session
AhmaDb0x@htb[/htb]$ xfreerdp /v:10.129.115.227 /u:htb-student /p:Academy_student_AD!
C:\Tools
```
HTB_@cademy_stdnt! 
htb-student
```shell-session
AhmaDb0x@htb[/htb]$ ssh htb-student@<ATTACK01 target IP>
/opt
```

```shell-session
AhmaDb0x@htb[/htb]$ xfreerdp /v:<ATTACK01 target IP> /u:htb-student /p:HTB_@cademy_stdnt!
```

```shell-session
/u:htb-student /p:HTB_@cademy_stdnt!
```

| Command                                                                                             | Description                                                                                                                                                                                                                                                                                                 |
| --------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nslookup ns1.inlanefreight.com`                                                                    | Used to query the domain name system and discover the IP address to domain name mapping of the target entered from a Linux-based host.                                                                                                                                                                      |
| `sudo tcpdump -i ens224`                                                                            | Used to start capturing network packets on the network interface proceeding the `-i` option a Linux-based host.                                                                                                                                                                                             |
| `sudo responder -I ens224 -A`                                                                       | Used to start responding to & analyzing `LLMNR`, `NBT-NS` and `MDNS` queries on the interface specified proceeding the `-I` option and operating in `Passive Analysis` mode which is activated using `-A`. Performed from a Linux-based host                                                                |
| `fping -asgq 172.16.5.0/23`                                                                         | Performs a ping sweep on the specified network segment from a Linux-based host.                                                                                                                                                                                                                             |
| `sudo nmap -v -A -iL hosts.txt -oN /home/User/Documents/host-enum`                                  | Performs an nmap scan that with OS detection, version detection, script scanning, and traceroute enabled (`-A`) based on a list of hosts (`hosts.txt`) specified in the file proceeding `-iL`. Then outputs the scan results to the file specified after the `-oN`option. Performed from a Linux-based host |
| `sudo git clone https://github.com/ropnop/kerbrute.git`                                             | Uses `git` to clone the kerbrute tool from a Linux-based host.                                                                                                                                                                                                                                              |
| `make help`                                                                                         | Used to list compiling options that are possible with `make` from a Linux-based host.                                                                                                                                                                                                                       |
| `sudo make all`                                                                                     | Used to compile a `Kerbrute` binary for multiple OS platforms and CPU architectures.                                                                                                                                                                                                                        |
| `./kerbrute_linux_amd64`                                                                            | Used to test the chosen complied `Kebrute` binary from a Linux-based host.                                                                                                                                                                                                                                  |
| `sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute`                                              | Used to move the `Kerbrute` binary to a directory can be set to be in a Linux user's path. Making it easier to use the tool.                                                                                                                                                                                |
| `./kerbrute_linux_amd64 userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o kerb-results` | Runs the Kerbrute tool to discover usernames in the domain (`INLANEFREIGHT.LOCAL`) specified proceeding the `-d` option and the associated domain controller specified proceeding `--dc`using a wordlist and outputs (`-o`) the results to a specified file. Performed from a Linux-based host.             |
