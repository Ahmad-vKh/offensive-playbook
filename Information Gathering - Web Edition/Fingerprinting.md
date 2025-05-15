## Fingerprinting Techniques

`Banner Grabbing` <> nc ,curl 
`Analysing HTTP Headers` <> discloses the web server software, `X-Powered-By` header might reveal additional technologies like scripting languages or frameworks.
`Probing for Specific Responses` <> For example, certain error messages or behaviours are characteristic of particular web servers or software components.



### Wafw00f
To detect the presence of a WAF, we'll use the `wafw00f` tool. To install `wafw00f`, you can use pip3:
```shell
AhmaDb0x@htb[/htb]$ pip3 install git+https://github.com/EnableSecurity/wafw00f
```
Once it's installed, pass the domain you want to check as an argument to the tool:
```shell
AhmaDb0x@htb[/htb]$ wafw00f inlanefreight.com
```
you might need to adapt techniques to bypass or evade the WAF's detection mechanisms.


### Nikto
```shell
AhmaDb0x@htb[/htb]$ nikto -h inlanefreight.com -Tuning b
```
The `-h` flag specifies the target host. The `-Tuning b` flag tells `Nikto` to only run the Software Identification modules.
`Nikto` will then initiate a series of tests, attempting to identify outdated software, insecure files or configurations, and other potential security risks.


|              |                                                                                                                       |                                                                                                     |
| ------------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `Wappalyzer` | Browser extension and online service for website technology profiling.                                                | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| `BuiltWith`  | Web technology profiler that provides detailed reports on a website's technology stack.                               | Offers both free and paid plans with varying levels of detail.                                      |
| `WhatWeb`    | Command-line tool for website fingerprinting.                                                                         | Uses a vast database of signatures to identify various web technologies.                            |
| `Nmap`       | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting.                          |
| `Netcraft`   | Offers a range of web security services, including website fingerprinting and security reporting.                     | Provides detailed reports on a website's technology, hosting provider, and security posture.        |
| `wafw00f`    | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs).                             | Helps determine if a WAF is present and, if so, its type and configuration.                         |