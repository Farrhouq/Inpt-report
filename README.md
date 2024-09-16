# Internal Network Penetration Test

### For: CyberLab Internship 2024

### Submitted by: Imoro Umar Farouq Mpagya

## Table of Contents
- Table of Contents
- Executive Summary
- Analysis of Overall Security Posture
- Key Recommendations
- Testing Methodology
- Summary of Findings
- Detailed Findings



## Testing Methodology
The scope of this engagement included the internal network `10.10.10.0/24` and the domain `https://virtualinfosecafrica.com/`.

Host discovery was conducted to identify active devices within the provided network. Using nmap, a ping scan was performed to locate live hosts, utilizing the -sn flag, as seen in the following screenshot:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/1.png)

This method efficiently determined which hosts were active. Once identified, active IP addresses were extracted for further analysis by redirecting the results into a file for use in subsequent scans:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/2.png)

Additionally, subdomain enumeration was performed on the domain using aiodnsbrute. This was essential to uncover any subdomains potentially hosting services or vulnerabilities that might be of interest during further testing:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/3.png)

After identifying active hosts, service discovery was performed using nmap with the -sV flag to identify open ports and services running on the discovered hosts. The results were saved in a greppable format (-oG) to facilitate the extraction of specific data for further use, as shown below:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/4.png)

To enhance analysis, services were categorized by protocol using grep, focusing on protocols such as mysql, vnc, rdp, smtp, telnet, and others. This organization was carried out using the following commands:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/5.png)

Additional services such as mysql, vnc, and rdp were similarly filtered:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/6.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/7.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/8.png)

Further sorting and filtering by protocol continued with smtp, telnet, netbios-ssn, and microsoft-ds services:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/9.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/10.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/11.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/12.png)

Finally, the associated IPs were filtered into separate files for more direct use:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/15.png)

A risk assessment was conducted following the guidelines in NIST Special Publication (800-30 R1). Each vulnerability identified during the engagement was mapped to a qualitative risk rating, taking into account both the likelihood of exploitation and the potential impact on the network.


There are associated vulnerabilities with these services and their versions. The relevant CVE id's are listed below:
### Apache httpd 2.4.49 (on http):
*CVE-2021-42013, CVE-2021-41773, CVE-2021-41524, CVE-2021-40438, CVE-2021-39275, CVE-2021-36160, CVE-2021-34798*

### MySQL 5.6.49 (on mysql)
*CVE-2020-14867, CVE-2020-14812, CVE-2020-14793, CVE-2020-14769, CVE-2020-14765, CVE-2020-14672*

### RealVNC 5.3.2 (on vnc)
*CVE-2024-6894, CVE-2024-23663, CVE-2024-1331, CVE-2023-49438, CVE-2023-45859, CVE-2022-41975, CVE-2022-3474, CVE-2022-27502, CVE-2022-27489, CVE-2022-0439, CVE-2021-42362, CVE-2021-40083, CVE-2021-34408, CVE-2021-24140, CVE-2021-23443, CVE-2021-20746, CVE-2020-5408, CVE-2020-5407, CVE-2020-35738, CVE-2020-35489, CVE-2019-17133, CVE-2019-17075, CVE-2019-17056, CVE-2019-17055, CVE-2019-17054, CVE-2019-17053, CVE-2019-17052, CVE-2018-6660, CVE-2018-6659, CVE-2018-12615, CVE-2018-12029, CVE-2018-12028, CVE-2018-12026, CVE-2017-7671, CVE-2017-7581, CVE-2017-3980, CVE-2017-3936, CVE-2016-8583, CVE-2016-8582, CVE-2016-8581, CVE-2016-8580, CVE-2016-8027, CVE-2016-6355, CVE-2016-1409, CVE-2016-1407, CVE-2016-0201, CVE-2015-6432, CVE-2015-5206, CVE-2015-5168, CVE-2015-4171, CVE-2015-4078, CVE-2014-6275, CVE-2013-6886, CVE-2013-2125, CVE-2012-2317, CVE-2010-4700, CVE-2010-3065, CVE-2010-3064, CVE-2010-3063, CVE-2010-3062, CVE-2010-2225, CVE-2010-2190, CVE-2010-2101, CVE-2010-2100, CVE-2010-2097, CVE-2010-2093, CVE-2010-1917, CVE-2010-1915, CVE-2010-1914, CVE-2010-1868, CVE-2010-1866, CVE-2010-1864, CVE-2010-1862, CVE-2010-1861, CVE-2010-1860, CVE-2010-1587, CVE-2009-1178, CVE-2008-4770, CVE-2008-3493, CVE-2007-5919, CVE-2007-1581, CVE-2006-2369, CVE-2005-0322, CVE-2004-2512, CVE-2004-2511, CVE-2004-1750, CVE-2004-0698, CVE-2004-0697, CVE-2004-0696, CVE-2004-0695*

### Microsoft Terminal Services (on rdp)
*CVE-2021-26887, CVE-2017-0176, CVE-2014-0296, CVE-2012-0152, CVE-2011-1991, CVE-2009-1929, CVE-2009-1133, CVE-2007-2593, CVE-2006-4465, CVE-2006-4219, CVE-2005-3176, CVE-2005-1794, CVE-2004-0900, CVE-2004-0899, CVE-2003-0807, CVE-2003-0109, CVE-2003-0003, CVE-2002-1933, CVE-2002-1795, CVE-2002-0864, CVE-2002-0863, CVE-2002-0726, CVE-2002-0694, CVE-2002-0693, CVE-2002-0444, CVE-2001-0908, CVE-2000-0089*

### Exim smtpd 4.92 (on smtp)
*CVE-2023-51766, CVE-2023-42119, CVE-2023-42117, CVE-2023-42116, CVE-2023-42115, CVE-2021-38371, CVE-2020-28024, CVE-2020-28023, CVE-2020-28021, CVE-2020-28020, CVE-2020-28018, CVE-2019-16928, CVE-2019-13917, CVE-2018-6789, CVE-2017-16944, CVE-2017-16943, CVE-2012-5671, CVE-2010-4345, CVE-2010-4344, CVE-2003-0743, CVE-2001-0690*

### BSD telnetd (on telnet)
*CVE-2011-4862, CVE-2005-0488, CVE-2005-0469, CVE-2005-0468, CVE-2001-0554, CVE-1999-1098*

### Samba 3.6.25 (on netbios-ssn)
*CVE-2015-0240*

### Windows 7 - Samba file sharing (on `microsoft-ds`)
*CVE-2010-2729, CVE-2009-2813, CVE-2007-2407*


## Vulnerability Scanning
Using the protocol-specific files we created under service discovery, we can scan for login vulnerabilities with the Metasploit Auxiliary module. We will scan for common credentials
for `mysql`, `vnc`, `rdp`, and `smb` services. This will be achieved by the following steps:

1. First, we access the Metasploit Framework Console using `msfconsole`:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/13.png)

2. Then, we access the mysql auxiliary login scanner as follows:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/14.png)

3. Next, we set the parameters we need for the module, and run the scan:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/16.png)

Similar steps will be followed for vnc, rdp, and smb scans:
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/17.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/18.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/19.png)


In the above scans, public password lists were used for each service. However, in situations where we suspect the target might be using site-specific or context-relevant passwords (e.g., company names, employee names, or phrases from the website), we can generate custom wordlists using a tool like `cewl`. This is demonstrated below:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/20.png)


## Web-Based Attack Surfaces
Using `eyewitness`, we can open the links and take screenshots of the web servers. This can be done as follows:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/21.png)

## Generating Payloads
The IP address 10.10.10.55 is running an Apache Tomcat web server. We can generate a payload for this server that can trigger a TCP bind when executed. This bind will give an attacker a shell on the server where they can run malicious code remotely. This can be achieved with the following command:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/22.png)

- The `-p` flag allows us to select the payload module from `msfvenom`. In this case, it is `java/jsp_shell_bind_tcp` because the server is Java-based.
- `RHOST` indicates the host IP address which is `10.10.10.55`.
- `LPORT` indicates the port number, which is 80.
- The`-f` flag allows us to specify the format of the output payload file. In this case, it is `war` because that is the type of file the server executes.
- The`-o` flag specifies the name of the output file.

A similar approach can be taken for the host 10.10.10.30 running a Python server that
can execute base64 encoded payloads:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/23.png)

The generated payloads ready to be delivered are shown in the directory below:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/24.png)


## References
- https://cve.mitre.org/cve/search_cve_list.html
