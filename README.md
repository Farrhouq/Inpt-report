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


## Summary of Findings

| Finding                                                                 | Severity |
|:-------------------------------------------------------------------------|:----------:|
| Path Traversal Attack in Apache HTTP Server                             | High     |
| MySQL Password Spraying Vulnerability                                    | Medium   |
| Local Privilege Escalation in RealVNC VNC Server                        | High     |
| VNC Password Bruteforcing Vulnerability                                  | Medium   |
| Elevation of Privilege via Folder Redirection in Microsoft Windows      | High     |
| SMTP Smuggling Vulnerability in Exim smtpd 4.92                         | Medium   |
| Buffer Overflow in BSD telnetd                                          | Critical |
| The Netlogon Server Issue in Samba 3.6.25                               | High     |
| Print Spooler Service Impersonation Vulnerability                        | High     |



Apache httpd 2.4.49 (on http):
Path Traversal Attack in Apache HTTP Server (CVE-2021-41773)
  A flaw in Apache 2.4.49 allows attackers to perform path traversal, accessing files outside restricted directories, possibly leading to remote code execution.
  7.5 (High)
  Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/25.png)


MySQL 5.6.49 (on mysql)
MySQL Password Spraying Vulnerability
  MySQL instances are vulnerable to password spraying attacks, where an attacker attempts to gain unauthorized access by systematically trying a set of common passwords across multiple accounts. Weak password policies or default credentials can lead to successful exploitation, compromising the database and potentially the broader network.
CVSS Score: 5.3 (Medium) (Estimated based on typical impact of password spraying attacks)
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/16.png)

RealVNC 5.3.2 (on vnc)
Local Privilege Escalation in RealVNC VNC Server
CVE ID: CVE-2022-41975
RealVNC VNC Server and VNC Viewer on Windows are vulnerable to local privilege escalation via the MSI installer Repair mode, allowing local attackers to elevate their privileges.
CVSS Score: 7.1 (High)
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/26.png)
-----
VNC Password Bruteforcing Vulnerability
  VNC instances are vulnerable to password bruteforcing attacks, where an attacker attempts to gain unauthorized access by systematically trying a set of common passwords across multiple accounts. Weak password policies or default credentials can lead to successful exploitation, compromising the database and potentially the broader network.
CVSS Score: 5.3 (Medium) (Estimated based on typical impact of password spraying attacks)
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/17.png)
----

Microsoft Terminal Services (on rdp)
Elevation of Privilege via Folder Redirection in Microsoft Windows
CVE ID: CVE-2021-26887
An attacker could exploit folder redirection to begin redirecting another user's personal data to a maliciously created folder, resulting in unauthorized access to sensitive data.
CVSS Score: 7.8 (High)
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/27.png)

Exim smtpd 4.92 (on smtp)
1. SMTP Smuggling Vulnerability
CVE ID: CVE-2023-51766
Summary: This allows attackers to inject emails with spoofed addresses in certain configurations. It can bypass SPF protection, potentially leading to unauthorized email transmission.
5.3 (Medium)
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/28.png)


### BSD telnetd (on telnet)
CVE-2011-4862
Description: Buffer overflow in telnetd allows remote attackers to execute arbitrary code via a long encryption key.
CVSS v2 Score: 10.0 (Critical)
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/29.png)


### Samba 3.6.25 (on netbios-ssn)
CVE-2015-0240
Description: The Netlogon server implementation in Samba 3.5.x and 3.6.x before 3.6.25, 4.0.x before 4.0.25, 4.1.x before 4.1.17, and 4.2.x before 4.2.0rc5 performs a free operation on an uninitialized stack pointer. This allows remote attackers to execute arbitrary code via crafted Netlogon packets using the ServerPasswordSet RPC API.
CVSS v2 Score: 7.5 (High)
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/30.png)


### Windows 7 - Samba file sharing (on `microsoft-ds`)
CVE-2010-2729
Description: The Print Spooler service in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP1 and SP2, Windows Server 2008 Gold, SP2, and R2, and Windows 7, when printer sharing is enabled, does not properly validate spooler access permissions. This allows remote attackers to create files in a system directory and execute arbitrary code by sending a crafted print request over RPC.
CVSS v2 Score: 7.5 (High)

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

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/26.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/27.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/28.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/29.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/30.png)
