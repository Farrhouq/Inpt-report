# Internal Network Penetration Test

### For: CyberLab Internship 2024

### Submitted by: Imoro Umar Farouq Mpagya

## Table of Contents
- **Table of Contents**
- **Testing Methodology**
- **Summary of Findings**
- **Detailed Findings**
- **References**


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

During the penetration testing, we utilized `eyewitness` to assess the web-based attack surfaces of the target servers. `eyewitness` is a tool that allows us to open the links and capture screenshots of web servers to analyze their public-facing interfaces. This helps in identifying potential vulnerabilities and understanding the security posture of the web applications.

**Tool Used:**
- `eyewitness`: Captures screenshots of web servers to document their security posture.

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
| Cewl for custom wordlists                                                |   NA     |
| Eyewitness for web vulnerability discovery                               |   NA     |

## Detailed Findings

### Remote Code Execution via Payloads on Apache Tomcat and Python Servers

| Current Rating | CVSS |
|----------------|------|
| High           | 7.5  |

**Finding Summary:**
The IP address 10.10.10.55 is running an Apache Tomcat web server, which is vulnerable to remote code execution. By generating a payload using `msfvenom` with the `java/jsp_shell_bind_tcp` module, attackers can trigger a TCP bind shell. This allows remote execution of malicious code. Similarly, the server at IP address 10.10.10.30, running a Python server, can execute base64 encoded payloads, which also poses a security risk.

**Evidence**
1. Payload generation for Apache Tomcat server:
   ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/22.png)
   - `-p java/jsp_shell_bind_tcp`: Specifies the payload module for Java-based servers.
   - `RHOST`: Remote host IP address (10.10.10.55).
   - `LPORT`: Local port number for the bind shell (80).
   - `-f war`: Specifies the format of the output file (WAR for Java applications).
   - `-o output_file.war`: Names the output file.

2. Payload generation for Python server:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/23.png)
   - The payload is base64 encoded to be executed on a Python server.

3. Directory with generated payloads:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/24.png)

**Affected Resources**
10.10.10.30, 10.10.10.55

**Recommendations**
For Apache Tomcat:
- Ensure that appropriate security measures are in place to prevent unauthorized execution of payloads. Regularly update Tomcat and review security configurations.

For Python Server:
- Implement stringent controls and input validation to prevent unauthorized execution of base64 encoded payloads.


### Path Traversal Attack in Apache HTTP Server

| Current Rating | CVSS |
|----------------|------|
| High           | 7.5  |

**Finding Summary:**
A flaw in Apache HTTP Server version 2.4.49 allows attackers to perform path traversal and access files outside of restricted directories. This vulnerability can potentially lead to remote code execution. Attackers can exploit this flaw by sending crafted requests to the server, allowing unauthorized file access and control over system resources.

**Evidence**
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/25.png)

**Affected Resources**
10.10.10.2, 10.10.10.30, 10.10.10.45, 10.10.10.55

**Recommendations**
Upgrade to Apache HTTP Server version 2.4.50 or later, which addresses this path traversal vulnerability.

---

### MySQL Password Spraying Vulnerability

| Current Rating | CVSS |
|----------------|------|
| Medium         | 5.3  |

**Finding Summary:**
MySQL 5.6.49 instances are vulnerable to password spraying attacks. Attackers can exploit weak password policies by systematically attempting common passwords across multiple accounts. This could lead to unauthorized access to the MySQL database and, consequently, compromise the broader network. This can be done using metasploit modules

**Evidence**
![Using metasploit to brute-force mysql passwords](https://github.com/Farrhouq/Inpt-report/blob/main/images/16.png)
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/13.png)
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/14.png)

**Affected Resources**
10.10.10.5, 10.10.10.40

**Recommendations**
- Implement strong, unique passwords for all MySQL accounts.
- Enforce password complexity and expiration policies.
- Monitor failed login attempts and lock accounts after multiple failed attempts to mitigate brute force attacks.
- Use multi-factor authentication (MFA) if available.

---

### Local Privilege Escalation in RealVNC VNC Server

| Current Rating | CVSS |
|----------------|------|
| High           | 7.1  |

**Finding Summary:**
A vulnerability in RealVNC VNC Server and Viewer on Windows allows local attackers to elevate privileges via the MSI installer Repair mode. This escalation could give attackers unauthorized access to sensitive system resources and allow them to perform actions typically reserved for administrators.

**Evidence**
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/26.png)

**Affected Resources**
10.10.10.10, 10.10.10.50

**Recommendations**
- Upgrade to the latest version of RealVNC VNC Server that addresses this privilege escalation issue.
- Restrict access to the VNC server to trusted users and networks.
- Regularly review and update your VNC server and associated software to patch known vulnerabilities.

---

### VNC Password Bruteforcing Vulnerability

| Current Rating | CVSS |
|----------------|------|
| Medium         | 5.3  |

**Finding Summary:**
RealVNC 5.3.2 is vulnerable to brute force attacks on the VNC password. Attackers can exploit weak password policies or default credentials to gain unauthorized access to VNC instances. Successful exploitation may result in control over affected systems and potential access to sensitive data.

**Evidence**
![Using metasploit to brute-force mysql passwords](https://github.com/Farrhouq/Inpt-report/blob/main/images/17.png)

**Affected Resources**
10.10.10.10, 10.10.10.50

**Recommendations**
- Use strong, unique passwords for VNC accounts.
- Configure the VNC server to lock out accounts after several failed login attempts.
- Regularly monitor VNC access logs for unusual activity.
- Consider using an additional layer of authentication or encryption to protect VNC sessions.

---

### Elevation of Privilege via Folder Redirection in Microsoft Windows

| Current Rating | CVSS |
|----------------|------|
| High           | 7.8  |

**Finding Summary:**
This vulnerability in Microsoft Terminal Services allows attackers to exploit folder redirection, redirecting another user's personal data to a maliciously created folder. By doing so, an attacker can gain unauthorized access to sensitive information stored on a compromised system, potentially leading to privilege escalation.

**Evidence**
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/27.png)

**Affected Resources**
10.10.10.31, 10.10.10.60

**Recommendations**
- Apply the latest security updates and patches from Microsoft to address this vulnerability.
- Review and restrict folder redirection settings to prevent unauthorized data access.
- Implement least privilege principles and regularly audit folder permissions.

---

### SMTP Smuggling Vulnerability in Exim smtpd 4.92

| Current Rating | CVSS |
|----------------|------|
| Medium         | 5.3  |

**Finding Summary:**
Exim SMTPd version 4.92 is vulnerable to SMTP smuggling, which allows attackers to inject spoofed emails in certain configurations. This vulnerability bypasses SPF protection mechanisms and can result in unauthorized email transmission, leading to further exploitation within email-based communications.

**Evidence**
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/28.png)

**Affected Resources**
10.10.10.15

**Recommendations**
- Upgrade to Exim version 4.94.1 or later to fix the SMTP smuggling vulnerability.
- Review and tighten email server configurations to prevent unauthorized email injection.
- Monitor email traffic for unusual patterns that might indicate exploitation attempts.

---

### Buffer Overflow in BSD telnetd

| Current Rating | CVSS |
|----------------|------|
| Critical       | 10   |

**Finding Summary:**
A buffer overflow vulnerability in BSD telnetd allows remote attackers to execute arbitrary code by sending a long encryption key during the telnet session. This vulnerability poses a significant threat as it allows attackers to take full control of the affected system without prior authentication.

**Evidence**
![](https://github.com/Farrhouq/Inpt-report/blob/main/images/29.png)

**Affected Resources**
10.10.10.20

**Recommendations**
- Upgrade to the latest version of BSD telnetd or use an alternative, more secure remote access tool.
- Disable telnet services if they are not required, and use secure alternatives like SSH.
- Regularly update and patch software to address known vulnerabilities.
---

### The Netlogon Server Issue in Samba 3.6.25

| Current Rating | CVSS |
|----------------|------|
| High           | 7.5  |

**Finding Summary:**
A vulnerability in the Netlogon server implementation of Samba allows remote attackers to execute arbitrary code by exploiting an uninitialized stack pointer in crafted Netlogon packets. Attackers can use the ServerPasswordSet RPC API to trigger this vulnerability, potentially leading to complete control of affected systems.

**Evidence**
Proof: ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/30.png)

**Affected Resources**
10.10.10.21

**Recommendations**
- Upgrade to Samba version 3.6.25 or later to mitigate this Netlogon server vulnerability.
- Review and configure Samba settings to limit exposure to untrusted networks.
- Regularly apply security updates and patches to Samba and associated services.

### `Eyewitness`
The screenshots taken by `eyewitness` revealed several important details about the web servers:
1. **Web Server Interfaces:**
   - Screenshots capture the interface and visible configurations of the web servers, highlighting any exposed or potentially vulnerable components.

2. **Potential Vulnerabilities:**
   - Certain web interfaces displayed signs of misconfigurations or exposed sensitive information that could be leveraged in an attack.

These findings provide a basis for deeper analysis and remediation recommendations to enhance the security of the web servers.

**Evidence:**
- ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/21.png)

### `Cewl`
The use of `cewl` for generating custom wordlists revealed several critical insights:

1. **Custom Wordlist Generation:**
   - `cewl` was used to scrape content from the target website to create a wordlist with contextually relevant terms.

2. **Effectiveness:**
   - The custom wordlists proved effective in identifying passwords that were specific to the target’s context, potentially increasing the success rate of brute-force attacks.

**Evidence:**
- ![](https://github.com/Farrhouq/Inpt-report/blob/main/images/20.png)

## References
### CVSS v3.0 Reference Table
| Qualitative Rating | CVSS Score |
|--------------------|------------|
| None/Informational | N/A        |
| Low                | 0.1 – 3.9  |
| Medium             | 4.0 – 6.9  |
| High               | 7.0 – 8.9  |
| Critical           | 9.0 – 10.0 |
