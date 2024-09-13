# Internal Network Penetration Test

### For: CyberLab Internship 2024

### Submitted by: Imoro Umar Farouq Mpagya

## Table of Contents
- **Host Discovery**
- **Service Discovery and Port Scanning**
- **Vulnerability Scanning**
- **Web-Based Attack Surfaces**
- **Generating Payloads**


## Host Discovery
A host is a network service which has an IP address. Host discovery forms part of the information gathering process, where we find information about the hosts that are active in the given network to know what is possible to hack through.
Using `nmap`, we can discover the hosts on the given network by performing a ping scan as follows:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/1.png)

- The `-sn` flag indicates a ping scan to determine which hosts are up.

Now, after determining which hosts are up from the `nmap` scan, it's we would want to extract the active IPs into a file for later use. This can be done by modifying the command as follows:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/2.png)
