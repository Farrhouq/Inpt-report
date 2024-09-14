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

Lastly, we can perform a subdomain enumeration on the given domain, in order to find the IP addresses of any subdomains, as they might be of interest. This can be done using a tool like `aiodnsbrute` as follows:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/3.png)


## Service Discovery and Port Scanning
After discovering the hosts that are up, in order to find and exploit potential vulnerabilities, we need to discover what services these hosts are running, and on what ports. It is these services we will hack into in the end.

We can use `nmap` to do a service discovery by scanning the ports on the hosts we discovered earlier. Also, it will be convenient for us to save the results in a file for later use:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/4.png)

- The `sV` flag indicates a service discovery scan.
- The `iL` flag is used to input the IP addresses from a file. In this case, I used the output file from the host discovery file as the input to this scan (`online_hosts.txt`).
- The `oG` flag indicates that the output be in a greppable format, which is easy to extract the results from. It requires an output file name, which is given as `service_scan.gnmap`.

In order to effectively use our results in later specific attacks, it would be more convenient to sort the services discovered into their respective protocols. Since our output file was saved in a greppable format, we can achieve this using `grep`:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/5.png)

- The `mkdir` command is used to create a new folder for better organisation of the protocol specific results.

Similar can be done for the other protocols: (mysql, vnc, rdp, smtp, telnet, netbios-ssn, microsoft-ds) as follows:

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/6.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/7.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/8.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/9.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/11.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/10.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/10.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/11.png)

![](https://github.com/Farrhouq/Inpt-report/blob/main/images/12.png)
