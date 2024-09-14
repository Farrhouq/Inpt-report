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


There are associated vulnerabilities with these services and their versions. The relevant CVE id's are listed below:
### Apache httpd 2.4.49 (on http):
  - CVE-2021-42013
  - CVE-2021-41773
  - CVE-2021-41524
  - CVE-2021-40438
  - CVE-2021-39275
  - CVE-2021-36160
  - CVE-2021-34798

### MySQL 5.6.49 (on mysql)
  - CVE-2020-14867
  - CVE-2020-14812
  - CVE-2020-14793
  - CVE-2020-14769
  - CVE-2020-14765
  - CVE-2020-14672

### RealVNC 5.3.2 (on vnc)
  - CVE-2024-6894
  - CVE-2024-23663
  - CVE-2024-1331
  - CVE-2023-49438
  - CVE-2023-45859
  - CVE-2022-41975
  - CVE-2022-3474
  - CVE-2022-27502
  - CVE-2022-27489
  - CVE-2022-0439
  - CVE-2021-42362
  - CVE-2021-40083
  - CVE-2021-34408
  - CVE-2021-24140
  - CVE-2021-23443
  - CVE-2021-20746
  - CVE-2020-5408
  - CVE-2020-5407
  - CVE-2020-35738
  - CVE-2020-35489
  - CVE-2019-17133
  - CVE-2019-17075
  - CVE-2019-17056
  - CVE-2019-17055
  - CVE-2019-17054
  - CVE-2019-17053
  - CVE-2019-17052
  - CVE-2018-6660
  - CVE-2018-6659
  - CVE-2018-12615
  - CVE-2018-12029
  - CVE-2018-12028
  - CVE-2018-12026
  - CVE-2017-7671
  - CVE-2017-7581
  - CVE-2017-3980
  - CVE-2017-3936
  - CVE-2016-8583
  - CVE-2016-8582
  - CVE-2016-8581
  - CVE-2016-8580
  - CVE-2016-8027
  - CVE-2016-6355
  - CVE-2016-1409
  - CVE-2016-1407
  - CVE-2016-0201
  - CVE-2015-6432
  - CVE-2015-5206
  - CVE-2015-5168
  - CVE-2015-4171
  - CVE-2015-4078
  - CVE-2014-6275
  - CVE-2013-6886
  - CVE-2013-2125
  - CVE-2012-2317
  - CVE-2010-4700
  - CVE-2010-3065
  - CVE-2010-3064
  - CVE-2010-3063
  - CVE-2010-3062
  - CVE-2010-2225
  - CVE-2010-2190
  - CVE-2010-2101
  - CVE-2010-2100
  - CVE-2010-2097
  - CVE-2010-2093
  - CVE-2010-1917
  - CVE-2010-1915
  - CVE-2010-1914
  - CVE-2010-1868
  - CVE-2010-1866
  - CVE-2010-1864
  - CVE-2010-1862
  - CVE-2010-1861
  - CVE-2010-1860
  - CVE-2010-1587
  - CVE-2009-1178
  - CVE-2008-4770
  - CVE-2008-3493
  - CVE-2007-5919
  - CVE-2007-1581
  - CVE-2006-2369
  - CVE-2005-0322
  - CVE-2004-2512
  - CVE-2004-2511
  - CVE-2004-1750
  - CVE-2004-0698
  - CVE-2004-0697
  - CVE-2004-0696
  - CVE-2004-0695

### Microsoft Terminal Services (on rdp)
  - CVE-2021-26887
  - CVE-2017-0176
  - CVE-2014-0296
  - CVE-2012-0152
  - CVE-2011-1991
  - CVE-2009-1929
  - CVE-2009-1133
  - CVE-2007-2593
  - CVE-2006-4465
  - CVE-2006-4219
  - CVE-2005-3176
  - CVE-2005-1794
  - CVE-2004-0900
  - CVE-2004-0899
  - CVE-2003-0807
  - CVE-2003-0109
  - CVE-2003-0003
  - CVE-2002-1933
  - CVE-2002-1795
  - CVE-2002-0864
  - CVE-2002-0863
  - CVE-2002-0726
  - CVE-2002-0694
  - CVE-2002-0693
  - CVE-2002-0444
  - CVE-2001-0908
  - CVE-2000-0089

### Exim smtpd 4.92 (on smtp)
  - CVE-2023-51766
  - CVE-2023-42119
  - CVE-2023-42117
  - CVE-2023-42116
  - CVE-2023-42115
  - CVE-2021-38371
  - CVE-2020-28024
  - CVE-2020-28023
  - CVE-2020-28021
  - CVE-2020-28020
  - CVE-2020-28018
  - CVE-2019-16928
  - CVE-2019-13917
  - CVE-2018-6789
  - CVE-2017-16944
  - CVE-2017-16943
  - CVE-2012-5671
  - CVE-2010-4345
  - CVE-2010-4344
  - CVE-2003-0743
  - CVE-2001-0690
