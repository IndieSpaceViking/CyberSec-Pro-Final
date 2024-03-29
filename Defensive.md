# Defensive: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

## Network Topology

| Name       | Function   | IP Address   | Operating System   |
|----------|----------|------------|------------------|
| Azure Machine. |Jump Box/Azure Cloud Environment  | 192.168.1.1   | Microsoft Windows RPC            |
| Kali. |Attacker/ Pen Test machine    | 192.168.1.90 |Kali Release 2020.1 / Kernel: Linux 5.4.0 |
| ELK Stack |Data Digestion, Logging, Systems Analysis Intrusion Detection System    | 192.168.1.100 |Ubuntu 18.04.1 LTS            |
| Capstone. |Sending logs to ELK Stack/Apache Web Server. |192.168.1.105. |Ubuntu 18.04.1 LTS. |
| Target1 |WordPress Host |192.168.1.110  |Debian GNU/Linux 8/v3.16.0-6 |
| Target2 |WordPress Host |192.168.1.115  |Debian GNU/Linux 8/v3.16.0-6 |


**Network Diagram:**
![CyberSec Final Network](https://user-images.githubusercontent.com/85250007/177862625-34e85132-685a-491e-95a8-f2256b5f5b2b.gif)



## Description of Targets
- The target of this attack was: `Target 1` (192.168.1.110).

- Two VMs on the network were vulnerable to attack due to weak security implementation services and administration: Target 1 (192.168.1.110) and Target 2 (192.168.1.115). However, only Target 1 is covered.

- Target 1 is an Apache web server and has SSH enabled, so ports 80 and 22 are possible ports of entry for attackers. As such, the following alerts have been implemented:

### Monitoring the Targets
This scan identifies the services below as potential points of entry:

**Target 1**

`nmap -A 192.168.1.0* `

-  Target 1 & Target 2: 
    - Port 22/tcp - ssh
    - Port 80/tcp - http
    - Port 111/tcp - rpcbind
    - Port 139/tcp - netbios-ssn Samba
    - Port 445/tcp - netbios-ssn Samba

![Nmap Target1 ports (3)](https://user-images.githubusercontent.com/85250007/174403812-1662b68d-c5e2-4c53-ba92-76d9babeb422.png)

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:


**Alert 1: Excessive HTTP Errors**

Excessive HTTP Errors is implemented as follows:

`WHEN count() GROUPED OVER top 5 'http.response.status_code' IS ABOVE 400 FOR THE LAST 5 minutes`

-  Metric: 
    - **WHEN count() GROUPED OVER top 5 ‘http.response.status_code’**
- Threshold: 
    - **IS ABOVE 400**
- Vulnerability Mitigated:
    - **Enumeration/Brute Force**
- Reliability: 
    - The alert is highly reliable. Measuring by error codes 400 and above will filter out any normal or successful responses. 400+ codes are client and server errors which are of more concern. Especially when taking into account these error codes going off at a high rate.

![ExcessiveHTTPErrors](https://user-images.githubusercontent.com/85250007/174405755-ccd74126-5e84-49f8-b570-2385d8060e59.png)

**Alert 2: HTTP Request Size Monitor**

HTTP Request Size Monitor is implemented as follows:

`WHEN sum() of http.request.bytes OVER all documents IS ABOVE 3500 FOR THE LAST 1 minute`

- Metric: 
    - **WHEN sum() of http.request.bytes OVER all documents**
- Threshold: 
    - **IS ABOVE 3500**
- Vulnerability Mitigated: 
    - **Code injection in HTTP requests (XSS and CRLF) or DDOS**
- Reliability:
    - Alert could create false positives. It comes in at a medium reliability. There is a possibility for a large non malicious HTTP request or legitimate HTTP traffic.

![HTTPRSM](https://user-images.githubusercontent.com/85250007/174405792-717b4e8c-6b4f-4b5e-b2f3-e492de2219a1.png)

**Alert 3: CPU Usage Monitor**

CPU Usage Monitor is implemented as follows:

`WHEN max() OF system.process.cpu.total.pct OVER all documents IS ABOVE 0.5 FOR THE LAST 5 minutes`

- Metric: 
    - **WHEN max() OF system.process.cpu.total.pct OVER all documents**
- Threshold: 
    - **IS ABOVE 0.5**
- Vulnerability Mitigated: 
    - **Malicious software, programs (malware or viruses) running taking up resources**
- Reliability: 
    - The alert is highly reliable. Even if there isn’t a malicious program running this can still help determine where to improve on CPU usage.

![CPUUsageMonitor](https://user-images.githubusercontent.com/85250007/174405814-ad309b1f-9592-403f-8bc8-b1a4cf99b58f.png)

## Suggestions for Going Further

Each alert above pertains to a specific vulnerability/exploit. If you recall that alerts only detect malicious behavior, but do not stop it. For each vulnerability/exploit identified by the alerts above, suggest a patch. E.g., implementing a blocklist is an effective tactic against brute-force attacks.

The logs and alerts generated during the assessment suggest that this network is susceptible to several active threats. In addition to watching for occurrences of such threats, the network should be hardened against them. The Defensive Team suggests that IT implement the fixes below to protect the network:

**Excessive HTTP Errors**
- Patch: WordPress Hardening
    - Implement regular updates to WordPress 
        - WordPress Core 
        - PHP version
        - Plugins
    - Install security plugin(s)
        - Ex. Wordfence (adds security functionality)
    - Disable unused WordPress features and settings like:
        - WordPress XML-RPC (on by default)
        - WordPress REST API (on by default)
    - Block requests to /?author=<number> by configuring web server settings
    - Remove WordPress logins from being publicly accessible specifically:
        - /wp-admin 
        - /wp-login.php
- Why It Works: 
    - Regular updates to WordPress, the PHP version and plugins is an easy way to implement patches or fixes to exploits/vulnerabilities.
    - Depending on the WordPress security plugin it can provide things like:
        - Malware scans
        - Firewall
        - IP options (to monitor/block suspicious traffic)
    - REST API is used by WPScan to enumerate users
        - Disabling it will help mitigate WPScan or enumeration in general
    - XML-RPC uses HTTP as it’s method of data transport
    - WordPress links (permalinks) can include authors (users)
        - Blocking request to view the all authors (users) helps mitigate against user enumeration attacks
    - Removal of public access to WordPress login helps reduce the attack surface

**HTTP Request Size Monitor**
- Patch: Code Injection/DDOS Hardening
    - Implementation of HTTP Request Limit on the web server
        - Limits can include a number of things:
            - Maximum URL Length
            - Maximum length of a query string
            - Maximum size of a request
    - Implementation of input validation on forms
- Why It Works: 
    - If an HTTP request URL length, query string and over size limit of the request a 404 range of errors will occur.
        - This will help reject these requests that are too large.
    - Input validation can help protect against malicious data anyone attempts to send to the server via the website or application in/across a HTTP request.

**CPU Usage Monitor**
- Patch: Virus or Malware hardening
    - Add or update to a good antivirus.
    - Implement and configure Host Based Intrusion Detection System (HIDS)
        - Ex. SNORT (HIDS)
- Why It Works: 
    - Antiviruses specialize in removal, detection and overall prevention of malicious threats against computers. 
        - Any modern antivirus usually covers more than viruses and are a robust solution to protecting a computer in general.
    - HIDS monitors and analyzes internals of computing systems. 
        - They also monitor and analyze network packets.
