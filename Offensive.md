# Offensive: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

Command: `$ nmap -sV 192.168.1.110` or `$ nmap -A 192.168.1.0/24`

Output screenshot:



This scan identifies the services below as potential points of entry:
- Target 1
  - Port 22/TCP Open SSH
  - Port 80/TCP Open HTTP
  - Port 111/TCP Open rcpbind
  - Port 139/TCP Open netbios-ssn
  - Port 445/TCP Open netbios-ssn

The following vulnerabilities were identified on each target:
- Target 1
  - Improper configured SSH
  - WordPress Enumation
  - Weak Password Implementation
  - No file security permission implemented
  - Use of weak password salted hashes
  - Python root escalation privileges
