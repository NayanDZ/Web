# 🌐 Web Application - VAPT

<p align="center">
  <img src="owasp.jpeg">
</p>

### A1:2017 Injection: 
Injection flaws, such as [SQL](https://github.com/NayanDZ/sql), OS, XXE, and LDAP injection occur when un-trusted data is sent to an interpreter as part of a command or query. 

### A2:2017 Broken Authentication: 
Application functions related to authentication and session management are often implemented incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to exploit other implementation flaws to assume other users’ identities.

### A3:2017 Sensitive Data Exposure:
Many web applications and APIs do not properly protect sensitive data, such as financial and PII. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without extra protection, such as encryption at rest or in transit, and requires special precautions when exchanged with the browser.

### A4:2017 XML External Entities (XXE):
Many older or poorly configured XML processors evaluate external entity references within XML documents. External entities can be used to disclose internal files using the file URI handler, internal file shares, internal port scanning, remote code execution, and denial of service attacks.

### A5:2017 Broken Access Control:
Restrictions on what authenticated users are allowed to do are often not properly enforced. Attackers can exploit these flaws to access unauthorized functionality or data, such as access other users' accounts, view sensitive files, modify other users’ data, change access rights, etc.

### A6:2017 Security Misconfiguration:
Good security requires having a secure configuration defined and deployed for the application, frameworks, application server, web server, database server, platform, etc. Secure settings should be defined, implemented, and maintained, as defaults are often insecure.

### [A7:2017 Cross-Site Scripting (XSS):](https://github.com//nayandz/xss)
XSS flaws occur whenever an application includes un-trusted data in a new web page without proper validation or escaping, or updates an existing web page with user supplied data using a browser API that can create JavaScript. 
XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.
XSS Type:
•	Stored - Stored XSS vulnerability exists when data provided to a web application by a user is first stored persistently on the server.
•	Reflected - Reflected XSS vulnerability exists when data provided by a web client is used immediately by server-side scripts to generate a page of results for that user.
•	DOM-Based (Document Object Model) - A DOM-based XSS vulnerability exists within a page’s client-side script itself.

### [A8:2017 Insecure Deserialization:](https://portswigger.net/web-security/deserialization)
Insecure Deserialization often leads to remote code execution. Even if Deserialization flaws do not result in remote code execution, they can be used to perform attacks, including replay attacks, injection attacks, and privilege escalation attacks.

### A9:2017 Using Components with Known Vulnerabilities:
Components, such as libraries, frameworks, and other software modules, run with the same privileges as the application. If a vulnerable component is exploited, such an attack can facilitate serious data loss or server takeover. Applications and APIs using components with known vulnerabilities may undermine application defenses and enable various attacks and impacts.

### A10:2017 Insufficient Logging & Monitoring
Insufficient logging and monitoring, coupled with missing or ineffective integration with incident response, allows attackers to further attack systems, maintain persistence, pivot to more systems, and tamper, extract, or destroy data. Most breach studies show time to detect a breach is over 200 days, typically detected by external parties rather than internal processes or monitoring.

## Strategies for VAPT
1. Reconnaissance (Foot Printing):- Information gathering
2. Network Scanning:- Find open ports and service running on the open ports
3. Exploitation:- Gaining system access
4. Maintaining Access:- Keep system access after leaving the system access
5. Clearing Logs:- Remove footprints


## Vulnerability Assessment & Penetration Testing is Divided into 2 Phase

### Phase 1 - Passive mode:
  Tries to understand the application’s logic and plays with the application. Tools can be used for information gathering. For example, an HTTP proxy can be used to observe all the HTTP requests and responses.
  
### Phase 2 - Active mode:
  Active tests have been split into 11 sub-categories.
1. Information Gathering
2. Configuration and Deployment Management Testing
3. Identity Management Testing 
4. Authentication Testing 
5. Authorization Testing 
6. Session Management Testing 
7. Input validation Testing
8. Error Handling
9. Cryptography
10. Business Logic Testing
11. Client Side Testing

## 1. Information Gathering
***1.1 Conduct Search Engine Discovery and Reconnaissance for Information Leakage***
- Search Engine:
  - Shodan: Shodan is a search engines that user find specific types (Computers, web cams, routers, servers, etc.)
  - censys.io: Find and analyze every reachable server and device on the Internet.
  - PunkSpider:	Global web application vulnerability search engine. Deeper, faster, harder scans
  - binsearch.info: News Groups Search
  - Duck Duck Go:	does not collect or share personal information
  - ixquick/Startpage: Combines the top ten results from multiple search engines
  - Builtwith.com: Find out what websites are Built With
  - OSINT Framework: OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., 
- Google Hacking Database
- [Google Search operators](https://moz.com/learn/seo/search-operators)
- https://gbhackers.com/latest-google-dorks-list

***1.2. Fingerprint Web Server:*** Knowing the version and type of running web server
  - Tools: 
    - Httprint, Httprecon,
  - Online Testing Sites:
    - https://w3techs.com/sites
    - Shodan: http://www.shodanhq.com
    - https://who.is
    - Netcraft: https://toolbar.netcraft.com/site_report?url=http://dulcedaynutrifood.com
    - https://www.dnsstuff.com
  - Browser Plug-in: wappalyzer (Firefox / Chrome browser Plug-in)


***1.3. Review Webserver Metafiles/Webpage Comments for Information Leakage:*** Analyze robots.txt and identify <META> Tags from website.
  - Tools:
    - curl: ```$ curl --url https://www.naano.com/robots.txt ```
    - wget: ```$ wget www.nano.com/robots.txt ```
    - Browser “view source” function (Ctrl + U)


***1.4. Enumerate Applications on Webserver:*** Find out which particular applications are hosted on a web server
      ```$ nmap –PN –sT –sV –p0-65535 192.168.1.100```
  
1.6. Identify application entry points

1.7. Map execution paths through application

1.8. Fingerprint Web Application Framework

***1.9. Fingerprint Web Application:*** Identify the web application and version to determine known vulnerabilities and the appropriate exploits to use during testing.
  - DNS Enumeration:
    - Dnsenum: ```	$ dnsenum Microsoft.com ```
    -	Dnsrecon: ```	$ dnsrecon –d Microsoft.com ```
    - nslookup: ``` $ nslookup Microsoft.com {-type=mx (Mail server), -type=soa (Technical information), -type=any (all available)} ```
    - Knock: Sub domain brute forcing ``` $ knockpy Microsoft.com ```
    - Dmitry: ```	$ Dmitry -winsepfb -o test.txt Microsoft.com ```
     - dig: ``` dig microsoft.com ```
    - whois: ``` $ whois example.com ```
    - recon-ng: https://hackertarget.com/recon-ng-tutorial
                    
                    $ recon-ng
                    
                    [recon-ng][default] > use recon/domains-hosts/hackertarget
                    
                    [recon-ng][default][hackertarget] > show options
                    
                    [recon-ng][default][hackertarget] > set SOURCE www.nano.com
                    
                    [recon-ng][default][hackertarget] > run 
               
  - Port Scanning (Service Fingerprinting & OS Detection):
    - Nmap: ``` $ nmap –sS –A –PN –p- --script=http-title nano.com [-sS:syn scan, -A:OS detection + service fingerprint, -PN:no ping, -p-: all ports] ```
    - Port scans top 1000 TCP ports: ``` $ nmap 192.168.100.2 ```
    - Port scans all 65535 TCP ports: ``` $ nmap –A –p- 192.168.100.2 ```
    - Port scans top 1000 UDP ports: ``` $ nmap -sU 192.168.100.2 ```
    - Port scans all 65535 UDP ports: ``` $ nmap –sU -p- -A 192.168.100.2 ```

  - Traceroute:
    - LFT: ``` $ lft –s Microsoft.com ```
    - tcptraceroute: ``` $ tcptraceroute Microsoft.com 433 ```
    - hping: ``` $ hping –traceroute -1 www.microsoft.com ```

  - Fingerprinting:
    - Nikto: ``` $ Nikto –h www.example.com || $ Nikto -h http://example.com –output Desktop/nikto.html -Format htm ```
    - Whatweb: ``` $ whatweb www.rsu.ac.in || $ whatweb –a 3 www.rsu.ac.in ```
    - w3af: web application attack & audit framework (Kali Linux)
    - Bliendelephant: ``` $ bliendelephant.py -h ```
    - Asp Auditor: ``` $ Asp-auditor.pl http://www.gtu.ac.in/default.aspx -bf ```
    - cms-explorer: ``` $ cms-explorer.pl –url http://microsoft.com –type drupal ```
    - joomscan: ``` $ joomscan –u http://www.joom.com/joomla ```
   
  - Web Application Firewall:
    - Waffit: ``` $ wafw00f https://microsoft.com ```
  
  - Directory:
    - cadaver:
    - w3af:
  
  - Load Balancer
    - lbd: ``` $ lbd www.microsoft.com ```
    - halberd: ```  halberd www.microsoft.com ```
  

1.10. Map Application Architecture

## 2. Configuration and Deployment Management Testing
2.1 Test Network/Infrastructure Configuration

2.2 Test Application Platform Configuration

2.3 Test File Extensions Handling for Sensitive Information

2.4 Backup and Unreferenced Files for Sensitive Information

2.5 Enumerate Infrastructure and Application Admin Interfaces

2.6 Test HTTP Methods

2.7 Test HTTP Strict Transport Security

2.8 Test RIA cross domain policy



## 3. Identity Management Testing 

3.1 Test Role Definitions

3.2 Test User Registration Process

3.3 Test Account Provisioning Process

3.4 Testing for Account Enumeration and Guessable User Account

3.5 Testing for Weak or unenforced username policy

3.6 Test Permissions of Guest/Training Accounts

3.7 Test Account Suspension/Resumption Process

## 4. Authentication Testing 

4.1 Testing for Credentials Transported over an Encrypted Channel

4.2 Testing for default credentials

4.3 Testing for Weak lock out mechanism

4.4 Testing for bypassing authentication schema

4.5 Test remember password functionality

4.6 Testing for Browser cache weakness

4.7 Testing for Weak password policy

4.8 Testing for Weak security question/answer

4.9 Testing for weak password change or reset functionalities

4.10 Testing for Weaker authentication in alternative channel


## 5. Authorization Testing 

5.1 Testing Directory traversal/file include

5.2 Testing for bypassing authorization schema

5.3 Testing for Privilege Escalation

5.4 Testing for Insecure Direct Object References

## 6. Session Management Testing 

6.1 Testing for Bypassing Session Management Schema

6.2 [Testing for Cookies attributes](https://github.com/NayanDZ/Cookie-Attributes)

6.3 Testing for Session Fixation

6.4 Testing for Exposed Session Variables

6.5 Testing for Cross Site Request Forgery

6.6 Testing for logout functionality

6.7 Test Session Timeout

6.8 Testing for Session puzzling (also known as Session Variable Overloading)


## 7. Input validation Testing

7.1 [Testing for Reflected Cross Site Scripting](https://github.com/NayanDZ/XSS)

7.2 [Testing for Stored Cross Site Scripting](https://github.com/NayanDZ/XSS)

7.3 Testing for HTTP Verb Tampering

7.4 Testing for HTTP Parameter pollution

7.5 [Testing for SQL Injection](https://github.com/NayanDZ/SQL/blob/main/README.md)

7.6 Oracle Testing

7.7 MySQL Testing

7.8 SQL Server Testing

7.9 Testing PostgreSQL

7.10 MS Access Testing

7.11 Testing for NoSQL injection

7.12 Testing for LDAP Injection

7.13 Testing for ORM Injection

7.14 Testing for XML Injection

7.15 Testing for SSI Injection

7.16 Testing for XPath Injection

7.17 IMAP/SMTP Injection

7.18 Testing for Code Injection

7.19 Testing for Local File Inclusion

7.20 Testing for Remote File Inclusion

7.21 Testing for Command Injection

7.22 Testing for Buffer overflow

7.23 Testing for Heap overflow

7.24 Testing for Stack overflow

7.25 Testing for Format string

7.26 Testing for incubated vulnerabilities

7.27 Testing for HTTP Splitting/Smuggling


## 8. Error Handling

***8.1 Analysis of Error Codes***
 - Web Server Errors: A common error that we can see during testing is the HTTP 404 Not Found.
  ![image](https://user-images.githubusercontent.com/65315090/128235946-c405fb72-d3cd-495e-ba89-8b563fb9a3fc.png)
 - Application Server Error: Application errors are returned by the application itself, rather than the web server. These could be error messages from framework code (ASP, JSP etc.) Detailed application errors typically provide information of server paths, installed libraries and application versions.
 - Database Error: Database errors are those returned by the Database System when there is a problem with the query or the connection
     80004005:- is a generic IIS error code which indicates that it could not establish a connection to its associated database
- ***Tools:*** ErrorMint

***8.2 Analysis of Stack Traces***
 - Stack traces are not vulnerabilities by themselves, but they often reveal information that is interesting to an attacker. 
 - Attackers attempt to generate these stack traces by tampering with the input to the web application with malformed HTTP requests and other input data.
 - Some tests to try include:
    -	Invalid input (such as input that is not consistent with application logic.
    -	Input that contains non alphanumeric characters or query syntax.
    -	Empty inputs.
    -	Inputs that are too long.
    -	Access to internal pages without authentication.
    -	Bypassing application flow.


## 9. Cryptography

***9.1 Testing for Weak SSL/TSL Ciphers, Insufficient Transport Layer Protection***
  - When the SSL/TLS service is present it is good but it following vulnerabilities exist:
    - SSL/TLS protocols, Ciphers, keys and renegotiation must be properly configured.
    - Certificate validity must be ensured:Testing SSL certificate validity – client and server (manually)

  - Tools:
    - sslscan: ```$ sslscan www.microsoft.com```
    - openssl: ```$ openssl s_client –connect www.facebook.com:443 –showcert```
    - sslyze ( TLS/SSL Implementation Analyzer): ```$ sslyze--regular www.microsoft.com```
    - testssl.sh: ```$ testssl.sh –t smtp smtp.gmail.com:25```
    - Nmap: ```$nmap --script ssl-enum-ciphers -p 443 microsoft.com
               $ nmap -p 443 --script ssl-css-injection microsoft.com```
    - SSL-heartbleed: ```$ nmap -p 433 --script ssl-heartbleed microsoft.com```
    - SSL-Poodle: ```$ nmap -sV --version-light --script ssl-poodle -p 443 microsoft.com```
  - Online SSL scan:
    - https://www.ssllabs.com/ssltest/
  

***9.2 Testing for Padding Oracle***
  - A padding oracle is a function of an application which decrypts encrypted data provided by the client, e.g. internal session state stored on the client, and leaks the state of the validity of the padding after decryption. 
  - The existence of a padding oracle allows an attacker to decrypt encrypted data and encrypt arbitrary data without knowledge of the key used for these cryptographic operations. 
  - This can lead to leakage of sensible data or to privilege escalation vulnerabilities, if integrity of the encrypted data is assumed by the application.

***9.3 Testing for Sensitive information sent via unencrypted channels***
  - As a rule of thumb if data must be protected when it is stored,this data must also be protected during transmission. 
  - Some examples for sensitive data are:
    - Information used in authentication (e.g. Credentials, PINs, Session identifiers, Tokens, Cookies…)
    - Information protected by laws, regulations or specific organizational policy (e.g. Credit Cards, Customers data)
  - If the application transmits sensitive information via unencrypted channels (e.g. HTTP) it is considered a security risk. Ex. are:
    - Basic authentication which sends authentication credentials in plain-text over HTTP
    - Form based authentication credentials sent via HTTP
    - Cookie Containing Session ID Sent over HTTP
  
## 10. Business Logic Testing

10.1 Test Business Logic Data Validation

10.2 Test Ability to Forge Requests

10.3 Test Integrity Checks

10.4 Test for Process Timing

10.5 Test Number of Times a Function Can be Used Limits

10.6 Testing for the Circumvention of Work Flows

10.7 Test Defenses Against Application Mis-use

10.8 Test Upload of Unexpected File Types

10.9 Test Upload of Malicious Files

## 11. Client Side Testing

11.1 [Testing for DOM based Cross Site Scripting](https://github.com/NayanDZ/XSS)

11.2 Testing for JavaScript Execution

11.3 Testing for HTML Injection

11.4 Testing for Client Side URL Redirect

11.5 Testing for CSS Injection

11.6 Testing for Client Side Resource Manipulation

11.7 [Test Cross Origin Resource Sharing](https://github.com/NayanDZ/CORS)

11.8 Testing for Cross Site Flashing

11.9 [Testing for Clickjacking](https://github.com/NayanDZ/clickjacking)

11.10 Testing WebSockets

11.11 Test Web Messaging

11.12 Test Local Storage

## Interception Proxies Tools:
 * Burp Suite – Burp Suite is an integrated platform for performing security testing of applications.
 * OWASP ZAP – OWASP Zed Attack Proxy Project is an open-source web application security scanner. It is intended to be used by both those new to application security as well as professional penetration testers.
 * Fiddler - Fiddler is an HTTP debugging proxy server application which can captures HTTP and HTTPS traffic and logs it for the user to review. Fiddler can also be used to modify HTTP traffic for troubleshooting purposes as it is being sent or received.
 * Charles Proxy – HTTP proxy / HTTP monitor / Reverse Proxy that enables a developer to view all of the HTTP and SSL / HTTPS traffic between their machine and the Internet.
