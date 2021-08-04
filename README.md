# 2-Web Application

<p align="center">
  <img src="owasp.jpeg">
</p>

### A1:2017 Injection: 
Injection flaws, such as SQL, OS, XXE, and LDAP injection occur when un-trusted data is sent to an interpreter as part of a command or query. 

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

### A7:2017 Cross-Site Scripting (XSS):
XSS flaws occur whenever an application includes un-trusted data in a new web page without proper validation or escaping, or updates an existing web page with user supplied data using a browser API that can create JavaScript. 
XSS allows attackers to execute scripts in the victim’s browser which can hijack user sessions, deface web sites, or redirect the user to malicious sites.
XSS Type:
•	Stored - Stored XSS vulnerability exists when data provided to a web application by a user is first stored persistently on the server.
•	Reflected - Reflected XSS vulnerability exists when data provided by a web client is used immediately by server-side scripts to generate a page of results for that user.
•	DOM-Based (Document Object Model) - A DOM-based XSS vulnerability exists within a page’s client-side script itself.

### A8:2017 Insecure Deserialization:
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
1.1 Conduct Search Engine Discovery and Reconnaissance for Information Leakage

1.2. Fingerprint Web Server

1.3. Review Webserver Metafiles for Information Leakage

1.4. Enumerate Applications on Webserver

1.5. Review Webpage Comments and Metadata for Information Leakage

1.6. Identify application entry points

1.7. Map execution paths through application

1.8. Fingerprint Web Application Framework

1.9. Fingerprint Web Application

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
## 6. Session Management Testing 
## 7. Input validation Testing
## 8. Error Handling
## 9. Cryptography
## 10. Business Logic Testing
## 11. Client Side Testing
