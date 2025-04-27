<p align="center">
    <img width="300" src="https://user-images.githubusercontent.com/48811414/225269122-4978b2e1-aa8c-4658-8050-bba073d3148d.gif" alt="Null Security Team">
</p>

<div align="center">
    <a href="https://github.com/sircryptic/cwv-scanner/stargazers"><img 
    src="https://img.shields.io/github/stars/sircryptic/cwv-scanner.svg" alt="GitHub stars"></a>
    <a href="https://github.com/sircryptic/cwv-scanner/network"><img src="https://img.shields.io/github/forks/sircryptic/cwv-scanner.svg" alt="GitHub forks"></a>
    <a href="https://github.com/sircryptic/cwv-scanner/watchers"><img src="https://img.shields.io/github/watchers/sircryptic/cwv-scanner.svg?style=social" alt="GitHub watchers"></a>
    <br>
    <a href="https://github.com/SirCryptic/cwv-scanner/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License"></a>
</div>
<h3 align="center">Web Application Vulnerability Scanner. [python Version]</h3>

This is a simple web application vulnerability scanner that checks if a given URL or IP address is vulnerable to common web application security vulnerabilities. The tool is designed to help website owners and security researchers identify vulnerabilities in their web applications that can be exploited by attackers.

## Installation
```bash
pip install cwv-scanner
```

## Usage
```bash
cwv-scanner example.com
```

## The scanner checks for the following 36 vulnerabilities:

| Vulnerability             | Description |
|---------------------------|-------------|
| SQL Injection             | This occurs when an attacker inserts malicious SQL code into an application's input which is then executed by the database. |
| XSS                       | This occurs when an attacker injects malicious scripts into a web page, which are then executed by unsuspecting users. |
| File Inclusion            | This occurs when unsanitized user input is used to load a file or resource that should not be publicly accessible. |
| Directory Traversal       | This occurs when user input is used to navigate to directories outside of the intended directory hierarchy. |
| Remote File Inclusion     | This occurs when malicious code is included from a remote server, allowing an attacker to execute code on the server. |
| Command Injection         | This occurs when user input is passed directly to the command line, allowing an attacker to execute arbitrary commands. |
| Cross-Site Request Forgery | This occurs when an attacker submits unauthorized requests on behalf of an authenticated user. |
| Unrestricted File Upload  | This occurs when malicious files are uploaded to a server and executed, allowing an attacker to execute code on the server. |
| Password Cracking         | This occurs when weak password policies allow attackers to guess or crack passwords. |
| Session Hijacking         | This occurs when an attacker gains access to a user's session ID and uses it to impersonate the user. |
| Broken Authentication and Session Management | This occurs when poorly implemented authentication and session management allow attackers to bypass authentication and hijack sessions. |
| Remote Code Execution     | This occurs when user input is passed directly to the command line, allowing an attacker to execute arbitrary commands. |
| Local File Inclusion      | This occurs when unsanitized user input is used to load a file or resource that should not be publicly accessible. |
| Server Side Request Forgery | This occurs when an attacker sends requests to internal or external servers on behalf of the vulnerable application. |
| XML External Entity (XXE) Injection | This occurs when external entities are injected into an XML document, leading to the disclosure of sensitive information or execution of remote code. |
| Cross-Site Script Inclusion (XSSI) | This occurs when an attacker can load a web page's JavaScript data from an external source, allowing them to execute malicious code on the victim's browser. |
| Server-Side Template Injection (SSTI) | This occurs when an attacker injects malicious code into a template that is parsed and executed on the server-side. |
| HTML Injection            | This is a vulnerability where an attacker can inject malicious HTML code into a web page. This can allow the attacker to steal sensitive information or execute arbitrary code in the user's browser. |
| XPath Injection           | This occurs when an attacker injects malicious input into an XPath query, allowing them to access or modify sensitive information. |
| Code Injection            | This occurs when an attacker can inject malicious code into a web application, allowing them to execute arbitrary code on the server. |
| Object Injection          | This occurs when an attacker can manipulate serialized objects in a web application to execute arbitrary code. |
| Cross-Domain Scripting    | This occurs when an attacker can inject a script into a web page from an external domain, allowing them to steal sensitive information from the victim's browser. |
| HTTP Response Splitting   | This occurs when an attacker can inject newlines into an HTTP response header, allowing them to insert additional HTTP headers and potentially perform other attacks. || Cross-Site Scripting (XSS)         | An attack where an attacker injects malicious code into a web page viewed by other users. This can allow them to steal sensitive information or perform actions on behalf of the user.                                 |
| SQL Injection                      | An attack where an attacker injects malicious SQL code into a web application to gain access to sensitive information or perform actions on the database.                                                           |
| Man-in-the-Middle (MitM)           | An attack where an attacker intercepts communication between two parties to steal or manipulate data. This can be done through various techniques, such as ARP poisoning or DNS spoofing.                  |
| Denial-of-Service (DoS)            | An attack where an attacker overwhelms a server or network with traffic or requests, rendering it unavailable to legitimate users.                                                                                  |
| Distributed Denial-of-Service (DDoS) | An attack where multiple systems are used to overwhelm a server or network with traffic or requests, rendering it unavailable to legitimate users.                                                           |
| Buffer Overflow                    | An attack where an attacker can exploit a buffer overflow vulnerability in a web application to execute arbitrary code on the server.                                                                          |
| Format String Attack               | An attack where an attacker can exploit a format string vulnerability in a web application to execute arbitrary code on the server.                                                                             |
| Command Injection (Windows)        | An attack where an attacker can inject malicious input into a command executed on a Windows system, allowing them to execute arbitrary code on the server.                                                        |
| Insecure Cryptographic Storage     | An attack where an attacker can exploit weak cryptographic hashing algorithms to gain access to sensitive information.                                                                                              |
| Insecure Direct Object References  | Unvalidated or insufficiently validated user input is used to access sensitive information or functionality directly through URL manipulation.                                                                   |
| Insufficient Logging and Monitoring | Insufficient or nonexistent logging and monitoring capabilities make it difficult to detect and respond to security incidents.                                                                                  |
| Security Misconfiguration          | Incorrectly configured server settings or application properties can result in vulnerabilities that can be exploited by attackers.                                                                               |
| Cross-Site Script Inclusion (CSSI) | Unsanitized user input is used to include external resources, such as stylesheets, that could potentially be controlled by an attacker.                                                                          |
| Click Fraud                        | An attack where an attacker generates fake clicks on online advertisements to increase their revenue or to exhaust a competitor's advertising budget.                                                            |
| Broken Access Control              | An attack where an attacker is able to gain unauthorized access to resources or actions that should be protected by access controls, allowing them to steal sensitive information or perform malicious actions. |
| Clickjacking                       | An attack where an attacker tricks a user into clicking on a button or link that is disguised as something else, such as a harmless button, but actually performs a malicious action.                           |
| Hidden Form Fields                 | This is a type of vulnerability where a form field is hidden from the user, but still included in the form submission. This can allow attackers to submit unexpected data, potentially bypassing form validation or performing other malicious actions. |
| Object Injection                   | This occurs when an attacker can manipulate serialized objects in a web application to execute arbitrary code.    
| Shellshock             | Shellshock is a security vulnerability in the Unix Bash shell that was discovered in 2014. It allows an attacker to execute arbitrary code on a target system by exploiting a flaw in how Bash evaluates environment variables. The vulnerability affects many versions of Bash on Unix-based operating systems, including Linux and Mac OS X. It can be used to launch a variety of attacks, including remote code execution, privilege escalation, and data theft. The vulnerability has been patched, but it remains a risk for systems that have not been updated. |

<h2> Credits </h2>

- ⭐ [SirCryptic](https://github.com/sircryptic), [cwvs - Version: 0.1 BETA](https://github.com/sircryptic/cwv-scanner)

## FootNote/s
- There is also a web based version in my [Basic-Websites-Portfolio](https://sircryptic.github.io/Basic-Websites-Portfolio) [Repo](https://github.com/SirCryptic/Basic-Websites-Portfolio) , This will also probably be likely incorperated into [phisherprice](https://github.com/sircryptic/phisherprice) at some point too.

- Results cannot be 100% Gaurenteed
