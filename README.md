# Common Web Application Vulnerability Scanner [[Demo]](https://nst-dev.000webhostapp.com/tools/scanner.php)
This is a simple web application vulnerability scanner that checks if a given URL or IP address is vulnerable to common web application security vulnerabilities. The tool is designed to help website owners and security researchers identify vulnerabilities in their web applications that can be exploited by attackers.

## How it works
The scanner uses regular expressions to search for common web application vulnerabilities in the HTML code of the target website. If a vulnerability is found, the tool displays a table of results indicating if it is vulnerable and to which vunlrabilties.

## The scanner checks for the following 35 vulnerabilities:

<details>
  <summary>Click to expand!</summary>
  
- SQL injection
- Cross-Site Scripting (XSS)
- File Inclusion
- Directory Traversal
- Remote File Inclusion
- Command Injection
- Cross-Site Request Forgery (CSRF)
- Unrestricted File Upload
- Password Cracking
- Session Hijacking
- Broken Authentication and Session Management
- Remote Code Execution
- Local File Inclusion
- Server Side Request Forgery (SSRF)
- XML External Entity (XXE) Injection
- Cross-Site Script Inclusion (XSSI)
- Server-Side Template Injection (SSTI)
- HTML Injection
- LDAP Injection
- XPath Injection
- Code Injection
- Object Injection
- Cross-Domain Scripting
- HTTP Response Splitting
- Buffer Overflow
- Format String Attack
- Command Injection (Windows)
- Insecure Cryptographic Storage
- Insecure Direct Object References
- Insufficient Logging and Monitoring
- Security Misconfiguration
- Cross-Site Script Inclusion (CSSI)
- Click Fraud
- Broken Access Control
- Clickjacking
- Hidden Form Fields.
</details>

<details>
  <summary>Click to for more info!</summary>
  
- SQL Injection - `this occurs when an attacker inserts malicious SQL code into an application's input which is then executed by the database.`
  
- XSS - `this occurs when an attacker injects malicious scripts into a web page, which are then executed by unsuspecting users.`
  
- File Inclusion - `this occurs when unsanitized user input is used to load a file or resource that should not be publicly accessible.`
  
- Directory Traversal - `this occurs when user input is used to navigate to directories outside of the intended directory hierarchy.`
  
- Remote File Inclusion - `this occurs when malicious code is included from a remote server, allowing an attacker to execute code on the server.`
  
- Command Injection - `this occurs when user input is passed directly to the command line, allowing an attacker to execute arbitrary commands.`
  
- Cross-Site Request Forgery (CSRF) - `this occurs when an attacker submits unauthorized requests on behalf of an authenticated user.`
  
- Unrestricted File Upload - `this occurs when malicious files are uploaded to a server and executed, allowing an attacker to execute code on the server.`
  
- Password Cracking - `this occurs when weak password policies allow attackers to guess or crack passwords.`
  
- Session Hijacking - `this occurs when an attacker gains access to a user's session ID and uses it to impersonate the user.`
  
- Broken Authentication and Session Management - `this occurs when poorly implemented authentication and session management allow attackers to bypass authentication and hijack sessions.`

- Remote Code Execution - `this occurs when user input is passed directly to the command line, allowing an attacker to execute arbitrary commands.`
  
- Local File Inclusion - `this occurs when unsanitized user input is used to load a file or resource that should not be publicly accessible.`
  
- Server Side Request Forgery (SSRF) - `this occurs when an attacker sends requests to internal or external servers on behalf of the vulnerable application.`
  
- XML External Entity (XXE) Injection - `this occurs when external entities are injected into an XML document, leading to the disclosure of sensitive information or execution of remote code.`

- Cross-Site Script Inclusion (XSSI) - `this occurs when an attacker can load a web page's JavaScript data from an external source, allowing them to execute malicious code on the victim's browser.`

- Server-Side Template Injection (SSTI) - `this occurs when an attacker injects malicious code into a template that is parsed and executed on the server-side.`
  
- HTML Injection - `this is a vulnerability where an attacker can inject malicious HTML code into a web page. This can allow the attacker to steal sensitive information or execute arbitrary code in the user's browser.`
  
- LDAP Injection - `this occurs when an attacker can inject malicious input into an LDAP search filter or command, allowing them to access or modify sensitive information in the LDAP directory.`

- XPath Injection - `this occurs when an attacker injects malicious input into an XPath query, allowing them to access or modify sensitive information.`
  
- Code Injection - `this occurs when an attacker can inject malicious code into a web application, allowing them to execute arbitrary code on the server.`
  
- Object Injection - `this occurs when an attacker can manipulate serialized objects in a web application to execute arbitrary code.`
  
- Cross-Domain Scripting - `this occurs when an attacker can inject a script into a web page from an external domain, allowing them to steal sensitive information from the victim's browser.`

- HTTP Response Splitting - `this occurs when an attacker can inject newlines into an HTTP response header, allowing them to insert additional HTTP headers and potentially perform other attacks.`

- Buffer Overflow - `An attack where an attacker can exploit a buffer overflow vulnerability in a web application to execute arbitrary code on the server.`
  
- Format String Attack - `An attack where an attacker can exploit a format string vulnerability in a web application to execute arbitrary code on the server.`
  
- Command Injection (Windows) - `An attack where an attacker can inject malicious input into a command executed on a Windows system, allowing them to execute arbitrary code on the server.`

- Insecure Cryptographic Storage - `An attack where an attacker can exploit weak cryptographic hashing algorithms to gain access to sensitive information.`
  
- Insecure Direct Object References - `Unvalidated or insufficiently validated user input is used to access sensitive information or functionality directly through URL manipulation.`

- Insufficient Logging and Monitoring - `Insufficient or nonexistent logging and monitoring capabilities make it difficult to detect and respond to security incidents.`
  
- Security Misconfiguration - `Incorrectly configured server settings or application properties can result in vulnerabilities that can be exploited by attackers.`
  
- Cross-Site Script Inclusion (CSSI) - `Unsanitized user input is used to include external resources, such as stylesheets, that could potentially be controlled by an attacker.`
  
- Click Fraud - `An attack where an attacker generates fake clicks on online advertisements to increase their revenue or to exhaust a competitor's advertising budget.`
  
- Broken Access Control - `An attack where an attacker is able to gain unauthorized access to resources or actions that should be protected by access controls, allowing them to steal sensitive information or perform malicious actions.`

- Clickjacking - `An attack where an attacker tricks a user into clicking on a button or link that is disguised as something else, such as a harmless button, but actually performs a malicious action, such as initiating a transfer of funds or installing malware.`

- Hidden Form Fields - `This is a type of vulnerability where a form field is hidden from the user, but still included in the form submission. This can allow attackers to submit unexpected data, potentially bypassing form validation or performing other malicious actions.`

- Object Injection - `This occurs when an attacker can manipulate serialized objects in a web application to execute arbitrary code.`
</details>

## How to use
To use the tool, simply enter the URL or IP address of the target webapplication in the input field and click the "Scan" button. The scanner will then check for vulnerabilities in the target webapplication and display a results table indicating what vulnrabilities are found with `not vulnrable` or `vulnrable` if any.

## Requirements
The tool requires PHP and cURL to be installed on the server in order to work properly.

## FootNotes 
- This is also in my [Basic-Websites-Portfolio](https://github.com/SirCryptic/Basic-Websites-Portfolio) Repo
