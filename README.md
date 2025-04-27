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

## Vulnerabilities Checked by cwv-scanner

The scanner checks for the following 36 vulnerabilities:

| Vulnerability                              | Description                                                                 |
|--------------------------------------------|-----------------------------------------------------------------------------|
| SQL Injection                              | Injecting malicious SQL code into inputs to manipulate database queries.     |
| XSS (Cross-Site Scripting)                 | Injecting malicious scripts into web pages viewed by users.                 |
| File Inclusion                             | Loading unauthorized files due to unsanitized user input.                   |
| Directory Traversal                        | Accessing restricted directories via manipulated input paths.               |
| Remote File Inclusion                      | Including malicious code from remote servers via user input.                |
| Command Injection                          | Executing arbitrary commands by injecting malicious input.                  |
| Cross-Site Request Forgery (CSRF)          | Tricking users into submitting unauthorized requests.                      |
| Unrestricted File Upload                   | Uploading malicious files that can be executed on the server.               |
| Password Cracking                          | Exploiting weak passwords to gain unauthorized access.                     |
| Session Hijacking                          | Stealing session IDs to impersonate authenticated users.                    |
| Broken Auth and Session Management         | Bypassing authentication or hijacking sessions due to poor implementation.  |
| Remote Code Execution                      | Executing arbitrary code on the server via malicious input.                |
| Local File Inclusion                       | Loading local files that should not be accessible via user input.          |
| Server Side Request Forgery (SSRF)         | Sending unauthorized requests to internal/external servers.                 |
| XML External Entity (XXE) Injection        | Exploiting XML parsing to access sensitive data or execute code.            |
| Cross-Site Script Inclusion (XSSI)         | Loading external JavaScript to execute malicious code in the browser.       |
| Server-Side Template Injection (SSTI)      | Injecting malicious code into server-side templates for execution.          |
| HTML Injection                             | Injecting malicious HTML to steal data or manipulate page content.          |
| XPath Injection                            | Manipulating XPath queries to access unauthorized data.                     |
| Code Injection                             | Injecting executable code into the application to run on the server.       |
| Object Injection                           | Manipulating serialized objects to execute arbitrary code.                  |
| Cross-Domain Scripting                     | Injecting scripts from external domains to steal browser data.              |
| HTTP Response Splitting                    | Injecting newlines into HTTP headers to manipulate responses.               |
| Buffer Overflow                            | Exploiting buffer overruns to execute arbitrary code.                      |
| Format String Attack                       | Exploiting format string vulnerabilities to execute code.                   |
| Command Injection (Windows)                | Injecting commands into Windows systems via malicious input.                |
| Insecure Cryptographic Storage             | Exploiting weak encryption to access sensitive data.                       |
| Insecure Direct Object References          | Accessing unauthorized resources via unvalidated input.                     |
| Insufficient Logging and Monitoring        | Failing to log or monitor security events, enabling undetected attacks.     |
| Security Misconfiguration                  | Exploiting misconfigured server or application settings.                   |
| Cross-Site Script Inclusion (CSSI)         | Including external stylesheets that could be controlled by attackers.       |
| Click Fraud                                | Generating fake ad clicks to manipulate revenue or budgets.                |
| Broken Access Control                      | Bypassing access controls to gain unauthorized access to resources.         |
| Clickjacking                               | Tricking users into clicking disguised malicious elements.                 |
| Hidden Form Fields                         | Submitting unexpected data via hidden form fields to bypass validation.     |
| Shellshock                                 | Exploiting Bash vulnerabilities to execute arbitrary code.                  |

<h2> Credits </h2>

- ⭐ [SirCryptic](https://github.com/sircryptic), [cwvs - Version: 1.0.0 Beta](https://github.com/sircryptic/cwv-scanner)

## FootNote/s
- Results cannot be 100% Gaurenteed
