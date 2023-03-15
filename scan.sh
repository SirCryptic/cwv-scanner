#!/bin/bash

## Title: Common Web Application Vulnerability Scanner [BASH\BETA]
## Developer: SirCryptic [ https://github.com/sircryptic ]
## Info: This is a simple web application vulnerability scanner 
##       that checks if a given URL or IP address is vulnerable to
##       common web application security vulnerabilities.
##
##       There is also a web based version here [ https://github.com/SirCryptic/Basic-Websites-Portfolio/tree/main/WebVulnrabilityScanner ]

# variables etc
HISTFILE="$HOME/.bash_history"
history -a "$HISTFILE"

if [[ $- == *i* ]]; then
    bind '"\e[A": history-search-backward'
    bind '"\e[B": history-search-forward'
    bind '"\e[C": forward-char'
    bind '"\e[D": backward-char'
fi
history -r
history -a
history -w

title="cwv-scanner"
echo -e '\033]2;'$title'\007'

# Set up color variables
black=`tput setaf 0`
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
magenta=`tput setaf 5`
cyan=`tput setaf 6`
white=`tput setaf 7`
reset=`tput sgr0`

# Set up banner files and color variables
info="
${cyan}Common Web Application Vulnerability Scanner${reset}

${yellow}THESE RESULTS MAY NOT BE 100% CORRECT!

${magenta}Developed By ${cyan}SirCryptic${reset}"

banner_files=(
    "banners/banner1.txt"
    "banners/banner2.txt"
    "banners/banner3.txt"
    "banners/banner4.txt"
    "banners/banner5.txt"
    "banners/banner6.txt"
)
colors=(
    "$(tput setaf 0)"
    "$(tput setaf 1)"
    "$(tput setaf 2)"
    "$(tput setaf 3)"
    "$(tput setaf 4)"
    "$(tput setaf 5)"
    "$(tput setaf 6)"
    "$(tput setaf 7)"
    "$(tput sgr0)"
)

# clear cli
clear

# Select a random banner file
selected_banner=${banner_files[RANDOM % ${#banner_files[@]}]}

# Select a random color
random_color=$((RANDOM % 8))
color=${colors[$random_color]}

# Print the banner with the selected color
cat "$selected_banner" | sed "s/.*/${color}&${colors[8]}/"
##
echo -e "${info}"
## We need some space......
echo ""
echo ""
 
# Read input from user and store in history file
read -e -p "Enter URL or IP address to scan: " url && echo "$url" >> ~/.bash_history 2>/dev/null

# Set variables
search_query=$(echo "$url"| sed 's#[/:]#\\#g') # escape forward slashes for regex

# Truncate search query if it exceeds maximum length
# This is done to limit the length of the search query that is displayed to the user and to prevent it from becoming too long and difficult to read or fit on the screen.
max_length=40
if (( ${#search_query} > $max_length )); then
    truncated_query=$(echo "${search_query:0:$max_length}...")
else
    truncated_query=$search_query
fi

# Print output
printf "\n\n${green}Host: %s\n" "${reset}$url"

# Check if input is a valid URL or IP address
if ! [[ $url =~ ^(([0-9]{1,3}\.){3}[0-9]{1,3})|([a-zA-Z]+://.*)$ ]]; then
    printf "${red}Error:${reset} Invalid URL or IP address entered.\n"
    exit 1
fi

# Set cURL options to verify SSL certificate
user_agents_file="./user_agents.txt"
user_agents=()
while read -r line; do
    user_agents+=("$line")
done < "$user_agents_file"
selected_user_agent=${user_agents[RANDOM % ${#user_agents[@]}]}
echo "$green Using user agent:$reset $selected_user_agent"
echo ""
curl_options=(
    --silent
    --show-error
    --max-time 10
    --insecure
    --user-agent "$selected_user_agent"
)
output=$(curl "${curl_options[@]}" "$url")
http_code=$(curl -o /dev/null -s -w "%{http_code}\n" "${curl_options[@]}" "$url")

# Check if SSL certificate is valid
if (( http_code == 0 )); then
    printf "${red}Error:${reset} Unable to connect to URL or IP address.\n"
    exit 1
elif (( http_code == 200 )); then
    # Array of regular expressions that match common web application vulnerabilities and their brief descriptions
    declare -A vulnerabilities=(
    ["SQL Injection"]="/'.*\\$/i" 
    # Malicious SQL code is inserted into an application's input and executed by the database.
    ["XSS"]="/<script>alert\\('XSS'\\);<\\/script>/i"
    # Malicious scripts are injected into a web page and executed by unsuspecting users.
    ["File Inclusion"]="/(include|require)(_once)?[\\s]*(\\(|[\"'])[\\s]*([A-Za-z0-9_]+)(\\.[A-Za-z]+)?([\"']|\\))/i"
    # Unsanitized user input is used to load a file or resource that should not be publicly accessible.
    ["Directory Traversal"]="/\.\.[\/\\\]/i"
    # User input is used to navigate to directories outside of the intended directory hierarchy.
    ["Remote File Inclusion"]="/(include|require)(_once)?[\s]*[\(\"']http(s)?:\/\/(.*)[\)\"']/i"
    # Malicious code is included from a remote server allowing an attacker to execute code on the server.
    ["Command Injection"]="/;.*;/i"
    # User input is passed directly to the command line allowing an attacker to execute arbitrary commands.
    ["Cross-Site Request Forgery (CSRF)"]="/<form.*action=[\"'](?!\s*https?:\/\/".$_SERVER['HTTP_HOST'].")[^\"']*\"/i"
    # An attacker submits unauthorized requests on behalf of an authenticated user.
    ["Unrestricted File Upload"]="/(jpg|jpeg|png|gif|svg|pdf|doc|docx|xls|xlsx|ppt|pptx|csv|txt)[\s]*$/i"
    # Malicious files are uploaded to a server and executed allowing an attacker to execute code on the server.
    ["Password Cracking"]="/\bpassword\b|\bpwd\b|\bpasscode\b|\bpin\b/i"
    # Weak password policies allow attackers to guess or crack passwords.
    ["Session Hijacking"]="/document\.cookie/i" #nst
    # An attacker gains access to a user's session ID and uses it to impersonate the user.
    ["Broken Auth and Session Management"]="/PHPSESSID|session_id|JSESSIONID/i"
    # Poorly implemented authentication and session management allow attackers to bypass authentication and hijack sessions.
    ["Remote Code Execution"]="/eval|exec|passthru|shell_exec|system|popen|pcntl_exec|proc_open/i"
    # User input is passed directly to the command line allowing an attacker to execute arbitrary commands.
    ["Local File Inclusion"]="/(include|require)(_once)?[\s]*(\(|[\"'])\.\.\/(.*)([\"']|\))/i"
    # Unsanitized user input is used to load a file or resource that should not be publicly accessible.
    ["Server Side Request Forgery (SSRF)"]="/curl|file_get_contents|fsockopen|pfsockopen|fopen|readfile|pop|imap|smtp|socket|ftp_(connect|login)|mysql_(connect|pconnect)/i" #sc@nst
    # An attacker sends requests to internal or external servers on behalf of the vulnerable application.
    ["XML External Entity (XXE) Injection"]="/<!ENTITY.*SYSTEM.*>/i"
    # An attack where external entities are injected into an XML document leading to the disclosure of sensitive information or execution of remote code.
    ["Cross-Site Script Inclusion (XSSI)"]="/[a-zA-Z0-9_]+\s*=\s*\[\s*\{.*\"/i"
    # An attack where an attacker can load a web page's JavaScript data from an external source allowing them to execute malicious code on the victim's browser.
    ["Server-Side Template Injection (SSTI)"]="/\{\{.*\}\}/i"
    # An attack where an attacker injects malicious code into a template that is parsed and executed on the server-side.
    ["HTML Injection"]="/<\s*script\s*>.*<\s*\/script\s*>/i" #scns
    # This is a vulnerability where an attacker can inject malicious HTML code into a web page. This can allow the attacker to steal sensitive information or execute arbitrary code in the user's browser.
    ["LDAP Injection"]="/[\|&;\$><\(\)]/i"
    # An attack where an attacker can inject malicious input into an LDAP search filter or command allowing them to access or modify sensitive information in the LDAP directory.
    ["XPath Injection"]="/'[^\']*'/i"
    # An attack where an attacker injects malicious input into an XPath query allowing them to access or modify sensitive information.
    ["Code Injection"]="/{{.*\..*}}|{{.*\|.*system.*}}|{{.*\|.*passthru.*}}/i"
    # An attack where an attacker can inject malicious code into a web application allowing them to execute arbitrary code on the server.
    ["Object Injection"]="/unserialize|__wakeup|__destruct/i"
    # An attack where an attacker can manipulate serialized objects in a web application to execute arbitrary code.
    ["Cross-Domain Scripting"]="/<script.*src=[\"'](?!https?:\/\/".$_SERVER['HTTP_HOST'].")[^\"']*\"/i"
    # An attack where an attacker can inject a script into a web page from an external domain allowing them to steal sensitive information from the victim's browser.
    ["HTTP Response Splitting"]="/\r\n|\n|\r/i"
    # An attack where an attacker can insert additional HTTP headers into a response allowing them to manipulate the behavior of the web application or perform phishing attacks.
    ["Buffer Overflow"]="/%s|%x|%n|%h|%p|%s|%u|%hn|%hhn|%lx|%lX|%llX/i"
    # An attack where an attacker can exploit a buffer overflow vulnerability in a web application to execute arbitrary code on the server.
    ["Format String Attack"]="/%n|%s|%p|%x|%d|%i|%o|%u|%e|%c|%f|%g|%h|%n|%hhn|%hn|%ln|%lln/i"
    # An attack where an attacker can exploit a format string vulnerability in a web application to execute arbitrary code on the server.
    ["Command Injection (Windows)"]="/\b(com|exe|bat|cmd)(\s*\/c|\s+\-c|\s+\-command|\s+\/k|\s+\-k|\s+\-batch|\s+\/b)\b/i"
    # An attack where an attacker can inject malicious input into a command executed on a Windows system allowing them to execute arbitrary code on the server.
    ["Insecure Cryptographic Storage"]="/(md5|sha1|sha256|sha384|sha512|crypt)\b/i"
    # An attack where an attacker can exploit weak cryptographic hashing algorithms to gain access to sensitive information.
    ["Insecure Direct Object References"]="/\/(users|accounts|orders)\/\d+/i"
    # Unvalidated or insufficiently validated user input is used to access sensitive information or functionality directly through URL manipulation.
    ["Insufficient Logging and Monitoring"]="/error_log\(|trigger_error\(|Exception|ERROR/i"
    # Insufficient or nonexistent logging and monitoring capabilities make it difficult to detect and respond to security incidents.
    ["Security Misconfiguration"]="/(phpinfo|display_errors|allow_url_include)\b/i"
    # Incorrectly configured server settings or application properties can result in vulnerabilities that can be exploited by attackers.
    ["Cross-Site Script Inclusion (CSSI)"]="/<link.*href=[\"'](?!\s*https?:\/\/".$_SERVER['HTTP_HOST'].")[^\"']*\"/i"
    # Unsanitized user input is used to include external resources such as stylesheets that could potentially be controlled by an attacker.
    ["Click Fraud"]="/(pay per click fraud|click fraud|ppc fraud|clickbot|click-spam|click spam|ad fraud)/i"
    # An attack where an attacker generates fake clicks on online advertisements to increase their revenue or to exhaust a competitor's advertising budget."
    ["Broken Access Control"]="/(path traversal|directory traversal|unauthorized access|access control|forceful browsing|privilege escalation|authorization bypass|insecure direct object reference|IDOR|access control matrix)/i"
    # An attack where an attacker is able to gain unauthorized access to resources or actions that should be protected by access controls allowing them to steal sensitive information or perform malicious actions.
    ["Clickjacking"]="/(clickjacking|UI redressing|UI redress attack|user interface redressing|user interface redress attack|UI overlay attack|overlay attack)/i" #root@nst
    # An attack where an attacker tricks a user into clicking on a button or link that is disguised as something else such as a harmless button but actually performs a malicious action such as initiating a transfer of funds or installing malware.
    ["Hidden Form Fields"]="/<input\s+type\s*=\s*[\"']?\s*hidden\s*[\"']?\s*>/i"
    # This is a type of vulnerability where a form field is hidden from the user but still included in the form submission. This can allow attackers to submit unexpected data potentially bypassing form validation or performing other malicious actions.
    ["Shellshock"]="/(bash( |%20|\\+|%2[Bb])?-c|\$\(printf|echo -ne|wget.*\?cmd=|curl.*\?data=.*bash|User-Agent:.*[\(\)\{\};\'\"\\\`\$][\(\)\{\};\'\"\\\`\$]|shellshock)/i"
    # Shellshock is a security vulnerability in the Unix Bash shell that was discovered in 2014. It allows an attacker to execute arbitrary code on a target system by exploiting a flaw in how Bash evaluates environment variables. The vulnerability affects many versions of Bash on Unix-based operating systems, including Linux and Mac OS X. It can be used to launch a variety of attacks, including remote code execution, privilege escalation, and data theft. The vulnerability has been patched, but it remains a risk for systems that have not been updated.   
    #
    ###################
    # LEAVE ME INTACT #
    ###################
    #   RJWDLY4EVA    #
    ###################
    #
    # //ADD FROM HERE
    # Feel Free To Add More
    )
    
    # Scan for vulnerabilities
    found_vulns=()
    for name in "${!vulnerabilities[@]}"; do
        if [[ $output =~ ${vulnerabilities[$name]} ]]; then
            found_vulns+=("$name:${green} Vulnerable${reset}")
        else
            found_vulns+=("$name:${red} Not Vulnerable${reset}")
        fi
    done

    # Output vulnerability scan results in a table
    printf "${cyan}Vulnerability Scan Results:${reset}\n\n"
    printf "%-50s %s\n" "${yellow}Vulnerability"           "${yellow} Status${reset}"
    for vuln in "${found_vulns[@]}"; do
        printf "%-40s %s\n" "${vuln%%:*}" "${vuln#*:}"
    done
    printf "\n"
    exit 0
else
    printf "${red}Error:${reset} HTTP ${yellow}$http_code ${reset} returned from URL or IP address.\n"
    exit 1
fi
