<!DOCTYPE html>
<html>
<head>
<!-- Hello & Welcome to my basic web vulnerability scanner, i see your peeking at the code (yes i left good comments this time :) enjoy ). -->

<!-- This tag sets the character encoding used by the document to UTF-8, which is a widely used character encoding that supports a wide range of characters from different languages. -->
<meta charset="UTF-8">
<!-- This tag specifies the name of the author of the document. -->
<meta name="Author" content="scns"/>
<!-- This tag specifies the copyright owner of the document. -->
<meta name="copyright" content="scns"/>
<!-- This tag provides a brief description of the document's content.  -->
<meta name="description" content="NullSecurityTeam Web Vulnerability Scanner, speed up your search for that pesky bug!"/>
<!-- This tag specifies the URL of an image to be used as a thumbnail when sharing the webpage on social media.  -->
<meta property="og:image" content="https://avatars.githubusercontent.com/u/67664600?s=200&v=4">
<!-- This tag specifies the URL of the favicon (short for "favorite icon"), which is the small icon that appears in the browser tab and bookmarks. -->
<link rel="icon" href="https://avatars.githubusercontent.com/u/67664600?s=200&v=4" type="image/png">

	<title>Web Vulnerability Scanner</title>
    <style>
form {
  display: flex;
  align-items: center;
}
#header {
  position: relative;
  height: 100px;
  background-color: #333;
  color: #fff;
}

#header img {
  position: absolute;
  top: 0;
  right: 0;
  height: 100px;
}

#header h1 {
  margin: 0;
  padding: 20px;
}

#content {
  margin-top: 120px;
}
#url {
  width: 500px;
  height: 30px;
  font-size: 18px;
  background-color: #f2f2f2;
  border: 1px solid #ccc;
  padding: 8px;

}
    
#submitBtn {
  width: 95px;
  height: 40px;
  font-size: 18px;
  background-color: #4CAF50;
  color: white;
  border: none;
  border-radius: 4px;
  cursor: pointer;
  margin-left: 10px;
}
    
#table {
  margin-top: 50px;
  border-collapse: collapse;
  width: 150%;
  border: 1px solid black;
  max-width: 625px;
}

#table td,
#table th {
  border: 1px solid #ddd;
  padding: 8px;
  text-align: left;
}

#table th {
  padding-top: 12px;
  padding-bottom: 12px;
  background-color: #4CAF50;
  color: white;
}

table {
  border: 1px solid black;
  width: 150%;
  border: 1px solid black;
  max-width: 625px;
}

table th {
  border: 1px solid black;
  background-color: #4CAF50;
  color: white;
}

table td {
  border: 1px solid black;
  padding: 8px;
  text-align: left;
}
body {
  background-color: #333;
  color: #fff;

}
header {
  height: 500px;
  background-image: url("https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fwallpapercave.com%2Fwp%2Fwp7120228.jpg&f=1&nofb=1&ipt=e9dcf69d45e1fd977eff57589e313bb2fabf3b0c60839f1f379f3b264b38f510&ipo=images");
  background-repeat: no-repeat;
  background-size: cover;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 10px;
  align-items: center;
  text-shadow: 2px 2px #000;
}
.banner {
  width: 600px; /* set the width of the box */
  height: 50px; /* set the height of the box */
  background-color: #333;
  border: 2px solid #fff;
  box-shadow: 0 0 10px #4CAF50;
  padding: 10px;
  text-align: center;
  font-size: 64px;
  font-weight: bold;
  margin-bottom: 5px;
}
#typing-effect {
    font-size: 24px;
    font-family: sans-serif;
    border-right: 3px solid black;
    white-space: nowrap;
    overflow: hidden;
    animation: blink-caret 0.75s step-end infinite;
    display: inline-block;
  }

  @keyframes blink-caret {
    from, to { border-right-color: transparent; }
    50% { border-right-color: black; }
  }
  .footer {
  position: fixed;
  bottom: 0;
  left: 0;
  width: 100%;
  text-align: center;
  font-size: 12px;
  color: #fff;
  padding: 10px;
}

.footer a {
  color: #fff;
}

.footer span {
  display: inline-block;
  vertical-align: middle;
  margin-right: 5px;
}

</style>
	<script>
		function changeBtnText() {
			document.getElementById("submitBtn").value = "Scanning...";
		}
	</script>
</head>
<body>
<div id="header">
  <img src="https://avatars.githubusercontent.com/u/67664600?s=200&v=4" alt="Your Logo">
        <div class="banner">
        <div id="typing-effect" style="font-size: 24px; font-family: sans-serif; border-right: 3px solid black; white-space: nowrap; overflow: hidden; animation: blink-caret 0.75s step-end infinite; vertical-align: top;"></div>
          </div>
	      <form method="POST" action="" onsubmit="changeBtnText()">
		  <label for="url"></label>
		<input type="text" id="url" name="url" required placeholder="Enter URL or IP Address..."><br><br>
	<input type="submit" id="submitBtn" value="Scan">
	</form>
	<br>
    <?php
    // Check if the form has been submitted and retrieve the URL input
      if(isset($_POST['url'])){
      $url = $_POST['url'];
      $search_query = htmlspecialchars($_POST['url']);
      $color = "#FFFFFF";
      $maxLength = 50;
      $truncated_query = substr($search_query, 0, $maxLength);
      $background_color1 = "#4CAF50";
      $background_color2 = "#FFA500";
      $box_width = "500px";

        echo "<p style='color: $color; display: inline-block; white-space: nowrap; box-shadow: 0px 0px 5px rgba(0, 0, 0, 0.3); padding: 10px; overflow: hidden;'>";
        echo "<span style='background-color: $background_color1;'>Host:</span>";
        echo "<span style='background-color: $background_color2;'>$truncated_query</span>";
        echo "</p>";

    // Check if input is a valid URL or IP address
    if(!filter_var($url, FILTER_VALIDATE_URL) && !filter_var($url, FILTER_VALIDATE_IP)){
        echo "<p>Error: Invalid URL or IP address entered.</p>";
        exit;
    }
    
    // Set cURL options to verify SSL certificate
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    $output = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    // Check if SSL certificate is valid
    if($http_code == 0){
        echo "<p>Error: Unable to connect to URL or IP address.</p>";
        exit;
    } elseif($http_code == 200){
/**
 * Array of regular expressions that match common web application vulnerabilities
 * and their brief descriptions. enjoy researching :)
 */
$vulnerabilities = array(
    "SQL Injection" => "/'.*\\\\$/i",
    // Malicious SQL code is inserted into an application's input and executed by the database.
    "XSS" => "/<script>alert\('XSS'\);<\/script>/i",
    // Malicious scripts are injected into a web page and executed by unsuspecting users.
    "File Inclusion" => "/(include|require)(_once)?[\s]*(\(|[\"'])[\s]*([A-Za-z0-9_]+)(\.[A-Za-z]+)?([\"']|\))/i",
    // Unsanitized user input is used to load a file or resource that should not be publicly accessible.
    "Directory Traversal" => "/\.\.[\/\\\]/i",
    // User input is used to navigate to directories outside of the intended directory hierarchy.
    "Remote File Inclusion" => "/(include|require)(_once)?[\s]*[\(\"']http(s)?:\/\/(.*)[\)\"']/i",
    // Malicious code is included from a remote server, allowing an attacker to execute code on the server.
    "Command Injection" => "/;.*;/i",
    // User input is passed directly to the command line, allowing an attacker to execute arbitrary commands.
    "Cross-Site Request Forgery (CSRF)" => "/<form.*action=[\"'](?!\s*https?:\/\/".$_SERVER['HTTP_HOST'].")[^\"']*\"/i",
    // An attacker submits unauthorized requests on behalf of an authenticated user.
    "Unrestricted File Upload" => "/(jpg|jpeg|png|gif|svg|pdf|doc|docx|xls|xlsx|ppt|pptx|csv|txt)[\s]*$/i",
    // Malicious files are uploaded to a server and executed, allowing an attacker to execute code on the server.
    "Password Cracking" => "/\bpassword\b|\bpwd\b|\bpasscode\b|\bpin\b/i",
    // Weak password policies allow attackers to guess or crack passwords.
    "Session Hijacking" => "/document\.cookie/i",
    // An attacker gains access to a user's session ID and uses it to impersonate the user.
    "Broken Authentication and Session Management" => "/PHPSESSID|session_id|JSESSIONID/i",
    // Poorly implemented authentication and session management allow attackers to bypass authentication and hijack sessions.
    "Remote Code Execution" => "/eval|exec|passthru|shell_exec|system|popen|pcntl_exec|proc_open/i",
    // User input is passed directly to the command line, allowing an attacker to execute arbitrary commands.
    "Local File Inclusion" => "/(include|require)(_once)?[\s]*(\(|[\"'])\.\.\/(.*)([\"']|\))/i",
    // Unsanitized user input is used to load a file or resource that should not be publicly accessible.
    "Server Side Request Forgery (SSRF)" => "/curl|file_get_contents|fsockopen|pfsockopen|fopen|readfile|pop|imap|smtp|socket|ftp_(connect|login)|mysql_(connect|pconnect)/i",
    // An attacker sends requests to internal or external servers on behalf of the vulnerable application.
    "XML External Entity (XXE) Injection" => "/<!ENTITY.*SYSTEM.*>/i",
    // An attack where external entities are injected into an XML document, leading to the disclosure of sensitive information or execution of remote code.
    "Cross-Site Script Inclusion (XSSI)" => "/[a-zA-Z0-9_]+\s*=\s*\[\s*\{.*\"/i",
    // An attack where an attacker can load a web page's JavaScript data from an external source, allowing them to execute malicious code on the victim's browser.
    "Server-Side Template Injection (SSTI)" => "/\{\{.*\}\}/i",
    // An attack where an attacker injects malicious code into a template that is parsed and executed on the server-side.
    "HTML Injection" => "/<\s*script\s*>.*<\s*\/script\s*>/i",
    // This is a vulnerability where an attacker can inject malicious HTML code into a web page. This can allow the attacker to steal sensitive information or execute arbitrary code in the user's browser.
    "LDAP Injection" => "/[\|&;\$><\(\)]/i",
    // An attack where an attacker can inject malicious input into an LDAP search filter or command, allowing them to access or modify sensitive information in the LDAP directory.
    "XPath Injection" => "/'[^\']*'/i",
    // An attack where an attacker injects malicious input into an XPath query, allowing them to access or modify sensitive information.
    "Code Injection" => "/{{.*\..*}}|{{.*\|.*system.*}}|{{.*\|.*passthru.*}}/i",
    // An attack where an attacker can inject malicious code into a web application, allowing them to execute arbitrary code on the server.
    "Object Injection" => "/unserialize|__wakeup|__destruct/i",
    // An attack where an attacker can manipulate serialized objects in a web application to execute arbitrary code.
    "Cross-Domain Scripting" => "/<script.*src=[\"'](?!https?:\/\/".$_SERVER['HTTP_HOST'].")[^\"']*\"/i",
    // An attack where an attacker can inject a script into a web page from an external domain, allowing them to steal sensitive information from the victim's browser.
    "HTTP Response Splitting" => "/\r\n|\n|\r/i",
    // An attack where an attacker can insert additional HTTP headers into a response, allowing them to manipulate the behavior of the web application or perform phishing attacks.
    "Buffer Overflow" => "/%s|%x|%n|%h|%p|%s|%u|%hn|%hhn|%lx|%lX|%llX/i",
    // An attack where an attacker can exploit a buffer overflow vulnerability in a web application to execute arbitrary code on the server.
    "Format String Attack" => "/%n|%s|%p|%x|%d|%i|%o|%u|%e|%c|%f|%g|%h|%n|%hhn|%hn|%ln|%lln/i",
    // An attack where an attacker can exploit a format string vulnerability in a web application to execute arbitrary code on the server.
    "Command Injection (Windows)" => "/\b(com|exe|bat|cmd)(\s*\/c|\s+\-c|\s+\-command|\s+\/k|\s+\-k|\s+\-batch|\s+\/b)\b/i",
    // An attack where an attacker can inject malicious input into a command executed on a Windows system, allowing them to execute arbitrary code on the server.
    "Insecure Cryptographic Storage" => "/(md5|sha1|sha256|sha384|sha512|crypt)\b/i",
    // An attack where an attacker can exploit weak cryptographic hashing algorithms to gain access to sensitive information.
    "Insecure Direct Object References" => "/\/(users|accounts|orders)\/\d+/i",
    // Unvalidated or insufficiently validated user input is used to access sensitive information or functionality directly through URL manipulation.
    "Insufficient Logging and Monitoring" => "/error_log\(|trigger_error\(|Exception|ERROR/i",
    // Insufficient or nonexistent logging and monitoring capabilities make it difficult to detect and respond to security incidents.
    "Security Misconfiguration" => "/(phpinfo|display_errors|allow_url_include)\b/i",
    // Incorrectly configured server settings or application properties can result in vulnerabilities that can be exploited by attackers.
    "Cross-Site Script Inclusion (CSSI)" => "/<link.*href=[\"'](?!\s*https?:\/\/".$_SERVER['HTTP_HOST'].")[^\"']*\"/i",
    // Unsanitized user input is used to include external resources, such as stylesheets, that could potentially be controlled by an attacker.
    "Click Fraud" => "/(pay per click fraud|click fraud|ppc fraud|clickbot|click-spam|click spam|ad fraud)/i",
    // An attack where an attacker generates fake clicks on online advertisements to increase their revenue or to exhaust a competitor's advertising budget."
    "Broken Access Control" => "/(path traversal|directory traversal|unauthorized access|access control|forceful browsing|privilege escalation|authorization bypass|insecure direct object reference|IDOR|access control matrix)/i",
    // An attack where an attacker is able to gain unauthorized access to resources or actions that should be protected by access controls, allowing them to steal sensitive information or perform malicious actions.
    "Clickjacking" => "/(clickjacking|UI redressing|UI redress attack|user interface redressing|user interface redress attack|UI overlay attack|overlay attack)/i",
    // An attack where an attacker tricks a user into clicking on a button or link that is disguised as something else, such as a harmless button, but actually performs a malicious action, such as initiating a transfer of funds or installing malware.
    "Hidden Form Fields" => "/<input\s+type\s*=\s*[\"']?\s*hidden\s*[\"']?\s*>/i"
    // This is a type of vulnerability where a form field is hidden from the user, but still included in the form submission. This can allow attackers to submit unexpected data, potentially bypassing form validation or performing other malicious actions.
);
        
        // Scan for vulnerabilities
        $found_vulns = array();
        foreach($vulnerabilities as $name => $regex){
            if(preg_match($regex, $output)){
                $found_vulns[] = array(
                    "name" => $name,
                    "status" => true
                );
            } else {
                $found_vulns[] = array(
                    "name" => $name,
                    "status" => false
                );
            }
        }
        
        // Output vulnerability scan results in a table
        echo "<table>";
        echo "<tr><th>Vulnerability</th><th>Status</th></tr>";
        foreach($found_vulns as $vuln){
            echo "<tr>";
            echo "<td>".$vuln['name']."</td>";
            if($vuln['status']){
                echo "<td style='color:green;'>Vulnerable</td>";
            } else {
                echo "<td style='color:red;'>Not Vulnerable</td>";
            }
            echo "</tr>";
        }
        echo "</table>";
		echo "<script>document.getElementById('submitBtn').value = 'Scan';</script>";
    } else {
        echo "<p>Error: HTTP ".$http_code." returned from URL or IP address.</p>";
        exit;
    }
}
?>
<script>
  const TEXT = "Web Vulnerability Scanner By NullSecurityTeam"; // Text to be typed
  const SPEED = 100; // Typing speed in milliseconds

  let index = 0;
  const typingEffect = setInterval(() => {
    const element = document.getElementById("typing-effect");
    if (index >= TEXT.length) {
      clearInterval(typingEffect);
      return;
    }
    element.textContent += TEXT.charAt(index);
    index++;
  }, SPEED);
</script>
</div>
<div class="footer">
<span>&copy; 2023 NullSecurityTeam. All rights reserved. Find us on <a href="https://github.com/NULL-Security-Team">GitHub</a>.</span>
</div>
</body>
</html>