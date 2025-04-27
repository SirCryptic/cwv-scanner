#!/usr/bin/env python3

import argparse
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple, Set
from urllib.parse import urlparse, urljoin
import random
import csv
from concurrent.futures import ThreadPoolExecutor

import requests
from fake_useragent import UserAgent
from tabulate import tabulate
from bs4 import BeautifulSoup, SoupStrainer

# Configure logging
logger = logging.getLogger(__name__)

def setup_logging(debug: bool):
    """Configure logging with optional debug mode."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)]
    )

class WebVulnScanner:
    """A class to scan web applications for common vulnerabilities."""
    
    def __init__(self, user_agents_file: str = "user_agents.txt", request_delay: float = 1.0):
        self.ua = UserAgent()
        self.user_agents_file = user_agents_file
        self.vulnerabilities = self.load_vulnerabilities()
        self.waf_indicators = self.load_waf_indicators()
        self.session = requests.Session()
        self.request_delay = request_delay
        self.active_payloads = {
            "Server-Side Template Injection (SSTI)": "{{7*7}}",
            "XSS": "<script>alert(1)</script>",
            "Cross-Site Request Forgery (CSRF)": {},
            "Directory Traversal": ["../../etc/passwd", "../../../../etc/shadow", "../config.php"]
        }
        self.confidence_scores = {
            "SQL Injection": 0.7,
            "XSS": 0.7,
            "File Inclusion": 0.6,
            "Directory Traversal": 0.6,
            "Remote File Inclusion": 0.7,
            "Command Injection": 0.7,
            "Cross-Site Request Forgery (CSRF)": 0.6,
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
            "Shellshock": 0.7
        }
        self.trusted_domains = [
            "youtube.com", "youtu.be", "google.com", "fonts.googleapis.com",
            "cdnjs.cloudflare.com", "fonts.gstatic.com", "googletagmanager.com",
            "cloudfront.net", "elfsight.com", "cdn.jsdelivr.net", "ajax.googleapis.com"
        ]
        self.waf_detected = False
        self.waf_block_counts = {}
        self.current_user_agent = self.get_user_agent()
        logger.info("Initialized with user agent: %s", self.current_user_agent)

    def load_vulnerabilities(self) -> Dict[str, str]:
        """Load vulnerability patterns from a JSON file."""
        vuln_file = Path(__file__).parent / "vulnerabilities.json"
        try:
            with vuln_file.open("r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error("Vulnerability file not found: %s", vuln_file)
            sys.exit(1)
        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in vulnerabilities file: %s", e)
            sys.exit(1)

    def load_waf_indicators(self) -> List[str]:
        """Load WAF indicators from a JSON file."""
        waf_file = Path(__file__).parent / "waf_indicators.json"
        default_indicators = ["access denied", "firewall", "sucuri", "block id", "cloudflare", "waf", "forbidden"]
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
            target = f"https://{target}" if "://" not in target else target
        
        if re.match(url_pattern, target) or re.match(ip_pattern, target):
            return True, target
        return False, target

    def get_user_agent(self) -> str:
        """Get a random user agent from file or fake-useragent."""
        user_agents_file = Path(__file__).parent / self.user_agents_file
        if user_agents_file.exists():
            with user_agents_file.open("r", encoding="utf-8") as f:
                user_agents = [line.strip() for line in f if line.strip()]
                if user_agents:
                    return random.choice(user_agents)
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
                normalized_target, headers=headers, timeout=10, verify=True
            )
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
            response = self.session.get(test_url, timeout=5, verify=True, headers=headers)
            logger.debug("WAF pre-scan: GET %s, Response: %s", test_url, response.text[:200])
            if self.is_waf_response(response.text):
                logger.warning("WAF detected at %s", target)
                return True
            return False
        except requests.RequestException as e:
            logger.debug("WAF pre-scan failed: %s", e)
            return False

    def crawl_pages(self, target: str, max_pages: int = 5) -> List[Tuple[str, int, str]]:
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

            results.append((current_url, status_code, content))
            visited.add(current_url)

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

        logger.info("Crawled %d pages: %s", len(results), ", ".join(visited))
        if invalid_urls:
            logger.warning("Skipped %d invalid URLs: %s", len(invalid_urls), ", ".join(sorted(invalid_urls)[:5]) + ("..." if len(invalid_urls) > 5 else ""))
        return results

    def active_scan(self, target: str, soup: BeautifulSoup, name: str) -> List[Tuple[str, str, float, str]]:
        """Perform active scanning by injecting payloads and analyzing responses."""
        matches = []
        parsed_url = urlparse(target)
        domain = parsed_url.netloc or parsed_url.path
        if not domain:
            logger.warning("Invalid target URL for active scanning: %s", target)
            return matches
        normalized_target = f"https://{domain}" if not target.startswith(("http://", "https://")) else target
        
        if self.waf_detected and name in ["Directory Traversal"]:
            logger.warning("Skipping active %s tests due to WAF detection", name)
            return matches

        if name in ["Server-Side Template Injection (SSTI)", "XSS"]:
            payload = self.active_payloads[name]
            forms = soup.find_all('form')
            for form in forms[:2]:
                action = form.get('action') or ''
                if not action.startswith(('http://', 'https://')):
                    action = urljoin(normalized_target, action)
                inputs = {
                    inp.get('name'): payload
                    for inp in form.find_all('input')
                    if inp.get('name') and inp.get('type') not in ['hidden', 'submit']
                }
                if inputs:
                    try:
                        time.sleep(self.request_delay)
                        response = self.session.post(action, data=inputs, timeout=5, verify=True)
                        logger.debug("Active %s test: POST %s with %s, Response: %s", name, action, inputs, response.text[:200])
                        if name == "SSTI" and "49" in response.text:
                            matches.append((response.text[:120], f"Active SSTI test: {payload} -> 49", 0.9, "Active"))
                        elif name == "XSS" and payload in response.text:
                            matches.append((response.text[:120], f"Active XSS test: {payload} reflected", 0.9, "Active"))
                    except requests.RequestException as e:
                        logger.debug("Active %s test failed: %s", name, e)
                        pass
            
            test_url = f"{normalized_target}?test={payload}"
            try:
                time.sleep(self.request_delay)
                response = self.session.get(test_url, timeout=5, verify=True)
                logger.debug("Active %s test: GET %s, Response: %s", name, test_url, response.text[:200])
                if name == "SSTI" and "49" in response.text:
                    matches.append((response.text[:120], f"Active SSTI test: {payload} -> 49", 0.9, "Active"))
                elif name == "XSS" and payload in response.text:
                    matches.append((response.text[:120], f"Active XSS test: {payload} reflected", 0.9, "Active"))
            except requests.RequestException as e:
                logger.debug("Active %s test failed: %s", name, e)
                pass

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
                        response = self.session.post(action, data=inputs, timeout=5, verify=True)
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
                        response = self.session.get(test_url, timeout=5, verify=True)
                        response_text = response.text.lower()
                        logger.debug("Active Directory Traversal test: GET %s, Response: %s", test_url, response.text[:200])
                        if self.is_waf_response(response_text):
                            self.waf_block_counts[name] = self.waf_block_counts.get(name, 0) + 1
                            logger.debug("WAF blocked Directory Traversal test: %s", test_url)
                            continue
                        if (
                            any(keyword in response_text for keyword in ["root:x:0:0", "bin/bash", "shadow", "<?php"])
                            and re.search(r"^[a-z0-9_]+:x:[0-9]+:[0-9]+:", response.text, re.MULTILINE)
                            and not response.text.strip().startswith("<!DOCTYPE html")
                            and not "<html" in response_text[:100]
                        ):
                            matches.append((
                                response.text[:120],
                                f"Active Directory Traversal test: {param}={payload} exposed sensitive file",
                                0.9,
                                "Active"
                            ))
                    except requests.RequestException as e:
                        logger.debug("Active Directory Traversal test failed: %s", e)
                        pass

        return matches

    def check_vulnerability(self, args: Tuple[str, str, str, BeautifulSoup, str, Dict]) -> Tuple[str, str, List[Tuple[str, str, float, str]]]:
        """Check a single vulnerability with passive and active scanning."""
        name, pattern, content, soup, target, headers = args
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
                            matches.append((form_str[:120], match, self.confidence_scores[name], "Passive"))
            elif name == 'Directory Traversal':
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), self.confidence_scores[name], "Passive")
                    for match in compiled_pattern.finditer(content)
                    if not any(attr in content[max(0, match.start() - 20):match.start()].lower() for attr in ['href="', 'href=\'', 'src="', 'src=\'', 'value="', 'value=\''])
                ]
            elif name == 'Cross-Domain Scripting':
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), self.confidence_scores[name], "Passive")
                    for match in compiled_pattern.finditer(content)
                    if not any(domain in match.group(0).lower() for domain in self.trusted_domains)
                    and not match.group(0).startswith(('<script src="/', '<script src="//'))
                    and re.match(r'<script\s+src=["\'][^\'"]*["\']\s*>', match.group(0))
                    and '://' in match.group(0)
                ]
            elif name == 'Cross-Site Script Inclusion (CSSI)':
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), self.confidence_scores[name], "Passive")
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
                        if (
                            not match.group(0).startswith(('<meta', '<noscript', '<div'))
                            and not any(domain in match.group(0).lower() for domain in self.trusted_domains)
                            and not match.group(0).startswith(('<script src="/', '<script src="./', '<script src="../'))
                            and 'w-script' not in match.group(0).lower()
                            and 'nonce=' not in match.group(0).lower()
                        ):
                            confidence = self.confidence_scores[name] * (0.5 if csp_present else 1.0)
                            matches.append((
                                content[max(0, match.start() - 10):match.end() + 10],
                                match.group(0),
                                confidence,
                                "Passive"
                            ))

            else:
                matches = [
                    (content[max(0, match.start() - 10):match.end() + 10], match.group(0), self.confidence_scores[name], "Passive")
                    for match in compiled_pattern.finditer(content)
                ]

            matches = [
                m for m in matches
                if (len(m[1]) >= 5 or m[1] in ['exec(', 'system(']) and not m[1].isspace()
            ][:50]

            if name in self.active_payloads:
                active_matches = self.active_scan(target, soup, name)
                matches.extend(active_matches)

            status = "\033[32mVulnerable\033[0m" if matches else "\033[31mNot Vulnerable\033[0m"
            return (name, status, matches)
        except re.error as e:
            logger.warning("Invalid regex pattern for %s: %s", name, e)
            return (name, "\033[33mError in pattern\033[0m", [])

    def check_vulnerabilities(self, pages: List[Tuple[str, int, str]]) -> List[Tuple[str, str, List[Tuple[str, str, float, str]]]]:
        """Check vulnerabilities across multiple pages."""
        aggregated_results = []
        self.waf_block_counts.clear()
        for url, status_code, content in pages:
            if status_code != 200:
                continue
            logger.debug("Scanning page: %s", url)
            soup = BeautifulSoup(content, 'html.parser', parse_only=SoupStrainer(['script', 'style', 'form', 'link']))
            
            content_cleaned = content
            if soup.find(['script', 'style']):
                for tag in soup(['script', 'style']):
                    tag.decompose()
                content_cleaned = str(soup)

            _, _, _, headers = self.scan_target(url, base_url=url)
            with ThreadPoolExecutor() as executor:
                tasks = [
                    (name, pattern, content if name in ['XSS', 'Cross-Site Script Inclusion (CSSI)', 'Cross-Domain Scripting', 'Cross-Site Request Forgery (CSRF)', 'Directory Traversal'] else content_cleaned, soup, url, headers)
                    for name, pattern in self.vulnerabilities.items()
                ]
                results = list(executor.map(self.check_vulnerability, tasks))
                if not aggregated_results:
                    aggregated_results = results
                else:
                    for i, (name, status, matches) in enumerate(results):
                        if matches:
                            aggregated_results[i] = (
                                name,
                                status,
                                aggregated_results[i][2] + matches
                            )

        for vuln, count in self.waf_block_counts.items():
            logger.warning("WAF blocked %d %s test(s) across all pages", count, vuln)

        return aggregated_results

    def display_results(self, results: List[Tuple[str, str, List[Tuple[str, str, float, str]]]]):
        """Display scan results in a formatted table with matched strings and confidence."""
        headers = ["\033[33mVulnerability\033[0m", "\033[33mStatus\033[0m", "\033[33mConfidence\033[0m", "\033[33mMatch Type\033[0m"]
        table_data = [
            (name, status, f"{max([m[2] for m in matches] or [0]):.0%}" if matches else "N/A", ", ".join(set(m[3] for m in matches)) if matches else "N/A")
            for name, status, matches in results
        ]
        print("\n\033[36mVulnerability Scan Results:\033[0m\n")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))

        if self.waf_detected:
            print("\n\033[33mWarning: Web Application Firewall (WAF) detected. Some active tests were skipped or may be blocked, affecting results.\033[0m")

        print("\n\033[36mDetails of Vulnerable Findings:\033[0m")
        for name, status, matches in results:
            if status == "\033[32mVulnerable\033[0m" and matches:
                print(f"\nVulnerability: {name}")
                print("Matched Strings:")
                for context, match, confidence, match_type in matches[:5]:
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
                    print(f"- {display_match} (Context: ...{display_context}..., Confidence: {confidence:.0%}, Type: {match_type}{', Note: ' + note if note else ''})")
                if len(matches) > 5:
                    print(f"... and {len(matches) - 5} more matches")

    def export_results(self, results: List[Tuple[str, str, List[Tuple[str, str, float, str]]]], output_file: str):
        """Export scan results to JSON or CSV."""
        if output_file.endswith('.json'):
            data = [
                {
                    "Vulnerability": name,
                    "Status": status.strip("\033[32m").strip("\033[31m").strip("\033[33m").strip("\033[0m"),
                    "Confidence": f"{max([m[2] for m in matches] or [0]):.0%}" if matches else "N/A",
                    "MatchType": ", ".join(set(m[3] for m in matches)) if matches else "N/A",
                    "Matches": [
                        (
                            context,
                            match,
                            confidence,
                            match_type,
                            "Likely safe relative path in HTML attribute" if name == "Directory Traversal" and match_type == "Passive"
                            else "Possible false positive due to WAF block" if name == "Directory Traversal" and "WAF" in match
                            else "Likely safe script source" if name == "Cross-Domain Scripting" and match_type == "Passive"
                            else "Likely safe stylesheet source" if name == "Cross-Site Script Inclusion (CSSI)" and match_type == "Passive"
                            else ""
                        )
                        for context, match, confidence, match_type in matches
                    ]
                }
                for name, status, matches in results
            ]
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        elif output_file.endswith('.csv'):
            with open(output_file, 'w', encoding='utf-8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Vulnerability", "Status", "Confidence", "Match Type", "Matches"])
                for name, status, matches in results:
                    status_clean = status.strip("\033[32m").strip("\033[31m").strip("\033[33m").strip("\033[0m")
                    confidence = f"{max([m[2] for m in matches] or [0]):.0%}" if matches else "N/A"
                    match_type = ", ".join(set(m[3] for m in matches)) if matches else "N/A"
                    matches_str = "; ".join([
                        f"{m[1]} (Context: {m[0]}, Confidence: {m[2]:.0%}, Type: {m[3]}, Note: {'Likely safe relative path in HTML attribute' if name == 'Directory Traversal' and m[3] == 'Passive' else 'Possible false positive due to WAF block' if name == 'Directory Traversal' and 'WAF' in m[1] else 'Likely safe script source' if name == 'Cross-Domain Scripting' and m[3] == 'Passive' else 'Likely safe stylesheet source' if name == 'Cross-Site Script Inclusion (CSSI)' and m[3] == 'Passive' else ''})"
                        for m in matches
                    ])
                    writer.writerow([name, status_clean, confidence, match_type, matches_str])
        logger.info("Results exported to %s", output_file)

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

def main():
    """Main function to run the scanner."""
    parser = argparse.ArgumentParser(
        description="Common Web Application Vulnerability Scanner"
    )
    parser.add_argument("target", help="URL or IP address to scan")
    parser.add_argument("--output", help="Output file (JSON or CSV)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--max-pages", type=int, default=5, help="Maximum number of pages to crawl")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests (seconds)")
    args = parser.parse_args()

    setup_logging(args.debug)
    
    print("\033[36m" + load_banner() + "\033[0m")
    print("\n\033[33mTHESE RESULTS MAY NOT BE 100% CORRECT!\033[0m")
    print("\033[35mDeveloped By \033[36mSirCryptic\033[0m\n")

    try:
        scanner = WebVulnScanner(request_delay=args.delay)
        logger.info("Scanning target: %s", args.target)
        
        scanner.waf_detected = scanner.detect_waf(args.target)
        
        pages = scanner.crawl_pages(args.target, max_pages=args.max_pages)
        if not pages:
            logger.error("No pages successfully crawled from %s", args.target)
            sys.exit(1)

        results = scanner.check_vulnerabilities(pages)
        scanner.display_results(results)
        
        if args.output:
            scanner.export_results(results, args.output)

    except KeyboardInterrupt:
        print("\n\033[33mScan interrupted. Thank you for using cwv-scanner by SirCryptic!\033[0m")
        sys.exit(0)

if __name__ == "__main__":
    main()