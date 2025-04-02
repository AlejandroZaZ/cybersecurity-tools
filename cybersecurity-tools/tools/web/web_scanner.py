import requests
import argparse
import sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import logging
import time
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='vulnerability_scan.log'
)

class VulnerabilityScanner:
    def __init__(self, url, timeout=10):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        })
        self.vulnerabilities_found = 0

    def print_result(self, message, is_vulnerable=False):
        color = Fore.RED if is_vulnerable else Fore.GREEN
        print(f"{color}{message}{Style.RESET_ALL}")
        logging.info(message)
        if is_vulnerable:
            self.vulnerabilities_found += 1

    def check_sql_injection(self):
        payloads = [
            "' OR '1'='1",
            "1; DROP TABLE users --",
            "' UNION SELECT NULL, NULL --"
        ]
        params = ['id', 'q', 'search', 'user']
        
        for param in params:
            for payload in payloads:
                try:
                    test_url = f"{self.url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    response_text = response.text.lower()
                    
                    error_indicators = [
                        "sql syntax",
                        "mysql_fetch",
                        "sql error",
                        "database error"
                    ]
                    
                    if any(indicator in response_text for indicator in error_indicators):
                        self.print_result(f"[!] Possible SQL Injection vulnerability at {test_url}", True)
                        return
                except requests.RequestException as e:
                    self.print_result(f"[WARNING] Error checking SQL Injection: {str(e)}")
        self.print_result("[✓] No obvious SQL Injection vulnerabilities found")

    def check_xss(self):
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        params = ['search', 'q', 'name', 'comment']
        
        for param in params:
            for payload in payloads:
                try:
                    test_url = f"{self.url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                    
                    if payload in response.text or "alert('XSS')" in response.text:
                        self.print_result(f"[!] Possible XSS vulnerability at {test_url}", True)
                        return
                except requests.RequestException as e:
                    self.print_result(f"[WARNING] Error checking XSS: {str(e)}")
        self.print_result("[✓] No obvious XSS vulnerabilities found")

    def check_directory_listing(self):
        directories = [
            "admin", "backup", "logs", "config",
            "test", "private", "uploads", "tmp"
        ]
        
        for directory in directories:
            try:
                test_url = urljoin(self.url, directory)
                response = self.session.get(test_url, timeout=self.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                if "index of" in response.text.lower() or soup.find('title', string=lambda t: t and "index of" in t.lower()):
                    self.print_result(f"[!] Directory listing enabled at {test_url}", True)
            except requests.RequestException as e:
                self.print_result(f"[WARNING] Error checking directory: {test_url} - {str(e)}")
        self.print_result("[✓] No directory listing vulnerabilities found")

    def check_security_headers(self):
        try:
            response = self.session.get(self.url, timeout=self.timeout)
            headers = response.headers
            
            important_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Content-Security-Policy': None,
                'Strict-Transport-Security': None
            }
            
            for header, expected in important_headers.items():
                if header not in headers:
                    self.print_result(f"[!] Missing security header: {header}", True)
                elif expected and headers[header] not in (expected if isinstance(expected, list) else [expected]):
                    self.print_result(f"[!] Weak {header}: {headers[header]}", True)
        except requests.RequestException as e:
            self.print_result(f"[WARNING] Error checking security headers: {str(e)}")

    def scan(self):
        print(f"{Fore.CYAN}Starting vulnerability scan for {self.url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        start_time = time.time()
        
        self.check_sql_injection()
        self.check_xss()
        self.check_directory_listing()
        self.check_security_headers()
        
        end_time = time.time()
        duration = round(end_time - start_time, 2)
        
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Scan completed in {duration} seconds")
        print(f"Vulnerabilities found: {self.vulnerabilities_found}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description="Basic Web Vulnerability Scanner")
    parser.add_argument("url", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds")
    args = parser.parse_args()

    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    try:
        scanner = VulnerabilityScanner(args.url, args.timeout)
        scanner.scan()
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()