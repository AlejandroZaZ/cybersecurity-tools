import argparse
import sys
import threading
import queue
import time
import socket
import logging
from colorama import init, Fore, Style

try:
    import dns.resolver
    import dns.exception
    DNSPYTHON_AVAILABLE = True
except ImportError:
    DNSPYTHON_AVAILABLE = False

init()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='dns_scanner.log'
)

DNS_RECORD_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']


class DNSScanner:
    def __init__(self, domain, wordlist_path=None, threads=20, timeout=3):
        self.domain = domain.rstrip('.')
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.timeout = timeout
        self.found_subdomains = []
        self.lock = threading.Lock()

    def resolve(self, hostname, record_type='A'):
        if DNSPYTHON_AVAILABLE:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            try:
                answers = resolver.resolve(hostname, record_type)
                return [r.to_text() for r in answers]
            except (dns.exception.DNSException, Exception):
                return []
        else:
            if record_type == 'A':
                try:
                    return [socket.gethostbyname(hostname)]
                except socket.gaierror:
                    return []
            return []

    def scan_records(self):
        print(f"{Fore.CYAN}DNS Records for {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")
        found_any = False
        for rtype in DNS_RECORD_TYPES:
            results = self.resolve(self.domain, rtype)
            if results:
                found_any = True
                for r in results:
                    print(f"  {Fore.GREEN}{rtype:6}{Style.RESET_ALL}  {r}")
                    logging.info(f"{self.domain} {rtype}: {r}")
        if not found_any:
            print(f"  {Fore.YELLOW}No records found{Style.RESET_ALL}")

    def probe_subdomain(self, subdomain):
        hostname = f"{subdomain}.{self.domain}"
        ips = self.resolve(hostname, 'A')
        if not ips:
            ips = self.resolve(hostname, 'AAAA')
        if ips:
            with self.lock:
                self.found_subdomains.append((hostname, ips))
                print(f"  {Fore.GREEN}[+] {hostname}{Style.RESET_ALL} -> {', '.join(ips)}")
                logging.info(f"Subdomain: {hostname} -> {', '.join(ips)}")

    def worker(self, sub_queue):
        while True:
            try:
                subdomain = sub_queue.get_nowait()
            except queue.Empty:
                break
            self.probe_subdomain(subdomain)
            sub_queue.task_done()

    def scan_subdomains(self):
        if not self.wordlist_path:
            # Built-in common subdomains
            common = [
                'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
                'admin', 'portal', 'api', 'dev', 'staging', 'test', 'beta',
                'app', 'blog', 'shop', 'store', 'cdn', 'static', 'media',
                'vpn', 'remote', 'ns1', 'ns2', 'mx', 'login', 'auth',
                'dashboard', 'panel', 'monitor', 'status', 'support', 'docs',
            ]
            wordlist = common
        else:
            try:
                with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{Fore.RED}[ERROR] Wordlist not found: {self.wordlist_path}{Style.RESET_ALL}")
                return

        print(f"\n{Fore.CYAN}Subdomain Enumeration ({len(wordlist)} words, {self.threads} threads){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*50}{Style.RESET_ALL}")

        sub_queue = queue.Queue()
        for word in wordlist:
            sub_queue.put(word)

        start = time.time()
        threads = []
        for _ in range(min(self.threads, len(wordlist))):
            t = threading.Thread(target=self.worker, args=(sub_queue,), daemon=True)
            t.start()
            threads.append(t)

        sub_queue.join()
        for t in threads:
            t.join()

        elapsed = round(time.time() - start, 2)
        print(f"\n{Fore.YELLOW}Found {len(self.found_subdomains)} subdomain(s) in {elapsed}s{Style.RESET_ALL}")

    def run(self):
        print(f"{Fore.CYAN}DNS Scanner — {self.domain}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

        if not DNSPYTHON_AVAILABLE:
            print(f"{Fore.YELLOW}[WARNING] dnspython not available — using socket fallback (A records only){Style.RESET_ALL}")

        self.scan_records()
        self.scan_subdomains()

        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="DNS & Subdomain Scanner")
    parser.add_argument("domain", help="Target domain (e.g., example.com)")
    parser.add_argument("--wordlist", help="Wordlist for subdomain brute-force (uses built-in list if omitted)")
    parser.add_argument("--threads", type=int, default=20, help="Threads for subdomain scan (default: 20)")
    parser.add_argument("--timeout", type=int, default=3, help="DNS query timeout in seconds (default: 3)")
    args = parser.parse_args()

    scanner = DNSScanner(args.domain, args.wordlist, args.threads, args.timeout)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
