import ssl
import socket
import argparse
import sys
import datetime
import logging
from colorama import init, Fore, Style

init()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='ssl_checker.log'
)

WEAK_CIPHERS = {
    'RC4', 'DES', '3DES', 'EXPORT', 'NULL', 'ANON', 'MD5'
}

DEPRECATED_PROTOCOLS = {
    'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'
}


class SSLChecker:
    def __init__(self, host, port=443, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.issues = []

    def _ok(self, msg):
        print(f"{Fore.GREEN}[✓] {msg}{Style.RESET_ALL}")
        logging.info(msg)

    def _warn(self, msg):
        print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")
        logging.warning(msg)
        self.issues.append(msg)

    def _info(self, msg):
        print(f"{Fore.CYAN}    {msg}{Style.RESET_ALL}")

    def get_cert(self):
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    return cert, cipher, protocol
        except ssl.SSLCertVerificationError as e:
            self._warn(f"Certificate verification failed: {e}")
            # Retry without verification to still inspect the cert
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as sock:
                with ctx_noverify.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    return cert, cipher, protocol

    def check_expiry(self, cert):
        not_after = cert.get('notAfter')
        if not not_after:
            self._warn("Could not determine certificate expiry date")
            return
        expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        days_left = (expiry - now).days
        if days_left < 0:
            self._warn(f"Certificate EXPIRED {abs(days_left)} days ago ({not_after})")
        elif days_left < 30:
            self._warn(f"Certificate expires in {days_left} days ({not_after})")
        else:
            self._ok(f"Certificate valid for {days_left} more days (expires {not_after})")

    def check_hostname(self, cert):
        subject = dict(x[0] for x in cert.get('subject', []))
        san = [v for _, v in cert.get('subjectAltName', [])]
        cn = subject.get('commonName', '')
        self._info(f"CN: {cn}")
        if san:
            self._info(f"SAN: {', '.join(san[:5])}{'...' if len(san) > 5 else ''}")
        host = self.host.lower()
        names = [v.lower() for _, v in cert.get('subjectAltName', [])]
        if not names:
            names = [cn.lower()] if cn else []
        matched = any(
            host == n or (n.startswith('*.') and host.endswith(n[1:]))
            for n in names
        )
        if matched:
            self._ok(f"Hostname '{self.host}' matches certificate")
        else:
            self._warn(f"Hostname '{self.host}' does not match certificate names: {names}")

    def check_protocol(self, protocol):
        if protocol in DEPRECATED_PROTOCOLS:
            self._warn(f"Deprecated protocol in use: {protocol}")
        else:
            self._ok(f"Protocol: {protocol}")

    def check_cipher(self, cipher):
        cipher_name, tls_version, bits = cipher
        self._info(f"Cipher: {cipher_name} ({bits} bits)")
        for weak in WEAK_CIPHERS:
            if weak in cipher_name.upper():
                self._warn(f"Weak cipher detected: {cipher_name}")
                return
        if bits and bits < 128:
            self._warn(f"Short key length: {bits} bits")
        else:
            self._ok(f"Cipher strength OK ({bits} bits)")

    def check_issuer(self, cert):
        issuer = dict(x[0] for x in cert.get('issuer', []))
        org = issuer.get('organizationName', 'Unknown')
        self._info(f"Issuer: {org}")

    def check(self):
        print(f"{Fore.CYAN}SSL/TLS Checker — {self.host}:{self.port}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

        try:
            cert, cipher, protocol = self.get_cert()
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Could not connect: {e}{Style.RESET_ALL}")
            sys.exit(1)

        self.check_issuer(cert)
        self.check_expiry(cert)
        self.check_hostname(cert)
        self.check_protocol(protocol)
        self.check_cipher(cipher)

        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        if self.issues:
            print(f"{Fore.YELLOW}Issues found: {len(self.issues)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}No issues found.{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="SSL/TLS Certificate Checker")
    parser.add_argument("host", help="Target hostname (e.g., example.com)")
    parser.add_argument("--port", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds (default: 10)")
    args = parser.parse_args()

    checker = SSLChecker(args.host, args.port, args.timeout)
    try:
        checker.check()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main()
