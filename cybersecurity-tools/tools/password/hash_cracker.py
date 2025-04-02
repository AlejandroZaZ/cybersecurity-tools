import hashlib
import time
import argparse
import sys
import threading
from queue import Queue
from colorama import init, Fore, Style
import logging

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='hash_cracker.log'
)

class HashCracker:
    def __init__(self, hash_to_crack, wordlist_path, hash_type='md5', threads=4):
        self.hash_to_crack = hash_to_crack.lower().strip()
        self.wordlist_path = wordlist_path
        self.hash_type = hash_type.lower()
        self.threads = threads
        self.hash_func = getattr(hashlib, self.hash_type, None)
        self.found = None
        self.queue = Queue()
        self.start_time = time.time()
        self.attempts = 0
        self.lock = threading.Lock()

    def validate(self):
        """Validate inputs."""
        if not self.hash_func:
            print(f"{Fore.RED}[ERROR] Unsupported hash type: {self.hash_type}{Style.RESET_ALL}")
            print(f"Supported types: md5, sha1, sha256, sha512")
            return False
        if not self.hash_to_crack:
            print(f"{Fore.RED}[ERROR] Hash cannot be empty{Style.RESET_ALL}")
            return False
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore'):
                pass
        except FileNotFoundError:
            print(f"{Fore.RED}[ERROR] Wordlist file not found: {self.wordlist_path}{Style.RESET_ALL}")
            return False
        return True

    def worker(self):
        """Thread worker to crack hash."""
        while True:
            try:
                word = self.queue.get_nowait()
                with self.lock:
                    self.attempts += 1
                hashed_word = self.hash_func(word.encode()).hexdigest()
                if hashed_word == self.hash_to_crack:
                    with self.lock:
                        if not self.found:
                            self.found = word
                            elapsed = time.time() - self.start_time
                            print(f"\n{Fore.GREEN}[+] Password found: {word}{Style.RESET_ALL}")
                            print(f"Time elapsed: {elapsed:.2f} seconds")
                            print(f"Attempts: {self.attempts:,}")
                            logging.info(f"Password found: {word}, Time: {elapsed:.2f}s, Attempts: {self.attempts}")
                self.queue.task_done()
            except Queue.Empty:
                break
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Thread error: {str(e)}{Style.RESET_ALL}")

    def crack(self):
        """Main cracking function."""
        if not self.validate():
            return

        print(f"{Fore.CYAN}Starting hash cracker...{Style.RESET_ALL}")
        print(f"Hash: {self.hash_to_crack}")
        print(f"Hash type: {self.hash_type}")
        print(f"Wordlist: {self.wordlist_path}")
        print(f"Threads: {self.threads}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

        # Load wordlist into queue
        with open(self.wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                self.queue.put(line.strip())

        # Start threads
        threads = []
        for _ in range(min(self.threads, self.queue.qsize())):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        # Wait for completion
        self.queue.join()
        for t in threads:
            t.join()

        elapsed = time.time() - self.start_time
        if not self.found:
            print(f"\n{Fore.RED}[-] Password not found in wordlist.{Style.RESET_ALL}")
            print(f"Time elapsed: {elapsed:.2f} seconds")
            print(f"Attempts: {self.attempts:,}")
            logging.info(f"Password not found, Time: {elapsed:.2f}s, Attempts: {self.attempts}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Hash Cracker")
    parser.add_argument("hash", help="Hash to crack")
    parser.add_argument("wordlist", help="Path to wordlist file")
    parser.add_argument("--type", default="md5", choices=['md5', 'sha1', 'sha256', 'sha512'], help="Hash type (default: md5)")
    parser.add_argument("--threads", type=int, default=4, help="Number of threads (default: 4)")
    args = parser.parse_args()

    try:
        cracker = HashCracker(args.hash, args.wordlist, args.type, args.threads)
        cracker.crack()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INFO] Cracking interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()