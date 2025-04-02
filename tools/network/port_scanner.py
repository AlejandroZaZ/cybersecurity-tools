import socket
import argparse
import threading
import queue
import sys
from datetime import datetime
import time
from colorama import init, Fore, Style

# Initialize colorama for colored output
init()

class PortScanner:
    def __init__(self, target, port_range, timeout=1, threads=100):
        self.target = target
        self.start_port, self.end_port = map(int, port_range.split('-'))
        self.ports = range(self.start_port, self.end_port + 1)
        self.timeout = timeout
        self.threads = threads
        self.open_ports = []
        self.port_queue = queue.Queue()
        self.lock = threading.Lock()

    def resolve_target(self):
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            print(f"{Fore.RED}[ERROR] Could not resolve hostname: {self.target}{Style.RESET_ALL}")
            sys.exit(1)

    def scan_port(self, ip, port):
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = self.get_service(port)
                with self.lock:
                    self.open_ports.append((port, service))
                    print(f"{Fore.GREEN}[OPEN] Port {port} - {service}{Style.RESET_ALL}")
            sock.close()
        except socket.error:
            pass  # Silently skip socket errors for individual ports

    def get_service(self, port):
        """Attempt to identify service running on the port."""
        try:
            return socket.getservbyport(port)
        except:
            return "Unknown"

    def worker(self, ip):
        """Thread worker function."""
        while True:
            try:
                port = self.port_queue.get_nowait()
            except queue.Empty:
                break
            self.scan_port(ip, port)
            self.port_queue.task_done()

    def scan(self):
        """Main scanning function."""
        print(f"{Fore.CYAN}Starting port scan on {self.target}{Style.RESET_ALL}")
        print(f"Time started: {datetime.now()}")
        print(f"Scanning ports {self.start_port} to {self.end_port} ({len(self.ports)} ports)")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")

        start_time = time.time()
        ip = self.resolve_target()
        print(f"Resolved IP: {ip}")

        # Fill the queue with ports
        for port in self.ports:
            self.port_queue.put(port)

        # Start worker threads
        threads = []
        for _ in range(min(self.threads, len(self.ports))):
            t = threading.Thread(target=self.worker, args=(ip,))
            t.start()
            threads.append(t)

        # Wait for all threads to complete
        for t in threads:
            t.join()

        # Wait for queue to be fully processed
        self.port_queue.join()

        end_time = time.time()
        duration = round(end_time - start_time, 2)

        # Summary
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Scan completed in {duration} seconds")
        if self.open_ports:
            print(f"Open ports found: {len(self.open_ports)}")
            for port, service in sorted(self.open_ports):
                print(f"  {port}: {service}")
        else:
            print(f"{Fore.GREEN}No open ports found.{Style.RESET_ALL}")

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Advanced Port Scanner")
    parser.add_argument("target", help="Target hostname or IP (e.g., example.com or 192.168.1.1)")
    parser.add_argument("ports", help="Port range to scan (e.g., 1-100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    args = parser.parse_args()

    # Validate port range
    try:
        start, end = map(int, args.ports.split('-'))
        if not (1 <= start <= end <= 65535):
            raise ValueError
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid port range. Use format 'start-end' (1-65535){Style.RESET_ALL}")
        sys.exit(1)

    # Initialize and run scanner
    try:
        scanner = PortScanner(args.target, args.ports, args.timeout, args.threads)
        scanner.scan()
    except KeyboardInterrupt:
        print(f"{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()