import socket
import struct
import textwrap
import argparse
import sys
from datetime import datetime
from colorama import init, Fore, Style
import logging

# Initialize colorama for colored output
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='packet_sniffer.log'
)

class PacketSniffer:
    def __init__(self, interface=None, filter_proto=None):
        self.interface = interface
        self.filter_proto = filter_proto.upper() if filter_proto else None
        self.running = True
        
        # Protocol numbers
        self.PROTO_IPV4 = 8
        self.PROTO_TCP = 6
        self.PROTO_UDP = 17
        self.PROTO_ICMP = 1

    def setup_socket(self):
        """Set up the raw socket."""
        try:
            # AF_PACKET for Linux, SOCK_RAW for raw packets
            conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            if self.interface:
                conn.bind((self.interface, 0))
            return conn
        except PermissionError:
            print(f"{Fore.RED}[ERROR] Permission denied. Run with sudo/admin privileges.{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to create socket: {str(e)}{Style.RESET_ALL}")
            sys.exit(1)

    def run(self):
        """Main sniffer loop."""
        print(f"{Fore.CYAN}Starting packet sniffer on {self.interface or 'all interfaces'}{Style.RESET_ALL}")
        print(f"Filter: {self.filter_proto or 'All protocols'}")
        print(f"Time started: {datetime.now()}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        conn = self.setup_socket()
        
        try:
            while self.running:
                raw_data, addr = conn.recvfrom(65536)
                self.process_packet(raw_data)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[INFO] Sniffer stopped by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Unexpected error: {str(e)}{Style.RESET_ALL}")
        finally:
            conn.close()

    def process_packet(self, raw_data):
        """Process each captured packet."""
        dest_mac, src_mac, eth_proto, data = self.ethernet_frame(raw_data)
        
        # Apply protocol filter if set
        if self.filter_proto and eth_proto != getattr(self, f'PROTO_{self.filter_proto}', None):
            return

        self.print_frame('Ethernet Frame', [
            f"Destination: {dest_mac}",
            f"Source: {src_mac}",
            f"Protocol: {self.get_eth_protocol_name(eth_proto)} ({eth_proto})"
        ])

        # IPv4
        if eth_proto == self.PROTO_IPV4:
            self.process_ipv4(data)

    def process_ipv4(self, data):
        """Process IPv4 packet."""
        version, header_length, ttl, proto, src, target, payload = self.ipv4_packet(data)
        self.print_frame('IPv4 Packet', [
            f"Version: {version}",
            f"Header Length: {header_length} bytes",
            f"TTL: {ttl}",
            f"Protocol: {self.get_ip_protocol_name(proto)} ({proto})",
            f"Source: {src}",
            f"Target: {target}"
        ])

        # TCP
        if proto == self.PROTO_TCP:
            self.process_tcp(payload)
        # UDP
        elif proto == self.PROTO_UDP:
            self.process_udp(payload)
        # ICMP
        elif proto == self.PROTO_ICMP:
            self.process_icmp(payload)

    def process_tcp(self, data):
        """Process TCP segment."""
        src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, payload = self.tcp_segment(data)
        self.print_frame('TCP Segment', [
            f"Source Port: {src_port}",
            f"Destination Port: {dest_port}",
            f"Sequence: {sequence}",
            f"Acknowledgment: {ack}",
            f"Flags: URG={flag_urg} ACK={flag_ack} PSH={flag_psh} RST={flag_rst} SYN={flag_syn} FIN={flag_fin}"
        ])

        if payload and (src_port == 80 or dest_port == 80):
            self.print_data('HTTP Data', payload)

    def process_udp(self, data):
        """Process UDP datagram."""
        src_port, dest_port, length, payload = self.udp_segment(data)
        self.print_frame('UDP Datagram', [
            f"Source Port: {src_port}",
            f"Destination Port: {dest_port}",
            f"Length: {length} bytes"
        ])
        if payload:
            self.print_data('UDP Data', payload)

    def process_icmp(self, data):
        """Process ICMP packet."""
        icmp_type, code, checksum, payload = self.icmp_packet(data)
        self.print_frame('ICMP Packet', [
            f"Type: {icmp_type} ({self.get_icmp_type_name(icmp_type)})",
            f"Code: {code}",
            f"Checksum: {checksum}"
        ])
        if payload:
            self.print_data('ICMP Data', payload)

    def print_frame(self, title, fields):
        """Print packet information with formatting."""
        print(f"{Fore.GREEN}{title}:{Style.RESET_ALL}")
        for field in fields:
            print(f"  {field}")
        logging.info(f"{title}: {', '.join(fields)}")

    def print_data(self, title, data):
        """Print payload data with wrapping."""
        print(f"{Fore.YELLOW}{title}:{Style.RESET_ALL}")
        try:
            text = data.decode('utf-8', errors='ignore')
            wrapped = textwrap.fill(text, width=80, initial_indent='    ', subsequent_indent='    ')
            print(wrapped)
        except:
            print(f"    {repr(data[:100])}{'...' if len(data) > 100 else ''}")
        logging.info(f"{title}: {repr(data[:100])}")

    def ethernet_frame(self, data):
        """Unpack Ethernet frame."""
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), socket.htons(proto), data[14:]

    def get_mac_addr(self, bytes_addr):
        """Convert MAC address bytes to readable format."""
        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()

    def ipv4_packet(self, data):
        """Unpack IPv4 packet."""
        version_header_length = data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_length, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_length:]

    def ipv4(self, addr):
        """Convert IP address bytes to readable format."""
        return '.'.join(map(str, addr))

    def tcp_segment(self, data):
        """Unpack TCP segment."""
        src_port, dest_port, sequence, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flags = {
            'urg': (offset_reserved_flags & 32) >> 5,
            'ack': (offset_reserved_flags & 16) >> 4,
            'psh': (offset_reserved_flags & 8) >> 3,
            'rst': (offset_reserved_flags & 4) >> 2,
            'syn': (offset_reserved_flags & 2) >> 1,
            'fin': offset_reserved_flags & 1
        }
        return src_port, dest_port, sequence, ack, flags['urg'], flags['ack'], flags['psh'], flags['rst'], flags['syn'], flags['fin'], data[offset:]

    def udp_segment(self, data):
        """Unpack UDP datagram."""
        src_port, dest_port, length = struct.unpack('! H H H 2x', data[:8])
        return src_port, dest_port, length, data[8:]

    def icmp_packet(self, data):
        """Unpack ICMP packet."""
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def get_eth_protocol_name(self, proto):
        """Map Ethernet protocol number to name."""
        return {8: 'IPv4', 1544: 'ARP', 56710: 'IPv6'}.get(proto, 'Unknown')

    def get_ip_protocol_name(self, proto):
        """Map IP protocol number to name."""
        return {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, 'Unknown')

    def get_icmp_type_name(self, icmp_type):
        """Map ICMP type to name."""
        return {0: 'Echo Reply', 8: 'Echo Request', 3: 'Destination Unreachable'}.get(icmp_type, 'Unknown')

def main():
    parser = argparse.ArgumentParser(description="Advanced Packet Sniffer")
    parser.add_argument("--interface", help="Network interface to sniff (e.g., eth0)")
    parser.add_argument("--filter", choices=['IPv4', 'TCP', 'UDP', 'ICMP'], help="Filter by protocol")
    args = parser.parse_args()

    sniffer = PacketSniffer(interface=args.interface, filter_proto=args.filter)
    sniffer.run()

if __name__ == "__main__":
    main()