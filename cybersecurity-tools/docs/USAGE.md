# **Usage Guide**  
This document provides instructions on how to use each tool in the **Cybersecurity Tools** suite.  

## **General Usage**  
Each tool can be executed via the terminal. To see available options, use the `--help` flag:  
```bash
python tools/<category>/<tool>.py --help
```
Example:  
```bash
python tools/network/port_scanner.py --help
```

---

## **1. Network Security Tools**  

### **Intrusion Detection System (IDS)**  
**Description:** Monitors network traffic for potential DoS attacks.  
**Usage:**  
```bash
python tools/network/ids.py -i eth0
```
**Options:**  
- `-i` or `--interface` → Specify network interface  
- `-t` or `--threshold` → Set request threshold for alerts  

---

### **Port Scanner**  
**Description:** Scans a target for open ports.  
**Usage:**  
```bash
python tools/network/port_scanner.py -t 192.168.1.1
```
**Options:**  
- `-t` or `--target` → Specify target IP or domain  
- `-p` or `--ports` → Range of ports to scan (default: 1-65535)  

---

### **Packet Sniffer**  
**Description:** Captures and analyzes network packets.  
**Usage:**  
```bash
python tools/network/packet_sniffer.py -i eth0
```
**Options:**  
- `-i` or `--interface` → Specify network interface  
- `-c` or `--count` → Number of packets to capture  

---

## **2. Password Security Tools**  

### **Hash Cracker**  
**Description:** Cracks password hashes using wordlists.  
**Usage:**  
```bash
python tools/password/hash_cracker.py -f hashes.txt -w wordlist.txt
```
**Options:**  
- `-f` or `--file` → Input file containing hashes  
- `-w` or `--wordlist` → Dictionary file for brute force attack  

---

### **Password Strength Checker**  
**Description:** Analyzes password strength and provides security suggestions.  
**Usage:**  
```bash
python tools/password/password_checker.py -p "MySecurePass123!"
```
**Options:**  
- `-p` or `--password` → Password to analyze  

---

## **3. Web Security Tools**  

### **Web Vulnerability Scanner**  
**Description:** Scans websites for common vulnerabilities like SQL Injection, XSS, etc.  
**Usage:**  
```bash
python tools/web/web_scanner.py -u https://example.com
```
**Options:**  
- `-u` or `--url` → Target URL  
- `-m` or `--mode` → Scan mode: `basic`, `deep`  

---

## **Running All Tools at Once**  
To execute all tools sequentially, use the **run_all_tools.py** script:  
```bash
python scripts/run_all_tools.py
```

---

## **Need Help?**  
For further details, refer to [GitHub Issues](https://github.com/GZ30eee/cybersecurity-tools/issues) or open a discussion.  