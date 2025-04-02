![image](https://github.com/user-attachments/assets/ba543ba9-d673-45cd-9ce1-f52d32dbb7ac)

## Cybersecurity Tools  
*A collection of powerful terminal-based security tools for network analysis, penetration testing, and vulnerability assessment.*  

---

### About the Project  
This repository provides a suite of open-source cybersecurity tools designed for security professionals, ethical hackers, and researchers. These tools cover various aspects of network security, password security, system monitoring, and web vulnerability scanning. The primary goal is to enhance security awareness and aid in the detection of potential vulnerabilities in networks and applications.  

**Important Notice:** These tools should only be used for ethical purposes. Ensure you have permission before conducting security tests on any network or system. Unauthorized testing is illegal and punishable by law.  

---

### Features & Tools  

#### Network Security  
- **Intrusion Detection System** (`ids.py`): Monitors network traffic and detects potential denial-of-service (DoS) attacks.  
- **Port Scanner** (`port_scanner.py`): Scans target systems for open ports and identifies potential vulnerabilities.  
- **Packet Sniffer** (`packet_sniffer.py`): Captures and analyzes network packets in real-time to detect anomalies.  

#### Password Security  
- **Hash Cracker** (`hash_cracker.py`): Uses wordlists to crack hashed passwords and assess security risks.  
- **Password Strength Checker** (`password_checker.py`): Evaluates password strength and suggests improvements to enhance security.  

#### Web Security  
- **Web Vulnerability Scanner** (`web_scanner.py`): Detects security vulnerabilities such as SQL injection, cross-site scripting (XSS), and misconfigurations.  

---

### Installation & Setup  

1. **Clone the Repository:**  
   ```bash
   git clone https://github.com/GZ30eee/cybersecurity-tools.git
   cd cybersecurity-tools
   ```  

2. **Install Dependencies:**  
   ```bash
   pip install -r requirements.txt
   ```  

3. **Run Any Tool:**  
   ```bash
   python tools/network/ids.py --help
   ```  

4. **Execute All Security Tools:**  
   ```bash
   python scripts/run_all_tools.py
   ```  

---

### Usage Examples  

#### Running the Port Scanner  
```bash
python tools/network/port_scanner.py -t 192.168.1.1 -p 1-1000
```

#### Checking Password Strength  
```bash
python tools/password/password_checker.py --password "MySecurePass123!"
```

#### Scanning a Website for Vulnerabilities  
```bash
python tools/web/web_scanner.py --url https://example.com
```

---

### Contributing  
Contributions are welcome. If you have improvements, bug fixes, or new security tools to add, feel free to submit a pull request. Please ensure that all contributions adhere to ethical hacking principles.  

To contribute:
1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit changes (`git commit -m "Added new security feature"`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a pull request.  

---

### License  
This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.  

---

### Contact & Support  
- **GitHub Repository:** [Cybersecurity Tools](https://github.com/GZ30eee/cybersecurity-tools)  
- **Issues & Bug Reports:** Please open an issue on the GitHub repository for any technical problems or feature requests.  

This project is intended to be a helpful resource for security research and awareness. Use it responsibly and contribute to building a safer cyberspace.
