## **Cybersecurity Tools** 🔐  
*A collection of powerful terminal-based security tools for network analysis, penetration testing, and vulnerability assessment.*  

---

### **📌 About the Project**  
This project provides a set of open-source **cybersecurity tools** designed for security professionals, ethical hackers, and researchers. The tools cover various aspects of **network security, password security, monitoring, and web vulnerability scanning**.  

> 🛠️ **Use these tools responsibly!** Ensure you have permission before testing on any network or system.  

---

### **📂 Features & Tools**  

#### 🛡 **Network Security**  
- **Intrusion Detection System** (`ids.py`) → Detects potential DoS attacks.  
- **Port Scanner** (`port_scanner.py`) → Scans for open ports on a target system.  
- **Packet Sniffer** (`packet_sniffer.py`) → Captures and analyzes network packets.  

#### 🔑 **Password Security**  
- **Hash Cracker** (`hash_cracker.py`) → Cracks password hashes using wordlists.  
- **Password Strength Checker** (`password_checker.py`) → Analyzes password security.  

#### 🌐 **Web Security**  
- **Web Vulnerability Scanner** (`web_scanner.py`) → Checks for SQL Injection, XSS, and other vulnerabilities.  

---

### **🚀 Installation & Setup**  

1️⃣ **Clone the Repository:**  
```bash
git clone https://github.com/GZ30eee/cybersecurity-tools.git
cd cybersecurity-tools
```

2️⃣ **Install Dependencies:**  
```bash
pip install -r requirements.txt
```

3️⃣ **Run Any Tool:**  
```bash
python tools/network/ids.py --help
```

4️⃣ **Run All Tools:**  
```bash
python scripts/run_all_tools.py
```

---

### **📖 Usage Example**  

🔹 **Run the Port Scanner:**  
```bash
python tools/network/port_scanner.py -t 192.168.1.1 -p 1-1000
```

🔹 **Check Password Strength:**  
```bash
python tools/password/password_checker.py --password "MySecurePass123!"
```

🔹 **Scan a Website for Vulnerabilities:**  
```bash
python tools/web/web_scanner.py --url https://example.com
```

---

### **📜 License**  
This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.  

---

### **📬 Contact & Contributions**  
- **GitHub:** [Cybersecurity Tools](https://github.com/GZ30eee/cybersecurity-tools)  
- **Issues & Suggestions:** Feel free to open an issue or submit a pull request!  

🤖 **Happy Hacking! Stay Secure!** 🛡  
