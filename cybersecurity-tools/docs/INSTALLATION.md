## **Installation Guide**  

Welcome to **Cybersecurity Tools** – a collection of powerful terminal-based security tools for penetration testing, network analysis, and vulnerability assessment. Follow the steps below to install and set up the tools on your system.  

---

### **Prerequisites**  
Before installation, ensure you have the following dependencies installed on your system:  

- **Python 3.8+**  
- **pip (Python package manager)**  
- **git**  

To check if these are installed, run:  
```bash
python --version
pip --version
git --version
```
If any are missing, install them:  
- **Linux/macOS**:  
  ```bash
  sudo apt update && sudo apt install python3 python3-pip git -y
  ```
- **Windows**:  
  - Download and install [Python](https://www.python.org/downloads/)  
  - Download and install [Git](https://git-scm.com/downloads)  

---

### **Step 1: Clone the Repository**  
Run the following command to clone the repository to your local machine:  
```bash
git clone https://github.com/GZ30eee/cybersecurity-tools.git
```
Navigate to the project directory:  
```bash
cd cybersecurity-tools
```

---

### **Step 2: Install Dependencies**  
Install the required dependencies using `pip`:  
```bash
pip install -r requirements.txt
```

---

### **Step 3: Run the Tools**  
Each tool can be run separately. To view available commands for a tool, use the `--help` flag:  
```bash
python tools/network/port_scanner.py --help
```
Example usage:  
```bash
python tools/network/port_scanner.py -t 192.168.1.1
```

---

### **Step 4: Optional - Create a Virtual Environment**  
It's recommended to use a virtual environment to prevent conflicts with other Python packages.  

#### **For Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### **For Windows:**
```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

---

### **Step 5: Updating the Tools**  
To get the latest updates, navigate to the project directory and run:  
```bash
git pull origin main
pip install --upgrade -r requirements.txt
```

---

### **Uninstallation**  
To remove the tools, simply delete the project folder:  
```bash
rm -rf cybersecurity-tools
```

---

### **Need Help?**  
For support, open an issue on [GitHub Issues](https://github.com/GZ30eee/cybersecurity-tools/issues) or contact us.