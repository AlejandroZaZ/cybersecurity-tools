import os

# Define tool paths
TOOLS = {
    "Intrusion Detection System": "tools/network/ids.py",
    "Port Scanner": "tools/network/port_scanner.py",
    "Packet Sniffer": "tools/network/packet_sniffer.py",
    "Hash Cracker": "tools/password/hash_cracker.py",
    "Password Strength Checker": "tools/password/password_checker.py",
    "Web Vulnerability Scanner": "tools/web/web_scanner.py",
}

def run_tool(tool_name, tool_path):
    print(f"\n[+] Running {tool_name}...\n")
    os.system(f"python {tool_path} --help")  # Run each tool with --help

if __name__ == "__main__":
    for name, path in TOOLS.items():
        if os.path.exists(path):
            run_tool(name, path)
        else:
            print(f"[-] {name} ({path}) not found. Skipping...")
    
    print("\n[+] All tools executed.\n")
