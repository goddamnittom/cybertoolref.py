#!/usr/bin/env python3
"""
CyberToolRef - A Python Reference Tool for Cybersecurity, OSINT, and Ethical Hacking Tools

This script provides documentation, examples, and basic commands for 20 of the most powerful
tools used in cybersecurity, OSINT, and ethical hacking as of February 20, 2025.

Usage:
    Run the script and select a tool number from the menu to view its details.
    Type 'q' to quit.

Author: Grok 3 (xAI)
Date: February 20, 2025
"""

import sys

# Dictionary containing tool details
tools = {
    1: {
        "name": "Nmap",
        "category": "Network Scanning",
        "description": "Nmap (Network Mapper) is a free, open-source tool for network discovery and security auditing. It maps networks, identifies hosts, and detects open ports and services.",
        "example": "Scan a target for open ports: nmap -sS -p 1-1000 192.168.1.1",
        "command": "nmap [scan type] [options] <target>",
    },
    2: {
        "name": "Metasploit",
        "category": "Exploitation",
        "description": "Metasploit Framework is a penetration testing tool that allows testing vulnerabilities with pre-built exploits and payloads.",
        "example": "Launch Metasploit and use an exploit: msfconsole; use exploit/windows/smb/ms17_010_eternalblue",
        "command": "msfconsole",
    },
    3: {
        "name": "Wireshark",
        "category": "Packet Analysis",
        "description": "Wireshark is a network protocol analyzer that captures and displays packet data for detailed inspection.",
        "example": "Capture traffic on eth0: wireshark -i eth0",
        "command": "wireshark [options]",
    },
    4: {
        "name": "Burp Suite",
        "category": "Web Application Testing",
        "description": "Burp Suite is an integrated platform for security testing of web applications, featuring proxy, scanner, and intruder tools.",
        "example": "Intercept HTTP requests: Set browser proxy to 127.0.0.1:8080 and start Burp",
        "command": "java -jar burpsuite.jar",
    },
    5: {
        "name": "Maltego",
        "category": "OSINT / Link Analysis",
        "description": "Maltego is an OSINT and graphical link analysis tool for visualizing relationships between entities like people, domains, and IPs.",
        "example": "Map a domain’s infrastructure: Run a domain transform in Maltego GUI",
        "command": "Launch via GUI (no direct CLI)",
    },
    6: {
        "name": "theHarvester",
        "category": "OSINT",
        "description": "theHarvester gathers emails, subdomains, and names from public sources like search engines and PGP key servers.",
        "example": "Harvest emails from a domain: theharvester -d example.com -b google",
        "command": "theharvester -d <domain> -b <source>",
    },
    7: {
        "name": "Recon-ng",
        "category": "OSINT / Reconnaissance",
        "description": "Recon-ng is a modular web reconnaissance framework written in Python for gathering OSINT data.",
        "example": "Find subdomains: recon-ng; modules load recon/domains-hosts/brute; set SOURCE example.com; run",
        "command": "recon-ng",
    },
    8: {
        "name": "Shodan",
        "category": "OSINT / IoT",
        "description": "Shodan is a search engine for internet-connected devices, useful for finding vulnerable systems.",
        "example": "Search for open cameras: shodan search webcam",
        "command": "shodan search <query> (CLI requires API key)",
    },
    9: {
        "name": "John the Ripper",
        "category": "Password Cracking",
        "description": "John the Ripper is a fast password cracker supporting multiple hash types.",
        "example": "Crack a hash file: john --format=raw-sha256 hashes.txt",
        "command": "john [options] <file>",
    },
    10: {
        "name": "Hashcat",
        "category": "Password Cracking",
        "description": "Hashcat is an advanced password recovery tool optimized for GPU cracking.",
        "example": "Crack MD5 hashes: hashcat -m 0 -a 0 hashes.txt wordlist.txt",
        "command": "hashcat -m <hash-type> -a <attack-mode> <hashfile> <wordlist>",
    },
    11: {
        "name": "SQLmap",
        "category": "Web Exploitation",
        "description": "SQLmap automates the detection and exploitation of SQL injection vulnerabilities.",
        "example": "Test a URL for SQL injection: sqlmap -u 'http://example.com?id=1' --dbs",
        "command": "sqlmap -u <url> [options]",
    },
    12: {
        "name": "Aircrack-ng",
        "category": "Wireless Security",
        "description": "Aircrack-ng is a suite of tools to assess WiFi network security, including packet capture and password cracking.",
        "example": "Crack WPA2: aircrack-ng -w wordlist.txt -b 00:14:22:33:44:55 capture.cap",
        "command": "aircrack-ng [options] <capture file>",
    },
    13: {
        "name": "Scapy",
        "category": "Packet Manipulation",
        "description": "Scapy is a Python library for crafting and analyzing network packets.",
        "example": "Send a ping: from scapy.all import *; sr1(IP(dst='8.8.8.8')/ICMP())",
        "command": "Python script (interactive or file)",
    },
    14: {
        "name": "SpiderFoot",
        "category": "OSINT",
        "description": "SpiderFoot automates OSINT collection across 200+ modules for footprinting and intelligence gathering.",
        "example": "Scan a domain: spiderfoot -t example.com -m all",
        "command": "spiderfoot -t <target> [options]",
    },
    15: {
        "name": "Sherlock",
        "category": "OSINT",
        "description": "Sherlock is a Python tool to find usernames across social media platforms.",
        "example": "Search for a username: python3 sherlock.py user123",
        "command": "python3 sherlock.py <username>",
    },
    16: {
        "name": "Hydra",
        "category": "Password Cracking",
        "description": "Hydra is a password cracking tool for brute-forcing login credentials.",
        "example": "Brute force SSH: hydra -l admin -P wordlist.txt ssh://192.168.1.1",
        "command": "hydra -l <login> -P <wordlist> <service>://<target>",
    },
    17: {
        "name": "Nikto",
        "category": "Web Scanning",
        "description": "Nikto is an open-source web server scanner for identifying vulnerabilities.",
        "example": "Scan a web server: nikto -h http://example.com",
        "command": "nikto -h <host> [options]",
    },
    18: {
        "name": "OSINT Framework",
        "category": "OSINT",
        "description": "OSINT Framework is a web-based directory of OSINT tools and resources.",
        "example": "Access via browser: Navigate to osintframework.com",
        "command": "No CLI; web-based",
    },
    19: {
        "name": "ExploitDB",
        "category": "Exploitation",
        "description": "Exploit Database is an archive of exploits and vulnerable software for research.",
        "example": "Search exploits: searchsploit 'windows smb'",
        "command": "searchsploit <search term>",
    },
    20: {
        "name": "Ghidra",
        "category": "Reverse Engineering",
        "description": "Ghidra is an open-source software reverse engineering tool developed by the NSA.",
        "example": "Analyze a binary: Launch Ghidra GUI and import file",
        "command": "ghidraRun (GUI launcher)",
    }
}

def display_menu():
    """Display the list of available tools."""
    print("\n=== CyberToolRef - Cybersecurity & OSINT Tools Reference ===")
    print("Select a tool by number (1-20) or 'q' to quit:\n")
    for num, tool in tools.items():
        print(f"{num}. {tool['name']} ({tool['category']})")
    print("\n==========================================")

def show_tool_details(choice):
    """Display detailed information for the selected tool."""
    if choice in tools:
        tool = tools[choice]
        print(f"\n=== {tool['name']} ===")
        print(f"Category: {tool['category']}")
        print(f"Description: {tool['description']}")
        print(f"Example: {tool['example']}")
        print(f"Basic Command: {tool['command']}")
    else:
        print("Invalid selection. Please choose a number between 1 and 20.")

def main():
    """Main loop to run the interactive tool."""
    while True:
        display_menu()
        user_input = input("Enter tool number (1-20) or 'q' to quit: ").strip().lower()
        
        if user_input == 'q':
            print("Exiting CyberToolRef. Stay safe!")
            sys.exit(0)
        
        try:
            choice = int(user_input)
            show_tool_details(choice)
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
