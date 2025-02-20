#!/usr/bin/env python3
"""
CyberToolRef50 - A Python Reference Tool for 50 Top Cybersecurity, OSINT, and Ethical Hacking Tools

This script provides documentation, examples, and basic commands for 50 powerful tools used in 
cybersecurity, OSINT, and ethical hacking as of February 20, 2025.

Usage:
    Run the script and select a tool number from the menu to view its details.
    Type 'q' to quit.

Author: Grok 3 (xAI)
Date: February 20, 2025
"""

import sys

# Dictionary containing 50 tool details
tools = {
    1: {"name": "Nmap", "category": "Network Scanning", "description": "Network discovery and security auditing tool.", "example": "nmap -sS -p 1-1000 192.168.1.1", "command": "nmap [scan type] [options] <target>"},
    2: {"name": "Metasploit", "category": "Exploitation", "description": "Penetration testing framework with exploits and payloads.", "example": "msfconsole; use exploit/windows/smb/ms17_010_eternalblue", "command": "msfconsole"},
    3: {"name": "Wireshark", "category": "Packet Analysis", "description": "Network protocol analyzer for packet capture and inspection.", "example": "wireshark -i eth0", "command": "wireshark [options]"},
    4: {"name": "Burp Suite", "category": "Web Application Testing", "description": "Platform for web app security testing.", "example": "Set proxy to 127.0.0.1:8080 and start Burp", "command": "java -jar burpsuite.jar"},
    5: {"name": "Maltego", "category": "OSINT / Link Analysis", "description": "Graphical OSINT tool for entity relationship mapping.", "example": "Run a domain transform in Maltego GUI", "command": "Launch via GUI"},
    6: {"name": "theHarvester", "category": "OSINT", "description": "Gathers emails and subdomains from public sources.", "example": "theharvester -d example.com -b google", "command": "theharvester -d <domain> -b <source>"},
    7: {"name": "Recon-ng", "category": "OSINT / Reconnaissance", "description": "Modular web recon framework for OSINT.", "example": "recon-ng; modules load recon/domains-hosts/brute; run", "command": "recon-ng"},
    8: {"name": "Shodan", "category": "OSINT / IoT", "description": "Search engine for internet-connected devices.", "example": "shodan search webcam", "command": "shodan search <query>"},
    9: {"name": "John the Ripper", "category": "Password Cracking", "description": "Fast password cracker for multiple hash types.", "example": "john --format=raw-sha256 hashes.txt", "command": "john [options] <file>"},
    10: {"name": "
