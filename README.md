# Advanced Parental Control Firewall

## Overview
This script provides an advanced firewall system with parental control capabilities. It includes network scanning, website blocking, traffic monitoring, and unauthorized device detection.

## Features

### 1️⃣ Network Scanning
- Scans the local network to detect connected devices.
- Displays their **IP Address, MAC Address, and Device Name**.

### 2️⃣ Device Management
- **Add Devices**: Register trusted devices by IP, MAC, and name.
- **Detect Unauthorized Devices**: Scans for unregistered devices and logs them.

### 3️⃣ Website Blocking
- **Block Websites**: Adds sites to the blocklist by modifying the `/etc/hosts` file.
- **Unblock Websites**: Removes sites from the blocklist.
- **View Blocked Websites**: Displays all blocked websites.

### 4️⃣ Internet Access Control
- Blocks internet access during restricted hours (default: 10 PM to 7 AM).
- Uses **iptables** to enforce firewall rules.

### 5️⃣ Traffic Monitoring
- Monitors network traffic for TCP, UDP, and ICMP packets.
- Logs source & destination IPs, ports, MAC addresses, and protocols.

### 6️⃣ Firewall Enforcement
- Starts a firewall enforcement thread to toggle internet access based on allowed hours.

### 7️⃣ CLI Interface
- Interactive menu to perform all firewall actions easily.

## Requirements
- **Python 3**
- **Scapy** (`pip install scapy`)
- **Root Privileges** (for modifying hosts file & firewall rules)

## Usage
Run the script:
```bash
sudo python3 firewall.py
```
Select options from the menu to perform desired actions.

🚀 Enjoy secure and controlled internet access!

