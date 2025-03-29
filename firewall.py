import os
import json
import time
import scapy.all as scapy
import socket
import threading
from datetime import datetime

# 🔹 File Storage
DEVICE_FILE = "device_profiles.json"
BLOCKLIST_FILE = "blocklist.json"
TRAFFIC_LOG = "traffic_log.txt"
UNAUTHORIZED_LOG = "unauthorized_devices.txt"

# 🔹 Firewall Rules
BLOCKED_HOURS = [(22, 7)]  # Example: Block from 10 PM to 7 AM
HOSTS_FILE = "/etc/hosts"
REDIRECT_IP = "127.0.0.1"

# 📌 Load & Save JSON Data
def load_json(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# ✅ Load Devices & Websites
def load_devices():
    return load_json(DEVICE_FILE)

def save_devices(devices):
    save_json(DEVICE_FILE, devices)

def load_blocklist():
    return load_json(BLOCKLIST_FILE)

def save_blocklist(blocklist):
    save_json(BLOCKLIST_FILE, blocklist)

# 🔹 Get Device Name
def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# 🔹 Add a Device
def add_device(ip, mac, role):
    devices = load_devices()
    device_name = get_device_name(ip)
    devices[mac] = {"IP": ip, "Role": role, "Name": device_name}
    save_devices(devices)
    print(f"[+] Device {device_name} ({ip}, {role}) added!")

# 🔹 Scan the Network
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())[:-1] + "1/24"
    except:
        return "192.168.1.1/24"

def scan_network():
    print("[*] Scanning Network...")
    network_ip = get_local_ip()
    arp_request = scapy.ARP(pdst=network_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for response in answered:
        ip = response[1].psrc
        mac = response[1].hwsrc
        name = get_device_name(ip)
        devices.append({"IP": ip, "MAC": mac, "Name": name})
    return devices

# 🔹 Unauthorized Device Detection
def detect_unauthorized_devices():
    print("[*] Checking for unauthorized devices...")
    known_devices = load_devices()
    current_devices = scan_network()

    unauthorized_found = False
    with open(UNAUTHORIZED_LOG, "a") as log_file:
        for device in current_devices:
            mac = device["MAC"]
            name = device["Name"]
            if mac not in known_devices:
                unauthorized_found = True
                alert_message = f"[!] Unauthorized Device Detected: {name} (IP {device['IP']} | MAC {mac})\n"
                print(alert_message)
                log_file.write(f"{datetime.now()} - {alert_message}")

    if not unauthorized_found:
        print("[✓] No unauthorized devices found.")

# 🔹 Internet Access Control
def is_access_allowed():
    current_hour = datetime.now().hour
    for start, end in BLOCKED_HOURS:
        if start <= current_hour or current_hour < end:
            return False
    return True

def block_internet():
    os.system("sudo iptables -A OUTPUT -j DROP")
    print("[!] Internet access blocked!")

def allow_internet():
    os.system("sudo iptables -F")
    print("[+] Internet access allowed!")

def enforce_firewall():
    while True:
        if is_access_allowed():
            allow_internet()
        else:
            block_internet()
        time.sleep(60)

# 🎯 CLI Interface
def menu():
    while True:
        print("\n🔥 Advanced Parental Control Firewall 🔥")
        print("1️⃣  Scan Network")
        print("2️⃣  Add Device")
        print("3️⃣  Start Firewall")
        print("4️⃣  Detect Unauthorized Devices")
        print("5️⃣  Exit")
        
        choice = input("Choose an option: ")
        
        if choice == "1":
            devices = scan_network()
            for d in devices:
                print(f"Device: {d['Name']} | IP: {d['IP']} | MAC: {d['MAC']}")
        elif choice == "2":
            ip = input("Enter Device IP: ")
            mac = input("Enter Device MAC: ")
            role = input("Enter Role (Restricted/Allowed): ")
            add_device(ip, mac, role)
        elif choice == "3":
            print("[*] Firewall started...")
            threading.Thread(target=enforce_firewall, daemon=True).start()
        elif choice == "4":
            detect_unauthorized_devices()
        elif choice == "5":
            print("[+] Exiting...")
            break
        else:
            print("[!] Invalid option!")

# 🚀 Run CLI
if __name__ == "__main__":
    menu()
