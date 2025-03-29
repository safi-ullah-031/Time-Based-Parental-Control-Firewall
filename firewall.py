import os
import json
import time
import scapy.all as scapy
import socket
import threading
from datetime import datetime

# 🔹 Device Storage
DEVICE_FILE = "device_profiles.json"
BLOCKED_HOURS = [(22, 7)]  # Example: Block from 10 PM to 7 AM

# 📌 Load & Save Device Data
def load_devices():
    try:
        with open(DEVICE_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_devices(devices):
    with open(DEVICE_FILE, "w") as file:
        json.dump(devices, file, indent=4)

# 🔹 Add a Device
def add_device(ip, mac, role):
    devices = load_devices()
    devices[mac] = {"IP": ip, "Role": role}
    save_devices(devices)
    print(f"[+] Device {ip} ({role}) added!")

# 🔹 Scan the Network
def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())[:-1] + "1/24"
    except:
        return "192.168.1.1/24"

def scan_network():
    """Scans the network for connected devices."""
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
        devices.append({"IP": ip, "MAC": mac})
    return devices

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
        print("\n🔥 Time-Based Parental Control Firewall 🔥")
        print("1️⃣  Scan Network")
        print("2️⃣  Add Device")
        print("3️⃣  Start Firewall")
        print("4️⃣  Exit")
        
        choice = input("Choose an option: ")
        
        if choice == "1":
            devices = scan_network()
            for d in devices:
                print(f"IP: {d['IP']}, MAC: {d['MAC']}")
        elif choice == "2":
            ip = input("Enter Device IP: ")
            mac = input("Enter Device MAC: ")
            role = input("Enter Role (Restricted/Allowed): ")
            add_device(ip, mac, role)
        elif choice == "3":
            print("[*] Firewall started...")
            threading.Thread(target=enforce_firewall, daemon=True).start()
        elif choice == "4":
            print("[+] Exiting...")
            break
        else:
            print("[!] Invalid option!")

# 🚀 Run CLI
if __name__ == "__main__":
    menu()
