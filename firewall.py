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

# 🔹 Firewall Rules
BLOCKED_HOURS = [(22, 7)]  # Example: Block from 10 PM to 7 AM
HOSTS_FILE = "/etc/hosts"
REDIRECT_IP = "127.0.0.1"

# 📌 Load & Save Device Data
def load_json(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

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

# 🔹 Website Blocking
def update_hosts(blocklist):
    try:
        with open(HOSTS_FILE, "r+") as file:
            lines = file.readlines()
            file.seek(0)
            for line in lines:
                if not any(site in line for site in blocklist):
                    file.write(line)
            for site in blocklist:
                file.write(f"{REDIRECT_IP} {site}\n")
            file.truncate()
        print("✅ Website blocking updated!")
    except PermissionError:
        print("❌ Run as root (sudo) to modify hosts file.")

def add_website(site):
    blocklist = load_blocklist()
    if site not in blocklist:
        blocklist.append(site)
        save_blocklist(blocklist)
        update_hosts(blocklist)
        print(f"✅ {site} added to blocklist.")

def remove_website(site):
    blocklist = load_blocklist()
    if site in blocklist:
        blocklist.remove(site)
        save_blocklist(blocklist)
        update_hosts(blocklist)
        print(f"✅ {site} removed from blocklist.")

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

# 🔹 Traffic Monitoring
def log_traffic():
    print("[*] Monitoring network traffic...")
    while True:
        packets = scapy.sniff(count=10, timeout=5)
        with open(TRAFFIC_LOG, "a") as f:
            for pkt in packets:
                f.write(f"{datetime.now()} - {pkt.summary()}\n")
        time.sleep(5)

# 🎯 CLI Interface
def menu():
    while True:
        print("\n🔥 Advanced Parental Control Firewall 🔥")
        print("1️⃣  Scan Network")
        print("2️⃣  Add Device")
        print("3️⃣  Block a Website")
        print("4️⃣  Unblock a Website")
        print("5️⃣  Show Blocked Websites")
        print("6️⃣  Start Firewall")
        print("7️⃣  Monitor Traffic")
        print("8️⃣  Exit")
        
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
            site = input("Enter website (e.g., youtube.com): ")
            add_website(site)
        elif choice == "4":
            site = input("Enter website to unblock: ")
            remove_website(site)
        elif choice == "5":
            print("\n🔒 Blocked Websites:")
            for site in load_blocklist():
                print(f" - {site}")
        elif choice == "6":
            print("[*] Firewall started...")
            threading.Thread(target=enforce_firewall, daemon=True).start()
        elif choice == "7":
            print("[*] Traffic monitoring started...")
            threading.Thread(target=log_traffic, daemon=True).start()
        elif choice == "8":
            print("[+] Exiting...")
            break
        else:
            print("[!] Invalid option!")

# 🚀 Run CLI
if __name__ == "__main__":
    menu()
