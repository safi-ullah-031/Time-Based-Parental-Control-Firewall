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

# 🔹 Device Management
def add_device(ip, mac, name, role):
    devices = load_devices()
    devices[mac] = {"IP": ip, "Name": name, "Role": role}
    save_devices(devices)
    print(f"[+] Device {name} ({ip} - {role}) added!")

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Device"

# 🔹 Network Scanning
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
    
    return [{"IP": response[1].psrc, "MAC": response[1].hwsrc, "Name": get_device_name(response[1].psrc)} for response in answered]

# 🔹 Unauthorized Device Detection
def detect_unauthorized_devices():
    print("[*] Checking for unauthorized devices...")
    known_devices = load_devices()
    current_devices = scan_network()
    unauthorized_found = False
    
    with open(UNAUTHORIZED_LOG, "a") as log_file:
        for device in current_devices:
            if device["MAC"] not in known_devices:
                unauthorized_found = True
                alert_message = f"[!] Unauthorized Device Detected: {device['Name']} (IP {device['IP']}, MAC {device['MAC']})\n"
                print(alert_message)
                log_file.write(f"{datetime.now()} - {alert_message}")
    
    if not unauthorized_found:
        print("[✓] No unauthorized devices found.")

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

# 🔹 Firewall Enforcement
def is_access_allowed():
    current_hour = datetime.now().hour
    return not any(start <= current_hour or current_hour < end for start, end in BLOCKED_HOURS)

def block_internet():
    os.system("sudo iptables -A OUTPUT -j DROP")
    print("[!] Internet access blocked!")

def allow_internet():
    os.system("sudo iptables -F")
    print("[+] Internet access allowed!")

def enforce_firewall():
    while True:
        allow_internet() if is_access_allowed() else block_internet()
        time.sleep(60)

# 🔹 Traffic Monitoring
def log_traffic():
    def process_packet(pkt):
        try:
            if pkt.haslayer(scapy.IP):
                with open(TRAFFIC_LOG, "a") as f:
                    log_entry = f"{datetime.now()} | {pkt[scapy.IP].src} -> {pkt[scapy.IP].dst}\n"
                    f.write(log_entry)
        except Exception as e:
            print(f"[!] Logging Error: {e}")
    
    print("[*] Monitoring network traffic... (Requires sudo)")
    scapy.sniff(filter="tcp or udp or icmp", prn=process_packet, store=False, iface="eth0")

def start_monitoring():
    threading.Thread(target=log_traffic, daemon=True).start()
    print("[✓] Traffic Monitoring Started.")

# 🎯 CLI Interface
def menu():
    while True:
        print("\n🔥 Advanced Parental Control Firewall 🔥")
        options = [
            "Scan Network", "Add Device", "Block a Website", "Unblock a Website",
            "Show Blocked Websites", "Start Firewall", "Monitor Traffic", "Detect Unauthorized Devices", "Exit"
        ]
        
        for i, option in enumerate(options, 1):
            print(f"{i}️⃣  {option}")
        
        choice = input("Choose an option: ")
        if choice == "1":
            for d in scan_network():
                print(f"🔹 {d['Name']} | {d['IP']} | {d['MAC']}")
        elif choice == "2":
            add_device(input("IP: "), input("MAC: "), input("Name: "), input("Role: "))
        elif choice == "3":
            add_website(input("Website: "))
        elif choice == "4":
            remove_website(input("Website: "))
        elif choice == "5":
            print("\n🔒 Blocked Websites:", load_blocklist())
        elif choice == "6":
            threading.Thread(target=enforce_firewall, daemon=True).start()
        elif choice == "7":
            start_monitoring()
        elif choice == "8":
            detect_unauthorized_devices()
        elif choice == "9":
            break
        else:
            print("[!] Invalid option!")

if __name__ == "__main__":
    menu()
