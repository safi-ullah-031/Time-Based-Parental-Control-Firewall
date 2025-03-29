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

# 🔹 Add a Device
def add_device(ip, mac, name, role):
    devices = load_devices()
    devices[mac] = {"IP": ip, "Name": name, "Role": role}
    save_devices(devices)
    print(f"[+] Device {name} ({ip} - {role}) added!")

# 🔹 Get Device Name
def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown Device"

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
            if mac not in known_devices:
                unauthorized_found = True
                alert_message = f"[!] Unauthorized Device Detected: {device['Name']} (IP {device['IP']}, MAC {mac})\n"
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

# 🔹 Traffic Monitoring (Fixed)
def log_traffic():
    def process_packet(pkt):
        try:
            with open(TRAFFIC_LOG, "a") as f:
                if pkt.haslayer(scapy.IP):
                    src_ip = pkt[scapy.IP].src
                    dst_ip = pkt[scapy.IP].dst
                    protocol = pkt[scapy.IP].proto

                    src_mac = pkt[scapy.Ether].src if pkt.haslayer(scapy.Ether) else "Unknown"
                    dst_mac = pkt[scapy.Ether].dst if pkt.haslayer(scapy.Ether) else "Unknown"

                    src_port = pkt[scapy.TCP].sport if pkt.haslayer(scapy.TCP) else (
                        pkt[scapy.UDP].sport if pkt.haslayer(scapy.UDP) else "N/A"
                    )
                    dst_port = pkt[scapy.TCP].dport if pkt.haslayer(scapy.TCP) else (
                        pkt[scapy.UDP].dport if pkt.haslayer(scapy.UDP) else "N/A"
                    )

                    log_entry = f"{datetime.now()} | Protocol: {protocol} | {src_ip}:{src_port} ({src_mac}) → {dst_ip}:{dst_port} ({dst_mac})\n"
                    f.write(log_entry)
        except Exception as e:
            print(f"[!] Logging Error: {e}")

    try:
        print("[*] Monitoring network traffic (TCP/UDP/ICMP)... (Requires sudo)")
        scapy.sniff(filter="tcp or udp or icmp", prn=process_packet, store=False, iface="eth0")
    except Exception as e:
        print(f"[!] Sniffing Error: {e}")

def start_monitoring():
    threading.Thread(target=log_traffic, daemon=True).start()
    print("[✓] Traffic Monitoring Started.")

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
        print("8️⃣  Detect Unauthorized Devices")
        print("9️⃣  Exit")
        
        choice = input("Choose an option: ")
        
        if choice == "1":
            devices = scan_network()
            for d in devices:
                print(f"🔹 Name: {d['Name']} | IP: {d['IP']} | MAC: {d['MAC']}")
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
