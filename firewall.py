import scapy.all as scapy
import socket

def get_local_network():
    """Gets the local network IP range (e.g., 192.168.1.1/24)."""
    try:
        ip = socket.gethostbyname(socket.gethostname())
        return ip[:-1] + "1/24"
    except:
        return "192.168.1.1/24"

def scan_network():
    """Scans the network and returns a list of connected devices."""
    network_ip = get_local_network()
    
    arp_request = scapy.ARP(pdst=network_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    
    answered = scapy.srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for response in answered:
        device_info = {"IP": response[1].psrc, "MAC": response[1].hwsrc}
        devices.append(device_info)

    return devices

if __name__ == "__main__":
    devices = scan_network()
    print("\n📡 Connected Devices:\n")
    for device in devices:
        print(f"IP: {device['IP']}  |  MAC: {device['MAC']}")
