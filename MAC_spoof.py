import os
import time
import nmap
import netifaces
from mac_vendor_lookup import MacLookup

VERBOSE = False

DEVICE_CATEGORIES = {
    "Phones": ["Apple", "Samsung", "Google", "Huawei", "OnePlus", "Xiaomi", "Motorola"],
    "Laptops": ["Dell", "HP", "Lenovo", "Apple", "Microsoft", "ASUSTek", "Acer"],
    "Smart TVs": ["LG", "Sony", "Samsung", "Hisense", "Vizio", "TCL", "Roku"],
    "Cameras": ["Hikvision", "Wyze", "Axis", "Foscam", "Reolink", "Amcrest"],
    "Game Consoles": ["Sony", "Microsoft", "Nintendo"],
    "Networking Devices": ["Cisco", "Netgear", "TP-Link", "D-Link", "Ubiquiti", "ARRIS"]
}

def vprint(msg):
    if VERBOSE:
        print("[DEBUG]", msg)

def get_interface():
    for iface in netifaces.interfaces():
        if iface == "lo":
            continue
        if netifaces.AF_INET in netifaces.ifaddresses(iface):
            addrs = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
            ip = addrs.get("addr", "")
            if ip and not ip.startswith("127."):
                vprint(f"Interface found: {iface} with IP {ip}")
                return iface
    return None

def get_subnet(iface):
    try:
        ip_info = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        cidr = sum(bin(int(octet)).count('1') for octet in netmask.split('.'))
        vprint(f"IP: {ip}, Netmask: {netmask}, CIDR: {cidr}")
        return f"{ip}/{cidr}"
    except Exception as e:
        vprint(f"Subnet detection error: {e}")
        return None

def get_original_mac(interface):
    output = os.popen(f"macchanger -s {interface}").read()
    for line in output.splitlines():
        if "Current MAC" in line:
            mac = line.split("Current MAC:")[1].split("(")[0].strip()
            vprint(f"Original MAC parsed: {mac}")
            return mac
    return None

def scan(subnet):
    print(f"\n[+] Scanning subnet {subnet} (fast mode)...")
    scanner = nmap.PortScanner()
    scanner.scan(
        hosts=subnet,
        arguments="-sn --max-retries 1 --host-timeout 500ms"
    )
    devices = []
    for host in scanner.all_hosts():
        vprint(f"Host scanned: {host}")
        if 'mac' in scanner[host]['addresses']:
            ip = scanner[host]['addresses'].get('ipv4', '')
            mac = scanner[host]['addresses'].get('mac', '')
            try:
                vendor = MacLookup().lookup(mac)
            except:
                vendor = "Unknown"
            devices.append((ip, mac, vendor))
    return devices

def filter_devices_by_category(devices):
    print("\n[?] What type of device do you want to spoof?")
    for i, category in enumerate(DEVICE_CATEGORIES.keys(), 1):
        print(f"[{i}] {category}")
    print(f"[{len(DEVICE_CATEGORIES)+1}] Show All")

    choice = input("Select a number: ").strip()
    try:
        index = int(choice)
        if index == len(DEVICE_CATEGORIES) + 1:
            return devices
        category = list(DEVICE_CATEGORIES.keys())[index - 1]
        keywords = DEVICE_CATEGORIES[category]
        filtered = [d for d in devices if any(kw.lower() in d[2].lower() for kw in keywords)]
        print(f"[+] Showing {category} devices:")
        return filtered
    except:
        print("[-] Invalid input. Showing all devices.")
        return devices

def spoof_mac(interface, new_mac):
    print(f"\n[+] Spoofing MAC to {new_mac} ...")
    os.system(f"ifconfig {interface} down")
    os.system(f"macchanger -m {new_mac} {interface}")
    os.system(f"ifconfig {interface} up")
    vprint(f"MAC spoofed using: macchanger -m {new_mac} {interface}")

def restore_mac(interface):
    print(f"\n[+] Restoring original MAC...")
    os.system(f"ifconfig {interface} down")
    os.system(f"macchanger -p {interface}")
    os.system(f"ifconfig {interface} up")
    vprint("MAC restored using: macchanger -p")

def reconnect_wifi(interface, ssid):
    print(f"[+] Reconnecting to Wi-Fi SSID '{ssid}' ...")
    os.system(f"nmcli device wifi connect '{ssid}' iface {interface}")
    vprint(f"Reconnection command: nmcli device wifi connect '{ssid}' iface {interface}")

def main():
    global VERBOSE

    if os.geteuid() != 0:
        print("[-] Please run this script with sudo.")
        return

    verbose_input = input("Enable verbose mode? (y/n): ").strip().lower()
    if verbose_input == "y":
        VERBOSE = True

    interface = get_interface()
    if not interface:
        print("[-] No active network interface found.")
        return
    print(f"[+] Using interface: {interface}")

    original_mac = get_original_mac(interface)
    print(f"[+] Original MAC: {original_mac}")

    subnet = get_subnet(interface)
    if not subnet:
        print("[-] Failed to detect subnet.")
        return

    devices = scan(subnet)
    if not devices:
        print("[-] No devices found on network.")
        return

    # 🔁 Main filter + select loop
    while True:
        filtered_devices = filter_devices_by_category(devices)

        if not filtered_devices:
            print("[-] No matching devices found.")
            continue

        print("\nFiltered Devices:")
        for i, (ip, mac, vendor) in enumerate(filtered_devices):
            print(f"[{i}] IP: {ip} | MAC: {mac} | Vendor: {vendor}")

        choice = input("\nEnter the number of the device to spoof, or type B to go back: ").strip().lower()
        if choice == "b":
            continue
        try:
            index = int(choice)
            _, target_mac, target_vendor = filtered_devices[index]
            break  # valid selection
        except:
            print("[-] Invalid selection.")

    print(f"[+] You selected {target_vendor} ({target_mac})")
    ssid = input("Enter your Wi-Fi SSID to reconnect: ").strip()
    spoof_mac(interface, target_mac)
    reconnect_wifi(interface, ssid)

    restore = input("Do you want to restore your original MAC now? (y/n): ").lower()
    if restore == "y":
        restore_mac(interface)
        print("[+] Original MAC restored.")

    print("[+] Done.")

if __name__ == "__main__":
    main()

#This tool was developed by MrE
