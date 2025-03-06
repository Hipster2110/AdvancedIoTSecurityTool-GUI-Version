import nmap
import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading

# Function to scan network for IoT devices
def scan_network(network_range):
    try:
        log_text.insert(tk.END, f"Scanning {network_range} for IoT devices...\n")
        arp_request = scapy.ARP(pdst=network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        devices = []
        for packet in answered_list:
            device = {"IP": packet[1].psrc, "MAC": packet[1].hwsrc}
            devices.append(device)

        return devices

    except Exception as e:
        log_text.insert(tk.END, f"Error scanning network: {e}\n")
        return []

# Function to scan ports and services of discovered IoT devices
def scan_ports(ip):
    open_ports = {}
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, '1-65535', '-sV')  # Scan all ports with service detection

        if ip in scanner.all_hosts():
            for port in scanner[ip]['tcp']:
                if scanner[ip]['tcp'][port]['state'] == 'open':
                    open_ports[port] = scanner[ip]['tcp'][port]['name']

    except Exception as e:
        log_text.insert(tk.END, f"Error scanning ports on {ip}: {e}\n")

    return open_ports

# Function to run the full scan in a separate thread
def run_scan():
    scan_button.config(state=tk.DISABLED)  # Disable scan button while scanning
    network = entry_network.get().strip()

    if not network:
        messagebox.showerror("Error", "Please enter a valid network range.")
        scan_button.config(state=tk.NORMAL)
        return

    devices = scan_network(network)
    
    log_text.insert(tk.END, "\nDiscovered IoT Devices:\n")
    results = []
    
    for device in devices:
        log_text.insert(tk.END, f"IP: {device['IP']}, MAC: {device['MAC']}\n")
        open_ports = scan_ports(device["IP"])
        log_text.insert(tk.END, f"Open Ports & Services: {open_ports}\n\n")
        results.append(f"IP: {device['IP']}, MAC: {device['MAC']}\nOpen Ports & Services: {open_ports}\n\n")

    # Save results to a file
    with open("iot_security_scan_results.txt", "w") as file:
        file.writelines(results)

    log_text.insert(tk.END, "\nScan complete! Results saved in 'iot_security_scan_results.txt'\n")
    scan_button.config(state=tk.NORMAL)  # Re-enable scan button

# Function to start scanning in a new thread
def start_scan():
    threading.Thread(target=run_scan, daemon=True).start()

# Create GUI Window
root = tk.Tk()
root.title("IoT Security Scanner")
root.geometry("600x400")

tk.Label(root, text="Enter Network (e.g., 192.168.1.1/24):").pack()
entry_network = tk.Entry(root, width=30)
entry_network.pack()

scan_button = tk.Button(root, text="Start Scan", command=start_scan)
scan_button.pack()

log_text = scrolledtext.ScrolledText(root, width=70, height=15)
log_text.pack()

root.mainloop()
