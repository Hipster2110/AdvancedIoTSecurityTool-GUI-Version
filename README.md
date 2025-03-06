# IoT Security Scanner

## Overview
The **IoT Security Scanner** is a Python-based tool that scans a network for connected IoT devices, retrieves their IP and MAC addresses, and performs port scanning to identify open services. It uses **Scapy** for network discovery and **Nmap** for port scanning. The tool features a **Tkinter GUI** for ease of use.

## Features
- **Network Scanning**: Detects IoT devices on a specified network range using ARP requests.
- **Port Scanning**: Identifies open ports and services on discovered devices using Nmap.
- **User-Friendly GUI**: Simple Tkinter interface for easy operation.
- **Results Logging**: Saves scan results to `iot_security_scan_results.txt`.
- **Error Handling**: Handles invalid inputs and scanning errors gracefully.
- **Multi-threading Support**: Ensures the GUI remains responsive while scanning.

## Prerequisites
Ensure you have the following dependencies installed before running the script:

- **Python 3.x**
- **Scapy** (`pip install scapy`)
- **Nmap** (`apt install nmap` or `brew install nmap`)
- **python-nmap** (`pip install python-nmap`)
- **Tkinter** (included with standard Python installation)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Hipster2110/AdvancedIoTSecurityTool-GUI-Version.git
   cd AdvancedIoTSecurityTool-GUI-Version
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool:
   ```bash
   sudo python iot_scanner.py
   ```
   > **Note:** Running as **root** is required for network scanning.

## Usage
1. Enter the target network range (e.g., `192.168.1.1/24`).
2. Click **Start Scan** to begin scanning.
3. View results in the GUI log.
4. Scan results will be saved in `iot_security_scan_results.txt`.

## Example Output
```
Scanning 192.168.1.1/24 for IoT devices...

Discovered IoT Devices:
IP: 192.168.1.10, MAC: AA:BB:CC:DD:EE:FF
Open Ports & Services: {22: 'ssh', 80: 'http'}

Scan complete! Results saved in 'iot_security_scan_results.txt'
```

## Known Issues
- Requires **sudo/root** privileges for full functionality.
- Scanning large networks may take time.
- Ensure **Nmap** is installed before running the script.

## Future Enhancements
- Add **device fingerprinting** to detect IoT device types.
- Implement **automatic vulnerability detection**.
- Provide **export options** (CSV, JSON).

## License
This project is licensed under the MIT License.

## Author
Developed by **[Your Name]**. Contributions and feedback are welcome!

## Repository Link
GitHub: [AdvancedIoTSecurityTool-GUI-Version](https://github.com/Hipster2110/AdvancedIoTSecurityTool-GUI-Version)

