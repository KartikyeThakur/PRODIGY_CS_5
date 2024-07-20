# PRODIGY_CS_5

# Network Packet Analyzer

## Introduction
The **Network Packet Analyzer** is a tool designed to capture and analyze network packets. This tool will help in understanding network traffic by displaying source and destination IP addresses, protocols, and payload data. It is intended for educational purposes and should be used responsibly and ethically. Unauthorized use of packet sniffing tools can lead to legal and ethical issues.

## Features
- **Packet Capture**: Captures network packets in real-time.
- **Packet Analysis**: Displays source and destination IP addresses, protocols, and payload data.
- **Protocol Identification**: Identifies and displays the type of protocol used (e.g., TCP, UDP, ICMP).
- **Payload Data**: Shows the data contained in the packet payload.
- **Real-Time Monitoring**: Provides real-time monitoring of network traffic.

## Installation Guide

### Prerequisites
Ensure you have Python installed on your system. If not, you can download it from [python.org](https://www.python.org/).

### Install Required Library
Install the `scapy` library, which is used for packet capturing and analysis:
```bash
pip install scapy
```

## Usage Instructions

### Running the Script
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/network-packet-analyzer.git
   ```
2. **Navigate to the Directory**:
   ```bash
   cd network-packet-analyzer
   ```
3. **Run the Application**:
   ```bash
   sudo python packet_analyzer.py
   ```

   **Note:** On Unix-like systems, capturing packets may require administrative privileges. Use `sudo` to run the script with the necessary permissions.

### Example Output
The tool will display output like:
```
Packet captured:
Source IP: 192.168.1.10
Destination IP: 192.168.1.1
Protocol: TCP
Payload: GET / HTTP/1.1

Packet captured:
Source IP: 192.168.1.1
Destination IP: 192.168.1.10
Protocol: HTTP
Payload: HTTP/1.1 200 OK
```

## Python Example Code

Here’s an example of how you can implement a network packet analyzer using `scapy`:

```python
from scapy.all import sniff

# Callback function to handle each packet
def packet_callback(packet):
    print(f"Packet captured:")
    print(f"Source IP: {packet[1].src}")
    print(f"Destination IP: {packet[1].dst}")
    print(f"Protocol: {packet[1].proto}")
    print(f"Payload: {packet[Raw].load if Raw in packet else 'No payload'}")
    print("-" * 50)

# Start capturing packets
def start_sniffing():
    print("Starting packet capture. Press Ctrl+C to stop.")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    start_sniffing()
```

## Detailed Features
- **Packet Capture**:
  - Captures live network traffic using `scapy`.
- **Packet Analysis**:
  - Extracts and displays source and destination IP addresses, protocols, and payload data.
- **Protocol Identification**:
  - Identifies and displays the type of protocol (e.g., TCP, UDP, ICMP).
- **Payload Data**:
  - Shows the data contained in the packet payload, if available.

## Lessons Learned
- **Network Packet Capture**:
  - Implementing real-time network packet capture using the `scapy` library.
- **Packet Analysis**:
  - Extracting and analyzing packet data, including IP addresses, protocols, and payloads.

## Optimizations
- **Filter Specific Packets**:
  - Add functionality to filter packets based on IP addresses, protocols, or port numbers.
- **Enhanced Payload Parsing**:
  - Implement advanced parsing of payload data for different protocols.
- **GUI Integration**:
  - Create a graphical user interface for easier interaction and visualization of captured packets.

## Ethical Considerations
- **Consent**:
  - Always obtain explicit consent from network administrators and users before capturing network traffic.
- **Legal Compliance**:
  - Ensure that the use of the packet analyzer complies with local laws and regulations. Unauthorized network monitoring can lead to legal consequences.
## Sample output
![Screenshot (133)](https://github.com/user-attachments/assets/210859db-887f-42b3-895d-b59c8841507f)
![Screenshot (142)](https://github.com/user-attachments/assets/d27a0291-1157-4749-8880-ad594c839571)
![Screenshot (141)](https://github.com/user-attachments/assets/da49b4a4-267a-4564-9681-f30cce953dcf)
![Screenshot (140)](https://github.com/user-attachments/assets/8acb885c-f574-4100-95e3-a79dde53e511)
![Screenshot (139)](https://github.com/user-attachments/assets/a81f1468-a09d-40da-bb0c-b96cc87de0f9)
![Screenshot (138)](https://github.com/user-attachments/assets/9b9fc41e-f74f-4540-8435-24e17c9dcd10)
![Screenshot (137)](https://github.com/user-attachments/assets/0bf39fdd-83eb-44bf-9fe9-e92fbe2a7875)
![Screenshot (136)](https://github.com/user-attachments/assets/d310dddb-d938-4cc7-9373-98b4e531a144)
![Screenshot (135)](https://github.com/user-attachments/assets/eb079a87-1647-4ac0-ae3b-73853027d9d6)
![Screenshot (134)](https://github.com/user-attachments/assets/53e26f02-37e7-493c-a7ea-226bc063aaa8)
