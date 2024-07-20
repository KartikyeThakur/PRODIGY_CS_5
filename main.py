from scapy.all import *

# Function to handle each packet
def handle_packet(packet):
    # Extract IP and TCP/UDP layers
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        payload = None

        # Check for TCP or UDP layer and extract payload
        if packet.haslayer(TCP):
            payload = str(packet.getlayer(TCP).payload)
            protocol_name = 'TCP'
        elif packet.haslayer(UDP):
            payload = str(packet.getlayer(UDP).payload)
            protocol_name = 'UDP'
        else:
            protocol_name = 'Unknown'

        # Print packet details
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol_name}")
        if payload:
            print(f"Payload: {payload[:100]}")  # Display first 100 characters of payload
        print("-" * 50)

# Main function to start packet sniffing
def main(interface):
    print(f"Starting packet capture on {interface}...")
    sniff(iface=interface, prn=handle_packet, store=0)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        interface = 'eth0' # Default interface if none provided
    else:
        interface = sys.argv[1]
        # Remove the '-f' prefix if present
        if interface.startswith('-f'):
            interface = interface[2:]
    main(interface)