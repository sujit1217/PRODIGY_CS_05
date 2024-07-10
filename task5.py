from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        print(f"Packet: {src_ip} -> {dst_ip}, Protocol: {protocol}")

        # Print payload (first 20 bytes)
        if Raw in packet:
            payload = packet[Raw].load[:20]
            print(f"Payload: {payload}")

# Start sniffing packets
print("Packet Sniffer started...")
sniff(prn=packet_callback, store=False)
