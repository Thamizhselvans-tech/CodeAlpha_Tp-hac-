from scapy.all import sniff, IP, TCP, UDP

def analyze_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        if proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Source IP: {src_ip}  -->  Destination IP: {dst_ip}  |  Protocol: {protocol}")

        if packet.haslayer(TCP):
            print("TCP Payload:", bytes(packet[TCP].payload))
        elif packet.haslayer(UDP):
            print("UDP Payload:", bytes(packet[UDP].payload))

        print("-" * 60)

print("Starting Network Sniffer...")
sniff(prn=analyze_packet, store=False)