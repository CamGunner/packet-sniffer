import scapy.all as scapy

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"[*] {source_ip} -> {destination_ip} Protocol: {protocol}")

interface = input("Enter the interface to sniff on (e.g., eth0): ")
sniff_packets(interface)

