import scapy.all as scapy


def sniff_packets(interface, output_file):
    print("[*] Starting packet capture...")
    packets = scapy.sniff(iface=interface, store=True)
    print(f"[*] Packet capture completed. Captured {len(packets)} packets.")

    print("[*] Writing captured packets to PCAP file...")
    scapy.wrpcap(output_file, packets)
    print(f"[*] Packets saved to {output_file}")


interface = input("Enter the interface to sniff on (e.g., eth0): ")
output_file = input("Enter the name of the output PCAP file: ")

sniff_packets(interface, output_file)


