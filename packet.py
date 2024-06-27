from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = ''

        if packet.haslayer(TCP):
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            protocol = 'UDP'

        payload = packet[Raw].load if packet.haslayer(Raw) else None

        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {protocol}")
        if payload:
            print(f"Payload: {payload}")
        print("\n")

def start_sniffing(interface=None):
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="A simple packet sniffer tool.")
    parser.add_argument('-i', '--interface', help="Network interface to sniff on (e.g., eth0, wlan0)")

    args = parser.parse_args()

    print("Starting packet sniffing...")
    print("Press Ctrl+C to stop...")
    start_sniffing(interface=args.interface)
    