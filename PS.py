from scapy.all import sniff

def packet_callback(packet):
    # Check if the packet has an IP layer
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst} (Protocol: {ip_layer.proto})")
        
        # Check if the packet has a TCP layer
        if packet.haslayer('TCP'):
            tcp_layer = packet['TCP']
            print(f"   [TCP] Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
        
        # Check if the packet has a UDP layer
        if packet.haslayer('UDP'):
            udp_layer = packet['UDP']
            print(f"   [UDP] Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
        
        # Check if the packet has a Raw layer (payload)
        if packet.haslayer('Raw'):
            print(f"   [Payload] {packet['Raw'].load}")
    
    print("\n")

# Sniffing packets on the default network interface
print("[*] Starting packet sniffer...")
sniff(prn=packet_callback, store=0)  # store=0 means we are not storing the packets in memory
