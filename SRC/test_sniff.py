from scapy.all import sniff

print("Sniffing... Press Ctrl+C to stop.")
packets = sniff(count=5)  # Capture 5 packets
for pkt in packets:
    print(pkt.summary())
