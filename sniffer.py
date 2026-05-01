from scapy.all import sniff
from datetime import datetime

count = 0

def process_packet(packet):
    global count
    count += 1

    if packet.haslayer("IP"):
        ip = packet["IP"]
        time_now = datetime.now().strftime("%H:%M:%S")

        protocol = "Other"
        if packet.haslayer("TCP"):
            protocol = "TCP"
        elif packet.haslayer("UDP"):
            protocol = "UDP"

        print("\n----------------------------")
        print(f"Packet No: {count}")
        print(f"Time: {time_now}")
        print(f"Protocol: {protocol}")
        print(f"{ip.src} -> {ip.dst}")

        with open("packets.txt", "a") as f:
            f.write(f"{time_now} | {protocol} | {ip.src} -> {ip.dst}\n")

print("Sniffer Running... Press Ctrl+C to stop")
sniff(prn=process_packet)