# network_packet_analyzer.py

import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):

    if IP in packet:
        ip_layer = packet[IP]
        print(f"[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
        print(f"    Protocol: {ip_layer.proto}")

        if ip_layer.proto == 6:  # TCP
            tcp_layer = packet[TCP]
            print(f"    TCP Payload: {tcp_layer.payload}")
        elif ip_layer.proto == 17:  # UDP
            udp_layer = packet[UDP]
            print(f"    UDP Payload: {udp_layer.payload}")
        elif ip_layer.proto == 1:  # ICMP
            icmp_layer = packet[ICMP]
            print(f"    ICMP Payload: {icmp_layer.payload}")

def main():
    print("Starting packet sniffer...")
    sniff(prn=packet_callback, store=0)

if __name__ == "__main__":
    main()