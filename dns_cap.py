
#!/usr/bin/env python3
from scapy.all import *



print("**************************************")
print("Get Dns response from spicific pcap file")
print("Coded by Eng yazeed")
print("**************************************")

def pcap(file):

    packets = rdpcap(file)

    
    for packet in packets:
        
        if packet.haslayer(DNSRR):
            
            if isinstance(packet.an, DNSRR):
            
                return(packet.an.rrname)


if __name__ == '__main__':
    file = input(" Pcap file ? ")
    print(pcap(file))
