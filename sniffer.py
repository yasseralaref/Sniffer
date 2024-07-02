from scapy.all import sniff, IP, TCP, UDP, ICMP
def packet_callback(packet):
	# To Check if the packet has an IP Layer 
	if IP in packet:
		ip_src = packet[IP].src
		ip_dst = packet[IP].dst 

		# Check if the packet has tcp layer 
		if TCP in packet:
			tcp_sport = packet[TCP].sport
			tcp_dport = packet[TCP].dport 
			print(f"IP {ip_src} : {tcp_sport} -> {ip_dst} : {tcp.dport}")
		#======================
		elif UDP in packet:
			udp_sport = packet[UDP].sport 
			udp_dport = packet[UDP].dport 
			print(f"UDP Packet: IP {ip_src} : {udp_sport} -> {ip_dst} : {udp_dport}")
		elif ICMP in packet:
				 print(f"ICMP Packet: IP {ip_src} -> {ip_dst}")
		else:
			print(f"IP {ip_src} -> {ip_dst}")

# Sniff the network traffic 
print("Starting network sniffer.....")
sniff(prn=packet_callback, store=0)


