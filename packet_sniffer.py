from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

def packet_callback(packet):
"""
Callback function to process each captured packet.
"""
print("\n" + "="*50)
print(f"Packet Captured at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}")

# Check for IP layer
if packet.haslayer(IP):
ip_layer = packet.getlayer(IP)
print(f" Source IP: {ip_layer.src}")
print(f" Destination IP: {ip_layer.dst}")
print(f" Protocol: {ip_layer.proto} ({ip_layer.proto_name})")

# Check for TCP layer
if packet.haslayer(TCP):
tcp_layer = packet.getlayer(TCP)
print(f" Source Port (TCP): {tcp_layer.sport}")
print(f" Destination Port (TCP): {tcp_layer.dport}")
print(f" TCP Flags: {tcp_layer.flags}")
if tcp_layer.flags & 0x02: # Check for SYN flag
print(" (SYN - Connection Request)")
if tcp_layer.flags & 0x10: # Check for ACK flag
print(" (ACK - Acknowledgment)")
if tcp_layer.flags & 0x01: # Check for FIN flag
print(" (FIN - Connection Teardown)")
if tcp_layer.flags & 0x04: # Check for RST flag
print(" (RST - Reset Connection)")


# Extract payload data for TCP
if packet.haslayer(Raw):
payload = packet.getlayer(Raw).load
print(f" TCP Payload (Raw): {payload[:50]}...") # Show first 50 bytes
# Try to decode if it looks like common text
try:
decoded_payload = payload.decode('utf-8', errors='ignore')
print(f" Decoded TCP Payload: {decoded_payload.strip()[:100]}...") # Show first 100 decoded chars
except UnicodeDecodeError:
print(" (Payload not easily decodable as UTF-8)")


# Check for UDP layer
elif packet.haslayer(UDP):
udp_layer = packet.getlayer(UDP)
print(f" Source Port (UDP): {udp_layer.sport}")
print(f" Destination Port (UDP): {udp_layer.dport}")

# Extract payload data for UDP
if packet.haslayer(Raw):
payload = packet.getlayer(Raw).load
print(f" UDP Payload (Raw): {payload[:50]}...") # Show first 50 bytes
try:
decoded_payload = payload.decode('utf-8', errors='ignore')
print(f" Decoded UDP Payload: {decoded_payload.strip()[:100]}...")
except UnicodeDecodeError:
print(" (Payload not easily decodable as UTF-8)")

else:
print(" Protocol Details: Other IP Protocol")
if packet.haslayer(Raw):
payload = packet.getlayer(Raw).load
print(f" Raw Payload: {payload[:50]}...") # Show first 50 bytes


else:
print(" Non-IP Packet (e.g., ARP, spanning tree, etc.)")
# You can add more layers here like ARP, Ethernet, etc.
# For example, to print Ethernet layer:
# if packet.haslayer(Ether):
# eth_layer = packet.getlayer(Ether)
# print(f" Ethernet Source: {eth_layer.src}")
# print(f" Ethernet Destination: {eth_layer.dst}")

print("="*50)

def main():
print("--- Simple Python Packet Sniffer ---")
print("Capturing packets. Press Ctrl+C to stop.")
print("\n*** IMPORTANT: Use this tool ethically and only on networks you have explicit permission to monitor. ***\n")

# You might need to specify your network interface name.
# On Linux/macOS, common interfaces are 'eth0', 'wlan0', 'en0'.
# On Windows, it could be something like 'Ethernet', 'Wi-Fi', or a GUID string.
# To find your interface name:
# - Linux/macOS: `ifconfig` or `ip a`
# - Windows: `ipconfig`
# If left as None, scapy might try to guess, or you might get an error.
interface = input("Enter network interface (e.g., eth0, wlan0, Ethernet, Wi-Fi). Leave blank for default: ").strip()
if not interface:
interface = None # Let Scapy try to find the default

# Filter packets. Examples:
# "tcp port 80" - only TCP packets on port 80
# "host 192.168.1.1" - packets to/from this IP
# "tcp and port 443" - TCP on port 443
# "" - capture all packets
bpf_filter = input("Enter BPF filter (e.g., 'tcp port 80', 'udp', 'icmp'). Leave blank for all packets: ").strip()

count = input("Enter number of packets to capture (e.g., 10), or leave blank for continuous: ").strip()
if count.isdigit():
count = int(count)
else:
count = 0 # 0 means continuous capture until stopped manually

try:
print(f"\nStarting capture on interface: {interface if interface else 'default'}")
print(f"Using filter: '{bpf_filter if bpf_filter else 'None (all packets)'}'")
print(f"Capturing {count if count > 0 else 'continuously'} packets...")
# Use store=0 to avoid storing packets in memory for continuous capture,
# especially for educational purposes where we just want to print.
sniff(iface=interface, prn=packet_callback, filter=bpf_filter, count=count, store=0)
except PermissionError:
print("\nERROR: Permission denied. You need root/administrator privileges to capture packets.")
print("Try running the script with 'sudo python your_script_name.py' (Linux/macOS) or as Administrator (Windows).")
except ImportError:
print("\nERROR: Scapy or required packet capture libraries are not installed correctly.")
print("Please ensure you have run 'pip install scapy' and installed libpcap/Npcap.")
except Exception as e:
print(f"\nAn unexpected error occurred: {e}")

if __name__ == "__main__":
main()