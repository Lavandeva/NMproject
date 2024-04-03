import scapy.all as scapy
import matplotlib.pyplot as plt
from collections import Counter

def analyze_pcap(filename):
    """Analyzes a PCAP file and provides insights into network traffic.

    Args:
        filename (str): The path to the PCAP file.

    Prints:
        Statistics on protocol distribution, IP communication patterns,
        and potential suspicious activity.
        Generates a visualization of protocol distribution.

    Raises:
        FileNotFoundError: If the specified PCAP file is not found.
    """

    try:
        packets = scapy.rdpcap(filename)
    except FileNotFoundError:
        print(f"Error: PCAP file '{filename}' not found.")
        return

    # Protocol Distribution
    protocols = Counter()
    for packet in packets:
        if hasattr(packet, 'proto'):
            protocols[packet.proto] += 1

    total_packets = len(packets)
    print("Protocol Distribution:")
    for protocol, count in protocols.items():
        percentage = (count / total_packets) * 100
        print(f"- {protocol}: {count} packets ({percentage:.2f}%)")

    # IP Communication Patterns
    source_ips = Counter()
    dest_ips = Counter()
    for packet in packets:
        if scapy.IP in packet:
            source_ip = packet[scapy.IP].src
            dest_ip = packet[scapy.IP].dst
            source_ips[source_ip] += 1
            dest_ips[dest_ip] += 1

    print("\nTop 10 Source IPs (by packet count):")
    sorted_source_ips = source_ips.most_common(10)
    for ip, count in sorted_source_ips:
        print(f"- {ip}: {count} packets")

    print("\nTop 10 Destination IPs (by packet count):")
    sorted_dest_ips = dest_ips.most_common(10)
    for ip, count in sorted_dest_ips:
        print(f"- {ip}: {count} packets")

    # Potential Suspicious Activity (more advanced examples)
    syn_packets = 0
    for packet in packets:
        if scapy.TCP in packet and packet[scapy.TCP].flags == 'S':
            syn_packets += 1

    syn_rate = (syn_packets / total_packets) * 100
    syn_threshold = 10  # Adjust this threshold based on network characteristics

    if syn_rate > syn_threshold:
        print("\nPotential Suspicious Activity:")
        print(f"High SYN packet rate detected ({syn_packets} packets, {syn_rate:.2f}%).")
        print("This could indicate a potential port scan or denial-of-service attack.")

    # Advanced Analysis (example using flow statistics)
    from scapy.stats import PacketList

    # Group packets by flow (source IP, destination IP, protocol, port combination)
    flows = PacketList(packets)
    flow_stats = flows.get_layer(scapy.IP).stats.most_common(10)

    # Analyze flow statistics (e.g., identify high bandwidth usage or unusual protocols)
    print("\nFlow Statistics (Top 10 by packet count):")
    for flow, count in flow_stats:
        print(f"- {flow}: {count} packets")

    # Protocol Distribution Visualization
    plt.figure(figsize=(8, 6))
    plt.pie(protocols.values(), labels=protocols.keys(), autopct="%1.1f%%")
    plt.title("Protocol Distribution")
    plt.show()

if __name__ == "__main__":
    filename = "path/to/your/pcap.pcap"  # Replace with your PCAP file path
    analyze_pcap(filename)