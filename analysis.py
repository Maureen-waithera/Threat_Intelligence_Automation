import pyshark
import json
from datetime import datetime


def extract_pcap_data(pcap_file):
    """Extract metadata from PCAP file."""
    capture = pyshark.FileCapture(pcap_file, display_filter="ip or tcp or udp or http or dns")
    traffic_data = []
    
    for packet in capture:
        try:
            data = {
                "timestamp": packet.sniff_time,
                "source_ip": packet.ip.src,
                "destination_ip": packet.ip.dst,
                "protocol": packet.highest_layer,
                "http_user_agent": getattr(packet.http, "User-Agent", "Unknown") if hasattr(packet, "http") else "N/A"
            }
            traffic_data.append(data)
        except AttributeError:
            continue
    capture.close()
    return traffic_data


def generate_report(traffic_data):
    """Generate a Markdown report for network analysis."""
    report_file = "network_analysis.md"
    with open(report_file, "w") as f:
        f.write("# Network Traffic Analysis Report\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Findings\n")
        f.write("### Extracted Metadata\n")
        for entry in traffic_data:
            f.write(f"- {entry['timestamp']} | {entry['source_ip']} -> {entry['destination_ip']} | {entry['protocol']} | User-Agent: {entry['http_user_agent']}\n")
        
        f.write("\n## Recommendations\n")
        f.write("- Monitor and filter traffic for unauthorized connections.\n")
        f.write("- Inspect unusual user-agent strings in HTTP traffic.\n")
        f.write("- Analyze traffic for potential data exfiltration.\n")
    
    print(f"Report saved as {report_file}")


def main():
    pcap_file = "analyze.pcap"  # Replace with actual file path
    traffic_data = extract_pcap_data(pcap_file)
    generate_report(traffic_data)


if __name__ == "__main__":
    main()

