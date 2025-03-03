import pyshark
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import argparse
import time
from datetime import datetime, timezone
import requests

# Function to lookup IP information
def lookup_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        print(f"⚠️ IP lookup failed for {ip}: {e}")
    return None

# Function to parse pcap file
def parse_pcap(filename):
    print("⏳ Loading and analyzing pcap file. This may take some time...")
    start_time = time.time()
    capture = list(pyshark.FileCapture(filename))
    
    print(f"📥 Captured {len(capture)} packets. Processing...")

    src_ips = set()
    dst_ips = set()
    protocols = set()
    file_signatures = set()
    user_agents = set()
    dns_queries = set()
    arp_attacks = set()
    syn_scan_sources = set()
    syn_scan_destinations = set()
    leaked_credentials = set()
    
    for packet in capture:
        try:
            if hasattr(packet, 'ip'):
                src_ips.add(packet.ip.src)
                dst_ips.add(packet.ip.dst)
            
            if hasattr(packet, 'eth') and hasattr(packet.eth, 'type'):
                protocols.add(packet.eth.type)
            
            if hasattr(packet, 'http'):
                if hasattr(packet.http, 'file_data'):
                    file_signatures.add(str(packet.http.file_data))
                if hasattr(packet.http, 'user_agent'):
                    user_agents.add(str(packet.http.user_agent))
                if hasattr(packet.http, 'authorization'):
                    leaked_credentials.add(str(packet.http.authorization))
            
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                dns_queries.add(str(packet.dns.qry_name))
            
            if hasattr(packet, 'arp') and hasattr(packet.arp, 'opcode') and packet.arp.opcode == '1':  # ARP request
                arp_attacks.add((packet.eth.src, packet.arp.src_proto_ipv4))
            
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags') and int(packet.tcp.flags, 16) == 2:  # SYN flag only
                syn_scan_sources.add(packet.ip.src)
                syn_scan_destinations.add(packet.ip.dst)
        except Exception as e:
            print(f"⚠️ Error processing packet: {e}")
    
    elapsed_time = time.time() - start_time
    print(f"✅ Analysis Complete in {elapsed_time:.2f} seconds.")
    return src_ips, dst_ips, protocols, file_signatures, user_agents, dns_queries, arp_attacks, syn_scan_sources, syn_scan_destinations, leaked_credentials

# Function to create data visualizations
def create_visualizations(src_ips, dst_ips, protocols, file_signatures, user_agents, dns_queries, arp_attacks, syn_scan_sources, syn_scan_destinations, leaked_credentials):
    print("📊 Generating visualizations...")
    
    categories = ['Source IPs', 'Destination IPs', 'Protocols', 'File Signatures', 'User Agents', 'DNS Queries', 'ARP Attacks', 'SYN Scan Sources', 'SYN Scan Destinations', 'Leaked Credentials']
    counts = [len(src_ips), len(dst_ips), len(protocols), len(file_signatures), len(user_agents), len(dns_queries), len(arp_attacks), len(syn_scan_sources), len(syn_scan_destinations), len(leaked_credentials)]
    
    df = pd.DataFrame({'Category': categories, 'Count': counts})
    plt.figure(figsize=(10, 6))
    sns.barplot(x='Category', y='Count', data=df)
    plt.title('Network Analysis Summary')
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.savefig('network_summary.png')
    print("✅ Visualization saved as network_summary.png")
    plt.show()

# Function to generate markdown report
def generate_report(src_ips, dst_ips, protocols, file_signatures, user_agents, dns_queries, arp_attacks, syn_scan_sources, syn_scan_destinations, leaked_credentials):
    print("📝 Generating network analysis report...")
    report = f"""
# Network Analysis Report

**Date and Time**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}

## Summary
- **Source IP Addresses**: {len(src_ips)}
- **Destination IP Addresses**: {len(dst_ips)}
- **Protocols Detected**: {len(protocols)}
- **File Signatures**: {len(file_signatures)}
- **HTTP User Agents**: {len(user_agents)}
- **DNS Queries**: {len(dns_queries)}
- **ARP Attacks Detected**: {len(arp_attacks)}
- **SYN Scan Sources**: {len(syn_scan_sources)}
- **SYN Scan Destinations**: {len(syn_scan_destinations)}
- **Leaked Credentials Found**: {len(leaked_credentials)}

## Detailed Information

### Source IP Addresses
"""
    for ip in src_ips:
        report += f"- {ip}\n"

    report += "\n### Destination IP Addresses\n"
    for ip in dst_ips:
        report += f"- {ip}\n"

    report += "\n### DNS Queries\n"
    for query in dns_queries:
        report += f"- {query}\n"

    report += "\n### File Signatures\n"
    for signature in file_signatures:
        report += f"- {signature}\n"

    report += "\n### HTTP User Agents\n"
    for agent in user_agents:
        report += f"- {agent}\n"

    report += "\n### ARP Attacks (Unique)\n"
    for mac, ip in arp_attacks:
        report += f"- MAC: {mac}, Source IP: {ip}\n"

    report += "\n### SYN Scan Sources (Unique)\n"
    for src_ip in syn_scan_sources:
        report += f"- {src_ip}\n"

    report += "\n### SYN Scan Destinations (Unique)\n"
    for dst_ip in syn_scan_destinations:
        report += f"- {dst_ip}\n"

    report += "\n### Leaked Credentials\n"
    for cred in leaked_credentials:
        report += f"- {cred}\n"

    with open("network_analysis_report.md", "w") as report_file:
        report_file.write(report)
    print("✅ Report generated: network_analysis_report.md")

# Main function
def main():
    parser = argparse.ArgumentParser(description="Analyze a pcap file and generate a report.")
    parser.add_argument("pcap_file", help="The pcap file to analyze.")
    args = parser.parse_args()

    print("🚀 Starting Network Analysis...")
    src_ips, dst_ips, protocols, file_signatures, user_agents, dns_queries, arp_attacks, syn_scan_sources, syn_scan_destinations, leaked_credentials = parse_pcap(args.pcap_file)
    
    print("📢 Analysis complete! Generating visualizations and report...")
    create_visualizations(src_ips, dst_ips, protocols, file_signatures, user_agents, dns_queries, arp_attacks, syn_scan_sources, syn_scan_destinations, leaked_credentials)

    print("📝 Calling generate_report() function...")
    generate_report(src_ips, dst_ips, protocols, file_signatures, user_agents, dns_queries, arp_attacks, syn_scan_sources, syn_scan_destinations, leaked_credentials)

    print("🎉 Analysis Complete. Check the generated report and visualizations.")

if __name__ == "__main__":
    main()
