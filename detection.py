import pyshark
import requests
import json
import os
from datetime import datetime

# Configuration: Replace with actual API keys
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"
ALIENVAULT_API_KEY = "your_alienvault_api_key"

def extract_ip_addresses(pcap_file):
    """Extract unique IP addresses from a PCAP file."""
    capture = pyshark.FileCapture(pcap_file, display_filter="ip")
    ip_addresses = set()
    
    for packet in capture:
        try:
            ip_addresses.add(packet.ip.src)
            ip_addresses.add(packet.ip.dst)
        except AttributeError:
            continue
    
    capture.close()
    return list(ip_addresses)

def query_threat_intelligence(ip):
    """Query multiple threat intelligence sources for a given IP."""
    results = {}
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }
    
    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_response = requests.get(vt_url, headers=headers)
    results["VirusTotal"] = vt_response.json() if vt_response.status_code == 200 else "Error"
    
    # AbuseIPDB
    headers_abuseipdb = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    abuseipdb_url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    abuseipdb_response = requests.get(abuseipdb_url, headers=headers_abuseipdb)
    results["AbuseIPDB"] = abuseipdb_response.json() if abuseipdb_response.status_code == 200 else "Error"
    
    # AlienVault OTX
    alienvault_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}"
    alienvault_response = requests.get(alienvault_url, headers={"X-OTX-API-KEY": ALIENVAULT_API_KEY})
    results["AlienVault"] = alienvault_response.json() if alienvault_response.status_code == 200 else "Error"
    
    return results

def analyze_ips(ip_list):
    """Analyze IP addresses and return threat intelligence results."""
    threat_results = {}
    
    for ip in ip_list:
        print(f"Analyzing {ip}...")
        threat_results[ip] = query_threat_intelligence(ip)
    
    return threat_results

def generate_report(ip_list, threat_findings):
    """Generate a Markdown security report."""
    report_file = "threat_intelligence_report.md"
    with open(report_file, "w") as f:
        f.write(f"# Threat Intelligence Report\n")
        f.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Introduction\n")
        f.write("This report analyzes network traffic and correlates findings with multiple threat intelligence feeds.\n\n")
        
        f.write("## Objective\n")
        f.write("- Extract IP addresses from PCAP network traffic.\n")
        f.write("- Query threat intelligence sources for malicious activity.\n")
        f.write("- Provide a detailed security assessment.\n\n")
        
        f.write("## Findings\n")
        for ip in ip_list:
            f.write(f"### IP Address: {ip}\n")
            for source, result in threat_findings[ip].items():
                f.write(f"- **{source}**: {json.dumps(result, indent=2)}\n")
            f.write("\n")
        
        f.write("## Recommendations\n")
        f.write("- Block identified malicious IP addresses in firewall rules.\n")
        f.write("- Conduct further analysis on flagged network activity.\n")
        f.write("- Keep threat intelligence sources up to date.\n\n")
        
        f.write("## References\n")
        f.write("- [VirusTotal](https://www.virustotal.com)\n")
        f.write("- [AbuseIPDB](https://www.abuseipdb.com)\n")
        f.write("- [AlienVault OTX](https://otx.alienvault.com)\n")
    
    print(f"Report saved as {report_file}")

def main():
    pcap_file = "analyze.pcap"  # Replace with actual file path
    ip_list = extract_ip_addresses(pcap_file)
    threat_findings = analyze_ips(ip_list)
    generate_report(ip_list, threat_findings)

if __name__ == "__main__":
    main()
