import os
import json
import requests
import time
import matplotlib.pyplot as plt
from scapy.all import rdpcap, IP, ARP, TCP, DNSQR, Raw
from dotenv import load_dotenv
from tqdm import tqdm
from datetime import datetime
import hashlib


# Load API keys from .env file
load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ALIENVAULT_API_KEY = os.getenv("ALIENVAULT_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

CACHE_FILE = "ioc_cache.json"
REPORT_FILE = "threat_analysis_report.md"
PLOT_FILE = "threat_visualization.png"

# Load or initialize cache
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        cache = json.load(f)
else:
    cache = {}

def save_cache():
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=4)

def query_api(url, headers, params=None):
    time.sleep(5)  # Prevent API rate limits
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return None

def query_abuseipdb(ip):
    if ip in cache:
        return cache[ip]
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    data = query_api("https://api.abuseipdb.com/api/v2/check", headers, params)
    if data:
        cache[ip] = data
    return data

def query_alienvault(ioc, ioc_type):
    if ioc in cache:
        return cache[ioc]
    headers = {"X-OTX-API-KEY": ALIENVAULT_API_KEY}
    data = query_api(f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general", headers)
    if data:
        cache[ioc] = data
    return data

def query_greynoise(ip):
    if ip in cache:
        return cache[ip]
    headers = {"key": GREYNOISE_API_KEY}
    data = query_api(f"https://api.greynoise.io/v3/community/{ip}", headers)
    if data:
        cache[ip] = data
    return data

def query_vt(ioc, ioc_type):
    if ioc in cache:
        return cache[ioc]
    headers = {"x-apikey": VT_API_KEY}
    data = query_api(f"https://www.virustotal.com/api/v3/{ioc_type}/{ioc}", headers)
    if data:
        cache[ioc] = data
    return data

def analyze_pcap(pcap_file):
    print("[+] Extracting IPs and anomalies from PCAP...")
    packets = rdpcap(pcap_file)
    results = []
    malicious_ips = set()
    malicious_domains = set()
    malicious_hashes = set()
    suspicious_urls = set()
    arp_attacks = set()
    syn_scans = set()
    ips = set()
    
    for packet in tqdm(packets, desc="Processing packets"):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            ips.update([src_ip, dst_ip])
            
            if src_ip not in malicious_ips:
                abuseipdb_data = query_abuseipdb(src_ip)
                alienvault_data = query_alienvault(src_ip, "IPv4")
                greynoise_data = query_greynoise(src_ip)
                if abuseipdb_data or alienvault_data or greynoise_data:
                    malicious_ips.add(src_ip)
                    results.append({"IP": src_ip, "AbuseIPDB": abuseipdb_data, "AlienVault": alienvault_data, "GreyNoise": greynoise_data})

        if DNSQR in packet:
            domain = packet[DNSQR].qname.decode()
            vt_data = query_vt(domain, "domains")
            alienvault_data = query_alienvault(domain, "domain")
            if vt_data or alienvault_data:
                malicious_domains.add(domain)
                results.append({"Domain": domain, "VirusTotal": vt_data, "AlienVault": alienvault_data})
        
        if ARP in packet and packet[ARP].op == 1:
            arp_attacks.add(packet[ARP].psrc)
        
        if TCP in packet and packet[TCP].flags == 2:
            syn_scans.add(packet[IP].src)
    
    total_malicious_iocs = len(malicious_ips) + len(malicious_domains) + len(malicious_hashes) + len(suspicious_urls) + len(arp_attacks) + len(syn_scans)
    print(f"[+] Total data captured from PCAP: {len(ips)} IPs")
    print(f"[+] Total malicious IOCs detected: {total_malicious_iocs}")
    
    save_cache()
    generate_report(results, malicious_ips, malicious_domains, malicious_hashes, suspicious_urls, arp_attacks, syn_scans)
    generate_visualization(malicious_ips, malicious_domains, malicious_hashes, suspicious_urls, arp_attacks, syn_scans)

def generate_report(results, malicious_ips, malicious_domains, malicious_hashes, suspicious_urls, arp_attacks, syn_scans):
    print("[+] Generating Markdown report...")
    with open(REPORT_FILE, "w") as f:
        f.write("# Threat Intelligence & Network Analysis Report\n\n")
        f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Summary of Malicious IOCs\n")
        f.write(f"- Malicious IPs: {len(malicious_ips)}\n")
        f.write(f"- Malicious Domains: {len(malicious_domains)}\n")
        f.write(f"- Malicious File Hashes: {len(malicious_hashes)}\n")
        f.write(f"- Suspicious URLs: {len(suspicious_urls)}\n")
        f.write(f"- ARP Attack Sources: {len(arp_attacks)}\n")
        f.write(f"- SYN Scan Sources: {len(syn_scans)}\n\n")
        
        
        f.write("## Malicious Indicators\n")
        for result in results:
            f.write(json.dumps(result, indent=4) + "\n\n")
        
        f.write(f"### Malicious Domains ({len(malicious_domains)}):\n")
        for domain in malicious_domains:
            f.write(f"- {domain}\n")
        
        f.write(f"### Detected ARP Attacks ({len(arp_attacks)}):\n")
        for arp in arp_attacks:
            f.write(f"- {arp}\n")
        
        f.write(f"### SYN Scan Sources ({len(syn_scans)}):\n")
        for syn in syn_scans:
            f.write(f"- {syn}\n")
    
    print(f"[+] Report saved to {REPORT_FILE}")
    
def generate_visualization(malicious_ips, malicious_domains, malicious_hashes, suspicious_urls, arp_attacks, syn_scans):
    categories = ["Malicious IPs", "Malicious Domains", "File Hashes", "Suspicious URLs", "ARP Attacks", "SYN Scans"]
    values = [len(malicious_ips), len(malicious_domains), len(malicious_hashes), len(suspicious_urls), len(arp_attacks), len(syn_scans)]
    
    plt.figure(figsize=(10, 6))
    plt.bar(categories, values, color=['red', 'blue', 'green', 'purple', 'orange', 'cyan'])
    plt.xlabel("IOC Categories")
    plt.ylabel("Count")
    plt.title("Threat Intelligence Analysis Summary")
    plt.xticks(rotation=30, ha='right')
    plt.tight_layout()
    plt.savefig(PLOT_FILE)
    plt.close()
    
    print(f"[+] Visualization saved to {PLOT_FILE}")  


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python analyze.py <pcap_file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
