# Threat_Intelligence_Automation

Network Traffic and Threat Intelligence Analysis

Overview
This project consists of two Python scripts that analyze network traffic from PCAP files and correlate extracted IP addresses with threat intelligence feeds.

Features:
1.	PCAP Traffic Analysis
o	Extracts metadata from network packets.
o	Identifies protocols and User-Agent strings.
o	Generates a Markdown report with findings and security recommendations.

2.	Threat Intelligence Correlation
o	Extracts unique IP addresses from network traffic.
o	Queries VirusTotal, AbuseIPDB, and AlienVault OTX for threat intelligence data.
o	Generates a detailed security report with threat analysis and recommendations.


📌 How to Use:

    1. Install Dependencies

   pip install -r requirements.txt

    2. Create a .env File in the script directory with your API keys:

   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ALIENVAULT_API_KEY=your_alienvault_api_key

    3. Place your PCAP file in the script directory and update pcap_file in main().
   (password key for pcap file is: infected_20240904)
   
   #Network Traffic Analysis
  - Extracts metadata from a given PCAP file and generates a report.

   python analysis.py

   #Threat Intelligence Analysis
  - Extracts IPs from a PCAP file, queries threat intelligence sources, and generates a security report.

   python detection.py


    4. Output
•	network_analysis_report.md: Summary report of network traffic.
•	threat_intelligence_report.md: Threat intelligence assessment report.
