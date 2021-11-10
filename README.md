# wireshark-forensics-plugin
Wireshark is the most widely used network traffic analyzer. It is an important tool for both live traffic analysis & forensic analysis for forensic/malware analysts. Even though Wireshark provides incredibly powerful functionalities for protocol parsing & filtering, it does not provide any contextual information about network endpoints. For a typical analyst, who has to comb through GBs of PCAP files to identify malicious activity, it's like finding a needle in a haystack.

Wireshark Forensics Toolkit is a cross-platform Wireshark plugin that correlates network traffic data with threat intelligence, asset categorization & vulnerability data to speed up network forensic analysis. It does it by extending Wireshark native search filter functionality to allow filtering based on these additional contextual attributes. It works with both PCAP files and real-time traffic captures.

This toolkit provides the following functionality
- Loads malicious Indicators CSV exported from Threat Intelligence Platforms like MISP and associates it with each source/destination IP from network traffic
- Loads asset classification information based on IP-Range to Asset Type mapping which enables filtering incoming/outgoing traffic from a specific type of assets (e.g. filter for ‘Database Server’, ‘Employee Laptop’ etc)
- Loads exported vulnerability scan information exported from Qualys/Nessus map IP to CVEs. 
- Extends native Wireshark filter functionality to allow filtering based severity, source, asset type & CVE information for each source or destination IP address in network logs

# How To Use
1. Download source Zip file or checkout the code
2. Folder data/formatted_reports has 3 files 
  * asset_tags.csv : Information about asset ip/domain/cidr and associated tags. Default file has few examples for intranet IPs & DNS servers
  * asset_vulnerabilities.csv : Details about CVE IDs and top CVSS score value for each asset
  * indicators.csv : IOC data with attributes type, value, severity & threat type
3. All 3 files mentioned in step (2) can either be manually edited or vulnerabilities & indicators file can be generated using exported MISP & Tenable Nessus scan report. Need to place exported files under following folders with exact name specified
 - raw_reports/misp.csv : this file can be exported from MISP from following location, Export->CSV_Sig->Generate then Download

![image](https://user-images.githubusercontent.com/12109344/141029639-d755edf0-4467-4a80-aae3-089b5e4ab175.png)

 - raw_reports/nessus.csv : this file can be exported from tenable nessus interface. Goto Scans->Scan Results->Select latest full scan entry. Select Vulnerability Detail List from Dropdown.

![image](https://user-images.githubusercontent.com/12109344/141030328-7940caef-21b3-41d3-b3de-86647f5ba424.png)
 
 Then goto Options->Export as CSV->Select All->Submit. Rename downloaded file as nessus.csv and copy it to raw_reports/nessus.csv

4. Run wft.exe if you are on windows, else run 'python wft.py' on Mac or Ubuntu. Script will automatically pick up Wireshark Install location. If you are using windows portable App provide path to Data location e.g. 'C:\Downloads\WiresharkPortable\Data\'

5. Post Installation, Open Wireshark & go to Edit->Configuration Profiles and select wireshark forensic toolkit profile. This will enable all additional columns
![image](https://user-images.githubusercontent.com/12109344/141031264-20beb1bf-8749-45a8-b67c-0a370e9f6e11.png)

6. Now either open a PCAP file or start a live capture. In search filter you can use additional filtering parameters each starting with 'wft'. Wireshark will show dropdown for all filtering parameters available. Note all these additional filtering parameters are available for both source & destinations IP/Domain values.

![image](https://user-images.githubusercontent.com/12109344/141031739-4a062634-cbe3-4f12-8445-88b7ab393690.png)




# LICENSE: [![License: CC BY-NC-SA 4.0](https://licensebuttons.net/l/by-nc-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-nc-sa/4.0/)


This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
