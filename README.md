# wireshark-forensics-plugin
Wireshark is the most widely used network traffic analyzer. It is an important tool for both live traffic analysis & forensic analysis for forensic/malware analysts. Even though Wireshark provides incredibly powerful functionalities for protocol parsing & filtering, it does not provide any contextual information about network endpoints. For a typical analyst, who has to comb through GBs of PCAP files to identify malicious activity, it's like finding a needle in a haystack.

Wireshark Forensics Toolkit is a cross-platform Wireshark plugin that correlates network traffic data with threat intelligence, asset categorization & vulnerability data to speed up network forensic analysis. It does it by extending Wireshark native search filter functionality to allow filtering based on these additional contextual attributes. It works with both PCAP files and real-time traffic captures.

This toolkit provides the following functionality
- Loads malicious Indicators CSV exported from Threat Intelligence Platforms like MISP and associates it with each source/destination IP from network traffic
- Loads asset classification information based on IP-Range to Asset Type mapping which enables filtering incoming/outgoing traffic from a specific type of assets (e.g. filter for ‘Database Server’, ‘Employee Laptop’ etc)
- Loads exported vulnerability scan information exported from Qualys/Nessus map IP to CVEs. 
- Extends native Wireshark filter functionality to allow filtering based severity, source, asset type & CVE information for each source or destination IP address in network logs

# LICENSE: [![License: CC BY-NC-SA 4.0](https://licensebuttons.net/l/by-nc-sa/4.0/80x15.png)](https://creativecommons.org/licenses/by-nc-sa/4.0/)


This work is licensed under a Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
