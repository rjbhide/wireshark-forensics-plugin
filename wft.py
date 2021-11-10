import csv
import sys
import os
import json
import shutil

ASSET_VULNERABILITY_CSV = "asset_vulnerabilities.csv"
INDICATOR_CSV = "indicators.csv"
ASSET_TAG_CSV = "asset_tags.csv"
CONFIG_FILE = "config.json"
CURRENT_USER = os.path.split(os.path.expanduser('~'))[-1]
SYSTEM_DRIVE = os.getenv("SystemDrive")
if not SYSTEM_DRIVE:
    SYSTEM_DRIVE = "C"

config = {}
if os.path.exists(CONFIG_FILE):
    config = json.loads(open(CONFIG_FILE).read())


def download_iocs_from_threatstream(output_path):
    import requests
    ts_api_base_url = config["threatstream"]["api_url"]
    ts_username = config["threatstream"]["username"]
    ts_api_key = config["threatstream"]["api_key"]
    ts_filter = config["threatstream"]["filter"]

    query = "({}) and (type=ip or type=domain)".format(ts_filter)
    next = "/api/v2/intelligence/?username={}&api_key={}&q={}".format(ts_username, ts_api_key, query)
    data = []
    while next:
        url = "{}{}".format(ts_api_base_url, next)
        resp = requests.get(url)
        obj = resp.json()
        if len(data) == 0:
            print("IOCs matching filter '{}' = {}.\nDownloading IOCs...".format(ts_filter, obj["meta"]["total_count"]))
        next = obj["meta"]["next"]
        data.extend(obj["objects"])

    with open(output_path, "w") as fp:
        fp.write("ioc_type,ioc_value,severity,threat_type\n")
        for i in range(0, len(data)):
            fp.write("{},{},{},{}\n".format(data[i]["type"], data[i]["value"], data[i]["meta"]["severity"].lower(), data[i]["threat_type"]))


def transform_nessus_report(report_path, output_path):
    # Parse nessus scan csv report
    assets = {}

    if not os.path.exists(report_path):
        print("Nessus vulnerability report not found at {}. Skipping this step.".format(report_path))
    else:
        with open(report_path, encoding="utf8", errors="ignore") as csvf:
            reader = csv.DictReader(csvf)
            for entry in reader:
                ip = entry.get("IP Address")
                cve = entry.get("CVE")
                cvss_score = entry.get("CVSS V3 Base Score", 0)
                if cvss_score == '':
                    cvss_score = 0
                cvss_score = float(cvss_score)
                os_cpe = entry.get("CPE", "")
                if ip:
                    if ip not in assets:
                        assets[ip] = {"cves": [], "top_cvss_score": 0, "os": ""}
                    top_cvss_score = float(assets[ip]["top_cvss_score"])
                    if cvss_score > top_cvss_score:
                        assets[ip]["top_cvss_score"] = cvss_score
                    if cve and cve not in assets[ip]["cves"]:
                        assets[ip]["cves"].append(cve)
                    if os_cpe.startswith("cpe:/o:"):
                        os_name = os_cpe.replace("cpe:/o:", "").replace(",", "")
                        if os_name.count(":") == 1:
                            os_name = os_name.split(":")[-1]
                        elif os.count(":") >=2:
                            os_name = "-".join(os_name.split(":")[1:])
                        assets[ip]["os"] = os_name

    if os.path.exists(output_path):
        print("Converted report file converted_reports\indicators.csv already found. Please delete existing one and rerun the script to create new one.".format(report_path))
        return
    else:
        print("Conversion successful, writing output asset vulnearability details to file {}".format(output_path))
        # Export data to CSV format required by LUA script
        with open(output_path, "w") as vcsv:
            vcsv.write("ip,os,top_cvss_score,cve_ids\n")
            for ip in assets.keys():
                if len(assets[ip]["cves"]):
                    vcsv.write("{},{},{},{}\n".format(
                        ip, assets[ip]['os'], assets[ip]['top_cvss_score'], ':'.join(assets[ip]['cves'])
                ))


def transform_misp_report(report_path, output_path):
    iocs = []
    # Parse MISP Indicators CSV report
    if not os.path.exists(report_path):
        print("MISP IOC file '{}' not found. Skipping this step.".format(report_path))
    else:
        with open(report_path, encoding="utf8", errors="ignore") as csvf:
            reader = csv.DictReader(csvf)
            for entry in reader:
                value_type = entry.get("type", "")
                if value_type in ["src_ip", "dst_ip", "domain", "domain|ip"]:
                    category = entry.get("category", "malicious").replace(",", "").lower()
                    value = entry.get("value")
                    if value_type == "domain|ip":
                        values = value.split("|")
                        iocs.append({"value_type": "domain", "value": values[0], "category": category})
                        iocs.append({"value_type": "ip", "value": values[1], "category": category})
                    elif value_type in ["src_ip", "dst_ip"]:
                        iocs.append({"value_type": "ip", "value": value, "category": category})
                    else:
                        iocs.append({"value_type": "domain", "value": value, "category": category})

    if os.path.exists(output_path):
        print("Converted report file {} already found. Please delete existing one and rerun the script to create new one.".format(report_path))
        return
    else:
        with open(output_path, "w") as fp:
            fp.write("ioc_type,ioc_value,severity,threat_type\n")
            for ioc in iocs:
                fp.write("{},{},high,{}\n".format(ioc["value_type"], ioc["value"], ioc["category"]))
        print("Conversion successful, writing output indicators to file {}".format(output_path))


def create_placeholder_asset_tag_report(output_path):
    if not os.path.exists(output_path):
        with open(output_path, "w") as fp:
            fp.write("asset_address_type,asset_address,tags\n")
            fp.write("ip,8.8.4.4,google-dns\n")
            fp.write("ip,8.8.8.8,google-dns\n")
            fp.write("cidr,10.0.0.0/8,private-ip\n")
            fp.write("cidr,172.16.0.0/12,private-ip\n")
            fp.write("cidr,192.168.0.0/16,private-ip\n")
            fp.write("domain,www.eicar.org,malware-test-site\n")
        print("Conversion successful, writing output asset tag to file {}".format(output_path))
    else:
        print("Converted report file {} already found. Please delete existing one and rerun the script to create new one.".format(output_path))


def install_wft_plugin(wireshark_path):
    plugin_path = os.path.join(wireshark_path, "plugins", "wireshark_forensics_toolkit")
    profile_path = os.path.join(wireshark_path, "profiles", "wireshark_forensics_toolkit")

    if not os.path.exists(os.path.dirname(wireshark_path)):
        print("Wireshark Installation not found on default path {}. Please pass Wireshark install or run directory (in case you are using portable app) as command line argument".format(wireshark_path))
        return

    if not os.path.exists(plugin_path):
        print("First time installation. Created plugin directory {}".format(plugin_path))
        os.makedirs(plugin_path)

    if not os.path.exists(profile_path):
        print("First time installation. Created profile directory {}".format(profile_path))
        os.makedirs(profile_path)

    # Transform data
    transform_nessus_report(report_path=os.path.join("data", "raw_reports", "nessus.csv"), output_path=os.path.join("data", "formatted_reports", ASSET_VULNERABILITY_CSV))
    if config != {} and config["threatstream"]["username"]:
        download_iocs_from_threatstream(output_path=os.path.join("data", "formatted_reports", INDICATOR_CSV))
    else:
        transform_misp_report(report_path=os.path.join("data", "raw_reports", "misp.csv"), output_path=os.path.join("data", "formatted_reports", INDICATOR_CSV))
    create_placeholder_asset_tag_report(output_path=os.path.join("data", "formatted_reports", ASSET_TAG_CSV))

    # Copy Files
    print("Copying src and data files to {}".format(plugin_path))
    shutil.copy(os.path.join("plugin", "wireshark_forensics_toolkit.lua"), plugin_path)
    for pf in ["decode_as_entries", "disabled_protos", "enabled_protos", "heuristic_protos", "io_graphs", "preferences", "recent"]:
        shutil.copy(os.path.join("plugin", "profile", pf), profile_path)

    shutil.copy(os.path.join("data", "formatted_reports", ASSET_VULNERABILITY_CSV),
                os.path.join(plugin_path, ASSET_VULNERABILITY_CSV))
    shutil.copy(os.path.join("data", "formatted_reports", INDICATOR_CSV),
                os.path.join(plugin_path, INDICATOR_CSV))
    shutil.copy(os.path.join("data", "formatted_reports", ASSET_TAG_CSV),
                os.path.join(plugin_path, ASSET_TAG_CSV))


def print_usage():
    D = 100
    T = 40
    print(D * "-")
    print(T * " " + "Wireshark Forensics Toolkit")
    print(D * "-")
    print("\nUsage:\nPass wireshark data folder path as command line argument. E.g.")
    print("Wireshark Windows Installed Path   : {}:\\Users\\{}\\AppData\\Roaming\\Wireshark".format(SYSTEM_DRIVE, CURRENT_USER))
    print("Wireshark Portable App sample Path : {}:\\Users\\{}\\Downloads\\WiresharkPortable\\Data".format(SYSTEM_DRIVE, CURRENT_USER))
    print("Wireshark Mac Install Path         : /Users/{}/.config/wireshark".format(CURRENT_USER))
    print("Wireshark Kali Linux Install Path  : /users/{}/.config/wireshark".format(CURRENT_USER))
    print(D * "-")


if __name__ == "__main__":
    print_usage()

    WIRESHARK_DEFAULT_DATA_DIR = "{}\\Users\\{}\\AppData\\Roaming\\Wireshark\\".format(SYSTEM_DRIVE,
                                                                                       CURRENT_USER)
    if os.name != "nt":
        WIRESHARK_DEFAULT_DATA_DIR = "/Users/{}/.config/wireshark".format(CURRENT_USER)
    wireshark_path = WIRESHARK_DEFAULT_DATA_DIR
    if len(sys.argv) == 1:
        print("\nWireshark Path Not Provided, using default path {}\n".format(WIRESHARK_DEFAULT_DATA_DIR))
    else:
        wireshark_path = sys.argv[1]
        print("Using custom path provided {}".format(wireshark_path))

    install_wft_plugin(wireshark_path)
    print("\nInstallation complete. Please close this terminal and restart Wireshark to load this plugin.\n")
    try:
        x = input()
    except:
        pass