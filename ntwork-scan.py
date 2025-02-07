import scapy.all as scapy
import nmap
import ipaddress
import argparse
import json
import socket

def print_banner():
    banner = """

 ________   _________  ___       __   ________  ________  ___  __                   ________  ________  ________  ________      
|\   ___  \|\___   ___\\  \     |\  \|\   __  \|\   __  \|\  \|\  \                |\   ____\|\   ____\|\   __  \|\   ___  \    
\ \  \\ \  \|___ \  \_\ \  \    \ \  \ \  \|\  \ \  \|\  \ \  \/  /|_  ____________\ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \   
 \ \  \\ \  \   \ \  \ \ \  \  __\ \  \ \  \\\  \ \   _  _\ \   ___  \|\____________\ \_____  \ \  \    \ \   __  \ \  \\ \  \  
  \ \  \\ \  \   \ \  \ \ \  \|\__\_\  \ \  \\\  \ \  \\  \\ \  \\ \  \|____________|\|____|\  \ \  \____\ \  \ \  \ \  \\ \  \ 
   \ \__\\ \__\   \ \__\ \ \____________\ \_______\ \__\\ _\\ \__\\ \__\               ____\_\  \ \_______\ \__\ \__\ \__\\ \__\
    \|__| \|__|    \|__|  \|____________|\|_______|\|__|\|__|\|__| \|__|              |\_________\|_______|\|__|\|__|\|__| \|__|
                                                                                      \|_________|                              
                                                                                                                                
                                                                                                                                
 ________      ___    ___      ________  ________      ___    ___ ________          ___  __    ________  ________  ___          
|\   __  \    |\  \  /  /|    |\   ____\|\   __  \    |\  \  /  /|\   __  \        |\  \|\  \ |\   __  \|\   ____\|\  \         
\ \  \|\ /_   \ \  \/  / /    \ \  \___|\ \  \|\  \   \ \  \/  / | \  \|\  \       \ \  \/  /|\ \  \|\  \ \  \___|\ \  \        
 \ \   __  \   \ \    / /      \ \  \  __\ \   __  \   \ \    / / \ \   __  \       \ \   ___  \ \   __  \ \  \    \ \  \       
  \ \  \|\  \   \/  /  /        \ \  \|\  \ \  \ \  \   \/  /  /   \ \  \ \  \       \ \  \\ \  \ \  \ \  \ \  \____\ \  \      
   \ \_______\__/  / /           \ \_______\ \__\ \__\__/  / /      \ \__\ \__\       \ \__\\ \__\ \__\ \__\ \_______\ \__\     
    \|_______|\___/ /             \|_______|\|__|\|__|\___/ /        \|__|\|__|        \|__| \|__|\|__|\|__|\|_______|\|__|     
             \|___|/                                 \|___|/                                                                    
                                                                                                                                
                                                                                                                                

    """
    print(banner)

def discover_devices(target_network, scan_type="arp"):
    devices = []
    if scan_type == "arp":
        arp_req_frame = scapy.ARP(pdst=target_network)
        broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast_req_frame = broadcast_frame / arp_req_frame
        answered_list = scapy.srp(broadcast_req_frame, timeout=1, verbose=False)[0]
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            try:
                client_dict["hostname"] = socket.gethostbyaddr(element[1].psrc)[0]
            except socket.herror:
                client_dict["hostname"] = "Unknown"
            devices.append(client_dict)

    elif scan_type == "ping":  
        for ip in ipaddress.IPv4Network(target_network):
            try:
                response = scapy.IP(dst=str(ip))/scapy.ICMP()
                ans = scapy.sr1(response, timeout=1, verbose=False)
                if ans:
                    devices.append({"ip": str(ip), "mac": "Unknown", "hostname":"Unknown"}) 
            except Exception as e:
                print(f"Error pinging {ip}: {e}") 
                pass

    return devices


def scan_ports(ip_address, port_range):
    nm = nmap.PortScanner()
    nm.scan(ip_address, port_range)
    open_ports = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            for protocol in nm[host].all_protocols():
                lport = nm[host][protocol].keys()
                for port in lport:
                    if nm[host][protocol][port]['state'] == 'open':
                        service = nm[host][protocol][port]['name']
                        version = nm[host][protocol][port].get('version', 'Unknown') 
                        open_ports.append({"port": port, "protocol": protocol, "service": service, "version": version})
    return open_ports


def basic_vulnerability_check(open_ports):
    vulnerabilities = []
    common_vulnerabilities = {
        21: {"description": "FTP - Potential anonymous login vulnerability", "severity": "Medium"},
        22: {"description": "SSH - Check for weak ciphers and brute-forcing", "severity": "Medium"},
        23: {"description": "Telnet - Clear text communication vulnerability", "severity": "High"},
        25: {"description": "SMTP - Open relay and outdated version vulnerabilities", "severity": "Medium"},
        53: {"description": "DNS - Zone transfer and cache poisoning vulnerabilities", "severity": "Medium"},
        80: {"description": "HTTP - Check for outdated web server software and vulnerabilities", "severity": "Medium"},
        110: {"description": "POP3 - Clear text authentication vulnerability", "severity": "Medium"},
        143: {"description": "IMAP - Clear text authentication and outdated version vulnerabilities", "severity": "Medium"},
        443: {"description": "HTTPS - Check for SSL/TLS vulnerabilities", "severity": "Medium"},
        445: {"description": "SMB - Remote code execution and outdated version vulnerabilities", "severity": "High"},
        1433: {"description": "MS SQL Server - Default credentials and outdated version vulnerabilities", "severity": "High"},
        3306: {"description": "MySQL - Weak authentication and outdated version vulnerabilities", "severity": "Medium"},
        3389: {"description": "RDP - BlueKeep and other remote desktop vulnerabilities", "severity": "High"},
        5432: {"description": "PostgreSQL - Weak authentication and outdated version vulnerabilities", "severity": "Medium"},
        8080: {"description": "HTTP Alternate - Web application vulnerabilities", "severity": "Medium"},
        27017: {"description": "MongoDB - Unauthenticated access and default configuration vulnerabilities", "severity": "High"}
        
    }
    for port_info in open_ports:
        port = port_info["port"]
        if port in common_vulnerabilities:
            vulnerabilities.append(common_vulnerabilities[port])
    return vulnerabilities

def generate_report(devices):
    report = []
    for device in devices:
        device_report = device.copy()
        open_ports = scan_ports(device["ip"], args.port_range)
        device_report["open_ports"] = open_ports
        device_report["vulnerabilities"] = basic_vulnerability_check(open_ports)
        report.append(device_report)
    return report

def save_report(report, output_file, output_format):
    if output_format == "json":
        with open(output_file, "w") as f:
            json.dump(report, f, indent=4)
    elif output_format == "csv":
        import csv
        with open(output_file, "w", newline="") as f:
            writer = csv.writer(f)
            # Write headers
            headers = ["IP", "MAC", "Hostname", "Port", "Protocol", "Service", "Version", "Vulnerability Description", "Severity"]
            writer.writerow(headers)
            # Write data
            for device in report:
                for port in device.get("open_ports", []):
                    for vuln in device.get("vulnerabilities", []):
                        writer.writerow([
                            device["ip"],
                            device["mac"],
                            device["hostname"],
                            port["port"],
                            port["protocol"],
                            port["service"],
                            port["version"],
                            vuln["description"],
                            vuln["severity"]
                        ])
    elif output_format == "txt":
        with open(output_file, "w") as f:
            for device in report:
                f.write(f"\nDevice Information:\n")
                f.write(f"IP Address: {device['ip']}\n")
                f.write(f"MAC Address: {device['mac']}\n")
                f.write(f"Hostname: {device['hostname']}\n\n")
                
                f.write("Open Ports:\n")
                for port in device.get("open_ports", []):
                    f.write(f"  Port {port['port']} ({port['protocol']}):\n")
                    f.write(f"    Service: {port['service']}\n")
                    f.write(f"    Version: {port['version']}\n")
                
                f.write("\nVulnerabilities:\n")
                for vuln in device.get("vulnerabilities", []):
                    f.write(f"  {vuln['description']}\n")
                    f.write(f"  Severity: {vuln['severity']}\n\n")
                f.write("-" * 50 + "\n")

if __name__ == "__main__":
    print_banner()
    parser = argparse.ArgumentParser(description="Network Analyzer")
    parser.add_argument("-t", "--target", dest="target_network", required=True, help="Target network or IP range")
    parser.add_argument("-s", "--scan_type", dest="scan_type", default="arp", choices=["arp", "ping"], help="Scan type (arp or ping)")
    parser.add_argument("-p", "--port_range", dest="port_range", default="1-1024", help="Port range to scan")
    parser.add_argument("-o", "--output", dest="output_file", default="report.json", help="Output file")
    parser.add_argument("-f", "--format", dest="output_format", default="json", choices=["json", "csv", "txt"], help="Output format (json, csv, txt)")
    args = parser.parse_args()

    devices = discover_devices(args.target_network, args.scan_type)
    report = generate_report(devices)
    save_report(report, args.output_file, args.output_format)

    print(f"Scan complete. Report saved to {args.output_file}")