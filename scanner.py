import scapy.all as scapy
import nmap

def scan_with_scapy(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list

def scan_with_nmap(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-F')

    clients_list = []
    for host in nm.all_hosts():
        client_dict = {
            "ip": host,
            "mac": nm[host]['addresses']['mac'],
            "hostname": nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else '',
            "vendor": nm[host]['vendor'][nm[host]['addresses']['mac']] if 'vendor' in nm[host] else ''
        }
        clients_list.append(client_dict)

    return clients_list

def display_result(results):
    print("IP Address\t\tMAC Address")
    print("-------------------------------------------------------------")
    for client in results:
        print(f"{client['ip']}\t\t{client['mac']}")

    print("\nAdditional Details (using nmap):")
    print("IP Address\t\tMAC Address\t\tHostname\t\tVendor")
    print("-------------------------------------------------------------")
    for client in results:
        print(f"{client['ip']}\t\t{client['mac']}\t\t{client['hostname']}\t\t{client['vendor']}")

# Get the user's input for the target IP range
target_ip_range = input("Enter the target IP range (e.g., 192.168.1.1-20): ")

# Perform the initial scan with scapy
scapy_results = scan_with_scapy(target_ip_range)

# Perform the detailed scan with nmap
nmap_results = scan_with_nmap(target_ip_range)

# Display the results from scapy
print("\nInitial Scan Results (using scapy):")
display_result(scapy_results)

# Display the detailed results from nmap
print("\nDetailed Scan Results (using nmap):")
display_result(nmap_results)
