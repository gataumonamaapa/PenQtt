from scapy.all import sniff, IP, TCP
from core.network_scanner import NetworkScanner
import nmap
from colorama import Fore, Style

class Sniffer:
    def __init__(self, interface, logger=None):
        self.interface = interface
        self.sniffed_brokers = set()  # Set of (ip, port)
        self.logger = logger

    def log(self, msg):
        if self.logger:
            self.logger(msg)
        else:
            print(msg)

    def sniff_broker_from_iot(self, iot_ip, duration=30):
        def callback(pkt):
            if IP in pkt and TCP in pkt:
                if pkt[TCP].dport in [1883, 8883]:
                    self.sniffed_brokers.add((pkt[IP].dst, pkt[TCP].dport))
                elif pkt[TCP].sport in [1883, 8883]:
                    self.sniffed_brokers.add((pkt[IP].src, pkt[TCP].sport))

        self.log(f"[*] Sniffing paket dari {iot_ip} di interface {self.interface} selama {duration} detik...")
        sniff(iface=self.interface, filter="tcp port 1883 or 8883", prn=callback, timeout=duration)

        if not self.sniffed_brokers:
            self.log("[!] Tidak ada broker terdeteksi dari sniffing, mencoba fallback scan...")
            fallback = self.scan_mqtt_ports_fallback()
            self.sniffed_brokers.update(fallback)

        return list(self.sniffed_brokers)

    def scan_mqtt_ports_fallback(self):
        scanner = NetworkScanner()
        network_cidr = scanner.get_network_cidr(self.interface)
        self.log(f"{Fore.CYAN}[*] Fallback: scanning port MQTT pada {network_cidr}...{Style.RESET_ALL}")

        nm = nmap.PortScanner()
        nm.scan(hosts=network_cidr, arguments="-p 1883,8883 --open")

        mqtt_hosts = []
        for host in nm.all_hosts():
            if 'tcp' in nm[host]:
                if 1883 in nm[host]['tcp']:
                    port=1883
                    mqtt_hosts.append((host, port))
                    
                if 8883 in nm[host]['tcp']:
                    port=8883
                    mqtt_hosts.append((host, port))
                    

        self.log(f"[✓] MQTT broker ditemukan (fallback): {mqtt_hosts}")
        return mqtt_hosts
