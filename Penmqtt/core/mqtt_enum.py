import socket
import time
from paho.mqtt import client as mqtt
from core.brute_force import BruteForcer
from core.tls_utils import setup_tls_context

class MQTTEnumerator:
    def __init__(self, logger=None):
        self.logger = logger
        self.valid_credentials = None

    def log(self, message):
        if self.logger:
            self.logger(message)

    def connect_plain(self, broker_ip, port):
        try:
            topics = []
            client = mqtt.Client()

            def on_message(client, userdata, msg):
                topic = msg.topic
                if topic not in topics:
                    topics.append(topic)
                    self.log(f"[+] Topik ditemukan: {topic}")

            client.on_message = on_message
            client.connect(broker_ip, port, 60)
            client.subscribe("#")
            client.loop_start()
            self.log("[*] Mencoba enum tanpa kredensial...")
            time.sleep(5)
            client.loop_stop()
            client.disconnect()
            return topics
        except Exception as e:
            self.log(f"[!] Gagal konek tanpa kredensial: {e}")
            return []

    def brute_force_plain(self, broker_ip, port):
        bruter = BruteForcer(logger=self.logger)
        creds = bruter.brute_force(broker_ip, port, use_tls=False)
        if creds:
            self.valid_credentials = creds
            self.log(f"[✓] Kredensial ditemukan: {creds[0]}:{creds[1]}")
            return self.enum(broker_ip, creds[0], creds[1], port, use_tls=False)
        else:
            self.log("[!] Brute force gagal.")
            return []

    def brute_force_tls(self, broker_ip, port):
        bruter = BruteForcer(logger=self.logger)
        creds = bruter.brute_force(broker_ip, port, use_tls=True)
        if creds:
            self.valid_credentials = creds
            self.log(f"[✓] Kredensial TLS ditemukan: {creds[0]}:{creds[1]}")
            return self.enum(broker_ip, creds[0], creds[1], port, use_tls=True)
        else:
            self.log("[!] Brute force TLS gagal.")
            return []

    def enum(self, broker_ip, username=None, password=None, port=None, use_tls=None):
        if port is None:
            self.log("[!] Port MQTT tidak diberikan.")
            return []

        if use_tls is None:
            use_tls = (port == 8883)

        topics = []
        try:
            client = mqtt.Client()

            if username is not None and password is not None:
                client.username_pw_set(username, password)

            if use_tls:
                client.tls_set_context(setup_tls_context())

            def on_message(client, userdata, msg):
                topic = msg.topic
                if topic not in topics:
                    topics.append(topic)
                    self.log(f"[+] Topik ditemukan: {topic}")

            client.on_message = on_message
            client.connect(broker_ip, port, 60)
            client.subscribe("#")
            client.loop_start()
            self.log("[*] Mendengarkan pesan selama 5 detik...")
            time.sleep(5)
            client.loop_stop()
            client.disconnect()

            if not topics and not (username and password):
                if use_tls:
                    return self.brute_force_tls(broker_ip, port)
                else:
                    return self.brute_force_plain(broker_ip, port)

        except Exception as e:
            self.log(f"[!] Gagal enum topik: {e}")
            if not (username and password):
                if use_tls:
                    return self.brute_force_tls(broker_ip, port)
                else:
                    return self.brute_force_plain(broker_ip, port)

        return topics
