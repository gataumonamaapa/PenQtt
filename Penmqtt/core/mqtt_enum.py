import socket
import time
import ssl
from paho.mqtt import client as mqtt
from core.brute_force import BruteForcer
from core.tls_utils import setup_tls_context

class MQTTEnumerator:
    def __init__(self, logger=None, allow_insecure=True):
        self.logger = logger
        self.allow_insecure = allow_insecure  # kontrol apakah gunakan TLS insecure
        self.valid_credentials = None
        self.last_successful_client = None


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
            self.last_successful_client = client
            client.subscribe("#")
            client.loop_start()
            self.log("[*] Mencoba enum tanpa kredensial...")
            time.sleep(5)
            client.loop_stop()
           
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

            if username and password:
                client.username_pw_set(username, password)

            if use_tls:
                setup_tls_context(client, allow_insecure=self.allow_insecure, logger=self.logger)

            def on_message(client, userdata, msg):
                topic = msg.topic
                if topic not in topics:
                    topics.append(topic)
                    self.log(f"[+] Topik ditemukan: {topic}")

            client.on_message = on_message
            client.connect(broker_ip, port, 60)
            self.last_successful_client = client
            client.subscribe("#")
            client.loop_start()
            self.log("[*] Mendengarkan pesan selama 5 detik...")
            time.sleep(5)
            client.loop_stop()


            if not topics and not (username and password):
                return self.brute_force_tls(broker_ip, port) if use_tls else self.brute_force_plain(broker_ip, port)

        except ssl.SSLError as ssl_err:
            self.log(f"[!] TLS Error: {ssl_err}")
            if not (username and password):
                return self.brute_force_tls(broker_ip, port)
        except Exception as e:
            self.log(f"[!] Gagal enum topik: {e}")
            if not (username and password):
                return self.brute_force_tls(broker_ip, port) if use_tls else self.brute_force_plain(broker_ip, port)

        return topics
    
    def cleanup(self):
        """Disconnect setelah semua modul selesai menggunakan koneksi."""
        if self.last_successful_client and self.last_successful_client.is_connected():
            self.last_successful_client.loop_stop()
            self.last_successful_client.disconnect()

