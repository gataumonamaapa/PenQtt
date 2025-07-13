import time
import random
from paho.mqtt import client as mqtt
from core.tls_utils import setup_tls_context


class QoSTester:
    def __init__(self, broker_ip, port=1883,username=None, password=None, retain=False, delay=0.005, logger=None,  use_tls=False, allow_insecure=True):
        self.broker_ip = broker_ip
        self.port = port
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.retain = retain
        self.delay = delay
        self.result = {}
        self.logger = logger
        self.allow_insecure = allow_insecure

    def log(self, msg):
        if self.logger:
            self.logger(msg)
        else:
            print(msg)

    def run(self):
        for qos in [0, 1, 2]:
            client = mqtt.Client()

            if self.username and self.password:
                client.username_pw_set(self.username, self.password)

            if self.use_tls:
                try:
                    setup_tls_context(client, allow_insecure=self.allow_insecure, logger=self.logger)
                except Exception as e:
                    self.log(f"[!] Gagal set TLS context: {e}")
                    continue

            try:
                client.connect(self.broker_ip, self.port, 60)
            except Exception as e:
                self.log(f"[!] Gagal koneksi ke broker ({self.broker_ip}:{self.port}): {e}")
                continue

            topic = f"qos_test/topic_{qos}"
            self.log(f"[*] Mengirim pesan ke topik {topic} dengan QoS {qos}...")

            start = time.time()
            for i in range(10):
                payload = f"Test QoS {qos} #{i} - {random.randint(1000,9999)}"
                client.publish(topic, payload, qos=qos, retain=self.retain)
                time.sleep(self.delay)
            end = time.time()

            elapsed = round(end - start, 4)
            self.result[qos] = elapsed
            self.log(f"[✓] Selesai QoS {qos} dalam {elapsed} detik")
            client.disconnect()

        self.log(f"\n[•] Hasil Pengujian Delay QoS:")
        for qos, delay in self.result.items():
            self.log(f"   - QoS {qos}: {delay} detik")
        return self.result
