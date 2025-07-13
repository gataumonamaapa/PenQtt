import random
import string
import paho.mqtt.client as mqtt
from core.tls_utils import setup_tls_context

class Fuzzer:
    def __init__(self, broker_ip, port=1883, username=None, password=None, use_tls=False, logger=None, allow_insecure=True):
        self.broker_ip = broker_ip
        self.port = int(port)  # pastikan port bertipe integer
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.allow_insecure = allow_insecure
        self.logger = logger

    def log(self, message):
        if self.logger:
            self.logger(message)

    def generate_payload(self, length=256):
        chars = string.ascii_letters + string.digits + string.punctuation + ''.join(chr(i) for i in range(32))
        return ''.join(random.choice(chars) for _ in range(length))

    def run(self, topics=None, iterations=20):
        topics = topics or ["fuzz/test"]
        client = mqtt.Client()

        if self.username and self.password:
            client.username_pw_set(self.username, self.password)

        if self.use_tls:
            setup_tls_context(client, allow_insecure=self.allow_insecure, logger=self.logger)

        try:
            client.connect(self.broker_ip, self.port, 60)
            client.loop_start()

            for i in range(iterations):
                topic = random.choice(topics)
                payload = self.generate_payload()
                client.publish(topic, payload, qos=0)
                self.log(f"[Fuzz] Sent to {topic} | Payload: {payload[:30]}...")

            client.loop_stop()
            client.disconnect()
        except Exception as e:
            self.log(f"[!] Gagal koneksi/publish: {e}")
