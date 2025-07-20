import time
import paho.mqtt.client as mqtt
from core.tls_utils import setup_tls_context

class QoSTester:
    def __init__(self, host, port=1883, username=None, password=None, logger=print):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.logger = logger
        self.qos_results = {}

    def log(self, message):
        if self.logger:
            self.logger(message)

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            self.connected = True
        else:
            self.connected = False

    def on_publish(self, client, userdata, mid):
        self.end_time = time.time()

    def test_qos(self, qos_level):
        
        topic = f"qos_test/topic_{qos_level}"
        payload = f"test message with qos {qos_level}"
        client = mqtt.Client()
        setup_tls_context(client, allow_insecure=True, logger=self.log)
        if self.username and self.password:
            client.username_pw_set(self.username, self.password)

        client.on_connect = self.on_connect
        client.on_publish = self.on_publish

        self.connected = False
        self.end_time = None
        start_time = time.time()

        try:
            client.connect(self.host, self.port, 60)
            client.loop_start()
            timeout = time.time() + 5
            while not self.connected and time.time() < timeout:
                time.sleep(0.1)

            if not self.connected:
                self.log(f"[!] Gagal koneksi ke broker pada QoS {qos_level}.")
                client.loop_stop()
                return -1

            self.start_time = time.time()
            result, mid = client.publish(topic, payload, qos=qos_level)

            timeout = time.time() + 5
            while self.end_time is None and time.time() < timeout:
                time.sleep(0.1)

            client.loop_stop()
            if self.end_time:
                delay = round(self.end_time - self.start_time, 4)
                return delay
            else:
                return -1

        except Exception as e:
            self.log(f"[!] Error saat pengujian QoS {qos_level}: {str(e)}")
            return -1

    def run(self):
        self.log("[*] Mengirim pesan ke topik qos_test/topic_0 dengan QoS 0...")
        delay_0 = self.test_qos(0)
        self.log(f"[✓] Rata-rata delay QoS 0: {delay_0} detik")

        self.log("[*] Mengirim pesan ke topik qos_test/topic_1 dengan QoS 1...")
        delay_1 = self.test_qos(1)
        self.log(f"[✓] Rata-rata delay QoS 1: {delay_1} detik")

        self.log("[*] Mengirim pesan ke topik qos_test/topic_2 dengan QoS 2...")
        delay_2 = self.test_qos(2)
        self.log(f"[✓] Rata-rata delay QoS 2: {delay_2} detik")

        self.qos_results = {
            "0": delay_0,
            "1": delay_1,
            "2": delay_2
        }

        self.log("\n[•] Hasil Pengujian Delay QoS:")
        for level in ["0", "1", "2"]:
            self.log(f"   - QoS {level}: {self.qos_results[level]} detik")

        return self.qos_results
