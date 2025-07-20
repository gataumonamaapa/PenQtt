import time
import random
import string

class AclCheck:
    def __init__(self, client, logger=None, timeout=5):
        """
        Inisialisasi pengecekan ACL aktif melalui pengujian publish + subscribe ke topik buatan.
        Args:
            client (mqtt.Client): Client MQTT aktif dari enum().
            logger (function): Fungsi log opsional.
            timeout (int): Waktu tunggu untuk menerima pesan balik.
        """
        self.client = client
        self.logger = logger
        self.timeout = timeout
        self.test_topics = [f"aclcheck/test/{i}" for i in range(10)]
        self.received = set()
        self.subscribe_success = set()
        self.publish_success = set()

    def log(self, msg):
        if self.logger:
            self.logger(msg)
        else:
            print(msg)

    def _on_message(self, client, userdata, msg):
        """Callback ketika menerima pesan dari broker."""
        decoded = msg.payload.decode(errors='ignore')
        self.log(f"[✓] Pesan diterima dari broker: {msg.topic} = {decoded}")
        self.received.add(msg.topic)

    def run(self):
        """
        Jalankan pengujian ACL aktif: subscribe + publish lalu cek apakah pesan balik diterima.
        Returns:
            Tuple[str, bool]: (output string untuk laporan/log, acl_is_strict)
        """
        output = []
        acl_is_strict = False

        try:
            self.client.on_message = self._on_message
            self.log("[*] Mulai pengecekan ACL aktif menggunakan topik buatan...")

            # 1. Subscribe ke topik uji
            self.log("[*] Subscribe ke 10 topik uji...")
            for topic in self.test_topics:
                res, _ = self.client.subscribe(topic)
                if res == 0:
                    self.subscribe_success.add(topic)
                    self.log(f"[✓] Subscribe OK: {topic}")
                else:
                    self.log(f"[!] Gagal subscribe: {topic} | res={res}")

            if not self.subscribe_success:
                output.append("[!] Semua subscribe gagal. Kemungkinan ACL aktif memblokir subscribe.")
                return "\n".join(output), True

            self.client.loop_start()
            time.sleep(0.5)  # waktu jeda agar subscribe stabil

            # 2. Publish ke topik uji
            self.log("[*] Publish pesan uji ke topik...")
            for topic in self.subscribe_success:
                payload = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
                result = self.client.publish(topic, payload)
                if result.rc == 0:
                    self.publish_success.add(topic)
                    self.log(f"[✓] Publish OK: {topic} = {payload}")
                else:
                    self.log(f"[!] Gagal publish: {topic} | rc={result.rc}")

            if not self.publish_success:
                output.append("[!] Semua publish gagal. Kemungkinan ACL aktif memblokir publish.")
                self.client.loop_stop()
                return "\n".join(output), True

            # 3. Tunggu pesan kembali dari broker
            self.log("[*] Menunggu pesan masuk dari broker...")
            start_time = time.time()
            while time.time() - start_time < self.timeout:
                if self.received >= self.publish_success:
                    break
                time.sleep(0.1)

            self.client.loop_stop()

            # 4. Evaluasi hasil akhir
            if self.received:
                output.append("[✓] ACL Lemah! Pesan berhasil diterima dari topik:")
                for t in sorted(self.received):
                    output.append(f"    - {t}")
                acl_is_strict = False
            else:
                output.append("[+] ACL Kuat. Tidak ada pesan yang dikembalikan dari broker.")
                acl_is_strict = True

        except Exception as e:
            output.append(f"[!] Terjadi kesalahan saat pengecekan ACL: {str(e)}")
            acl_is_strict = True

        return "\n".join(output), acl_is_strict
