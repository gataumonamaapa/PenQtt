import paho.mqtt.client as mqtt
import time

class AclCheck:
    def __init__(self, host, port=1883, username=None, password=None):
        """
        Inisialisasi Pengecek ACL.
        Args:
            host (str): Alamat IP broker.
            port (int): Port broker.
            username (str): Username untuk otentikasi.
            password (str): Password untuk otentikasi.
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = mqtt.Client(client_id="penmqtt_acl_checker")
        self.detected_topics = []
        self.connection_status = -1
        
        # Atur callback
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc):
        """Callback saat terhubung."""
        self.connection_status = rc
        if rc == 0:
            # Berlangganan ke semua topik jika koneksi berhasil
            client.subscribe("#", qos=0)
        else:
            # Jika koneksi gagal, langsung hentikan loop
            client.loop_stop()

    def _on_message(self, client, userdata, msg):
        """Callback saat menerima pesan."""
        if msg.topic not in self.detected_topics:
            self.detected_topics.append(msg.topic)

    def run(self):
        """
        Menjalankan proses pengecekan ACL.
        Returns:
            str: Hasil pengecekan dalam bentuk string untuk ditampilkan di UI.
        """
        output = []
        try:
            output.append(f"[*] Mencoba terhubung ke {self.host}:{self.port}...")
            
            if self.username and self.password:
                self.client.username_pw_set(self.username, self.password)

            # Koneksi dengan timeout
            self.client.connect(self.host, self.port, 60)
            
            # Jalankan loop di background
            self.client.loop_start()

            # Beri waktu 5 detik untuk koneksi dan menerima pesan
            time.sleep(5)
            
            # Hentikan loop
            self.client.loop_stop()
            self.client.disconnect()

            # Analisis hasil koneksi
            if self.connection_status == 0:
                output.append("[+] Koneksi Berhasil!")
                if self.detected_topics:
                    output.append("[!] ACL Lemah! Topik berhasil dideteksi tanpa otorisasi spesifik:")
                    output.extend([f"    - {topic}" for topic in self.detected_topics])
                else:
                    output.append("[+] ACL Kuat. Tidak ada topik yang terdeteksi dari langganan ke '#'.")
            elif self.connection_status == 5:
                output.append("[-] Koneksi Gagal: Otorisasi Ditolak (Not authorized).")
                output.append("[*] Info: Broker memerlukan username/password yang valid.")
            else:
                 output.append(f"[-] Koneksi Gagal dengan kode: {self.connection_status}")

        except Exception as e:
            output.append(f"[!] Terjadi kesalahan: {str(e)}")
        
        return "\n".join(output)