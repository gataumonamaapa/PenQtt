import ssl
import os

def setup_tls_context(client, ca_path="certs/ca.crt", allow_insecure=True, logger=None):
    """
    Setup TLS context for MQTT client.

    Params:
    - client: paho.mqtt.client.Client instance
    - ca_path: path to CA certificate file
    - allow_insecure: if True, will allow connection without verifying cert
    - logger: optional function to output log messages
    """
    def log(msg):
        if logger:
            logger(msg)
        else:
            print(msg)

    if os.path.exists(ca_path):
        client.tls_set(ca_certs=ca_path, cert_reqs=ssl.CERT_REQUIRED)
        client.tls_insecure_set(False)
        log("[✓] TLS CA certificate ditemukan. Koneksi akan diverifikasi.")
        return "TLS verified"
    elif allow_insecure:
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.tls_insecure_set(True)
        log("[!] CA certificate tidak ditemukan. TLS insecure (tidak diverifikasi) diaktifkan!")
        return "TLS insecure"
    else:
        log("[✗] TLS gagal: CA certificate tidak ditemukan dan koneksi insecure tidak diizinkan.")
        raise FileNotFoundError("CA certificate tidak ditemukan, dan koneksi TLS insecure tidak diizinkan.")
