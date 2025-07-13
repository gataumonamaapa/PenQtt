import ssl
import os

def setup_tls_context(client, ca_path="certs/ca.crt"):
    if os.path.exists(ca_path):
        client.tls_set(ca_certs=ca_path, cert_reqs=ssl.CERT_REQUIRED)
        client.tls_insecure_set(False)
        return "TLS verified"
    else:
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.tls_insecure_set(True)
        return "TLS insecure"
