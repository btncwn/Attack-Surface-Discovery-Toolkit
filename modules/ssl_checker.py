import ssl
import socket
import tempfile
from datetime import datetime


def get_ssl_certificate(domain: str) -> dict:
    try:
        pem_cert = ssl.get_server_certificate((domain, 443))

        with tempfile.NamedTemporaryFile(delete=False, mode="w") as temp_cert:
            temp_cert.write(pem_cert)
            temp_cert_path = temp_cert.name

        cert = ssl._ssl._test_decode_cert(temp_cert_path)

        return {
            "issuer": cert.get("issuer"),
            "subject": cert.get("subject"),
            "valid_from": cert.get("notBefore"),
            "valid_until": cert.get("notAfter"),
            "serial_number": cert.get("serialNumber"),
        }

    except Exception as e:
        return {
            "error": str(e)
        }
