import ssl

from loguru import logger

from utils.constants import EMPTY_RESPONSE

class CertificateCrawler:
    def __init__(self):
        pass
    def collect_cert(self, url) -> str:
        pem_cert = EMPTY_RESPONSE
        logger.info("Start collecting certificate for {}", url)

        try:
            pem_cert = ssl.get_server_certificate((url, 443), ssl_version=ssl.PROTOCOL_SSLv23)
        except Exception as e:
            logger.exception("Failed to download certificate for {} with protocol sslv23", url)
            return pem_cert
        try:
            pem_cert = ssl.get_server_certificate((url(url), 443), ssl_version=ssl.PROTOCOL_TLS)
        except Exception as e:
            logger.exception("Failed to download certificate for {} with protocol TLS", url)
            return pem_cert
        return pem_cert
