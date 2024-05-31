from difflib import SequenceMatcher

from loguru import logger

from utils.util_functions import convert_float_to_str

class DNSParser:
    def __init__(self):
        pass
    def parse_dns(self, url, dns_records) -> dict:
        logger.info("Parsing DNS data for url {}", url)
        result = {
            "num_unique_a_records" : 0,

        }