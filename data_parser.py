import gc
import time
from datetime import datetime
from loguru import logger

from database.dynamodb_storage import DynamodbStorage
from parsers.certificate_parser import CertificateParser
from parsers.dns_parser import DNSParser
from parsers.nmap_parser import NmapParser
from utils.constants import DYNAMO_DB_PARSED_DATA_TABLE_NAME, DATETIME_FORMAT, DYNAMO_DB_RAW_DATA_TABLE_NAME
from utils.util_functions import get_legitimate_url_list

class DataParser:
    def __init__(self):
        self.raw_data_dynamodb_storage = DynamodbStorage(DYNAMO_DB_RAW_DATA_TABLE_NAME)
        self.parsed_data_dynamodb_storage = DynamodbStorage(DYNAMO_DB_PARSED_DATA_TABLE_NAME)
        self.cert_parser = CertificateParser()
        self.nmap_parser = NmapParser()
        self.dns_parser = DNSParser()

    def parse(self, url):
        logger.info("start parsing data for url {}", url)

        if self.deduplicate_url(url):
            logger.info("Url {} already parsed and stored in db {}", url, DYNAMO_DB_PARSED_DATA_TABLE_NAME)
            return

        start_time = time.time()
        dynamodb_record = self.raw_data_dynamodb_storage.get_record(url)
        end_time = time.time()

        logger.info("DynamoDB call for {} completed in {} seconds", url, end_time - start_time)

        if dynamodb_record:
            logger.info("Dynamodb record for url {} is: {}", url, dynamodb_record)
        else:
            logger.info("Mapping record for url {} not exists.", url)
            return

        dynamodb_item = dynamodb_record[0]
        data_collection_timestamp = dynamodb_item["timestamp"]

        pem_cert = dynamodb_item["certificate"]
        cert_feature = self.cert_parser.get_info(url, pem_cert, data_collection_timestamp)

        nmap_raw = dynamodb_item["nmap"]
        nmap_feature = self.nmap_parser.parse_nmap(nmap_raw)

        dns_raw = dynamodb_item["dns"]
        dns_feature = self.dns_parser.parse_dns(url, dns_raw)

        data = {}
        for k in cert_feature.keys():
            data[k] = cert_feature[k]

        for k in nmap_feature.keys():
            data[k] = nmap_feature[k]

        for k in dns_feature.keys():
            data[k] = dns_feature[k]

        data["url"] = dynamodb_item["url"]
        data["label"] = dynamodb_item["label"]
        data["average_rtt"] = dynamodb_item["average_rtt"]
        data["hop_distance"] = dynamodb_item["hop_distance"]
        data["http_redirection_count"] = dynamodb_item["http_redirection"]
        data["http_different_domains_in_redirection"] = dynamodb_item["http_different_domains_in_redirection"]
        data["http_header_count"] = len(dynamodb_item["http_header"])
        data["label"] = dynamodb_item["label"]

        for k in dynamodb_item["landing_url)lexical"].keys():
            landing_url_lexical_key = dynamodb_item["landing_url"] + k
            data[landing_url_lexical_key] = dynamodb_item["landing_url_lexical"][k]

        for k in dynamodb_item["origin_url_lexical"].keys():
            original_url_lexical_key = "origin_url_" + k
            data[original_url_lexical_key] = dynamodb_item["origin_url_lexical"][k]

        data["timestamp"] = str(datetime.now().strftime(DATETIME_FORMAT))
        self.parsed_data_dynamodb_storage.store_item(data)
        logger.info("Complete parsing data for url {}", url)

    def deduplicate_url(self, url):
        return self.parsed_data_dynamodb_storage.check_existence(url)
