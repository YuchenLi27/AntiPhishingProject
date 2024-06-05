import csv
from datetime import datetime

from crawlers.certificate_crawler import CertificateCrawler
from crawlers.dns_crawler import DNSCrawler
from crawlers.http_header_crawler import HttpHeaderCrawler
from crawlers.network_crawler import NetworkCrawler
from crawlers.nmap_port_crawler import NmapPortCrawler
from crawlers.url_lexical import UrlLexical
from database.dynamodb_storage import DynamodbStorage
from utils import util_functions
from utils.constants import DATETIME_FORMAT
from utils.constants import DYNAMO_DB_RAW_DATA_TABLE_NAME
from loguru import logger


class DataCollector:
    def __init__(self):
        self.cert_crawler = CertificateCrawler()
        self.dns_crawler = DNSCrawler()
        self.https_crawler = HttpHeaderCrawler()
        self.network_crawler = NetworkCrawler()
        self.nmap_crawler = NmapPortCrawler()
        self.url_lexical = UrlLexical()
        self.dynamodb_storage = DynamodbStorage(DYNAMO_DB_RAW_DATA_TABLE_NAME)

    def run_crawl(self, url, label):
        logger.info("Start crawl data for {}", url)
        hostname = util_functions.get_hostname(url)

        if self.deduplicate_url(url):
            logger.info("{} already exist in DynamoDB, skip it", url)
            return
        full_url = "https://" + hostname

        logger.info("hostname is {}, full url is {}", hostname, full_url)

        certificate_raw = self.cert_crawler.collect_cert(hostname)
        dns_raw = self.dns_crawler.dns_query(hostname)

        if url.startswith("http") or url.startswith("https"):
            self.https_crawler.get_response(url)
        else:
            self.https_crawler.get_response(full_url)
        http_header_raw = self.https_crawler.scan_http_headers()
        http_redirection_count = self.https_crawler.scan_http_redirection()
        http_redirection_chain = self.https_crawler.get_redirection_chain()
        http_different_domains_in_redirection = self.https_crawler.get_different_domains_crossed_in_redirection_chain()

        hop_distance, average_rtt = self.network_crawler.trace_route(hostname)
        origin_url_lexical_dict = self.url_lexical.get_url_lexical(hostname)
        landing_url = self.https_crawler.get_landing_domain()
        if not landing_url:
            landing_url = full_url
        logger.info("Landing url for {} is {}", url, landing_url)
        landing_url_lexical_dict = self.url_lexical.get_url_lexical(landing_url)

        nmap_raw = self.nmap_crawler.nmap_scan(hostname)
        raw_data_dict = {
            "url": url,
            "timestamp": str(datetime.now().strftime(DATETIME_FORMAT)),
            "certificate": certificate_raw,
            "dns": dns_raw,
            "http_header": http_header_raw,
            "http_redirection": http_redirection_count,
            "http_redirection_chain": http_redirection_chain,
            "http_different_domains_in_redirection": http_different_domains_in_redirection,
            "hop_distance": hop_distance,
            "average_rtt": average_rtt,
            "origin_url_lexical": origin_url_lexical_dict,
            "landing_url_lexical": landing_url_lexical_dict,
            "nmap": nmap_raw,
            "label": label,
        }

        self.dynamodb_storage.store_item(raw_data_dict)
        logger.info("Completed crawl data for {}", url)

    def deduplicate_url(self, url):
        return self.dynamodb_storage.check_existence(url)

if __name__ == '__main__':
    DataCollector().run_crawl()


