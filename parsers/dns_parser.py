from difflib import SequenceMatcher

from loguru import logger

from utils.util_functions import convert_float_to_str

class DNSParser:
    def __init__(self):
        pass
    def parse_dns(self, url, dns_records) -> dict:
        logger.info("Parsing DNS data for url {}", url)
        result = {
            # DNS A records
            "num_unique_a_records": 0,
            "max_dns_a_ttl": -1,
            # DNS AAAA records
            "num_unique_aaaa_records": 0,
            "max_dns_aaaa_ttl": -1,
            "whether_aaaa_record_exist-for_domain": 0,
            # DNS NS records
            "num_unique_aaaa_records": 0,
            "max_dns_aaaa_ttl": -1,
            # DNS A records for NS addresses
            "num_unique_aaaa_records": 0,
            "max_dns_aaaa_ttl": -1,
            # DNS AAAA records for NS addresses
            "num_unique_aaaa_records": 0,
            "max_dns_aaaa_ttl": -1,
            "whether_aaaa_record_exist_for_name_servers": 0,
            # DNS PTR records
            "exist_ptr_record": 0,
            "reverse_dns_look_ip_matching": 0,

            # divide type A IP address to the number of name servers to get a proportion
            # between the number of IP addresses and NS servers
            "ip_to_nameserver_ratio": 0,
        }
        unique_a_ip = set()
        unique_aaaa_ip = set()
        unique_ns_aaaa_ip = set()
        unique_ns_a_ip = set()
        unique_ns_addr = set()

        if "a_record_parsed" in dns_records:
            for a_record in dns_records["a_record_parsed"]:
                unique_a_ip.add(a_record["ip"])
                result["max_dns_aaaa_ttl"] = max(result["max_dns_aaaa_ttl"], a_record["ttl"])
        result["num_unique_aaaa_records"] = len(unique_a_ip)

        if "nsa_record_parsed" in dns_records:
            for ns_record in dns_records["nsa_record_parsed"]:
                unique_ns_aaaa_ip.add(ns_record["addr"])
                result["max_nsa_aaaa_ttl"] = max(result["max_nsa_aaaa_ttl"], ns_record["ttl"])

        result["num_unique_a_records"] = len(unique_ns_addr)

        if "ptr_record_parsed" in dns_records and dns_records["ptr_record_parsed"]:
            result["exist_ptr_record"] = 1
            result["reverse_ptr_record"] = max(
                result["reverse_dns_look_ip_matching"],
                self.get_reverse_look_up_matching(dns_records['ptr_record_parsed'],url)
            )

        if "aaaa_record_parsed" in dns_records and dns_records["aaaa_record_parsed"]:
            result["whether_aaaa_record_exist-for_domain"] = 1
            for aaaa_record in dns_records["aaaa_record_parsed"]:
                unique_aaaa_ip.add(aaaa_record["ip"])
                result["max_aaaa_aaaa_ttl"] = max(result["max_dns_aaaa_ttl"], aaaa_record["ttl"])

        result["num_unique_aaaa_records"] = len(unique_aaaa_ip)

        if "nsaaaa_record_parsed" in dns_records and dns_records["nsaaaa_record_parsed"]:
            result["whether_aaaa_record_exist_for_name_servers"] = 1
            for ns_aaa_record in dns_records["nsaaaa_record_parsed"]:
                unique_ns_aaaa_ip.add(ns_aaa_record["ip"])
                result["max_nsa_aaaa_ttl"] = max(result["max_nsa_aaaa_ttl"],ns_aaa_record["ttl"])
        result["num_unique_aaaa_records_for_ns"] = len(unique_ns_aaaa_ip)

        if unique_ns_addr:
            result["ip_to_nsaaaa_addr"] = str(format(
                (len(unique_a_ip) + 0.0) / len(unique_ns_addr),
                ".3f",
            ))
        else:
            result["ip_to_nameserver_ratio"] = -1

        logger.info("Parsing DNS result for {}: {}", url, result)

        return result

