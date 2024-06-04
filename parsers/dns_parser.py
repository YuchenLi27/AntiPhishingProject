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
            # match hostname and web name, if so, it means good one.
            # max to see the max degree of matching.
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

    def get_reverse_look_up_matching(self,ptr_record, url) -> str:
        """
        Get the matching ratio of the DNS reverse look up resulted url with the origin url.
        :param ptr_record.
        :param url: original url we used for crawling.
        :return: String representation of matching ratio in Decimal.
        """
        max_match_ratio = 0.0
        for ele in ptr_record:
            ptr_addr = ele["addr"]
            match_ratio = SequenceMatcher(None, ptr_addr, url).ratio() # to get the longest contiguous matching subsequence
            max_match_ratio = max(max_match_ratio, match_ratio)

        return convert_float_to_str(max_match_ratio)

# for testing
if __name__ == "__main__":
    low_level_data = {
        "a_record_parsed": {
            "L": [
                {
                    "M": {
                        "addr": {
                            "S": ""
                        },
                        "ttl": {
                            "N": "300"
                        },
                        "ip": {
                            "S": "142.250.190.99"
                        }
                    }
                }
            ]
        },
        "nsaaaa_record_parsed": {
            "L": [
                {
                    "M": {
                        "addre": {
                            "S": "ns1.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "2001:4860:4802:32::a"
                        }
                    }
                },
                {
                    "M": {
                        "addre": {
                            "S": "ns3.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "2001:4860:4802:36::a"
                        }
                    }
                },
                {
                    "M": {
                        "addre": {
                            "S": "ns4.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "2001:4860:4802:38::a"
                        }
                    }
                },
                {
                    "M": {
                        "addre": {
                            "S": "ns2.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "2001:4860:4802:34::a"
                        }
                    }
                }
            ]
        },
        "ptr_record_raw": {
            "S": "id 53690\nopcode QUERY\nrcode NOERROR\nflags QR RD RA\nedns 0\npayload 65494\n;QUESTION\n99.190.250.142.in-addr.arpa. IN PTR\n;ANSWER\n99.190.250.142.in-addr.arpa. 300 IN PTR ord37s35-in-f3.1e100.net.\n;AUTHORITY\n;ADDITIONAL"
        },
        "ns_record_parsed": {
            "L": [
                {
                    "M": {
                        "addr": {
                            "S": "ns1.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": ""
                        }
                    }
                },
                {
                    "M": {
                        "addr": {
                            "S": "ns3.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": ""
                        }
                    }
                },
                {
                    "M": {
                        "addr": {
                            "S": "ns4.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": ""
                        }
                    }
                },
                {
                    "M": {
                        "addr": {
                            "S": "ns2.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": ""
                        }
                    }
                }
            ]
        },
        "nsa_record_parsed": {
            "L": [
                {
                    "M": {
                        "addr": {
                            "S": "ns1.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "216.239.32.10"
                        }
                    }
                },
                {
                    "M": {
                        "addr": {
                            "S": "ns3.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "216.239.36.10"
                        }
                    }
                },
                {
                    "M": {
                        "addr": {
                            "S": "ns4.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "216.239.38.10"
                        }
                    }
                },
                {
                    "M": {
                        "addr": {
                            "S": "ns2.google.com."
                        },
                        "ttl": {
                            "N": "345600"
                        },
                        "ip": {
                            "S": "216.239.34.10"
                        }
                    }
                }
            ]
        },
        "aaaa_record_parsed": {
            "L": [
                {
                    "M": {
                        "addr": {
                            "S": ""
                        },
                        "ttl": {
                            "N": "300"
                        },
                        "ip": {
                            "S": "2607:f8b0:4009:80b::2003"
                        }
                    }
                }
            ]
        },
        "dns_record_raw": {
            "S": "id 25457\nopcode QUERY\nrcode NOERROR\nflags QR AA RD\nedns 0\npayload 512\n;QUESTION\ngoogle.rw. IN A\n;ANSWER\ngoogle.rw. 300 IN A 142.250.190.99\n;AUTHORITY\n;ADDITIONAL"
        },
        "ptr_records_parsed": {
            "L": [
                {
                    "M": {
                        "addr": {
                            "S": "ord37s35-in-f3.1e100.net."
                        },
                        "ttl": {
                            "N": "300"
                        },
                        "ip": {
                            "S": "142.250.190.99"
                        }
                    }
                }
            ]
        }
    }
    from boto3.dynamodb.types import TypeDeserializer
    deserializer = TypeDeserializer()
    python_data = {k: deserializer.deserialize(v) for k, v in low_level_data.items()}
    DNSParser().parse_dns("google.com", python_data)