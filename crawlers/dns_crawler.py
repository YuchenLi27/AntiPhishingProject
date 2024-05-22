import dns
import dns.reversename
import dns.resolver
import dns.rdatatype
from dns.resolver import NoAnswer, NoNameservers
from dns.exception import DNSException
from loguru import logger

class DNSCrawler:
    DNS_TIMEOUT = 10

    def __init__(self):
        pass
    def query_ns(self,tmp_resolver, domain, nsa_candidates):
        ns_result = tmp_resolver.resolve(domain, rdtype=dns.rdatatype.NS)
        ns_rrset = ns_result.rrset
        ns_candidates = []
        for rr in ns_rrset:
            if rr != dns.rdatatype.NS:
                continue
            ns_candidates.append(rr.to_text())
        for ns_chosen in ns_candidates:
            ns_a_result = tmp_resolver.resolve(ns_chosen, rdtype=dns.rdatatype.A)
            ns_a_rrset = ns_a_result.rrset

        for rr in ns_a_rrset:
            if rr.rdtype!= dns.rdatype.A:
                continue
            nsa_candidates.append(rr.to_text())

    def dns_query(self,url):
        logger.info("Start collecting dns infor for{}", url)
        a_list = []
        aaaa_list = []
        ns_list = []
        nsa_list = []
        ns_aaaa_list = []
        ptr_addrs = set()
        ptr_list = []
        ret = {
            "dns_record_raw": " ",
            "a_record_parsed": a_list,
            "aaaa_record_parsed": aaaa_list,
            "ns_record_parsed": ns_list,
            "nsa_record_parsed": nsa_list,
            "nsaaaa_record_parsed": ns_aaaa_list,
            "ptr_record_raw": "",
            "ptr_records_parsed": ptr_list,
        }
        tmp_resolver = dns.resolver.Resolver()
        tmp_resolver.timeout = DNSCrawler.DNS_TIMEOUT
        tmp_resolver.nameservers = ["8.8.8.8", "1.1.1.1"]

        nsa_candidates = []
        try:
            self._query_ns(tmp_resolver, url,nsa_candidates)
        except Exception as e:
            try:
                self.dns_query_ns(tmp_resolver, url,nsa_candidates)
            except Exception as e:
                logger.exception("Cannot find Authority DNS resolver for domain {}", url)
        except Exception as e:
            logger.exception("Unexpected exception crawling DNS for domain {}", url)

        resolver = dns.resolver.Resolver()
        resolver.timeout = DNSCrawler.DNS_TIMEOUT
        if nsa_candidates:
            resolver.nameservers = nsa_candidates
            logger.info("Using Authoritative DNS resolver list {}", nsa_candidates)
        # if no ADNS servers found, use default ones

        # A records
        ns_rrsets = []
        try:
            answer = resolver.resolve(url, rdtype=dns.rdatatype.A)
            ret["dns_record_raw"] = answer.response.to_text()
            a_rrset = answer.rrset
            for rr in a_rrset:
                if rr.rdtype != dns.rdatatype.A:
                    continue
                addr = rr.to_text()
                ptr_addrs.add(addr)
                new_pair = {
                    "addr": "",
                    "ip": addr,
                    "ttl": a_rrset.ttl
                }
                a_list.append(new_pair)

            # Realize that query NS records not always get back correct
            # answers, thus the hack use the authoritative section of A
            # records query for NS records
            ns_rrsets = answer.response.authority  # this answer is from A query
            for ns_rrset in ns_rrsets:
                for rr in ns_rrset:
                    if rr.rdtype != dns.rdatatype.NS:
                        continue
                    new_pair = {
                        "addr": rr.to_text(),
                        "ip": "",
                        "ttl": ns_rrset.ttl,
                    }
                    ns_list.append(new_pair)

        except Exception:
            pass

        # AAAA records
        try:
            aaaa_answer = resolver.resolve(url, rdtype=dns.rdatatype.AAAA)
            aaaa_rrset = aaaa_answer.rrset
            for rr in aaaa_rrset:
                if rr.rdtype == dns.rdatatype.AAAA:
                    ip = rr.to_text()
                    new_pair = {
                        "addr": "",
                        "ip": ip,
                        "ttl": aaaa_rrset.ttl,
                    }
                    aaaa_list.append(new_pair)
        except Exception as e:
            pass

        try:
            # in the case there is no ns records in authoritative section
            if not ns_list or not ns_rrsets:
                # for later nsa query
                ns_rrsets = []
                # obatin NS records by querying NS type() as a remedy
                answer = resolver.resolve(url, rdtype=dns.rdatatype.NS)
                ns_rrset = answer.rrset
                ns_rrsets.append(ns_rrset)
                for rr in ns_rrset:
                    if rr.rdtype != dns.rdatatype.NS:
                        continue
                    new_pair = {
                        "addr": rr.to_text(),
                        "ip": "",
                        "ttl": ns_rrset.ttl,
                    }
                    ns_list.append(new_pair)

            for ns_rrset in ns_rrsets:
                for ns_rr in ns_rrset:
                    if ns_rr.rdtype != dns.rdatatype.NS:
                        continue
                    ns_name = ns_rr.to_text()
                    answer = resolver.resolve(ns_name, rdtype=dns.rdatatype.A)
                    nsa_rrset = answer.rrset
                    for rr in nsa_rrset:
                        if rr.rdtype != dns.rdatatype.A:
                            continue
                        new_pair = {
                            "addr": ns_name,
                            "ip": rr.to_text(),
                            "ttl": nsa_rrset.ttl,
                        }
                        nsa_list.append(new_pair)
        except Exception as e:
            pass

        # AAAA records for Name servers
        try:
            for name_server in ns_list:
                answer = resolver.resolve(name_server["addr"], rdtype=dns.rdatatype.AAAA)
                ns_aaaa_rrset = answer.rrset
                for rr in ns_aaaa_rrset:
                    if rr.rdtype == dns.rdatatype.AAAA:
                        new_pair = {
                            "addr": name_server["addr"],
                            "ip": rr.to_text(),
                            "ttl": ns_aaaa_rrset.ttl,
                        }
                        ns_aaaa_list.append(new_pair)
        except Exception as e:
            pass

        # ptr query
        # see the following doc for a discussion of the impact of cloud service to PTR records
        # [feature doc](https://docs.google.com/document/d/1AQMuxkWJw4OeQch9vIxQlEs6eMwHgCYlUpnnbqBcnIU/edit#heading=h.4ugewg3ia9wp)
        try:
            if len(ptr_addrs) != 0:
                for ip in ptr_addrs:
                    # get the reverse-map domain name of the address
                    addr_arpa = dns.reversename.from_address(ip)
                    logger.debug("Query {} for PTR records of {}", addr_arpa, url)
                    answer = resolver.resolve(addr_arpa, dns.rdatatype.PTR)
                    ret["ptr_record_raw"] = answer.response.to_text()
                    # ptr records
                    ptr_rrset = answer.rrset
                    for rr in ptr_rrset:
                        ptr = rr.to_text()
                        new_pair = {
                            "ip": ip,
                            "addr": ptr,
                            "ttl": ptr_rrset.ttl,
                        }
                        ptr_list.append(new_pair)

        except Exception as e:
            logger.exception("DNSException for url {}", url)
            # simply ignore the exception and this will be missing features
            pass

        return ret

    # for testing
    if __name__ == "__main__":
        print(DNSCrawler().dns_query("symantec.com"))











