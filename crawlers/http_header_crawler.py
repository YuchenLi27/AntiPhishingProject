import requests

from loguru import logger

from utils import util_functions

# to see if there is any response then to get the header,

class HttpHeaderCrawler:
    def __init__(self):
        self.response = None
        pass
    def get_response(self, url):
        logger.info("Start collecting http headers for {}", url)
        request_headers = {"user-agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, "
                           "like Gecko) Chrome/120.0.0.0 Safari/537.36"}

        try:
            response = requests.get(url, headers=request_headers, timeout = 3000, verify = False)
            if response and response.status_code == 200:
                self.response = response
                logger.info("Successfully collected http headers for{} as {}", url, response)
            else:
                logger.error("Response timeout or response code is not 200 {}", response.__dict__)
        except Exception as e:
            logger.exception("HTTP request failed for {}, url")
    def scan_http_headers(self):
        if self.response:
            return dict(self.response.headers)
        else:
            return {}

    def get_redirection_chain(self):
        redirection_chain = []
        if self.response and self.response.history:
            for r in self.response.history:
                if r.url:
                    redirection_chain.append(self.response.url)
        if self.response:
            redirection_chain.append(self.response.url)
        return redirection_chain

    def get_different_domains_crossed_in_redirection_chain(self):
        redirection_chain = self.get_redirection_chain()
        domains = set()
        for ele in redirection_chain:
            current_domain = util_functions.get_hostname(ele)
            domains.add(current_domain)
        return len(domains)

    def get_landing_domain(self):
        if self.response:
            if self.response.url.endswith("/"):
                return self.response.url[:-1]
            return self.response.url
        return None
