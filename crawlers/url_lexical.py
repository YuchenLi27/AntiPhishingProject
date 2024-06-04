import socket
import re

class UrlLexical:
    def __init__(self):
        pass

    def get_url_lexical(self, url):
        ip_address_in_hostname = self.__check_ip_address(url)
        num_of_dots = len(re.findall("\.", url))
        num_of_dash = len(re.findall("-", url))
        len_of_domain = len(url)
        num_of_slash = len(re.findall("/", url))
        num_of_path_token = (len(re.findall("\?", url)) + len(re.findall("\&", url))
                             + len(re.findall("\=", url)))
        return {
            "ip_address_in_hostname": ip_address_in_hostname,
            "num_of_dot": num_of_dots,
            "num_of_dash": num_of_dash,
            "num_of_slash": num_of_slash,
            "num_of_path_token": num_of_path_token,
            "len_of_domain": len_of_domain,
        }

    def __check_ip_address(self, url):
        pat = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        potentials = re.findall(pat, url)
        for potential in potentials:
            try:
                socket.inet_aton(potential)
                return True
            except socket.error:
                continue

        return False
