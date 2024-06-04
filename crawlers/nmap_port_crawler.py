import subprocess
from loguru import logger

from utils.constants import EMPTY_RESPONSE

class NmapPortCrawler():
    def __init__(self):
        pass
# network map
    def nmap_scan(self,url) -> str:
        logger.info("Start nmap scar for {}", url)
        nmap_output = EMPTY_RESPONSE

        nmap_command = (
            'nmap --top-ports 50 -0 -v --host-timeout 5m --data-string '
            '"Scan data used for research. For detailed info, please send '
            'email to li.yuchen3@northeastern.edu" {}'.format(url)
        )
        logger.info("Nmap command to scan {} is {}", url, nmap_command)

        try:
            nmap_output = subprocess.check_output(nmap_command, shell=True)
        except subprocess.CalledProcessError:
            logger.exception("Cannot run nmap {}".format(url))
            return nmap_output

        logger.info("Nmap output is {}", url, nmap_output)

        return nmap_output.decode()