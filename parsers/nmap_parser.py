from utils.constants import EMPTY_RESPONSE
from loguru import logger

class NmapParser:
    def __init__(self):
        pass

    def parse_nmap(self,nmap_str) -> dict:
        """
        Parse nmap raw output and return open ports and OS information of the given host.
        :param nmap_str: raw nmap output.
        """
        logger.info("Parsing nmap raw input {}", nmap_str)
        open_ports = set()
        server_os = ""
        device_type = ""
        nmap_result = {
            "open_ports": list(),
            "open_ports_count": -1,
            "server_os": EMPTY_RESPONSE,
            "device_type": EMPTY_RESPONSE,

        }
        if nmap_str and nmap_str != EMPTY_RESPONSE:
            nmap_lines = nmap_str.split("\n")
            for line in nmap_lines:
                line = line.strip()
                if "Discovered open port" in line:
                    pos = line.find("Discovered open port") + \
                        len("Discovered open port") + 1
                    open_port = int(line[pos: line.find("/")])
                    open_ports.add(open_port)

                if "OS guesses" in line:
                    pos = line.find("OS guesses") + len("OS guesses") + 2
                    OS = line[pos:]
                    # pick the first guess which is the most possible guess
                    OS = OS.split(',')[0]
                    server_os = self.select_os(OS)

                if "OS details:" in line:
                    pos = line.find("OS details") + len("OS details") + 2
                    OS = line[pos:]
                    OS = OS.split(',')[0]
                    server_os = self.select_os(OS)

                if server_os:
                    nmap_result["server_os"] = server_os

                if "Device type:" in line:
                    pos = line.find("Device type:") + len("Device type:") + 1
                    device_type = line[pos:]

                if device_type:
                    nmap_result["device_type"] = device_type

            if open_ports:
                nmap_result["open_ports"] = list(open_ports)
                nmap_result["open_ports_count"] = len(open_ports)

            logger.info("Nmap parse result is {}", nmap_result)

            return nmap_result

    def select_os(self, os_line):
        if "Linux" in os_line:
            return "Linux"
        elif "Windows" in os_line:
            return u'Windows'
        elif "OpenBSD" in os_line:
            return "OpenBSD"
        elif "FreeBSD" in os_line:
            return "FreeBSD"
        elif "BSD" in os_line:
            return "BSD"
        elif "HP-UX" in os_line:
            return "HP-UX"
        elif "Mac" in os_line or "Macintosh" in os_line or "Darwin" in os_line:
            return "MacOSX"
        elif "Solaris" or "SunOS" in os_line:
            return "Solaris"
        elif "Android" in os_line:
            return "Android"
        else:
            return "Others"

# for testing
if __name__ == "__main__":
    nmap_str = """Starting Nmap 7.80 ( https://nmap.org ) at 2024-04-03 20:44 UTC
Initiating Ping Scan at 20:44
Scanning google.gp (142.250.190.131) [4 ports]
Completed Ping Scan at 20:44, 0.03s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:44
Completed Parallel DNS resolution of 1 host. at 20:44, 0.00s elapsed
Initiating SYN Stealth Scan at 20:44
Scanning google.gp (142.250.190.131) [50 ports]
Discovered open port 80/tcp on 142.250.190.131
Discovered open port 443/tcp on 142.250.190.131
Completed SYN Stealth Scan at 20:44, 1.54s elapsed (50 total ports)
Initiating OS detection (try #1) against google.gp (142.250.190.131)
Retrying OS detection (try #2) against google.gp (142.250.190.131)
Nmap scan report for google.gp (142.250.190.131)
Host is up (0.017s latency).
Other addresses for google.gp (not scanned): 2607:f8b0:4009:81b::2003
rDNS record for 142.250.190.131: ord37s36-in-f3.1e100.net

PORT      STATE    SERVICE
21/tcp    filtered ftp
22/tcp    filtered ssh
23/tcp    filtered telnet
25/tcp    filtered smtp
26/tcp    filtered rsftp
53/tcp    filtered domain
80/tcp    open     http
81/tcp    filtered hosts2-ns
110/tcp   filtered pop3
111/tcp   filtered rpcbind
113/tcp   filtered ident
135/tcp   filtered msrpc
139/tcp   filtered netbios-ssn
143/tcp   filtered imap
179/tcp   filtered bgp
199/tcp   filtered smux
443/tcp   open     https
445/tcp   filtered microsoft-ds
465/tcp   filtered smtps
514/tcp   filtered shell
515/tcp   filtered printer
548/tcp   filtered afp
554/tcp   filtered rtsp
587/tcp   filtered submission
646/tcp   filtered ldp
993/tcp   filtered imaps
995/tcp   filtered pop3s
1025/tcp  filtered NFS-or-IIS
1026/tcp  filtered LSA-or-nterm
1027/tcp  filtered IIS
1433/tcp  filtered ms-sql-s
1720/tcp  filtered h323q931
1723/tcp  filtered pptp
2000/tcp  filtered cisco-sccp
2001/tcp  filtered dc
3306/tcp  filtered mysql
3389/tcp  filtered ms-wbt-server
5060/tcp  filtered sip
5666/tcp  filtered nrpe
5900/tcp  filtered vnc
6001/tcp  filtered X11:1
8000/tcp  filtered http-alt
8008/tcp  filtered http
8080/tcp  filtered http-proxy
8443/tcp  filtered https-alt
8888/tcp  filtered sun-answerbook
10000/tcp filtered snet-sensor-mgmt
32768/tcp filtered filenet-tms
49152/tcp filtered unknown
49154/tcp filtered unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): FreeBSD 8.X (86%)
OS CPE: cpe:/o:freebsd:freebsd:8.2
Aggressive OS guesses: FreeBSD 8.2-RELEASE (86%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.000 days (since Wed Apr  3 20:44:33 2024)
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros

Read data files from: /usr/bin/../share/nmap
OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5.95 seconds
           Raw packets sent: 183 (21.012KB) | Rcvd: 20 (1.236KB)

    """
    NmapParser().parse_nmap(nmap_str)


