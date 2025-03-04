from decimal import Decimal

from utils import util_functions
from loguru import logger
import trparse
import subprocess

from utils.util_functions import convert_float_to_str


class NetworkCrawler():
    def __init__(self):
        pass

    def trace_route(self,hostname):
        logger.info("Start collecting trace route for {}", hostname)
        hop_distance = -1 # missing and 0 is not same, 0 could be a distance from a to a
        average_rtt = -1
        output = ""

        try:

            logger.info("Starting ICMP trace route for {}", hostname)
            # check_output can use terminal/shell to run a command
            # check_output() return bytes,need decode
            output = subprocess.check_output(
                "traceroute -I -m 40 -z 10 {}".format(hostname),
                shell=True,
            )
            trace_result = trparse.loads(output.decode())# trparse.loads can turn response to dict

            # if traceroute with ICMP protocol not work, use traceroute with UDP protocol instead
            # we consider it not work on condition:
            # 1. output of traceroute is empty
            # 2. last hop of traceroute returns None as name, indicating the last host is unreachable
            if not output or (
                trace_result.hop[-1].probes[0].name is None and
                # from left to right
                # ie. "108.170.255.197" (108.170.255.197)  4.217 ms
                len(trace_result.hops[-1].probes) == 1

            ):
                logger.info("Starting UDP traceroute for {}", hostname)
                output = subprocess.check_output(
                    "traceroute -m 40 -z 10 {}".format(hostname),
                    shell=True,
                )
        except subprocess.CalledProcessError:
            logger.exception("Error while executing traceroute for {}", hostname)

        if output:
            logger.info("Collected raw traceroute for {}", hostname, output)
            trace_result = trparse.loads(output.decode())
            rtt_list = []
            for probe in trace_result.hops[-1].probes:
                if probe.name:
                    hop_distance = trace_result.hop[-1].idx
                if probe.hop:
                    rtt_list.append(probe.rtt)
            if rtt_list:
                average_rtt = convert_float_to_str(sum(rtt_list) / len(rtt_list))
        return hop_distance, average_rtt


