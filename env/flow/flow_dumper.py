import datetime
import logging
import os
import re
import requests
import socket
import sys
from threading import Thread
import time

import dpkt
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder
import pcapy


# if queue has no data, sleep
QUEUE_SLEEP_TIME = 1

# every INTERVAL seconds to recreate a new pacp file
INTERVAL = 60 * 10

# which interface to capture packages
INTERFACE = "eth0"

# Max bytes to capture
MAX_BYTES = 65535

# whether to use promiscuous model
PROMSIC = False

# read timeout, ms
READ_TIMEOUT = 100

# time format for pacp file name
TIME_FORMART = "%Y%m%d-%H%M%S"

# report ip and port to server
REPORT_URL = "http://1.1.1.1"

# dest port
PORT = 9999

# where to sotre pacp files
SAVE_PATH = "/home/ctf/packages"

# log path
LOG_PATH = "/var/log/flow_dumper.log"


# temp flow set
FLOW_SET = set()

SPLIT_STR = "--"

SET_SLEEP_TIME = 5

SRC_EXCLUDE_PATTERN = re.compile(r"173\.30\.[0-9]{1,3}\.250")

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


def choose_interface():
    ifaces = pcapy.findalldevs()
    if not ifaces:
        logging.error("No interface for you on this system.")
        sys.exit(1)

    for index, iface in enumerate(ifaces):
        print "%i - %s" % (index, iface)

    while 1:
        try:
            idx = int(raw_input('Please select an interface: '))
            if idx <= index:
                break
        except Exception as e:
            continue
    return ifaces[idx]


class FlowSetReporter(Thread):
    def __init__(self, report_url):
        super(FlowSetReporter, self).__init__()
        self.report_url = report_url

    def run(self):
        while 1:
            global FLOW_SET
            temp_flow_set = FLOW_SET
            FLOW_SET = set()

            for flow_data in temp_flow_set:
                logging.info("Get flow %s from set ." % flow_data)
                saddr, daddr, dport = flow_data.split(SPLIT_STR)
                try:
                    r = requests.post(self.report_url, json={
                                                             'attack_ip': saddr,
                                                             'target_ip': daddr,
                                                             'task_port': int(dport),
                                                             'pwn': 0})
                    logging.debug(r.text)
                except:
                    logging.error("Unable to post flow %s ." % flow_data)
            # logging.debug("Sleep {}s before another loop .".format(SET_SLEEP_TIME))
            time.sleep(SET_SLEEP_TIME)


class FlowReporter(Thread):
    def __init__(self, queue, report_url):
        super(FlowReporter, self).__init__()
        self.report_url = report_url
        self.flow_queue = queue

    def run(self):
        while 1:
            try:
                flow_data = self.flow_queue.get(block=True, timeout=2)
                logging.info("get %s from queue ." % flow_data)
                r = requests.post(self.report_url, json={'round': 1,
                                                         'attack_ip': flow_data[0],
                                                         'target_ip': flow_data[2],
                                                         'task_port': flow_data[3],
                                                         'pwn': 0})
                logging.debug(r.text)
            except:
                logging.debug("wait %ss" % QUEUE_SLEEP_TIME)
                time.sleep(QUEUE_SLEEP_TIME)


class FlowDumper(Thread):
    def __init__(self, iface, max_byrtes, promsic, read_timeout, pac_filter):
        super(FlowDumper, self).__init__()
        # self.flow_queue = queue
        self.save_path = SAVE_PATH
        self._create_folder()
        self.iface = iface
        self.last_time = time.time()
        self.pcap = pcapy.open_live(iface, max_byrtes, promsic, read_timeout)
        self.pcap.setfilter(pac_filter)
        self.pkg_dumper = None

        if pcapy.DLT_EN10MB == self.pcap.datalink():
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == self.pcap.datalink():
            self.decoder = LinuxSLLDecoder()
        else:
            logging.error("Datalink type not supported: " % self.pcap.datalink())
            raise Exception("Datalink type not supported: " % self.pcap.datalink())

    def _create_folder(self):
        if not os.path.exists(self.save_path):
            os.makedirs(self.save_path)

    # def push_to_queue(self, data):
    #     logging.info("push %s to queue" % data)
    #     self.flow_queue.put(data)

    def push_to_set(self, data):
        global FLOW_SET
        # logging.info("push %s to set" % data)
        FLOW_SET.add(SPLIT_STR.join(data))

    def _dump_path(self):
        curr_time_str = datetime.datetime.now().strftime(TIME_FORMART)
        pacp_file_name = "{}-{}{}".format(self.iface, curr_time_str, ".pcap")
        return os.path.join(self.save_path, pacp_file_name)

    def get_dumper(self):
        # change dump file name by interval
        if not self.pkg_dumper:
            logging.info("No dumper, create one.")
            self.pkg_dumper = self.pcap.dump_open(self._dump_path())
            return

        now_time = time.time()
        if now_time - self.last_time >= INTERVAL:
            # close the dumper and recreate a new one
            logging.info("Create a new dumper.")
            self.pkg_dumper = None
            self.last_time = now_time
            self.pkg_dumper = self.pcap.dump_open(self._dump_path())

    def packet_handler(self, hdr, data):
        # packet = self.decoder.decode(data)
        self.get_dumper()

        try:
            ether = dpkt.ethernet.Ethernet(str(data))
            if ether.type == dpkt.ethernet.ETH_TYPE_IP:
                ip_data = ether.data
                saddr = socket.inet_ntoa(ip_data.src)
                daddr = socket.inet_ntoa(ip_data.dst)
                
                if SRC_EXCLUDE_PATTERN.match(saddr):
                    logging.debug("Exclude source addr %s" % saddr)
                    return
                
                tcp_data = ip_data.data
                if isinstance(tcp_data, dpkt.tcp.TCP):
                    dport = tcp_data.dport
                    sport = tcp_data.sport
                    if tcp_data.flags & dpkt.tcp.TH_PUSH and dport and sport:
                        # self.push_to_queue([saddr, sport, daddr, dport])
                        self.push_to_set([saddr, daddr, str(dport)])

                    self.pkg_dumper.dump(hdr, data)
        except Exception as e:
            # logging.info("Exception %s", e)
            pass

    def run(self):
        self.pcap.loop(-1, self.packet_handler)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-5.5s : %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=LOG_PATH or None)
    logging.info("Starting monitor...")

    iface = INTERFACE or choose_interface()
    pac_filter = "dst port %d and src host not %s" % (PORT, get_local_ip())
    # pac_filter = "src net 192.168.1.0/24 and dst net 192.168.1.0/24 and not arp and not icmp"

    # queue = Queue.Queue()

    dumper = FlowDumper(iface, MAX_BYTES, PROMSIC, READ_TIMEOUT, pac_filter)
    dumper.start()

    reporter = FlowSetReporter(REPORT_URL)
    reporter.start()
