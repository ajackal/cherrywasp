from scapy.all import *
import argparse
from termcolor import colored
import os
# from threading import BoundedSemaphore


class CherryWasp:
    """ Cherry Wasp

        The object that inspects each packet and determines how to handle it

        1. scan_type is defined on the CLI by the user:
            a. Scan Type 0 = Beacons only
            b. Scan Type 1 = Probe Requests only
            c. Scan Type 2 = Beacon & Probe Requests

        2. self.access_points is a list of BSSIDs or MAC addresses of devices beaconing ESSIDs.
        3. self.clients is a list of BSSIDs or MAC addresses of devices that are sending probe requests.
    """

    def __init__(self, scan_type):
        self.scan_type = scan_type
        self.access_points = set()
        self.access_points_bssids = []
        self.clients = []
        self.clients_bssids = set()
        # for interface in interfaces:
        #    self.create_mon_interface(interface)
        # MAX_CONNECTIONS = 20  # max threads that can be created
        # self.CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)

    @staticmethod
    def create_mon_interface(interface):
        os.system("ip link set " + interface + " down")
        os.system("iw phy " + interface + " interface add mon0 type monitor")
        os.system("iw dev " + interface + " del")
        os.system("ip link set mon0 up")

    @staticmethod
    def channel_hop(band):
        if band is "2.4":
            channels = ["2412", "2417", "2422", "2427", "2432", "2437", "2442", "2447", "2452", "2457", "2462", "2467",
                        "2472", "2484"]
        if band is "5.0":
            channels = ["5160", "5170", "5180", "5190", "5200", "5210", "5220", "5230", "5240", "5250", "5260", "5270",
                        "5280", "5290", "5300", "5310", "5320", "5340", "5480", "5500", "5510", "5520", "5530", "5540",
                        "5550", "5560", "5570", "5580", "5590", "5600", "5610", "5620", "5630", "5640", "5660", "5670",
                        "5680", "5690", "5700", "5710", "5720", "5745", "5755", "5765", "5775", "5785", "5795", "5805",
                        "5825"]
        while True:
            for channel in channels:
                os.system("iw dev mon0 set freq " + channel)
                print("[*] Scanning channel {}".format(channel))
                time.sleep(5)

    def scan_packet(self, pkt):
        # self.CONNECTION_LOCK.acquire()
        try:
            if self.scan_type == '0' or self.scan_type == '2':
                packet_type = "beacon"
                if pkt.haslayer(Dot11Beacon):
                    essid = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.info%}")
                    bssid = pkt.sprintf("%Dot11.addr2%")
                    if bssid not in self.access_points:
                        bssid = CherryAccessPoint(bssid)
                        self.access_points.add(bssid)
                    if essid != "":
                        for access_point in self.access_points:
                            if bssid is access_point.bssid and essid not in access_point.beaconed_essid:
                                access_point.add_new_essid(essid)
                                print("[+] <{0}> is beaconing as {1}".format(colored(bssid.bssid, 'red'),
                                                                             colored(essid, 'green')))
                                CherryLogger.write_to_file(packet_type, bssid.bssid, essid)
            if self.scan_type == '1' or self.scan_type == '2':
                packet_type = "probe_request"
                if pkt.haslayer(Dot11ProbeReq):
                    essid = pkt.sprintf("{Dot11ProbeReq:%Dot11ProbeReq.info%}")
                    bssid = pkt.sprintf("%Dot11.addr2%")
                    if bssid not in self.clients:
                        bssid = CherryClient(bssid)
                        self.clients.append(bssid)
                    if essid != "":
                        for client in self.clients:
                            if bssid is client.bssid and essid not in client.beaconed_essid:
                                client.add_new_essid(essid)
                                print("[+] Probe Request for {0} from <{1}>".format(colored(essid, 'green'),
                                                                                    colored(bssid.bssid, 'red')))
                                CherryLogger.write_to_file(packet_type, bssid.bssid, essid)
        except Exception:
            raise
        # finally:
        #     self.CONNECTION_LOCK.release()


class CherryLogger:
    """ Creates log files and logs results.

    Inputs: file_name_prefix(str)

    Returns: file written to disk"""
    def __init__(self, file_name_prefix):
        self.file_path = os.getcwd() + os.path.join("logs")
        if os.path.exists(self.file_path) is False:
            os.mkdir(os.getcwd() + os.path.join("logs"))
        self.file_name_prefix = file_name_prefix
        self.headers = "bssid,essid"
        self.write_headers()

    def write_headers(self):
        packet_types = ["beacon", "probe_request"]
        for packet_type in packet_types:
            file_name = self.file_name_prefix + "_" + packet_type + ".csv"
            with open(file_name, 'a') as f:
                f.write(self.headers)

    def write_to_file(self, packet_type, bssid, essid):
        file_name = self.file_name_prefix + "_" + packet_type + ".csv"
        with open(file_name, "a") as r:
            r.write("{0},{1}\n".format(bssid, essid))


class CherryAccessPoint:
    """ Cherry Access Point:

        An object that represents an Access Point seen in the environment.

        1. Type defines it as an access point.
        2. BSSID is the MAC address of the access point.
        3. beaconed_essid is a list that holds all of the essids the MAC address has beaconed
        4. evil_access_point is False by default, but switches to True if it appear to beaconing too many ESSIDs

        add_new_essid adds a new ESSID or network name to the list for the particular client.
    """
    def __init__(self, bssid):
        self.type = "access_point"
        self.bssid = bssid
        self.beaconed_essid = []

    def add_new_beaconded_essid(self, new_essid):
        self.beaconed_essid.append(new_essid)


class CherryClient:
    """ Cherry Client
        An object that represents a wireless client seen in that environment.

        1. Type defines it as a client.
        2. BSSID is the MAC address of the client seen.
        3. requested_essid is all of the ESSIDs that the client has requested.

        add_new_essid adds a new ESSID or network name to the list for the particular client.
    """
    def __init__(self, bssid):
        self.type = "client"
        self.bssid = bssid
        self.requested_essid = []

    def add_new_requested_essid(self, new_essid):
        self.requested_essid.append(new_essid)


def main():
    parser = argparse.ArgumentParser(description='Scan for 802.11 Beacon and/or Probe Requests.')
    parser.add_argument('-m', '--mode', help='0=beacons, 1=probe requests, 2=both')
    parser.add_argument('-i', '--interface', help='specify interface(s) to listen on')
    parser.add_argument('-b', '--band', help='specify the band to scan, 2.4 or 5.0')
    parser.add_argument('-B', '--bssid', help='specify bssid to filter <mode 0 only> <optional>')
    parser.add_argument('-o', '--output', help='specify a file prefix for saved files.')
    args = parser.parse_args()

    try:
        valid_modes = [0, 1, 2]
        assert args.mode is not None
        assert args.mode in valid_modes
        scan_type = args.mode
        cherry_wasp = CherryWasp(scan_type)
    except AssertionError:
        print("[!] Error, invalid mode selected!")
        print(parser.usage)
        exit(0)
    except Exception:
        raise

    try:
        assert args.interface is not None
        conf.iface = args.interface
        cherry_wasp.create_mon_interface(conf.iface)
    except AssertionError:
        print("[!] Must define an interface with <-i>!")
        print(parser.usage)
        exit(0)

    try:
        valid_bands = [2.4, 5.0, None]
        assert args.band in valid_bands
        if args.band is 2.4 or 5.0:
            band = str(args.band)
            print("[*] Scanning on {0}GHz band".format(band))
        else:
            print("[*] No band defined, defaulting to 2.4GHz.")
            band = "2.4"
    except AssertionError:
        print("[!] Invalid band selected.")
        print(parser.usage)
        exit(0)

    try:
        if args.bssid is None:
            sniff(prn=cherry_wasp.scan_packet)
            cherry_wasp.channel_hop(band)
        else:  # TODO: add BSSID input validation here
            assert args.mode is 0
            filter_bssid = str("ether src " + args.bssid)
            sniff(filter=filter_bssid, prn=cherry_wasp.scan_packet)
            cherry_wasp.channel_hop(band)
    except AssertionError:
        print("[!] Invalid mode selected. No mode selected or must use mode 0 when filtering by BSSID")
        print(parser.usage)
        exit(0)


if __name__ == "__main__":
    main()
