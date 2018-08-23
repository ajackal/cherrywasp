from scapy.all import *
import argparse
import os
import datetime
from threading import Thread
from accesspoint import CherryAccessPoint
from client import CherryClient
# from threading import BoundedSemaphore


class CherryWasp:
    """ Cherry Wasp

        The object that inspects each packet and determines how to handle it.

        Inputs: scan_type(str)
            - 0 = Beacons only
            - 1 = Probe Requests only
            - 2 = Beacon & Probe Requests

        Returns: prints results to screen and saves to .csv file.

        self.clients_bssids(set) of BSSIDs (MAC addresses) of devices sending probe requests.
        self.access_points_bssids(set) of BSSIDs (MAC addresses) of devices beaconing ESSIDs.
        self.clients(dict) of client objects {BSSID: <Obj>, BSSID: <Obj>}.
        self.access_points(dict) of client objects {BSSID: <Obj>, BSSID: <Obj>}.
    """

    def __init__(self, scan_type):
        self.scan_type = scan_type
        self.clients_bssids = set()
        self.access_points_bssids = set()
        self.clients = {}
        self.access_points = {}
        self.file_prefix = ""
        # for interface in interfaces:
        #    self.create_mon_interface(interface)
        # MAX_CONNECTIONS = 20  # max threads that can be created
        # self.CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)

    @staticmethod
    def create_mon_interface(interface):
        """Method uses Linux system commands to stand up a monitoring interface.

        Inputs: interface(str) the source interface to create a monitor interface.

        Returns: None
        """
        os.system("ip link set " + interface + " down")
        os.system("iw phy " + interface + " interface add mon0 type monitor")
        os.system("iw dev " + interface + " del")
        os.system("ip link set mon0 up")

    @staticmethod
    def channel_hop(band, dev_descriptor):
        """Method uses Linux system commands to change the channel the wireless card is listening on.

        Inputs: band(str) "2.4", "5.0" or None

        Returns: None
        """

        if "2.4" in band:
            channels = ["2412", "2417", "2422", "2427", "2432", "2437", "2442", "2447", "2452", "2457", "2462", "2467",
                        "2472", "2484"]
        elif "5.0" in band:
            channels = ["5160", "5170", "5180", "5190", "5200", "5210", "5220", "5230", "5240", "5250", "5260", "5270",
                        "5280", "5290", "5300", "5310", "5320", "5340", "5480", "5500", "5510", "5520", "5530", "5540",
                        "5550", "5560", "5570", "5580", "5590", "5600", "5610", "5620", "5630", "5640", "5660", "5670",
                        "5680", "5690", "5700", "5710", "5720", "5745", "5755", "5765", "5775", "5785", "5795", "5805",
                        "5825"]
        else:
            channels = []
        while True:
            for channel in channels:
                os.system("iwconfig {0} freq {1}M".format(dev_descriptor, channel))
                print('[*] Scanning channel {0}'.format(channel))
                time.sleep(5)

    def scan_packet(self, pkt):
        """ Function run by scapy's sniff function.

        Inputs: self, pkt(scapy object)

        Returns: value printed to console.

        Cannot add any additional inputs, would need to create a nested function to add additional inputs.
        Can add additional functionality by having it call methods from its class.
        """
        # self.CONNECTION_LOCK.acquire()
        try:
            if self.scan_type == '0' or self.scan_type == '2':
                packet_type = "beacon"
                if pkt.haslayer(Dot11Beacon):
                    essid = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.info%}")
                    bssid = pkt.sprintf("%Dot11.addr2%")
                    if bssid not in self.access_points:
                        new_ap = CherryAccessPoint(bssid, self.file_prefix)
                        self.access_points[bssid] = new_ap
                    if essid != "":
                        self.access_points[bssid].add_new_beaconed_essid(essid)
            if self.scan_type == '1' or self.scan_type == '2':
                packet_type = "probe_request"
                if pkt.haslayer(Dot11ProbeReq):
                    essid = pkt.sprintf("{Dot11ProbeReq:%Dot11ProbeReq.info%}")
                    bssid = pkt.sprintf("%Dot11.addr2%")
                    if bssid not in self.clients:
                        new_client = CherryClient(bssid, self.file_prefix)
                        self.clients[bssid] = new_client
                    if essid != "":
                        self.clients[bssid].add_new_requested_essid(essid)
        except Exception:
            raise
        # finally:
        #     self.CONNECTION_LOCK.release()


def main():
    parser = argparse.ArgumentParser(description='Scan for 802.11 Beacon and/or Probe Requests.')
    parser.add_argument('-m', '--mode', help='0=beacons, 1=probe requests, 2=both')
    parser.add_argument('-i', '--interface', help='specify interface(s) to listen on')
    parser.add_argument('-b', '--band', help='specify the band to scan, 2.4 or 5.0')
    parser.add_argument('-B', '--bssid', help='specify bssid to filter <mode 0 only> <optional>')
    parser.add_argument('-o', '--output', help='specify a file prefix for saved files.')
    args = parser.parse_args()

    try:
        valid_modes = ["0", "1", "2"]
        assert args.mode is not None
        assert args.mode in valid_modes
        scan_type = args.mode
        cherry_wasp = CherryWasp(scan_type)
        if args.output is not None:
            file_prefix = args.output
        else:
            now = datetime.datetime.now()
            file_prefix = str(now.year) + str(now.month) + str(now.day)
        cherry_wasp.file_prefix = file_prefix
    except AssertionError:
        print("[!] Error, invalid mode selected!")
        print(parser.usage)
        exit(0)
    except Exception:
        raise

    create_mon_interface = False

    try:
        assert args.interface is not None
        conf.iface = args.interface
        if create_mon_interface:
            cherry_wasp.create_mon_interface(conf.iface)
    except AssertionError:
        print("[!] Must define an interface with <-i>!")
        print(parser.usage)
        exit(0)

    try:
        valid_bands = ["2.4", "5.0", None]
        assert args.band in valid_bands
        if args.band is "2.4" or "5.0":
            band = str(args.band)
            print("[*] Scanning on {0}GHz band".format(band))
        else:
            print("[*] No band defined, defaulting to 2.4GHz.")
            band = "2.4"
    except AssertionError:
        print("[!] Invalid band selected.")
        print(parser.usage)
        exit(0)

    if scan_type is "1":
        channel_hop = False
    else:
        channel_hop = True

    try:
        if args.bssid is None:
            if channel_hop:
                channel_hopper = Thread(target=cherry_wasp.channel_hop, args=[band, args.interface])
                channel_hopper.daemon = True
                channel_hopper.start()
            sniff(prn=cherry_wasp.scan_packet, store=0)
        else:  # TODO: add BSSID input validation here
            assert args.mode is 0
            filter_bssid = str("ether src " + args.bssid)
            if channel_hop:
                channel_hopper = Thread(target=cherry_wasp.channel_hop, args=[band, args.interface])
                channel_hopper.daemon = True
                channel_hopper.start()
            sniff(filter=filter_bssid, prn=cherry_wasp.scan_packet, store=0)
    except AssertionError:
        print("[!] Invalid mode selected. No mode selected or must use mode 0 when filtering by BSSID")
        print(parser.usage)
        exit(0)


if __name__ == "__main__":
    main()
