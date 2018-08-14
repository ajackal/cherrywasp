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
        self.access_points = []  # TODO: convert to set
        self.access_points_bssids = []
        self.clients = []
        self.clients_bssids = []  # TODO: convert to set
        # for interface in interfaces:
        #    self.create_mon_interface(interface)
        # MAX_CONNECTIONS = 20  # max threads that can be created
        # self.CONNECTION_LOCK = BoundedSemaphore(value=MAX_CONNECTIONS)

    def create_mon_interface(self, interface):
        os.system("ip link set " + interface + " down")
        os.system("iw phy " + interface + " interface add mon0 type monitor")
        os.system("iw dev " + interface + " del")
        os.system("ip link set mon0 up")

    def channel_hop(self, band):
        if band is "2.4":
            channels: "2412, 2417, 2422, 2427, 2432, 2437, 2442, 2447, 2452, 2457, 2462, 2467, 2472, 2484"
        if band is "5.0":
            channels: ""
        for channel in channels:
            os.system("iw dev mon0  set freq " + channel)

    def scan_packet(self, pkt):
        # self.CONNECTION_LOCK.acquire()
        try:
            if self.scan_type == '0' or self.scan_type == '2':
                if pkt.haslayer(Dot11Beacon):
                    essid = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.info%}")
                    bssid = pkt.sprintf("%Dot11.addr2%")
                    no_broadcast = False
                    if bssid not in self.access_points:
                        bssid = CherryAccessPoint(bssid)
                        self.access_points.append(bssid)
                    if essid != "":
                        no_broadcast = True
                    if no_broadcast is True:
                        for access_point in self.access_points:
                            if bssid is access_point.bssid and essid not in access_point.beaconed_essid:
                                access_point.add_new_essid(essid)
                                print("[+] <{0}> is beaconing as {1}".format(colored(bssid.bssid, 'red'),
                                                                             colored(essid, 'green')))
                                with open("beacon_essids.csv", "a") as b:
                                    b.write("{0},{1}\n".format(bssid.bssid, essid))
            if self.scan_type == '1' or self.scan_type == '2':
                if pkt.haslayer(Dot11ProbeReq):
                    essid = pkt.sprintf("{Dot11ProbeReq:%Dot11ProbeReq.info%}")
                    bssid = pkt.sprintf("%Dot11.addr2%")
                    no_broadcast = False
                    if bssid not in self.clients:
                        bssid = CherryClient(bssid)
                        self.clients.append(bssid)
                    if essid != "":
                        no_broadcast = True
                    if no_broadcast is True:
                        for client in self.clients:
                            if bssid is client.bssid and essid not in client.beaconed_essid:
                                client.add_new_essid(essid)
                                print("[+] Probe Request for {0} from <{1}>".format(colored(essid, 'green'),
                                                                                    colored(bssid.bssid, 'red')))
                                with open("probe_requests.csv", "a") as r:
                                    r.write("{0},{1}\n".format(bssid.bssid, essid))
        except Exception:
            raise
        # finally:
        #     self.CONNECTION_LOCK.release()


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
    parser.add_argument('-b', '--bssid', help='specify bssid to filter <mode 0 only> <optional>')
    parser.add_argument('-B', '--band', help='specify the band to scan, 2.4 or 5.0')
    args = parser.parse_args()

    try:
        scan_type = args.mode
        cherry_wasp = CherryWasp(scan_type)
    except Exception:
        raise

    if args.interface is None:
        print("[!] must define an interface with <-i>!")
        print(parser.usage)
        exit(0)
    else:  # TODO: check interface for monitor mode
        conf.iface = args.interface
        cherry_wasp.create_mon_interface(conf.iface)

    if args.band is None:
        band = "2.4"
    elif args.band is 2.4 or 5.0:
        band = str(args.band)

    if args.bssid is None:
        if args.mode is not None:
            sniff(prn=cherry_wasp.scan_packet)
            cherry_wasp.channel_hop(band)
        else:
            print("[!] invalid mode selected")
            print(parser.usage)
            exit(0)

    if args.bssid is not None:  # TODO: add BSSID input validation here
        if args.mode is "0":
            filter_bssid = str("ether src " + args.bssid)
            sniff(filter=filter_bssid, prn=cherry_wasp.scan_packet)
            cherry_wasp.channel_hop(band)
        else:
            print("[!] must use mode 0 when filtering by BSSID")
            exit(0)
    else:
        print("[!] must define a mode with <-m>!")
        print(parser.usage)
        exit(0)


if __name__ == "__main__":
    main()
