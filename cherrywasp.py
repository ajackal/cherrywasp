from scapy.all import *
import optparse
from termcolor import colored


class CherryWasp:
    def __init__(self, scan_type):
        """ Cherry Wasp

            The object that inspects each packet and determines how to handle it

            1. scan_type is defined on the CLI by the user:
                a. Scan Type 0 = Beacons only
                b. Scan Type 1 = Probe Requests only
                c. Scan Type 2 = Beacon & Probe Requests

            2. self.access_points is a list of BSSIDs or MAC addresses of devices beaconing ESSIDs.
            3. self.clients is a list of BSSIDs or MAC addresses of devices that are sending probe requests.
        """
        self.scan_type = scan_type
        self.access_points = []
        self.clients = []

    def scan_packet(self, pkt):
        if self.scan_type == 0 or self.scan_type == 2:
            if pkt.haslayer(Dot11Beacon):
                essid = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.info%}")
                bssid = pkt.sprintf("%Dot11.addr2%")
                no_broadcast = False
                if bssid not in self.access_points:
                    bssid = CherryAccessPoint(bssid)
                if essid != "":
                    no_broadcast = True
                    self.access_points.append(bssid)
                if no_broadcast is True and essid not in bssid.beaconed_essid:
                    bssid.beaconed_essid.append(essid)
                    print "[+] <{0}> is beaconing as {1}".format(colored(bssid, 'red'), colored(essid, 'green'))
                    # with open("essid_beacons.csv", "a") as b:
                    #     b.write("{0},{1}\n".format(bssid, essid))
        if self.scan_type == 1 or self.scan_type == 2:
            if pkt.haslayer(Dot11ProbeReq):
                essid = pkt.sprintf("{Dot11ProbeReq:%Dot11ProbeReq.info%}")
                bssid = pkt.sprintf("%Dot11.addr2%")
                no_broadcast = False
                if bssid not in self.clients:
                    bssid = CherryClient(bssid)
                if essid != "":
                    no_broadcast = True
                if no_broadcast is True and essid not in bssid.requested_essid:
                    bssid.add_new_essid(essid)
                    print "[+] Probe Request for {0} from <{1}>".format(colored(essid, 'green'), colored(bssid, 'red'))
                    # with open("essid_requests.csv", "a") as r:
                    #     r.write("{0},{1}\n".format(bssid, essid))


class CherryAccessPoint:
    """ Cherry Access Point:

        An object that represents an Access Point seen in the environment.

        1. Type defines it as an access point.
        2. BSSID is the MAC address of the access point.
        3. beaconed_essid is a list that holds all of the essids the MAC address has beaconed
        4. evil_access_point is False by default, but switches to True if it appear to beaconing too many ESSIDs
    """
    def __init__(self, bssid):
        self.type = "access_point"
        self.bssid = bssid
        self.beaconed_essid = []

    def add_new_essid(self, new_essid):
        self.beaconed_essid.append(new_essid)


class CherryClient:
    """ Cherry Client
        An object that reprenets a wireless client seen in that environment.

        1. Type defines it as a client.
        2. BSSID is the MAC address of the client seen.
        3. requested_essid is all of the ESSIDs that the client has requested.
    """
    def __init__(self, bssid):
        self.type = "client"
        self.bssid = bssid
        self.requested_essid = []

    def add_new_essid(self, new_essid):
        self.requested_essid.append(new_essid)


def main():
    parser = optparse.OptionParser('usage for print probe ' + '-m <scanning mode> ' + '-i <interface> ' + '-b <filter bssid> ')
    parser.add_option('-m', dest='mode', type='string', help='0=beacons, 1=probe requests, 2=both')
    parser.add_option('-i', dest='interface', type='string', help='specify interface to listen on')
    parser.add_option('-b', dest='bssid', type='string', help='specify target bssid to filter <optional>')
    (options, args) = parser.parse_args()

    if options.interface is None:
        print "[!] must define an interface with <-i>!"
        print parser.usage
        exit(0)
    else:  # TODO: check interface for monitor mode
        conf.iface = options.interface

    scan_type = options.mode
    cherry_wasp = CherryWasp(scan_type)

    if options.bssid is None:
        if options.mode is not None:
            sniff(prn=cherry_wasp.scan_packet())
        else:
            print "[!] invalid mode selected"
            exit(0)

    if options.bssid is not None:  # TODO: add BSSID input validation here
        if options.mode is "0":
            filter_bssid = str("ether src " + options.bssid)
            sniff(filter=filter_bssid, prn=cherry_wasp.scan_packet())
        else:
            print "[!] must use mode 0 when filtering by BSSID"
            exit(0)
    else:
        print "[!] must define a mode with <-m>!"
        print parser.usage
        exit(0)


if __name__ == "__main__":
    main()
