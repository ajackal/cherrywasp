from termcolor import colored
from logger import CherryLogger


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
        self.beaconed_essid = set()
        self.log = CherryLogger("test1")

    def add_new_beaconded_essid(self, new_essid):
        if new_essid not in self.beaconed_essid:
            self.beaconed_essid.add(new_essid)
            self.log.write_to_file("beacon", self.bssid, new_essid)
            print("[+] <{0}> is beaconing as {1}".format(colored(self.bssid, 'red'),
                                                         colored(new_essid, 'green')))