from termcolor import colored
from logger import CherryLogger


class CherryClient:
    """An object that represents a wireless client seen in that environment.

    Inputs: bssid(str) the MAC address of the wireless client.

    Returns: prints results to console and .csv file.
    """
    def __init__(self, bssid):
        self.type = "client"
        self.bssid = bssid
        self.requested_essid = set()
        self.log = CherryLogger("test1")

    def add_new_requested_essid(self, new_essid):
        if new_essid not in self.requested_essid:
            self.requested_essid.add(new_essid)
            self.log.write_to_file("probe_request", self.bssid, new_essid)
            print("[+] Probe Request for {0} from <{1}>".format(colored(new_essid, 'green'),
                                                                colored(self.bssid, 'red')))
