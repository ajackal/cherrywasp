from termcolor import colored
from cherrywasp import logger


class CherryClient:
    """An object that represents a wireless client seen in that environment.

    Inputs:

    - bssid(str) the MAC address of the wireless client.
    - file_prefix(str) the file prefix to use when creating the .csv file.

    Returns: prints results to console and .csv file.
    """
    def __init__(self, bssid, file_prefix):
        self.type = "client"
        self.bssid = bssid
        self.requested_essid = set()
        self.log = logger.CherryLogger(file_prefix)

    def add_new_requested_essid(self, new_essid):
        if new_essid not in self.requested_essid:
            self.requested_essid.add(new_essid)
            self.log.write_to_file("probe_request", self.bssid, new_essid)
            print("[+] Probe Request for {0} from <{1}>".format(colored(new_essid, 'green'),
                                                                colored(self.bssid, 'red')))
