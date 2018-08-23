from termcolor import colored
from logger import CherryLogger


class CherryAccessPoint:
    """ An object that represents an Access Point seen in the environment.

    Inputs:

    - bssid(str) the MAC address of the device sending beacon frames
    - file_prefix(str) the file prefix to use when creating the .csv file.

    Returns: prints to console and .csv file.

    add_new_essid adds a new ESSID or network name to the list for the particular client.
    """
    def __init__(self, bssid, file_prefix):
        self.type = "access_point"
        self.bssid = bssid
        self.beaconed_essid = set()
        self.log = CherryLogger(file_prefix)

    def add_new_beaconed_essid(self, new_essid):
        if new_essid not in self.beaconed_essid:
            self.beaconed_essid.add(new_essid)
            self.log.write_to_file("beacon", self.bssid, new_essid)
            print("[+] <{0}> is beaconing as {1}".format(colored(self.bssid, 'red'),
                                                         colored(new_essid, 'green')))
