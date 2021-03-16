from unittest import TestCase
from cherrywasp.corescanner import CoreScanner
from scapy.all import *


class TestCherryWasp(TestCase):

    # def test_create_mon_interface(self):
    #     self.fail()
    #
    # def test_channel_hop(self):
    #     self.fail()

    def test_scan_packet_beacon_fail(self):
        scan_type = "0"
        expected = 'My_SSID'
        pkt_ap = Dot11(addr1="de:ad:be:ef:01:23", addr2="00:00:11:11:22:22") / Dot11Beacon() / Dot11Elt(ID=0, info="My_SSID")
        cherry_wasp = CoreScanner(scan_type)
        actual = cherry_wasp.scan_packet(pkt_ap)
        self.assertIn(expected, actual, msg="Failed SSID match.")


    def test_scan_packet_beacon_fail(self):
        scan_type = "0"
        expected = 'My_SSID'
        pkt_ap = Dot11(addr1="de:ad:be:ef:01:23", addr2="00:00:11:11:22:22") / Dot11Beacon() / Dot11Elt(ID=0, info="My_SSID")
        cherry_wasp = CoreScanner(scan_type)
        actual = cherry_wasp.scan_packet(pkt_ap)
        self.assertIn(expected, actual, msg="Failed SSID match.")

    def test_scan_packet_probe_req(self):
        scan_type = "1"
        expected = 'My_SSID'
        pkt_pr = Dot11(addr1="de:ad:be:ef:01:23", addr2="00:00:11:11:22:22") / Dot11ProbeReq() / Dot11Elt(ID=0, info="My_SSID")
        cherry_wasp = CoreScanner(scan_type)
        actual = cherry_wasp.scan_packet(pkt_pr)
        self.assertIn(expected, actual, msg="Failed SSID match.")


if __name__ == "__main__":
    TestCherryWasp()
