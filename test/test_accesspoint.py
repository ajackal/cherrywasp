import pytest
from corescanner import CherryWasp

pkt_ap = "80000000DEADBEEF0123000011112222000000000000000000000000000000006400000000074D795F53534944"


def test_recover_ssid(pkt_ap):
    scan_type = 0
    test = CherryWasp(scan_type)
    try:
        test.scan_packet(pkt_ap)
    except AssertionError:
        print("failed assertion")
