from unittest import TestCase
from cherrywasp import accesspoint


class TestCherryAccessPoint(TestCase):
    def test_add_new_beaconed_essid(self):
        expected_essid = "Don't Mess With My Wi-Fi"
        expeced_bssid = "DE:AD:BE:EF:12:34"
        some_access_point = accesspoint.CherryAccessPoint("DE:AD:BE:EF:12:34", "test")
        actual = some_access_point.add_new_beaconed_essid("Don't Mess With My Wi-Fi")
        self.assertIn(expected_essid, actual, msg="ESSIDs don't match.")
        self.assertIn(expeced_bssid, actual, msg="BSSIDs don't match.")
