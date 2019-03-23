from unittest import TestCase
import cherrywasp.accesspoint


class TestCherryAccessPoint(TestCase):
    def test_add_new_beaconed_essid(self):
        expected = "Don't Mess With My Wi-Fi"
        some_access_point = cherrywasp.accesspoint.CherryAccessPoint("DE:AD:BE:EF:12:34", "test")
        actual = some_access_point.add_new_beaconed_essid("Don't Mess With My Wi-Fi")
        self.assertIn(expected, actual, msg="SSIDs don't match.")
        # self.fail()
