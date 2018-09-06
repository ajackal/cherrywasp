from unittest import TestCase
from cherrywasp import logger
from datetime import datetime


class TestCherryLogger(TestCase):

    def test_file_setup(self):
        now = datetime.now()
        file_prefix = str(now.year) + str(now.month) + str(now.day)
        log = logger.CherryLogger()
        expected = log.file_setup(file_prefix)
        self.assertTrue(expected, msg="Log file setup failed.")
        # self.fail()

    def test_write_headers(self):
        now = datetime.now()
        file_prefix = str(now.year) + str(now.month) + str(now.day)
        log = logger.CherryLogger()
        log.file_name_prefix = file_prefix
        expected = log.write_headers()
        self.assertTrue(expected, msg="Log file write headers failed.")
        # self.fail()

    def test_write_to_file(self):
        bssid = "de:ad:be:ef:01:23"
        essid = "FBI_van_1"
        now = datetime.now()
        file_prefix = str(now.year) + str(now.month) + str(now.day)
        log = logger.CherryLogger()
        log.file_name_prefix = file_prefix
        expected = log.write_to_file("probe_request", bssid, essid)
        self.assertTrue(expected, msg="Log file write new entry failed.")
        # self.fail()
