from unittest import TestCase
import cherrywasp.logger
from datetime import datetime
import os


class TestCherryLogger(TestCase):

    def test_file_setup(self):
        now = datetime.now()
        file_prefix = str(now.year) + str(now.month) + str(now.day)
        filename = file_prefix + "_beacon.csv"
        log = cherrywasp.logger.CherryLogger()
        log.file_setup(file_prefix)
        if os.path.isdir(os.path.join(os.getcwd(), "logs")) and os.path.isfile(os.path.join(os.getcwd(), "logs", filename)):
            expected = True
        else:
            expected = False
        self.assertTrue(expected, msg="Log file setup failed.")
        # self.fail()

    # def test_write_headers(self):
    #     now = datetime.now()
    #     file_prefix = str(now.year) + str(now.month) + str(now.day)
    #     log = logger.CherryLogger()
    #     log.file_name_prefix = file_prefix
    #     expected = log.write_headers()
    #     self.assertTrue(expected, msg="Log file write headers failed.")
        # self.fail()

    def test_write_to_file(self):
        now = datetime.now()
        file_prefix = str(now.year) + str(now.month) + str(now.day)
        filename = file_prefix + "_beacon.csv"
        log_file = os.path.join(os.getcwd(), "logs", filename)
        bssid = "de:ad:be:ef:01:23"
        essid = "FBI_van_1"
        now = datetime.now()
        file_prefix = str(now.year) + str(now.month) + str(now.day)
        log = cherrywasp.logger.CherryLogger()
        log.file_name_prefix = file_prefix
        log.write_to_file("beacon", bssid, essid)
        with open(log_file) as open_file:
            if essid in open_file.read():
                expected = True
            else:
                expected = False
        self.assertTrue(expected, msg="Log file write new entry failed.")
        # self.fail()
