import unittest

from sslscan import status
from sslscan import poodle
from unittest import TestCase, main


class TestPoodle(unittest.TestCase):
    def test_stVuln1(self):
        self.val=poodle.poodlefun('yandex.ru')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stVuln2(self):
        self.val=poodle.poodlefun('google.com')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stOk1(self):
        self.val=poodle.poodlefun('www.vmware.com')
        self.assertEqual(self.val, status.Status.stOk)

    def test_stOk2(self):
        self.val=poodle.poodlefun('www.va.gov')
        self.assertEqual(self.val, status.Status.stOk)

suite = unittest.TestLoader().loadTestsFromTestCase(TestPoodle)
unittest.TextTestRunner(verbosity=2).run(suite)