import unittest

from sslscan import status
from sslscan import heartbleed
from unittest import TestCase, main


class TestHeartbleed(unittest.TestCase):
    def test_stVuln1(self):
        self.val=heartbleed.check('fitnessland.spb.ru')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stVuln2(self):
        self.val=heartbleed.check('jquery.page2page.ru')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stOk1(self):
        self.val=heartbleed.check('google.com')
        self.assertEqual(self.val, status.Status.stOk)

    def test_stOk2(self):
        self.val=heartbleed.check('vk.com')
        self.assertEqual(self.val, status.Status.stOk)

suite = unittest.TestLoader().loadTestsFromTestCase(TestHeartbleed)
unittest.TextTestRunner(verbosity=2).run(suite)