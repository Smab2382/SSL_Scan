import unittest

from sslscan import status
from sslscan import freak
from unittest import TestCase, main


class TestFreak(unittest.TestCase):
    def test_stVuln1(self):
        self.val=freak.check('insidesecure.com')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stVuln2(self):
        self.val=freak.check('edit.aag.standardchartered.com')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stOk1(self):
        self.val=freak.check('google.com')
        self.assertEqual(self.val, status.Status.stOk)

    def test_stOk2(self):
        self.val=freak.check('yandex.ru')
        self.assertEqual(self.val, status.Status.stOk)

suite = unittest.TestLoader().loadTestsFromTestCase(TestFreak)
unittest.TextTestRunner(verbosity=2).run(suite)