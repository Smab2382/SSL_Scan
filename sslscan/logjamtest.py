import unittest

from sslscan import status
from sslscan import logjam
from unittest import TestCase, main


class TestLogjam(unittest.TestCase):
    def test_stVuln1(self):
        self.val=logjam.funlogjam('insidesecure.com')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stVuln2(self):
        self.val=logjam.funlogjam('jquery.page2page.ru')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stOk1(self):
        self.val=logjam.funlogjam('google.com')
        self.assertEqual(self.val, status.Status.stOk)

    def test_stOk2(self):
        self.val=logjam.funlogjam('yandex.ru')
        self.assertEqual(self.val, status.Status.stOk)

suite = unittest.TestLoader().loadTestsFromTestCase(TestLogjam)
unittest.TextTestRunner(verbosity=2).run(suite)