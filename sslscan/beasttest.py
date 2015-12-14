import unittest

from sslscan import status
from sslscan import beast
from unittest import TestCase, main


class TestBeast(unittest.TestCase):
    def test_stVuln1(self):
        self.val=beast.funbest('yandex.ru')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stVuln2(self):
        self.val=beast.funbest('google.ru')
        self.assertEqual(self.val, status.Status.stVuln)

    def test_stOk1(self):
        self.val=beast.funbest('github.com')
        self.assertEqual(self.val, status.Status.stOk)

    def test_stOk2(self):
        self.val=beast.funbest('ruranobe.ru')
        self.assertEqual(self.val, status.Status.stOk)

suite = unittest.TestLoader().loadTestsFromTestCase(TestBeast)
unittest.TextTestRunner(verbosity=2).run(suite)