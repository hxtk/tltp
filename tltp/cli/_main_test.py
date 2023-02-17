"""Unit tests for the main CLI."""
import io
import unittest

from tltp.cli import _main


class TestGetArgs(unittest.TestCase):

    def test_windows_flag_file(self):
        flags = io.StringIO('-L 20\r\n--noshow\r\n-x\r\n')
        args = _main.get_arguments(['foo'], flags)
        self.assertEqual(args.show, False)
        self.assertEqual(args.size, 20)


if __name__ == '__main__':
    unittest.main()
