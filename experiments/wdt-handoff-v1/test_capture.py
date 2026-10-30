# SPDX-License-Identifier: MIT
"""Evidence rejection tests, no hardware or network access."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools/arm64'))
from watchdog_capture_admission_v1 import check_capture, STOPPED


class Capture(unittest.TestCase):
    def test_positive_order(self):
        self.assertTrue(check_capture(('[47.0] airoha-wdt: '+STOPPED+'\r\n[0.0] Booting Linux on physical CPU 0\r\n').encode())['marker_precedes_new_kernel'])

    def test_missing_late_duplicate_or_failure(self):
        boot='[0.0] Booting Linux on physical CPU 0\n'
        for text in (boot, STOPPED, boot+STOPPED, STOPPED+'\n'+STOPPED+'\n'+boot,
                     'BE6L_WDT_KEXEC_STOP_FAILED\n'+STOPPED+'\n'+boot,
                     'BE6L_WDT_KEXEC_REFUSED nowayout=1\n'+STOPPED+'\n'+boot,
                     STOPPED+'\n'+boot+'U-Boot 2014.04', STOPPED+'\n'+boot+'Linux version 5.4'):
            with self.assertRaises(AssertionError):check_capture(text.encode())


if __name__=='__main__':unittest.main()
