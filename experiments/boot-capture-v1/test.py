"""CPU-only fixtures; no serial library, device, subprocess or network access."""
from pathlib import Path
import importlib.util
import json
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('boot_capture_v1', BASE / 'tools/arm64/boot_capture_v1.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Clock:
    def __init__(self): self.ns = 0
    def now(self): return self.ns
    def sleep(self, seconds): self.ns += int(seconds * 1e9)


class UART:
    def __init__(self, chunks, fail=False):
        self.chunks, self.sent, self.fail = list(chunks), [], fail
    def read_all(self): return self.chunks.pop(0) if self.chunks else b''
    def write(self, data):
        self.sent.append(data)
        if self.fail: raise OSError('fixture write failure')
        return len(data)


class Fixtures(unittest.TestCase):
    def run_capture(self, chunks, fail=False):
        clock, uart = Clock(), UART(chunks, fail)
        with tempfile.TemporaryDirectory() as directory:
            raw, events = Path(directory) / 'raw', Path(directory) / 'events'
            kwargs = dict(seconds=.3, confirmation_seconds=.12,
                          monotonic_ns=clock.now, utc_ns=clock.now, sleep=clock.sleep)
            if fail:
                with self.assertRaises(OSError) as caught:
                    m.capture_boot(uart, raw, events, **kwargs)
                result = caught.exception.capture_result
            else:
                result = m.capture_boot(uart, raw, events, **kwargs)
            rows = [json.loads(line) for line in events.read_text().splitlines()]
            return result, uart.sent, raw.read_bytes(), rows

    def test_autoboot_every_split(self):
        for split in range(1, len(m.AUTOBOOT)):
            with self.subTest(split=split):
                result, sent, raw, rows = self.run_capture([m.AUTOBOOT[:split], m.AUTOBOOT[split:], b'\r\nEC', b'NT> '])
                self.assertEqual(sent, [b'\x03', b'\x03\r'])
                self.assertTrue(result['autoboot_interception_confirmed'])
                self.assertTrue(result['bootloader_prompt_confirmed'])
                chunks = [row for row in rows if row['event'] == 'rx_chunk']
                self.assertEqual([row['offset'] for row in chunks], [0, split, len(m.AUTOBOOT), len(m.AUTOBOOT) + 4])
                self.assertEqual(raw, m.AUTOBOOT + b'\r\nECNT> ')

    def test_ecnt_every_split(self):
        for split in range(1, len(m.ECNT)):
            with self.subTest(split=split):
                result, sent, _, _ = self.run_capture([m.AUTOBOOT, m.ECNT[:split], m.ECNT[split:]])
                self.assertTrue(result['bootloader_prompt_confirmed'])
                self.assertEqual(len(sent), 2)

    def test_attempt_without_prompt_is_not_confirmation(self):
        result, sent, _, _ = self.run_capture([m.AUTOBOOT])
        self.assertTrue(result['interrupt_attempted'])
        self.assertTrue(result['interrupt_write_completed'])
        self.assertFalse(result['bootloader_prompt_confirmed'])
        self.assertFalse(result['autoboot_interception_confirmed'])
        self.assertEqual(result['end_reason'], 'interrupt_confirmation_deadline')

    def test_same_chunk_preinterrupt_prompt_not_confirmation(self):
        result, _, _, _ = self.run_capture([m.AUTOBOOT + b'\r\n' + m.ECNT])
        self.assertFalse(result['bootloader_prompt_confirmed'])

    def test_partial_prompt_from_before_interrupt_not_confirmation(self):
        result, _, _, _ = self.run_capture([m.AUTOBOOT + b'\r\n' + m.ECNT[:3], m.ECNT[3:]])
        self.assertFalse(result['bootloader_prompt_confirmed'])

    def test_timeout_without_reset_does_not_qualify_boot(self):
        result, sent, _, _ = self.run_capture([b'Linux version 6.18.55\n'])
        self.assertFalse(sent)
        self.assertFalse(result['capture_timeout_is_containment_proof'])
        self.assertFalse(result['boot_success_qualified'])
        self.assertEqual(result['end_reason'], 'capture_deadline')

    def test_reset_banner_without_autoboot_never_sends(self):
        result, sent, _, _ = self.run_capture([b'U-Boot 2014.', b'04-rc1\n'])
        self.assertTrue(result['reset_banner_observed'])
        self.assertFalse(sent)
        self.assertFalse(result['autoboot_interception_confirmed'])

    def test_stock_boot_never_claims_containment(self):
        result, _, _, _ = self.run_capture([m.AUTOBOOT, b'Linux version 5.', b'4.0\nECNT> '])
        self.assertTrue(result['stock_kernel_observed'])
        self.assertTrue(result['bootloader_prompt_confirmed'])
        self.assertFalse(result['autoboot_interception_confirmed'])
        self.assertFalse(result['flash_unchanged_qualified'])

    def test_serial_write_failure_evidence(self):
        result, sent, _, rows = self.run_capture([m.AUTOBOOT], fail=True)
        self.assertTrue(result['interrupt_attempted'])
        self.assertFalse(result['interrupt_write_completed'])
        self.assertFalse(result['bootloader_prompt_confirmed'])
        self.assertEqual(result['capture_error_type'], 'OSError')
        self.assertEqual(rows[-1]['event'], 'capture_end')
        self.assertEqual(sent, [b'\x03'])

    def test_repeated_autoboot_does_not_repeat_transmissions(self):
        result, sent, _, _ = self.run_capture([m.AUTOBOOT, b'\n' + m.AUTOBOOT, b'\nECNT> '])
        self.assertEqual(sent, [b'\x03', b'\x03\r'])
        self.assertTrue(result['bootloader_prompt_confirmed'])


if __name__ == '__main__': unittest.main(verbosity=2)
