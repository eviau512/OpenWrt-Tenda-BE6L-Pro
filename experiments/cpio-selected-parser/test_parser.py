# SPDX-License-Identifier: MIT
"""Independent synthetic newc cases; no extraction, network, build or device.

The hardlink and negative-size cases intentionally fail against a parser that
accepts ambiguous effective contents or non-hex unsigned header fields.
"""
from pathlib import Path
import json
import stat
import sys
import unittest

BASE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BASE / 'tools'))
from cpio_selected_files import selected_files


def entry(name, payload=b'', mode=stat.S_IFREG | 0o755, *, inode=1,
          links=1, crc=False, field_override=None):
    """Construct wire-format newc independently, retaining exact supplied data."""
    name = name.encode() + b'\0'
    fields = [inode, mode, 0, 0, links, 0, len(payload), 0, 0, 0, 0,
              len(name), sum(payload) & 0xffffffff if crc else 0]
    encoded = [f'{x:08x}'.encode() for x in fields]
    for index, value in (field_override or {}).items():
        assert len(value) == 8
        encoded[index] = value
    head = (b'070702' if crc else b'070701') + b''.join(encoded) + name
    head += b'\0' * (-len(head) % 4)
    return head + payload + b'\0' * (-len(payload) % 4)


def trailer():
    return entry('TRAILER!!!', mode=0, inode=0)


class ParserTests(unittest.TestCase):
    def reject(self, data, selected=('sbin/procd',)):
        with self.assertRaises((AssertionError, ValueError, UnicodeError)):
            selected_files(data, set(selected))

    def test_selected_bytes_mode_and_symlink(self):
        data = (entry('sbin/procd', b'ELF-fixture') +
                entry('sbin/init', b'procd', stat.S_IFLNK | 0o777, inode=2) +
                trailer())
        actual = selected_files(data, {'sbin/procd', 'sbin/init'})
        self.assertEqual(actual['sbin/procd'],
                         {'mode': stat.S_IFREG | 0o755, 'data': b'ELF-fixture'})
        self.assertEqual(actual['sbin/init'],
                         {'mode': stat.S_IFLNK | 0o777, 'data': b'procd'})

    def test_concatenated_crc_archives_and_padding(self):
        first = entry('./sbin/procd', b'one', crc=True) + trailer()
        second = entry('lib/loader', b'two', crc=True) + trailer()
        actual = selected_files(first + bytes(512) + second + bytes(8),
                                {'sbin/procd', 'lib/loader'})
        self.assertEqual(actual['lib/loader']['data'], b'two')

    def test_empty_regular_one_link_is_valid(self):
        self.assertEqual(selected_files(entry('empty', b'') + trailer(), {'empty'})
                         ['empty']['data'], b'')

    def test_every_truncation_of_one_complete_archive_rejected(self):
        archive = entry('sbin/procd', b'four') + trailer()
        for length in range(len(archive)):
            with self.subTest(length=length):
                self.reject(archive[:length])

    def test_partial_payload_with_advertised_size_rejected(self):
        self.reject(entry('sbin/procd', b'abc', field_override={6: b'00000008'}))

    def test_duplicate_aliases_rejected(self):
        for alias in ('./sbin/procd', 'sbin//procd', '/sbin/procd',
                      '././sbin/./procd'):
            with self.subTest(alias=alias):
                self.reject(entry('sbin/procd', b'a') + entry(alias, b'a') + trailer())

    def test_duplicate_across_archives_rejected(self):
        self.reject(entry('sbin/procd', b'a') + trailer() +
                    entry('./sbin/procd', b'a') + trailer())

    def test_traversal_even_in_unselected_path_rejected(self):
        for name in ('sbin/../procd', '../outside', 'safe/../../outside'):
            with self.subTest(name=name):
                self.reject(entry(name, b'x') + entry('sbin/procd', b'a') + trailer())

    def test_crc_wrong_on_selected_or_unselected_rejected(self):
        bad_selected = entry('sbin/procd', b'abc', crc=True,
                             field_override={12: b'00000000'})
        bad_other = entry('unselected', b'abc', crc=True,
                          field_override={12: b'00000000'})
        self.reject(bad_selected + trailer())
        self.reject(bad_other + entry('sbin/procd', b'ok') + trailer())

    def test_missing_required_selected_file_rejected(self):
        self.reject(entry('other', b'a') + trailer())

    def test_missing_final_trailer_rejected(self):
        self.reject(entry('sbin/procd', b'a'))

    def test_unexpected_selected_type_rejected(self):
        self.reject(entry('sbin/procd', mode=stat.S_IFDIR | 0o755) + trailer())

    def test_empty_hardlink_placeholder_rejected(self):
        self.reject(entry('sbin/procd', b'', links=2) + trailer())

    def test_nonempty_selected_hardlink_later_alias_rejected(self):
        # A newc extractor can link the second pathname to the first inode.
        # The second payload then changes effective bytes under the first name.
        data = (entry('sbin/procd', b'GOOD', inode=77, links=2) +
                entry('unselected-alias', b'EVIL', inode=77, links=2) + trailer())
        self.reject(data)

    def test_negative_size_is_not_unsigned_newc_hex(self):
        # -1 aligns to the next header just like a zero-size payload here.
        # Do not allow Python int(base16) permissiveness to admit this syntax.
        self.reject(entry('empty', b'', field_override={6: b'-0000001'}) + trailer(),
                    selected=('empty',))

    def test_nonhex_field_syntax_rejected(self):
        self.reject(entry('sbin/procd', b'abc', field_override={6: b'0000000z'}) + trailer())

    def test_header_name_missing_nul_rejected(self):
        data = bytearray(entry('sbin/procd', b'a') + trailer())
        data[110 + len('sbin/procd')] = ord('x')
        self.reject(bytes(data))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ParserTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = dict(tests_run=result.testsRun,
                   failures=[str(case) for case, _ in result.failures],
                   errors=[str(case) for case, _ in result.errors],
                   passed=result.wasSuccessful(), pure_cpu=True,
                   archive_extraction=False, hardware_access=False,
                   candidate_artifacts_modified=False)
    Path(__file__).with_name('result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    sys.exit(not result.wasSuccessful())
