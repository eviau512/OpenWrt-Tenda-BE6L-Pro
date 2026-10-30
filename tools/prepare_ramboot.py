"""Validate a BE6L RAM-only FIT, then prepare the proven split-kexec payloads."""
import argparse
import hashlib
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import zlib

BASE = Path(__file__).resolve().parents[1]

def tree(blob):
    assert len(blob) >= 40 and blob[:4] == bytes.fromhex('d00dfeed'), 'Not an FDT/FIT'
    total, off, strings_off = struct.unpack_from('>III', blob, 4)
    assert 40 <= total <= len(blob)
    strings_len, struct_len = struct.unpack_from('>II', blob, 32)
    assert off + struct_len <= total and strings_off + strings_len <= total
    strings = blob[strings_off:strings_off + strings_len]
    nodes, stack = {}, []
    while off < total:
        token = struct.unpack_from('>I', blob, off)[0]
        off += 4
        if token == 1:
            end = blob.index(0, off)
            stack.append(blob[off:end].decode())
            off = (end + 4) & ~3
            nodes['/' + '/'.join(stack[1:])] = {}
        elif token == 2:
            assert stack
            stack.pop()
        elif token == 3:
            length, nameoff = struct.unpack_from('>II', blob, off)
            off += 8
            assert nameoff < len(strings) and off + length <= total
            name = strings[nameoff:strings.index(0, nameoff)].decode()
            nodes['/' + '/'.join(stack[1:])][name] = blob[off:off + length]
            off = (off + length + 3) & ~3
        elif token == 9:
            assert not stack
            return nodes
        else:
            assert token == 4, token
    raise ValueError('No FDT_END')

def text(value):
    return value.rstrip(b'\0').decode()

def image(nodes, name):
    path = '/images/' + name
    data = nodes[path]['data']
    count = 0
    for child, props in nodes.items():
        if child.startswith(path + '/hash'):
            algo = text(props['algo'])
            if algo == 'crc32':
                actual = struct.pack('>I', zlib.crc32(data))
            else:
                assert algo in ('sha1', 'sha256', 'sha384', 'sha512'), algo
                actual = hashlib.new(algo, data).digest()
            assert actual == props['value'], 'FIT hash mismatch: ' + child
            count += 1
    assert count, 'Missing image hash: ' + name
    return data, nodes[path]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fit', type=Path)
    parser.add_argument('--output-dir', type=Path,
                        help='New directory under artifacts; preserve the existing recovery payload')
    parser.add_argument('--require-watchdog-handoff', action='store_true')
    parser.add_argument('--omit-wan-phy-reset-gpio13', action='store_true')
    parser.add_argument('--diagnostic-option', action='append', default=[],
    choices=('initcall_debug', 'clk_ignore_unused', 'pd_ignore_unused', 'rdinit=/bin/sh',
             'trace_event=gpio:gpio_value,gpio:gpio_direction',
             'trace_options=stacktrace', 'trace_buf_size=256K'))
    args = parser.parse_args()
    source = args.fit.resolve()
    fit_bytes = source.read_bytes()
    # The old 32MiB input cap describes the recovery payload, not the NPU RAM
    # boundary. An independently output checked-WDT candidate may carry the
    # full package set; the actual decoded-kernel boundary remains unchanged.
    fit_limit = (64 if args.require_watchdog_handoff and args.output_dir else 32) * 1024 * 1024
    assert len(fit_bytes) <= fit_limit, 'Unexpectedly large FIT'
    nodes = tree(fit_bytes)
    config = text(nodes['/configurations']['default'])
    refs = nodes['/configurations/' + config]
    packed, props = image(nodes, text(refs['kernel']))
    dtb, _ = image(nodes, text(refs['fdt']))
    assert text(props['arch']) == 'arm'
    assert struct.unpack('>I', props['load'])[0] == 0x80088000
    assert struct.unpack('>I', props['entry'])[0] == 0x80088000
    max_kernel = 0x84000000 - 0x80088000
    compression = text(props['compression'])
    if compression == 'lzma':
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
        kernel = decoder.decompress(packed, max_length=max_kernel)
        assert decoder.eof and not decoder.unused_data, 'Image exceeds safe RAM range'
    else:
        assert compression == 'none', compression
        kernel = packed
    assert 0x178000 < len(kernel) < max_kernel, 'Image overlaps NPU reserved memory'
    assert b'airoha,bmt-read-only\0' in kernel, 'Kernel does not contain the matching BMT guard'
    assert b'mtk-bmt: physical writes disabled for RAM-only bring-up' in kernel
    if args.require_watchdog_handoff:
        for marker in (b'BE6L_WDT_KEXEC_STOPPED enable_readback=0',
                       b'BE6L_WDT_KEXEC_STOP_FAILED', b'BE6L_WDT_KEXEC_REFUSED nowayout=1'):
            assert marker in kernel, 'Compiled watchdog handoff marker missing'
    board = tree(dtb)
    assert b'tenda,be6l-pro' in board['/']['compatible'].split(b'\0')
    nand = '/soc/spi@1fa10000/nand@0'
    assert 'airoha,bmt-read-only' in board[nand] and 'airoha,bmt' in board[nand]
    partitions = [props for path, props in board.items()
                  if path.startswith(nand + '/partitions/partition@') and '/nvmem-layout' not in path]
    assert len(partitions) == 10 and all('read-only' in p for p in partitions)
    assert not any(p.get('label', b'').rstrip(b'\0') in (b'ubi', b'firmware') for p in partitions)
    assert board['/reserved-memory/npu-firmware@84000000']['reg'] == struct.pack('>II', 0x84000000, 0x400000)
    assert board['/reserved-memory/npu-pkt@84400000']['reg'] == struct.pack('>II', 0x84400000, 0x1600000)

    out = args.output_dir.resolve() if args.output_dir else BASE / 'artifacts/ramboot'
    if args.output_dir:
        assert out.is_relative_to((BASE / 'artifacts').resolve())
        assert out != (BASE / 'artifacts').resolve() and not out.exists()
    out.mkdir(parents=True, exist_ok=not bool(args.output_dir))
    (out / 'openwrt-kernel').write_bytes(kernel)
    (out / 'openwrt.dtb').write_bytes(dtb)
    loader_args = [sys.executable, str(BASE / 'tools/build_split_loader.py'),
                   '--payload-dir', str(out)]
    for option in args.diagnostic_option:
        loader_args += ['--diagnostic-option', option]
    if args.omit_wan_phy_reset_gpio13:
        loader_args.append('--omit-wan-phy-reset-gpio13')
    subprocess.run(loader_args, check=True)
    ram_nodes = tree((out / 'openwrt-ramonly.dtb').read_bytes())
    original_nodes = tree(dtb)
    assert set(ram_nodes) == set(original_nodes)
    for node, properties in original_nodes.items():
        for name, value in properties.items():
            if node == '/chosen' and name in ('bootargs', 'bootargs-override'):
                continue
            if args.omit_wan_phy_reset_gpio13 and node.endswith('/ethernet-phy@f') and name in ('reset-gpios', 'reset-assert-us', 'reset-deassert-us'):
                assert name not in ram_nodes[node]
                continue
            assert ram_nodes[node][name] == value, (node, name)
    assert sum('read-only' in properties for properties in ram_nodes.values()) == 10
    assert any('airoha,bmt-read-only' in properties for properties in ram_nodes.values())

    old = BASE.parent / 'tools/ramboot'
    lock = json.loads((old / 'manifest.json').read_text(encoding='utf-8'))
    for item, name in zip(lock['files'][:3], ['kexec', 'libz.so.1', 'ld-musl-arm.so.1']):
        data = (old / item['local']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item['sha256']
        (out / name).write_bytes(data)
    names = ['kexec', 'libz.so.1', 'ld-musl-arm.so.1', 'openwrt-kernel',
             'kexec-split-loader', 'openwrt-ramonly.dtb']
    manifest = {
        'board': 'tenda,be6l-pro', 'rootfs': 'initramfs',
        'source_commit': json.loads((BASE / 'source-lock.json').read_text())['commit'],
        'fit': source.name, 'fit_sha256': hashlib.sha256(fit_bytes).hexdigest(),
        'wireless_disabled': False, 'flash': 'read-only', 'files': [],
        'diagnostic_options': args.diagnostic_option,
        'diagnostic_no_wan_phy_reset': args.omit_wan_phy_reset_gpio13,
        'compiled_watchdog_handoff_markers': args.require_watchdog_handoff,
        'watchdog_handoff_runtime_qualified': False,
        'fit_file_limit_bytes': fit_limit,
        'kernel_bytes': len(kernel),
        'kernel_load_address': '0x80088000',
        'kernel_reserved_boundary': '0x84000000',
    }
    for name in names:
        data = (out / name).read_bytes()
        manifest['files'].append({'name': name, 'size': len(data),
                                  'sha256': hashlib.sha256(data).hexdigest(),
                                  'md5': hashlib.md5(data).hexdigest()})
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Validated FIT and prepared', len(names), 'RAM payloads in', out)

if __name__ == '__main__':
    main()
