# SPDX-License-Identifier: MIT
"""Read exact ARM64 module metadata and compile a value-only ABI probe.

The probe reuses a cached kernel GCC command with private output paths. It
does not invoke make, load a module, or modify kernel sources/configuration.
"""
from pathlib import Path
import hashlib
import json
import shlex
import struct
import subprocess


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sections(path):
    data = Path(path).read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01', 'Require ELF64 little endian'
    assert struct.unpack_from('<HH', data, 16) == (1, 183), 'Require ARM64 relocatable object'
    offset, = struct.unpack_from('<Q', data, 40)
    stride, count, names = struct.unpack_from('<HHH', data, 58)
    assert stride == 64 and 0 < names < count and offset + stride * count <= len(data)
    rows = [struct.unpack_from('<IIQQQQIIQQ', data, offset + stride * i) for i in range(count)]
    row = rows[names]
    strings = data[row[4]:row[4] + row[5]]
    assert len(strings) == row[5]
    result = {}
    for row in rows:
        assert row[0] < len(strings)
        end = strings.index(0, row[0])
        name = strings[row[0]:end].decode('ascii')
        assert name not in result
        if row[1] == 8:  # SHT_NOBITS occupies memory, not file bytes.
            content = None
        else:
            assert row[4] + row[5] <= len(data)
            content = data[row[4]:row[4] + row[5]]
        result[name] = dict(size=row[5], data=content)
    return result


def module_record(path, expected):
    table = sections(path)
    info = table['.modinfo']['data'].split(b'\0')
    magic = [x[len(b'vermagic='):] for x in info if x.startswith(b'vermagic=')]
    assert len(magic) == 1, 'Require one module vermagic'
    actual = magic[0].decode('ascii')
    assert actual == expected['vermagic'], 'Module vermagic mismatch: ' + str(path)
    assert table['.gnu.linkonce.this_module']['size'] == expected['module_struct_bytes'], 'Module struct layout mismatch'
    return dict(sha256=digest(path), vermagic=actual,
                module_struct_bytes=table['.gnu.linkonce.this_module']['size'],
                elf_class=2, elf_machine=183)


def probe(kernel, output):
    kernel, output = Path(kernel).resolve(), Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    command_file = kernel / 'net/core/.flow_offload.o.cmd'
    line = command_file.read_text().splitlines()[0]
    assert line.startswith('savedcmd_net/core/flow_offload.o := ')
    args = shlex.split(line.split(' := ', 1)[1])
    assert all(x not in args for x in (';', '&&', '||', '|'))
    wrapper = None
    if args[0] == 'ccache':
        wrapper = args.pop(0)
    assert Path(args[0]).name == 'aarch64-openwrt-linux-musl-gcc'
    compiler, = kernel.parents[3].glob('staging_dir/toolchain-aarch64_*/bin/aarch64-openwrt-linux-musl-gcc')
    compiler = compiler.resolve()
    if Path(args[0]).is_absolute():
        assert Path(args[0]).resolve() == compiler
    args[0] = str(compiler)
    assert compiler.is_file()
    assert '-c' in args and args.count('-o') == 1 and args[-1] == 'net/core/flow_offload.c'
    before = {name: digest(kernel / name) for name in ('.config', 'include/net/flow_offload.h', 'Module.symvers')}
    source, obj = output / 'flow-abi.c', output / 'flow-abi.o'
    source.write_text('''// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <net/flow_offload.h>
#define INCLUDE_VERMAGIC
#include <linux/vermagic.h>
static const u32 be6l_flow_layout[] __used __section(".be6l_flow_abi") = {
  0x42464131, 1, sizeof(struct module), sizeof(struct flow_rule),
  offsetof(struct flow_rule, action), sizeof(struct flow_rule_ct_context),
  offsetof(struct flow_rule, ct_context), FLOW_RULE_CT_CONTEXT_VERSION,
  sizeof(struct flow_action_entry)
};
static const char be6l_magic[] __used __section(".be6l_vermagic") = VERMAGIC_STRING;
''')
    args = [('-Wp,-MMD,' + str(output / '.flow-abi.o.d')) if x.startswith('-Wp,-MMD,') else x for x in args]
    args[args.index('-o') + 1] = str(obj)
    args[-1] = str(source)
    if '-DMODULE' not in args:
        args.insert(1, '-DMODULE')
    result = subprocess.run(args, cwd=kernel, capture_output=True)
    (output / 'compile.log').write_bytes(result.stdout + result.stderr)
    assert result.returncode == 0, 'Value-only ABI probe compile failed; see compile.log'
    table = sections(obj)
    values = struct.unpack('<9I', table['.be6l_flow_abi']['data'])
    assert values[:2] == (0x42464131, 1)
    magic = table['.be6l_vermagic']['data']
    assert magic.endswith(b'\0') and b'\0' not in magic[:-1]
    after = {name: digest(kernel / name) for name in before}
    assert before == after, 'Kernel source/config changed during the isolated probe'
    report = dict(schema=1, module_struct_bytes=values[2], flow_rule_bytes=values[3],
                  flow_rule_action_offset=values[4], ct_context_bytes=values[5],
                  ct_context_offset=values[6], ct_context_version=values[7],
                  flow_action_entry_bytes=values[8], vermagic=magic[:-1].decode('ascii'),
                  kernel_inputs=before, compiler_sha256=digest(compiler),
                  cached_command_sha256=digest(command_file), probe_object_sha256=digest(obj),
                  cached_command_wrapper=wrapper,
                  isolated_compile=True, kernel_inputs_unchanged=True, loaded_on_hardware=False)
    assert report['ct_context_version'] == 1 and report['ct_context_bytes'] == 16
    assert report['ct_context_offset'] < report['flow_rule_action_offset'] < report['flow_rule_bytes']
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report
