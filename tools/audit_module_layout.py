"""Reject stale external modules using a fresh current-kernel layout probe."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import struct
import subprocess
import tempfile

def elf_sections(path):
    data=Path(path).read_bytes()
    assert data[:4]==b'\x7fELF' and data[5]==1, 'Expected little-endian ELF: '+str(path)
    cls=data[4];machine=struct.unpack_from('<H',data,18)[0]
    assert cls in (1,2) and struct.unpack_from('<H',data,16)[0]==1
    off=struct.unpack_from('<I' if cls==1 else '<Q',data,32 if cls==1 else 40)[0]
    stride,count,names=struct.unpack_from('<HHH',data,46 if cls==1 else 58)
    assert count and names<count and off+stride*count<=len(data)
    def row(index):
        start=off+index*stride
        name=struct.unpack_from('<I',data,start)[0]
        pos,size=struct.unpack_from('<II' if cls==1 else '<QQ',data,start+(16 if cls==1 else 24))
        return name,pos,size
    _,pos,size=row(names);strings=data[pos:pos+size];assert len(strings)==size
    result={}
    for index in range(count):
        name,_,size=row(index)
        assert name<len(strings)
        end=strings.index(0,name)
        result[strings[name:end].decode('ascii')]=size
    return cls,machine,result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--kernel',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--arch',choices=('arm','arm64'),required=True)
    parser.add_argument('--cross-compile',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    assert (args.kernel/'vmlinux').is_file() and (args.kernel/'Module.symvers').is_file()
    work=Path('/root/be6l-openwrt/module-layout-audit');work.mkdir(exist_ok=True)
    env=dict(os.environ);env['PATH']='/root/be6l-openwrt/host/bin:'+env['PATH']
    with tempfile.TemporaryDirectory(prefix=args.arch+'-',dir=work) as temporary:
        directory=Path(temporary)
        (directory/'Makefile').write_text('obj-m += module_layout_probe.o\n')
        (directory/'module_layout_probe.c').write_text('''// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
static const unsigned char be6l_expected_module_layout[sizeof(struct module)]
    __used __section(".be6l_module_layout") = {1};
MODULE_LICENSE("GPL");
''')
        command=['make','-C',str(args.kernel),'M='+str(directory),'ARCH='+args.arch,
                 'CROSS_COMPILE='+args.cross_compile,'SHELL=/root/be6l-openwrt/host/bin/bash','modules']
        result=subprocess.run(command,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(result.stdout.decode(errors='replace')[-3000:])
        cls,machine,sections=elf_sections(directory/'module_layout_probe.ko')
        expected=sections['.be6l_module_layout']
        assert expected==sections['.gnu.linkonce.this_module']
    modules=sorted((args.root/'lib/modules').rglob('*.ko'))
    assert modules, 'No modules found in audited root'
    failures=[]
    for module in modules:
        actual_cls,actual_machine,sections=elf_sections(module)
        actual=sections.get('.gnu.linkonce.this_module')
        if (actual_cls,actual_machine,actual)!=(cls,machine,expected):
            failures.append({'module':str(module.relative_to(args.root)),
                             'expected_size':expected,'actual_size':actual,
                             'elf_class':actual_cls,'elf_machine':actual_machine})
    report={'kernel_config_sha256':hashlib.sha256((args.kernel/'.config').read_bytes()).hexdigest(),
            'expected_module_struct_bytes':expected,'elf_class':cls,'elf_machine':machine,
            'module_count':len(modules),'failures':failures,'passed':not failures,
            'probe_loaded_on_hardware':False}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
    if failures:raise SystemExit(1)

if __name__=='__main__':main()
