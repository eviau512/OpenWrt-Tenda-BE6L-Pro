"""WSL: standard source-built ARM32 soft-float packages for a COMPAT rootfs."""
from pathlib import Path
import os,re,subprocess,json
root=Path('/root/be6l-openwrt');src=root/'source'
base=Path(__file__).resolve().parents[1]
logs=base/'logs/proxy-build-1213';logs.mkdir(exist_ok=True)
os.environ['PATH']=str(root/'host/bin')+':'+os.environ['PATH']
os.environ['FORCE_UNSAFE_CONFIGURE']='1'
os.environ['CONFIG_SHELL']=str(root/'host/bin/bash')
coreutils=src/'feeds/packages/utils/coreutils/Makefile'
recipe=coreutils.read_text()
if 'PKG_BUILD_DEPENDS:=acl\n' in recipe:
    recipe=recipe.replace('PKG_BUILD_DEPENDS:=acl\n','PKG_BUILD_DEPENDS:=acl libcap\n')
    coreutils.write_text(recipe)
if 'PKG_BUILD_DEPENDS:=acl libcap' not in recipe:
    assert recipe.count('PKG_INSTALL:=1\n')==1
    coreutils.write_text(recipe.replace('PKG_INSTALL:=1\n','PKG_INSTALL:=1\nPKG_BUILD_DEPENDS:=acl libcap\n'))
patch=subprocess.check_output(['git','diff','--','utils/coreutils/Makefile'],cwd=src/'feeds/packages')
(base/'upstream/coreutils-acl-build-dependency.patch').write_bytes(patch)
def run(args):
    p=subprocess.run(args,cwd=src,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    with (logs/'configure.log').open('a') as f:f.write('COMMAND '+repr(args)+'\n'+p.stdout)
    if p.returncode:raise RuntimeError(p.stdout[-3000:])
for name in ['passwall','passwall_packages']:
    link=src/'feeds'/name
    if not link.exists():link.symlink_to(root/name,target_is_directory=True)
feed=src/'feeds.conf'
text=feed.read_text()
for name in ['passwall','passwall_packages']:
    line='src-link '+name+' '+str(root/name)
    if line not in text:text+='\n'+line+'\n'
feed.write_text(text)
run(['./scripts/feeds','update','-i','packages','luci','passwall','passwall_packages'])
requested=['tailscale','sing-box','luci-app-passwall','luci-i18n-passwall-zh-cn',
           'chinadns-ng','dns2socks','ipt2socks','tcping','microsocks','lyaml',
           'luarocks','ucode-mod-lua','wget-ssl','libtirpc','libacl','libattr','coreutils',
           'coreutils-base64','coreutils-nohup','coreutils-timeout']
run(['./scripts/feeds','install',*requested])
config=src/'.config'
backup=logs/'config.before'
if not backup.exists():backup.write_bytes(config.read_bytes())
opts={name:'y' for name in ['tailscale','sing-box','luci-app-passwall',
        'luci-i18n-passwall-zh-cn','dnsmasq-full','ip-full','ucode-mod-lua','wget-ssl','libacl','libattr','libcap']}
opts.update({'dnsmasq':'n','ip-tiny':'n','sing-box-tiny':'n','xray-core':'n'})
options={'CONFIG_PACKAGE_'+k:v for k,v in opts.items()}
options['CONFIG_PACKAGE_luci-app-passwall_Nftables_Transparent_Proxy']='y'
options['CONFIG_PACKAGE_luci-app-passwall_Iptables_Transparent_Proxy']='n'
options['CONFIG_TARGET_INITRAMFS_COMPRESSION_NONE']='n'
options['CONFIG_TARGET_INITRAMFS_COMPRESSION_GZIP']='y'
ui=(root/'passwall/luci-app-passwall/Makefile').read_text()
for key in re.findall(r'^config (PACKAGE_\$\(PKG_NAME\)_INCLUDE_\w+)',ui,re.M):
    key='CONFIG_'+key.replace('$(PKG_NAME)','luci-app-passwall')
    options[key]='y' if key.endswith('_SingBox') else 'n'
data=[]
for line in config.read_text().splitlines():
    m=re.match(r'(?:# )?(CONFIG_\w[\w+.-]*)',line)
    if not(m and m.group(1) in options):data.append(line)
data += [k+'='+v if v!='n' else '# '+k+' is not set' for k,v in options.items()]
config.write_text('\n'.join(data)+'\n')
run(['make','defconfig'])
resolved=config.read_text().splitlines()
for k,v in options.items():
    expected=k+'='+v if v!='n' else '# '+k+' is not set'
    assert (expected in resolved if v!='n' else k+'=y' not in resolved and k+'=m' not in resolved),expected
for pkg in ['luci','luci-i18n-base-zh-cn','curl','lua','luci-lib-nixio','luci-theme-argon','btop']:
    assert 'CONFIG_PACKAGE_'+pkg+'=y' in resolved,pkg
assert 'CONFIG_HAS_FPU=y' not in resolved
assert 'CONFIG_TARGET_ROOTFS_INITRAMFS=y' in resolved
assert '# CONFIG_TARGET_ROOTFS_SQUASHFS is not set' in resolved
defaults=src/'files/etc/uci-defaults/98-be6l-proxy-packages'
defaults.parent.mkdir(parents=True,exist_ok=True)
defaults.write_text('''#!/bin/sh
# Development RAM image: installed for use, never join an account or proxy by default.
for service in tailscale sing-box passwall; do
    [ ! -x /etc/init.d/$service ] || /etc/init.d/$service disable
done
uci -q set passwall.@global[0].enabled=0 || true
uci -q commit passwall || true
exit 0
''')
defaults.chmod(0o755)
(logs/'config.resolved').write_text('\n'.join(resolved)+'\n')
(logs/'selection.json').write_text(json.dumps({'userland':'arm_cortex-a7 / ARM EABI soft-float','goarm':5,'proxy_core':'sing-box only','xray':False,'tailscale_login':False,'selected':options},indent=2)+'\n')
print('PROXY_PACKAGES_SELECTED_ARM32_SOFTFLOAT_SINGBOX_ONLY',flush=True)
