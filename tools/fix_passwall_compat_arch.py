"""WSL: do not select arm64 downloads for an ARM32 userland on a 64-bit kernel."""
from pathlib import Path
import subprocess
base=Path(__file__).resolve().parents[1]
root=Path('/root/be6l-openwrt/passwall')
p=root/'luci-app-passwall/luasrc/passwall/api.lua'
marker='-- Kernel uname can be AArch64 while the installed userland is ARM32.'
data=p.read_text()
if marker not in data:
    old='\tif arch:match("^i[%d]86$") then\n'
    new='''\t-- Kernel uname can be AArch64 while the installed userland is ARM32.
\tlocal user_arch = OPENWRT_ARCH or DISTRIB_ARCH or ""
\tif (arch == "aarch64" or arch == "armv8l") and user_arch:match("^arm_") then
\t\tarch = "armv7"
\tend

'''+old
    assert data.count(old)==1
    p.write_text(data.replace(old,new))
patch=subprocess.check_output(['git','diff','--','luci-app-passwall/luasrc/passwall/api.lua'],cwd=root)
assert patch and marker.encode() in patch
(base/'upstream/passwall-arm32-userland-arch.patch').write_bytes(patch)
start=p.read_text().index('local function auto_get_arch()')
end=p.read_text().index('\nfunction parseURL(',start)
function=p.read_text()[start:end]
test='''local kernel, user
local nixio={uname=function() return {machine=kernel} end}
local fs={access=function() return false end}
local function trim(s) return s end
local OPENWRT_ARCH,DISTRIB_ARCH,OPENWRT_BOARD
'''+function+'''
local cases={
  {"aarch64","arm_cortex-a7","armv5"},
  {"armv8l","arm_cortex-a7","armv5"},
  {"armv7l","arm_cortex-a7","armv5"},
  {"aarch64","aarch64_cortex-a53","aarch64"},
  {"aarch64","arm_cortex-a7_neon-vfpv4","armv7"}
}
for _,c in ipairs(cases) do
 kernel=c[1];OPENWRT_ARCH=c[2];DISTRIB_ARCH=c[2]
 assert(auto_get_arch()==c[3],c[1].."/"..c[2])
end
print("PASSWALL_USERLAND_ARCH_BOUNDARIES_PASSED_5")
'''
lua=Path('/root/be6l-openwrt/source/staging_dir/hostpkg/bin/lua')
assert lua.exists(),str(lua)
r=subprocess.run([str(lua),'-'],input=test.encode(),stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
(base/'logs/proxy-build-1213/passwall-architecture-test.txt').write_bytes(r.stdout)
assert r.returncode==0,r.stdout
print(r.stdout.decode().strip(),flush=True)
