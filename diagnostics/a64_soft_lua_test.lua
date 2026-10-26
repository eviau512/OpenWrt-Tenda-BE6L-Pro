-- SPDX-License-Identifier: MIT
-- Run only in a fresh RAM test directory; no saved configuration is read.
io.stdout:setvbuf('no')
print('PHASE_LUA_SCRIPT_ENTRY')
local n = require('nixio')
print('PHASE_NIXIO_LOADED')
local checks = 0
local function check(x) assert(x); checks = checks + 1; print('CHECK ' .. checks) end
check(_VERSION == 'Lua 5.1')
check(1.5 + 2.25 == 3.75)
local square_root = math.sqrt(2)
print('PHASE_SQRT_RETURNED')
local square = square_root^2
print('PHASE_POW_RETURNED')
check(square > 1.999999999 and square < 2.000000001)
check(tonumber('3.75') == 3.75)
check(string.format('%.6f', 1.5 + 2.25) == '3.750000')
local payload = string.rep('binary\0lua\255', 1024)
print('PHASE_FILE')
local f = assert(n.open('scratch', 'w+', '600'))
check(f:write(payload) == #payload)
check(f:seek(0) == 0)
local chunks, received = {}, 0
while received < #payload do
    local block = assert(f:read(#payload - received)); assert(#block > 0)
    chunks[#chunks + 1] = block; received = received + #block
end
check(table.concat(chunks) == payload)
check(f:seek(4294967303) == 4294967303)
check(f:tell() == 4294967303)
check(f:seek(0) == 0)
check(f:close())
local r, w = n.pipe(); assert(r and w)
print('PHASE_PIPE')
check(w:write('pipe\0fraction') == 13)
check(r:read(13) == 'pipe\0fraction')
check(w:close()); check(r:close())
local sec, usec = n.gettimeofday()
print('PHASE_TIME')
check(type(sec) == 'number' and type(usec) == 'number' and usec >= 0 and usec < 1000000)
local c = coroutine.create(function() coroutine.yield(3.75); return 7.5 end)
local ok, value = coroutine.resume(c); check(ok and value == 3.75)
ok, value = coroutine.resume(c); check(ok and value == 7.5)
local fn = assert(loadstring(string.dump(function() return 1.5 + 2.25 end)))
check(fn() == 3.75)
local foreign, error = package.loadlib('/usr/lib/lua/nixio.so', 'luaopen_nixio')
print('PHASE_FOREIGN_MODULE_REJECTION')
check(foreign == nil and type(error) == 'string')
-- OpenWrt deliberately serializes string lengths as unsigned int. Matching
-- number models therefore have portable bytecode across ARM32/AArch64.
local portable = assert(loadfile('arm32.luac'))
check(portable() == 3.75)
local bytecode = assert(io.open('arm32.luac', 'rb'))
local bytes = bytecode:read('*a'); bytecode:close()
local bad, message = loadstring(bytes:sub(1, 4) .. string.char(0x50) .. bytes:sub(6))
check(bad == nil and type(message) == 'string')
collectgarbage('collect')
print('NATIVE_LUA_NIXIO_PASS checks=' .. checks)
