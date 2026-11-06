-- SPDX-License-Identifier: MIT
local n = require "nixio"
require "nixio.util"
local fs = require "nixio.fs"
assert(math.abs(math.sin(0.5)^2 + math.cos(0.5)^2 - 1) < 1e-12)
local path = assert(arg[1]) .. "/lua-file"
local f = assert(n.open(path, "w", "600"))
assert(f:writeall("standard Lua FP and Nixio\n"))
assert(f:close())
f = assert(n.open(path, "r"))
assert(f:readall() == "standard Lua FP and Nixio\n")
assert(f:close())
assert(fs.stat(path).size == 26)
local r, w = assert(n.pipe())
assert(r and w)
local child = assert(n.fork())
if child == 0 then
    r:close()
    assert(w:writeall("fork-pipe"))
    w:close()
    os.exit(0)
end
w:close()
assert(r:readall() == "fork-pipe")
r:close()
local pid, status, code = n.waitpid(child)
assert(pid == child and status == "exited" and code == 0)
print("LUA_NIXIO_FP_FILE_FORK_PIPE_OK")
