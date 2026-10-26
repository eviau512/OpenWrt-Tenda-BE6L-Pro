-- SPDX-License-Identifier: MIT
-- Private socket and empty config/save directories must be created by the runner.
local ubus = require('ubus')
local uloop = require('uloop')
assert(uloop.init())
local connection = assert(ubus.connect('ubus.sock'))
if arg[1] == 'server' then
    connection:add({['be6l.soft.probe'] = {
        echo = {function(request, message)
            assert(type(message.value) == 'number')
            -- The cached upstream Lua binding serializes numbers as integers.
            -- Keep the wire contract integer and format fractions explicitly.
            connection:reply(request, {value = message.value + 1,
                fraction = string.format('%.2f', message.value + 0.75), text = 'soft64'})
        end, {value = ubus.INT32}}
    }})
    local ready = assert(io.open('server-ready', 'w')); ready:write('ready'); ready:close()
    local deadline = uloop.timer(function() uloop.cancel() end, 20000)
    uloop.run()
    deadline:cancel()
    connection:close()
    return
end
local uci = require('uci')
local cursor = assert(uci.cursor('config', 'save'))
assert(cursor:set('probe', 'test', 'section'))
assert(cursor:set('probe', 'test', 'value', 'soft64'))
assert(cursor:commit('probe'))
assert(cursor:get('probe', 'test', 'value') == 'soft64')
cursor:unload('probe')
assert(cursor:get('probe', 'test', 'value') == 'soft64')
local result = assert(connection:call('be6l.soft.probe', 'echo', {value = 3}))
assert(result.value == 4 and result.fraction == '3.75' and result.text == 'soft64')
connection:close()
local ticks = 0
local timer = uloop.timer(function() ticks = ticks + 1; uloop.cancel() end, 10)
uloop.run()
timer:cancel()
assert(ticks == 1)
print('NATIVE_LUA_UCI_UBUS_ULOOP_PASS')
