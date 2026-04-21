#!/usr/bin/env luajit

--
-- example from https://www.matthew.ath.cx/misc/dbus
--

local uv = require('luv')
local dbus = require('dbus')

local unpack = unpack or table.unpack

package.path = table.concat({
    "../../src/daemon/modules/?.lua",
    "../../src/daemon/modules/?/init.lua",
    "../../src/daemon/modules/seharden/?.lua",
    "../../src/daemon/modules/seharden/?/init.lua",
}, ";") .. ";" .. package.path

local function listen(verbose)
    local con, err = dbus.bus_get()
    if not con then
        return nil, err
    end
    local ret, err = con:request_name('test.method.server')
    if ret ~= 'primary' then
        return nil, err
    end

    while true do
        con:read_write()
        local message = con:pop_message()
        if message then
            if verbose then
                local m = message:marshal()
                print(string.format('message: [%d] %s', #m, m))
            end
            if message:is_method_call('test.method.Type', 'Method') then
                local t = message:decode()
                assert(#t == 1)
                assert(type(t[1]) == 'string')
                print('Method called with: ', t[1])

                local reply = message:new_method_return()
                if reply then
                    local r = reply:append(true, 9527, t[1]) -- status, level
                    assert(r)
                    r = con:send(reply, true)
                    assert(r)
                end
            end
        else
            uv.sleep(1)
        end
    end
end

local function query(args)
    print('Call remote method with: ', args)
    local con, err = dbus.bus_get()
    if not con then
        return nil, err
    end
    local ret, err = con:request_name('test.method.caller')
    if ret ~= 'primary' then
        return nil, err
    end

    local req = dbus.message_new_method_call('test.method.server',
        '/test/method/Object',
        'test.method.Type', 'Method')
    if not req then
        return nil, 'no memory'
    end
    local r = req:append(args)
    assert(r)

    local pending = con:send_with_reply(req, true)
    assert(pending)
    pending:block()

    local reply = pending:steal_reply()
    assert(reply)
    local t = reply:decode()
    assert(type(t) == 'table')
    local status, level, message = unpack(t)
    assert(type(status) == 'boolean')
    assert(type(level) == 'number')
    print('Got reply: ', status, level, message)
    return true
end

local function recv(verbose)
    local con, err = dbus.bus_get()
    if not con then
        return nil, err
    end
    local ret, err = con:request_name('test.signal.sink')
    if ret ~= 'primary' then
        return nil, err
    end
    local r, err = con:add_match([[type='signal',interface='test.signal.Type']])
    if not r then
        return nil, err
    end
    con:flush()

    while true do
        con:read_write()
        local message = con:pop_message()
        if message then
            if verbose then
                local m = message:marshal()
                print(string.format('message: [%d] %s', #m, m))
            end
            if message:is_signal('test.signal.Type', 'Test') then
                local t = message:decode()
                assert(#t == 1)
                assert(type(t[1]) == 'string')
                print('Got signal with value: ', t[1])
            end
        else
            uv.sleep(1)
        end
    end
end

local function send(args)
    local con, err = dbus.bus_get()
    if not con then
        return nil, err
    end
    local ret, err = con:request_name('test.signal.source')
    if ret ~= 'primary' then
        return nil, err
    end

    local signal = dbus.message_new_signal('/test/signal/Object',
        'test.signal.Type', 'Test')
    if not signal then
        return nil, 'message new signal'
    end
    local r = signal:append(args)
    assert(r)
    r = con:send(signal, true)
    assert(r)
    print('Signal sent with value: ', args)
    return true
end


local cmd, args = ...
cmd = cmd or 'query'
local verbose = args and true or false
args = args or 'hello'

local rc, err
if cmd == 'listen' then
    rc, err = listen(verbose)
elseif cmd == 'query' then
    rc, err = query(args)
elseif cmd == 'recv' then
    rc, err = recv(verbose)
elseif cmd == 'send' then
    rc, err = send(args)
end

print('done!', rc, err)
