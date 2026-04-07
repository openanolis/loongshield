#!/usr/bin/env luajit

local uv = require('luv')

local function msleep(msec, thread)
    thread = thread or coroutine.running()
    local timer = uv.new_timer()
    timer:start(msec, 0, function()
        timer:stop()
        uv.close(timer)
        assert(coroutine.resume(thread))
    end)
    return coroutine.yield()
end

local function set_timeout(millisec, fn)
    local timer = uv.new_timer()
    timer:start(millisec, 0, function()
        timer:stop()
        uv.close(timer)
        fn()
    end)
    return timer
end

local function set_interval(millisec, fn)
    local timer = uv.new_timer()
    timer:start(millisec, millisec, function()
        fn()
    end)
    return timer
end

local function timer_close(timer)
    timer:stop()
    uv.close(timer)
end

return {
    msleep = msleep,
    set_timeout = set_timeout,
    set_interval = set_interval,
    timer_close = timer_close
}
