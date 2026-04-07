#!/usr/bin/env luajit

package.path = "../src/daemon/modules/?.lua"

local uv = require("luv")
local cjson = require("cjson.safe")
local msleep = require("util.timer").msleep
local fetch = require("net.uvcurl").fetch

local function log(idx, field, s)
    local s = string.format('[%s  %d %-8s] %s', os.date(), idx, field, s)
    print(s)
end

local function worker(args, field)
    log(args, field, 'start')
    local resp, info, err = fetch("https://ipinfo.io")
    if not resp then
        log(args, field, string.format('fetch: err = %s', err))
        return nil, err
    end
    if info then
        local len = 0
        if type(resp) == 'string' then
            len = string.len(resp)
        end
        local s = string.format('fetch: %d %d, [%s](%d), time = %ds, %ds  %s',
            info.status, info.errno, type(resp), len,
            info.time_total, info.time_namelookup,
            info.effective_url)
        log(args, field, s)
    end

    msleep(3000)

    local r, err = cjson.decode(resp)
    if not r then
        log(args, field, string.format('decode: err = %s', err))
        return nil, err
    end
    log(args, field, r[field])
end

local fields = { "ip", "city", "region", "country", "loc", "timezone" }
for i = 1, #fields do
    local co = coroutine.create(worker)
    coroutine.resume(co, i, fields[i])
end

uv.run()
print('done!')
