#!/usr/bin/env luajit

local lua_lsm = require("lua_lsm.securityfs")
local readiness = require("lua_lsm.readiness")

local cmd, arg = ...
cmd = cmd or "status"

if cmd == "doctor" then
    local result = readiness.doctor()
    for _, item in ipairs(result.checks) do
        print(string.format("%s\t%s\t%s", item.ok and "OK" or "FAIL", item.id, tostring(item.detail or "")))
    end
    os.exit(result.ready and 0 or 1)
elseif cmd == "status" then
    local status = lua_lsm.status()
    print("root:", status.root)
    print("available:", status.available)
    print("version:", status.version or status.error)
    print("modules:", #status.modules)
elseif cmd == "load" then
    assert(arg, "policy path required")
    local ok, err = lua_lsm.load_file(arg)
    assert(ok, err)
elseif cmd == "unload" then
    assert(arg, "module name required")
    local ok, err = lua_lsm.unload(arg)
    assert(ok, err)
elseif cmd == "list" then
    local modules, raw = lua_lsm.list_modules()
    assert(modules, raw)
    io.write(raw)
else
    error("unsupported command: " .. tostring(cmd))
end
