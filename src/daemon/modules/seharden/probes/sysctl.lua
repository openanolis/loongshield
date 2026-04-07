local log = require('runtime.log')
local M = {}

local procfs_root = "/proc/sys"

function M.set_procfs_root(path)
    procfs_root = path
end

local function key_to_path(key)
    if not key or not key:match("^[a-zA-Z0-9_.]+$") or key:match("%.%.") then
        log.error("Invalid or malicious sysctl key provided: %s", key)
        return nil
    end
    return procfs_root .. "/" .. key:gsub("%.", "/")
end

function M.get_live_value(params)
    if not params or not params.key then
        return nil, "Probe 'sysctl.get_live_value' requires a 'key' parameter."
    end

    local path = key_to_path(params.key)
    if not path then
        return nil, "Invalid key"
    end

    local f, err = io.open(path, "r")
    if not f then
        log.warn("Could not read sysctl key '%s' from path '%s': %s",
            params.key, path, tostring(err))
        return nil, string.format("Could not read sysctl key '%s' from path '%s': %s",
            params.key, path, tostring(err))
    end

    local value = f:read("*l")
    f:close()

    return { value = value }
end

return M
