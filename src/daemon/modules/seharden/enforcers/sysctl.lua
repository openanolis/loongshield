local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local DEFAULT_SYSCTL_CONF = "/etc/sysctl.d/99-loongshield.conf"
local DEFAULT_PROCFS_ROOT = "/proc/sys"

local SYSCTL_CONF = DEFAULT_SYSCTL_CONF
local PROCFS_ROOT = DEFAULT_PROCFS_ROOT

local _default_dependencies = {
    io_open  = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
    SYSCTL_CONF = deps.sysctl_conf or DEFAULT_SYSCTL_CONF
    PROCFS_ROOT = deps.procfs_root or DEFAULT_PROCFS_ROOT
end

M._test_set_dependencies()

local function key_to_path(key)
    if not key or not key:match("^[a-zA-Z0-9_.]+$") or key:match("%.%.") then
        log.error("sysctl enforcer: invalid key '%s'", tostring(key))
        return nil
    end
    return PROCFS_ROOT .. "/" .. key:gsub("%.", "/")
end

-- Write or update key=value in the persistent sysctl conf file. Idempotent.
local function persist_sysctl(key, value)
    local existing = {}
    local updated = false

    if fsutil.is_symlink(SYSCTL_CONF, _dependencies) then
        return nil, string.format("sysctl.set_value: refusing to overwrite symlink '%s'", SYSCTL_CONF)
    end

    -- Read existing lines, replacing matching key if present
    local f_in = _dependencies.io_open(SYSCTL_CONF, "r")
    if f_in then
        for line in f_in:lines() do
            local k = line:match("^%s*([%w_.]+)%s*=")
            if k == key then
                table.insert(existing, string.format("%s = %s", key, tostring(value)))
                updated = true
            else
                table.insert(existing, line)
            end
        end
        f_in:close()
    end

    if not updated then
        table.insert(existing, string.format("%s = %s", key, tostring(value)))
    end

    return fsutil.write_lines_atomically(SYSCTL_CONF, existing, "sysctl.set_value", _dependencies)
end

-- Set a sysctl key live (via /proc/sys) and persist it. Idempotent.
function M.set_value(params)
    if not params or not params.key or params.value == nil then
        return nil, "sysctl.set_value: requires 'key' and 'value' parameters"
    end

    local key   = params.key
    local value = tostring(params.value)

    local proc_path = key_to_path(key)
    if not proc_path then
        return nil, string.format("sysctl.set_value: invalid key '%s'", key)
    end

    -- Apply live
    log.debug("Enforcer sysctl.set_value: setting %s = %s (live)", key, value)
    local live_err
    local f_live, err_live = _dependencies.io_open(proc_path, "w")
    if not f_live then
        log.warn("sysctl.set_value: could not write to %s: %s (may need root)", proc_path, tostring(err_live))
        live_err = string.format("could not write to %s: %s", proc_path, tostring(err_live))
    else
        f_live:write(value .. "\n")
        local closed, close_err = f_live:close()
        if not closed then
            live_err = string.format("could not close %s: %s", proc_path, tostring(close_err))
            log.warn("sysctl.set_value: %s", live_err)
        end
    end

    -- Persist
    log.debug("Enforcer sysctl.set_value: persisting %s = %s to %s", key, value, SYSCTL_CONF)
    local ok, err = persist_sysctl(key, value)
    if not ok then
        if live_err then
            return nil, string.format("sysctl.set_value: live apply failed: %s; %s", live_err, tostring(err))
        end
        return nil, err
    end

    if live_err then
        return nil, string.format("sysctl.set_value: live apply failed after persisting value: %s", live_err)
    end

    return true
end

return M
