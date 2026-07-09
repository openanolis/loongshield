local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local sysctl_keys = require('seharden.shared.sysctl_keys')
local M = {}

local DEFAULT_SYSCTL_CONF = '/etc/sysctl.d/99-loongshield.conf'
local DEFAULT_PROCFS_ROOT = '/proc/sys'

local _default_dependencies = {
    io_open = io.open,
    os_rename = os.rename,
    os_remove = os.remove,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    sysctl_conf = DEFAULT_SYSCTL_CONF,
    procfs_root = DEFAULT_PROCFS_ROOT,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function normalize_key(key)
    local normalized = sysctl_keys.validate(key)
    if not normalized then
        log.error("sysctl enforcer: invalid key '%s'", tostring(key))
        return nil
    end
    return normalized
end

-- Write or update key=value in the persistent sysctl conf file. Idempotent.
local function persist_sysctl(key, value)
    local existing = {}
    local updated = false

    if fsutil.is_symlink(_dependencies.sysctl_conf, _dependencies) then
        return nil, string.format("sysctl.set_value: refusing to overwrite symlink '%s'", _dependencies.sysctl_conf)
    end

    -- Read existing lines, replacing matching key if present
    local f_in = _dependencies.io_open(_dependencies.sysctl_conf, 'r')
    if f_in then
        for line in f_in:lines() do
            local k = line:match('^%s*([%w_.]+)%s*=')
            if k == key then
                table.insert(existing, string.format('%s = %s', key, tostring(value)))
                updated = true
            else
                table.insert(existing, line)
            end
        end
        f_in:close()
    end

    if not updated then
        table.insert(existing, string.format('%s = %s', key, tostring(value)))
    end

    return fsutil.write_lines_atomically(_dependencies.sysctl_conf, existing, 'sysctl.set_value', _dependencies)
end

-- Set a sysctl key live (via /proc/sys) and persist it. Idempotent.
function M.set_value(params)
    if not params or not params.key or params.value == nil then
        return nil, "sysctl.set_value: requires 'key' and 'value' parameters"
    end

    local key = normalize_key(params.key)
    if not key then
        return nil, string.format("sysctl.set_value: invalid key '%s'", tostring(params.key))
    end
    local value = tostring(params.value)

    local proc_path = sysctl_keys.procfs_path(key, _dependencies.procfs_root)

    -- Apply live
    log.debug('Enforcer sysctl.set_value: setting %s = %s (live)', key, value)
    local live_err
    local f_live, err_live = _dependencies.io_open(proc_path, 'w')
    if not f_live then
        log.warn('sysctl.set_value: could not write to %s: %s (may need root)', proc_path, tostring(err_live))
        live_err = string.format('could not write to %s: %s', proc_path, tostring(err_live))
    else
        f_live:write(value .. '\n')
        local closed, close_err = f_live:close()
        if not closed then
            live_err = string.format('could not close %s: %s', proc_path, tostring(close_err))
            log.warn('sysctl.set_value: %s', live_err)
        end
    end

    -- Persist
    log.debug('Enforcer sysctl.set_value: persisting %s = %s to %s', key, value, _dependencies.sysctl_conf)
    local ok, err = persist_sysctl(key, value)
    if not ok then
        if live_err then
            return nil, string.format('sysctl.set_value: live apply failed: %s; %s', live_err, tostring(err))
        end
        return nil, err
    end

    if live_err then
        return nil, string.format('sysctl.set_value: live apply failed after persisting value: %s', live_err)
    end

    return true
end

return M
