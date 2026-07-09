local lfs = require('lfs')
local log = require('runtime.log')
local systemctl = require('seharden.shared.systemctl')
local M = {}

local _default_dependencies = {
    io_popen = io.popen,
    lfs_attributes = lfs.attributes,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
    _dependencies.lfs_attributes = deps.lfs_attributes or _default_dependencies.lfs_attributes
end

M._test_set_dependencies()

local function apply_state(operation, params, valid_states, invalid_state_message)
    if not params or not params.name or not params.state then
        return nil, string.format("services.%s: requires 'name' and 'state' parameters", operation)
    end

    local unit = systemctl.sanitize_unit_name(params.name)
    if not unit then
        return nil, string.format("services.%s: invalid unit name '%s'", operation, tostring(params.name))
    end

    if not valid_states[params.state] then
        return nil, string.format(invalid_state_message, params.state)
    end

    log.debug('Enforcer services.%s: systemctl %s %s', operation, params.state, unit)
    local ok, out = systemctl.capture_checked(
        string.format('%s %s', params.state, unit),
        _dependencies,
        { stderr_redirect = '2>&1' }
    )
    if not ok then
        return nil, out
    end
    return true
end

-- Enable or disable a service unit file. state: "enable" | "disable" | "mask"
function M.set_filestate(params)
    return apply_state(
        'set_filestate',
        params,
        { enable = true, disable = true, mask = true, unmask = true },
        "services.set_filestate: invalid state '%s'"
    )
end

-- Start, stop, or restart a service. state: "start" | "stop" | "restart"
-- Note: mask/unmask are persistent unit-file operations; use set_filestate for those.
function M.set_active_state(params)
    return apply_state(
        'set_active_state',
        params,
        { start = true, stop = true, restart = true },
        "services.set_active_state: invalid state '%s' (use set_filestate for mask/unmask)"
    )
end

return M
