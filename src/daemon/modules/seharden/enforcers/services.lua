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

local function run_systemctl(args)
    return systemctl.capture_checked(args, _dependencies, { stderr_redirect = "2>&1" })
end

-- Enable or disable a service unit file. state: "enable" | "disable" | "mask"
function M.set_filestate(params)
    if not params or not params.name or not params.state then
        return nil, "services.set_filestate: requires 'name' and 'state' parameters"
    end

    local unit = systemctl.sanitize_unit_name(params.name)
    if not unit then
        return nil, string.format("services.set_filestate: invalid unit name '%s'", tostring(params.name))
    end

    local valid_states = { enable = true, disable = true, mask = true, unmask = true }
    if not valid_states[params.state] then
        return nil, string.format("services.set_filestate: invalid state '%s'", params.state)
    end

    log.debug("Enforcer services.set_filestate: systemctl %s %s", params.state, unit)
    local ok, out = run_systemctl(string.format("%s %s", params.state, unit))
    if not ok then return nil, out end
    return true
end

-- Start, stop, or restart a service. state: "start" | "stop" | "restart"
-- Note: mask/unmask are persistent unit-file operations; use set_filestate for those.
function M.set_active_state(params)
    if not params or not params.name or not params.state then
        return nil, "services.set_active_state: requires 'name' and 'state' parameters"
    end

    local unit = systemctl.sanitize_unit_name(params.name)
    if not unit then
        return nil, string.format("services.set_active_state: invalid unit name '%s'", tostring(params.name))
    end

    local valid_states = { start = true, stop = true, restart = true }
    if not valid_states[params.state] then
        return nil, string.format(
            "services.set_active_state: invalid state '%s' (use set_filestate for mask/unmask)", params.state)
    end

    log.debug("Enforcer services.set_active_state: systemctl %s %s", params.state, unit)
    local ok, out = run_systemctl(string.format("%s %s", params.state, unit))
    if not ok then return nil, out end
    return true
end

return M
