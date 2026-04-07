local lfs = require('lfs')
local log = require('runtime.log')
local M = {}

local SYSTEMCTL_CANDIDATES = {
    "/usr/bin/systemctl",
    "/bin/systemctl",
    "/usr/sbin/systemctl",
    "/sbin/systemctl",
}

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

local function sanitize_unit_name(name)
    if type(name) ~= "string" then return nil end
    if not name:match("^[%w@%._:-]+$") then return nil end
    return name
end

local function resolve_systemctl_path()
    for _, path in ipairs(SYSTEMCTL_CANDIDATES) do
        local attr = _dependencies.lfs_attributes(path)
        if attr and attr.mode == "file" then
            return path
        end
    end

    return "systemctl"
end

local function run_systemctl(args)
    local cmd = resolve_systemctl_path() .. " " .. args .. " 2>&1"
    local handle = _dependencies.io_popen(cmd, "r")
    if not handle then
        return nil, "failed to run: " .. cmd
    end
    local out = handle:read("*a")
    local ok, _, code = handle:close()
    if ok ~= true or (code ~= nil and code ~= 0) then
        local trimmed = (out or ""):match("^%s*(.-)%s*$")
        if trimmed == "" then
            trimmed = string.format("systemctl failed (exit %s): %s", tostring(code), cmd)
        end
        return nil, trimmed
    end
    return true, out
end

-- Enable or disable a service unit file. state: "enable" | "disable" | "mask"
function M.set_filestate(params)
    if not params or not params.name or not params.state then
        return nil, "services.set_filestate: requires 'name' and 'state' parameters"
    end

    local unit = sanitize_unit_name(params.name)
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

    local unit = sanitize_unit_name(params.name)
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
