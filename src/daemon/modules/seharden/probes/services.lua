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
    bus_default_system = function()
        local systemd = require('systemd')
        return systemd.bus_default_system()
    end,
    io_popen = io.popen,
    lfs_attributes = lfs.attributes,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.bus_default_system = deps.bus_default_system or _default_dependencies.bus_default_system
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
    _dependencies.lfs_attributes = deps.lfs_attributes or _default_dependencies.lfs_attributes
end

M._test_set_dependencies()

local function sanitize_unit_name(name)
    if type(name) ~= "string" then
        return nil
    end
    if not name:match("^[%w@%._:-]+$") then
        return nil
    end
    return name
end

local function normalize_unit_name(unit_name)
    local safe_name = sanitize_unit_name(unit_name)
    if not safe_name then
        return nil
    end
    if safe_name:match("%.[%w%-]+$") then
        return safe_name
    end
    return safe_name .. ".service"
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

local function run_systemctl_command(args)
    local cmd = string.format("%s %s 2>/dev/null", resolve_systemctl_path(), args)
    local handle = _dependencies.io_popen(cmd, "r")
    if not handle then
        return nil, nil, nil, cmd
    end

    local out = handle:read("*a") or ""
    local ok, _, code = handle:close()
    return out, ok, code, cmd
end

local function get_systemctl_enabled_state(unit_name)
    local normalized_name = normalize_unit_name(unit_name)
    if not normalized_name then
        log.warn("Invalid unit name for systemctl: %s", tostring(unit_name))
        return nil
    end

    local out = run_systemctl_command(string.format("--root=/ is-enabled %s", normalized_name))
    if not out then
        log.debug("Failed to run systemctl --root=/ is-enabled for unit '%s'.", normalized_name)
        return nil
    end

    local state = out:match("^%s*(.-)%s*$")
    if state == "" then
        log.debug("Could not parse systemctl --root=/ is-enabled output for unit '%s'.", normalized_name)
        return nil
    end

    if not state:match("^[%w%-]+$") then
        log.debug("Unexpected systemctl --root=/ is-enabled output for unit '%s': %s",
            normalized_name, state)
        return nil
    end

    return state
end

local function get_systemctl_properties(unit_name)
    local normalized_name = normalize_unit_name(unit_name)
    if not normalized_name then
        log.warn("Invalid unit name for systemctl: %s", tostring(unit_name))
        return nil
    end

    local out = run_systemctl_command(string.format(
        "show -p LoadState -p UnitFileState -p ActiveState %s",
        normalized_name
    ))
    if not out then
        log.debug("Failed to run systemctl show for unit properties.")
        local offline_state = get_systemctl_enabled_state(unit_name)
        if offline_state then
            return { UnitFileState = offline_state }
        end
        return nil
    end

    local properties = {}
    for line in (out .. "\n"):gmatch("([^\n]*)\n") do
        local key, value = line:match("^([%w]+)=(.*)$")
        if key then
            properties[key] = value
        end
    end

    if properties.LoadState == "not-found" and
        (properties.UnitFileState == nil or properties.UnitFileState == "") then
        properties.UnitFileState = "not-found"
    end

    if properties.UnitFileState == nil or properties.UnitFileState == "" then
        local offline_state = get_systemctl_enabled_state(unit_name)
        if offline_state then
            properties.UnitFileState = offline_state
        end
    end

    if not next(properties) then
        log.debug("Could not parse systemctl show output for unit '%s'.", normalized_name)
        return nil
    end

    if properties.UnitFileState == nil or properties.UnitFileState == "" then
        log.debug("Could not determine unit file state for unit '%s'.", normalized_name)
        return nil
    end

    return properties
end

local function get_file_state(unit_name, get_fallback_props)
    log.debug("Connecting to system D-Bus for unit file state query...")
    local bus, err = _dependencies.bus_default_system()
    if not bus then
        log.debug("D-Bus unavailable for unit file state query: %s", tostring(err))
        local fallback_props = get_fallback_props and get_fallback_props() or nil
        if fallback_props and fallback_props.UnitFileState and fallback_props.UnitFileState ~= "" then
            return fallback_props.UnitFileState
        end
        return "unknown"
    end

    local reply = bus:unit_filestate(unit_name)
    if not reply then
        local fallback_props = get_fallback_props and get_fallback_props() or nil
        if fallback_props and fallback_props.UnitFileState and fallback_props.UnitFileState ~= "" then
            return fallback_props.UnitFileState
        end
        return "not-found"
    end

    local state, read_err = reply:read('s')
    if not state then
        log.debug("Could not read D-Bus reply for unit file state: %s", tostring(read_err))
        local fallback_props = get_fallback_props and get_fallback_props() or nil
        if fallback_props and fallback_props.UnitFileState and fallback_props.UnitFileState ~= "" then
            return fallback_props.UnitFileState
        end
        return "unknown"
    end

    return state
end

-- ToDo: enhance to use D-Bus for checking active state as well.
-- The shell fallback is still less ideal than D-Bus, but the unit name is sanitized.
local function get_active_state(unit_name, fallback_props)
    if fallback_props and fallback_props.ActiveState and fallback_props.ActiveState ~= "" then
        return fallback_props.ActiveState
    end

    local normalized_name = normalize_unit_name(unit_name)
    if not normalized_name then
        log.warn("Invalid unit name for systemctl: %s", tostring(unit_name))
        return "unknown"
    end
    local cmd = string.format("%s is-active %s 2>/dev/null", resolve_systemctl_path(), normalized_name)
    local handle = _dependencies.io_popen(cmd, "r")
    if not handle then
        log.debug("Failed to run systemctl command for active state.")
        return "unknown"
    end
    local state = handle:read("*a"):match("^%s*(.-)%s*$")
    handle:close()
    if state == "" then
        return "unknown"
    end
    return state
end

function M.get_unit_properties(params)
    if not params or not params.name then
        return nil, "Probe 'services.get_unit_properties' requires a 'name' parameter."
    end

    local unit_name = params.name
    local fallback_props
    local fallback_loaded = false
    local function get_fallback_props()
        if not fallback_loaded then
            fallback_props = get_systemctl_properties(unit_name)
            fallback_loaded = true
        end
        return fallback_props
    end
    local unit_file_state = get_file_state(unit_name, get_fallback_props)

    return {
        UnitFileState = unit_file_state,
        ActiveState = get_active_state(unit_name, fallback_loaded and fallback_props or nil)
    }
end

return M
