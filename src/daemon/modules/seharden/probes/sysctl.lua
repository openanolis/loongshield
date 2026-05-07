local log = require('runtime.log')
local config_paths = require('seharden.shared.config_paths')
local key_value_file = require('seharden.shared.key_value_file')
local lfs = require('lfs')
local M = {}

local procfs_root = "/proc/sys"

local _default_dependencies = {
    io_open = io.open,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
    config_paths._test_set_dependencies({
        lfs_attributes = _dependencies.lfs_attributes,
        lfs_dir = _dependencies.lfs_dir,
    })
end

M._test_set_dependencies()

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

local function normalize_sysctl_key(key)
    if not key then
        return nil
    end
    key = tostring(key):gsub("^%-", "")
    return key:gsub("/", ".")
end

local function parse_sysctl_assignment(line)
    local entry = key_value_file.parse_line(line, {
        allow_whitespace_assignment = false,
        normalize_key = normalize_sysctl_key,
    })
    if entry and entry.key then
        return entry.key, entry.value
    end
    return nil
end

local function effective_sysctl_files(params)
    local files = config_paths.sorted_unique_files(params.sysctl_d_dirs or {
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/local/lib/sysctl.d",
        "/usr/lib/sysctl.d",
        "/lib/sysctl.d",
    }, nil, "%.conf$")

    local sysctl_conf = params.sysctl_conf or "/etc/sysctl.conf"
    if _dependencies.lfs_attributes(sysctl_conf, "mode") == "file" then
        files[#files + 1] = sysctl_conf
    end

    return files
end

function M.get_live_value(params)
    if not params or not params.key then
        return nil, "Probe 'sysctl.get_live_value' requires a 'key' parameter."
    end

    local path = key_to_path(params.key)
    if not path then
        return nil, "Invalid key"
    end

    local f, err = _dependencies.io_open(path, "r")
    if not f then
        local message = string.format("Could not read sysctl key '%s' from path '%s': %s",
            params.key, path, tostring(err))
        log.warn("%s", message)
        return {
            available = false,
            path = path,
            value = nil,
            error = message,
        }
    end

    local value = f:read("*l")
    f:close()

    return {
        available = true,
        path = path,
        value = value,
    }
end

function M.get_persistent_value(params)
    if not params or not params.key then
        return nil, "Probe 'sysctl.get_persistent_value' requires a 'key' parameter."
    end

    local target_key = normalize_sysctl_key(params.key)
    if not target_key or not target_key:match("^[a-zA-Z0-9_.]+$") or target_key:match("%.%.") then
        return nil, "Invalid key"
    end

    local result = {
        found = false,
        value = nil,
        source = nil,
    }

    for _, path in ipairs(effective_sysctl_files(params)) do
        local file, err = _dependencies.io_open(path, "r")
        if not file then
            log.warn("Could not open sysctl configuration '%s': %s", path, tostring(err))
            return nil, string.format("Could not open sysctl configuration '%s': %s", path, tostring(err))
        end

        for line in file:lines() do
            local key, value = parse_sysctl_assignment(line)
            if key == target_key then
                result.found = true
                result.value = value
                result.source = path
            end
        end
        file:close()
    end

    return result
end

function M.get_effective_value(params)
    if not params or not params.key then
        return nil, "Probe 'sysctl.get_effective_value' requires a 'key' parameter."
    end

    local live, live_err = M.get_live_value(params)
    if not live then
        return nil, live_err
    end

    local persistent, persistent_err = M.get_persistent_value(params)
    if not persistent then
        return nil, persistent_err
    end

    local value
    if live.available and persistent.found and live.value == persistent.value then
        value = live.value
    end

    return {
        value = value,
        live_available = live.available,
        live_value = live.value,
        live_error = live.error,
        persistent_found = persistent.found,
        persistent_value = persistent.value,
        source = persistent.source,
    }
end

return M
