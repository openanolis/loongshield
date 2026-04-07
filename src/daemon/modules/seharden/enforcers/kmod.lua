local log = require('runtime.log')
local fsutil = require('seharden.enforcers.fsutil')
local M = {}

local MODPROBE_D_DIR = "/etc/modprobe.d"

local _lfs = (function() local ok, lib = pcall(require, 'lfs'); return ok and lib or nil end)()

local _default_dependencies = {
    os_execute = os.execute,
    io_open    = io.open,
    io_lines   = function(path) return io.lines(path) end,
    lfs_dir    = function(path) return _lfs and _lfs.dir(path) or nil end,
    lfs_symlinkattributes = fsutil.default_lfs_symlinkattributes,
    os_rename  = os.rename,
    os_remove  = os.remove,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function sanitize_module_name(name)
    if type(name) ~= "string" then return nil end
    if not name:match("^[%w_-]+$") then return nil end
    return name
end

-- Run a shell command, returning true/nil, err
local function run(cmd)
    local ok, _, code = _dependencies.os_execute(cmd)
    if ok == true or code == 0 then
        return true
    end
    return nil, string.format("Command failed (exit %s): %s", tostring(code), cmd)
end

local function is_module_loaded(name)
    local ok, iter_or_err = pcall(_dependencies.io_lines, "/proc/modules")
    if not ok or not iter_or_err then
        return nil, string.format("Unable to read /proc/modules: %s", tostring(iter_or_err))
    end

    local loaded = false
    local iter_ok, iter_err = pcall(function()
        for line in iter_or_err do
            local module_name = line:match("^(%S+)%s")
            if module_name == name then
                loaded = true
                break
            end
        end
    end)

    if not iter_ok then
        return nil, string.format("Unable to inspect /proc/modules: %s", tostring(iter_err))
    end

    return loaded
end

-- Check if a line matching pattern already exists in any modprobe.d conf file
local function line_exists_in_modprobe_d(pattern)
    local dir_iter = _dependencies.lfs_dir(MODPROBE_D_DIR)
    if not dir_iter then return false end
    for name in dir_iter do
        if name:match("%.conf$") then
            local path = MODPROBE_D_DIR .. "/" .. name
            local ok, err_msg = pcall(function()
                for line in _dependencies.io_lines(path) do
                    if line:match(pattern) then
                        error("found", 0)
                    end
                end
            end)
            if not ok and err_msg == "found" then
                return true
            end
        end
    end
    return false
end

-- Unload a kernel module (modprobe -r). Idempotent: no-op if not loaded.
function M.unload(params)
    local name = sanitize_module_name(params and params.name)
    if not name then
        return nil, "kmod.unload: missing or invalid 'name' parameter"
    end

    local loaded, load_err = is_module_loaded(name)
    if loaded == false then
        log.debug("kmod.unload: module '%s' is already unloaded, skipping.", name)
        return true
    end
    if loaded == nil then
        log.warn("kmod.unload: could not determine whether '%s' is loaded: %s", name, tostring(load_err))
    end

    log.debug("Enforcer kmod.unload: unloading module '%s'", name)
    local ok, err = run(string.format("modprobe -r %s 2>/dev/null", name))
    if not ok then
        return nil, string.format("kmod.unload: failed to unload '%s': %s", name, tostring(err))
    end
    return true
end

-- Blacklist a kernel module by writing a conf file. Idempotent.
function M.blacklist(params)
    local name = sanitize_module_name(params and params.name)
    if not name then
        return nil, "kmod.blacklist: missing or invalid 'name' parameter"
    end

    local blacklist_line = "blacklist " .. name
    if line_exists_in_modprobe_d("^blacklist%s+" .. name .. "%s*$") then
        log.debug("kmod.blacklist: '%s' already blacklisted, skipping.", name)
        return true
    end

    local conf_path = string.format("%s/loongshield-disable-%s.conf", MODPROBE_D_DIR, name)
    log.debug("Enforcer kmod.blacklist: writing '%s' to %s", blacklist_line, conf_path)

    return fsutil.append_unique_line(conf_path, blacklist_line, "kmod.blacklist", _dependencies)
end

-- Set module install command to /bin/true (prevents loading). Idempotent.
function M.set_install_command(params)
    local name = sanitize_module_name(params and params.name)
    if not name then
        return nil, "kmod.set_install_command: missing or invalid 'name' parameter"
    end

    local install_line = string.format("install %s /bin/true", name)
    if line_exists_in_modprobe_d("^install%s+" .. name .. "%s+/bin/true%s*$") then
        log.debug("kmod.set_install_command: install command for '%s' already set, skipping.", name)
        return true
    end

    local conf_path = string.format("%s/loongshield-disable-%s.conf", MODPROBE_D_DIR, name)
    log.debug("Enforcer kmod.set_install_command: writing '%s' to %s", install_line, conf_path)

    return fsutil.append_unique_line(conf_path, install_line, "kmod.set_install_command", _dependencies)
end

return M
