local securityfs = require("lua_lsm.securityfs")

local M = {}

local deps = {
    getenv = os.getenv,
    io_open = io.open,
    popen = io.popen,
}

local function strip_trailing_slash(path)
    if path == "/" then
        return path
    end
    return (path:gsub("/+$", ""))
end

local function read_file(path)
    local file, err = deps.io_open(path, "rb")
    if not file then
        return nil, err or ("failed to open " .. path)
    end
    local content = file:read("*a")
    file:close()
    return content or ""
end

local function exists(path)
    local file = deps.io_open(path, "rb")
    if file then
        file:close()
        return true
    end
    return false
end

local function shell_quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end

local function command_output(cmd)
    local pipe = deps.popen(cmd, "r")
    if not pipe then
        return nil
    end
    local output = pipe:read("*a")
    pipe:close()
    return output
end

local function uname_r()
    local output = command_output("uname -r 2>/dev/null")
    if not output then
        return nil
    end
    return output:match("^%s*(.-)%s*$")
end

local function read_maybe_gzip(path)
    local content = read_file(path)
    if content and content:find("CONFIG_", 1, true) then
        return content
    end

    local output = command_output("gzip -dc " .. shell_quote(path) .. " 2>/dev/null")
    if output and output:find("CONFIG_", 1, true) then
        return output
    end

    return content
end

local function proc_root(opts)
    opts = opts or {}
    return strip_trailing_slash(opts.proc_root
        or deps.getenv("LOONGSHIELD_LUA_LSM_PROC_ROOT")
        or "/proc")
end

local function boot_root(opts)
    opts = opts or {}
    return strip_trailing_slash(opts.boot_root
        or deps.getenv("LOONGSHIELD_LUA_LSM_BOOT_ROOT")
        or "/boot")
end

local function kernel_config_path(opts)
    opts = opts or {}
    local explicit = opts.config_file
        or deps.getenv("LOONGSHIELD_LUA_LSM_CONFIG_FILE")
        or deps.getenv("KCONFIG_CONFIG")
    if explicit and explicit ~= "" then
        return explicit
    end

    local proc_config = proc_root(opts) .. "/config.gz"
    if exists(proc_config) then
        return proc_config
    end

    local release = uname_r()
    if release and release ~= "" then
        local boot_config = boot_root(opts) .. "/config-" .. release
        if exists(boot_config) then
            return boot_config
        end
    end

    return nil
end

function M.parse_kernel_config(content)
    local config = {}
    for line in tostring(content or ""):gmatch("[^\r\n]+") do
        local key, value = line:match("^(CONFIG_[%w_]+)=(.*)$")
        if key then
            value = value:gsub('^"(.*)"$', "%1")
            config[key] = value
        else
            key = line:match("^# (CONFIG_[%w_]+) is not set$")
            if key then
                config[key] = "n"
            end
        end
    end
    return config
end

function M.read_kernel_config(opts)
    local path = kernel_config_path(opts)
    if not path then
        return nil, "kernel config not found"
    end

    local content, err = read_maybe_gzip(path)
    if not content or not content:find("CONFIG_", 1, true) then
        return nil, err or ("kernel config is unreadable: " .. path)
    end

    return M.parse_kernel_config(content), path
end

local function read_security_lsms(opts)
    local lsm_path = securityfs.securityfs_mount(opts) .. "/lsm"
    local content = read_file(lsm_path)
    if content then
        return content
    end

    local config = M.read_kernel_config(opts)
    if config and config.CONFIG_LSM then
        return config.CONFIG_LSM
    end

    return nil
end

local function csv_contains(list, item)
    for value in tostring(list or ""):gmatch("[^,%s]+") do
        if value == item then
            return true
        end
    end
    return false
end

local function check(id, label, ok, detail, required)
    return {
        id = id,
        label = label,
        ok = ok,
        detail = detail,
        required = required ~= false,
    }
end

local function securityfs_mounted(opts)
    local mounts_path = proc_root(opts) .. "/mounts"
    local content = read_file(mounts_path)
    if not content then
        return false, "cannot read " .. mounts_path
    end

    local expected = securityfs.securityfs_mount(opts)
    for line in content:gmatch("[^\r\n]+") do
        local _source, mountpoint, fstype = line:match("^(%S+)%s+(%S+)%s+(%S+)")
        if fstype == "securityfs" and strip_trailing_slash(mountpoint) == expected then
            return true, mountpoint
        end
    end

    return false, "securityfs is not mounted at " .. expected
end

function M.doctor(opts)
    opts = opts or {}
    local checks = {}

    local mounted, mounted_detail = securityfs_mounted(opts)
    checks[#checks + 1] = check("securityfs_mounted", "securityfs mounted", mounted, mounted_detail)

    local version = securityfs.version(opts)
    checks[#checks + 1] = check(
        "lua_securityfs",
        "Lua-LSM securityfs ABI",
        version ~= nil,
        version and ("version " .. version) or "missing " .. securityfs.path("version", opts)
    )

    local lsm_list = read_security_lsms(opts)
    checks[#checks + 1] = check(
        "lsm_active",
        "active LSM list contains lua",
        csv_contains(lsm_list, "lua"),
        lsm_list or "active LSM list unavailable"
    )

    local config, config_path_or_err = M.read_kernel_config(opts)
    checks[#checks + 1] = check(
        "kernel_config",
        "kernel config readable",
        config ~= nil,
        config_path_or_err,
        false
    )

    if config then
        checks[#checks + 1] = check("config_securityfs", "CONFIG_SECURITYFS=y", config.CONFIG_SECURITYFS == "y", config.CONFIG_SECURITYFS or "missing")
        checks[#checks + 1] = check("config_lua", "CONFIG_LUA=y", config.CONFIG_LUA == "y", config.CONFIG_LUA or "missing")
        checks[#checks + 1] = check("config_security_lua_lsm", "CONFIG_SECURITY_LUA_LSM=y", config.CONFIG_SECURITY_LUA_LSM == "y", config.CONFIG_SECURITY_LUA_LSM or "missing")
        checks[#checks + 1] = check("config_lsm", "CONFIG_LSM contains lua", csv_contains(config.CONFIG_LSM, "lua"), config.CONFIG_LSM or "missing")
    end

    local ready = true
    for _, item in ipairs(checks) do
        if item.required and item.ok ~= true then
            ready = false
            break
        end
    end

    return {
        ready = ready,
        checks = checks,
        root = securityfs.root(opts),
        securityfs_mount = securityfs.securityfs_mount(opts),
    }
end

function M._test_set_dependencies(overrides)
    overrides = overrides or {}
    for key, value in pairs(overrides) do
        deps[key] = value
    end
end

function M._test_reset_dependencies()
    deps.getenv = os.getenv
    deps.io_open = io.open
    deps.popen = io.popen
end

return M
