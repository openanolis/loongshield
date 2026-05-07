local M = {}

local DEFAULT_ROOT = "/sys/kernel/security/lua"

local deps = {
    getenv = os.getenv,
    io_open = io.open,
    require = require,
}

local function strip_trailing_slash(path)
    if path == "/" then
        return path
    end
    return (path:gsub("/+$", ""))
end

local function dirname(path)
    local normalized = strip_trailing_slash(path)
    local parent = normalized:match("^(.*)/[^/]+$")
    if parent == "" or parent == nil then
        return "/"
    end
    return parent
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

local function write_file(path, content)
    local file, err = deps.io_open(path, "wb")
    if not file then
        return nil, err or ("failed to open " .. path)
    end

    local ok, write_err = file:write(content)
    file:close()
    if not ok then
        return nil, write_err or ("failed to write " .. path)
    end

    return true
end

local function exists(path)
    local file = deps.io_open(path, "rb")
    if file then
        file:close()
        return true
    end
    return false
end

local function trim(value)
    return tostring(value or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

function M.root(opts)
    opts = opts or {}
    return strip_trailing_slash(opts.root
        or deps.getenv("LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT")
        or DEFAULT_ROOT)
end

function M.securityfs_mount(opts)
    opts = opts or {}
    return strip_trailing_slash(opts.securityfs_mount
        or deps.getenv("LOONGSHIELD_LUA_LSM_SECURITYFS_MOUNT")
        or dirname(M.root(opts)))
end

function M.path(name, opts)
    return M.root(opts) .. "/" .. name
end

function M.exists(name, opts)
    return exists(M.path(name, opts))
end

function M.read(name, opts)
    return read_file(M.path(name, opts))
end

function M.write(name, content, opts)
    return write_file(M.path(name, opts), content)
end

function M.version(opts)
    local content, err = M.read("version", opts)
    if not content then
        return nil, err
    end
    return trim(content)
end

local function parse_module_line(line)
    local first = line:match("^%s*(%S+)")
    if not first then
        return nil
    end

    if first == "modules" or first == "name" or first:match("^%-+$") then
        return nil
    end

    local name, license, size, nlsm, nload, shdict, kvnode, author = line:match(
        "^%s*(%S+)%s+(%S+)%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s+(%d+)%s*(.*)$"
    )
    if not name then
        return {
            name = first,
            raw = line,
        }
    end

    return {
        name = name,
        license = license,
        size = tonumber(size),
        nlsm = tonumber(nlsm),
        nload = tonumber(nload),
        shdict = tonumber(shdict),
        kvnode = tonumber(kvnode),
        author = author ~= "" and author or nil,
        raw = line,
    }
end

function M.parse_modules(raw)
    local modules = {}
    for line in tostring(raw or ""):gmatch("[^\r\n]+") do
        local module = parse_module_line(line)
        if module then
            modules[#modules + 1] = module
        end
    end
    return modules
end

function M.list_modules(opts)
    local raw, err = M.read("modules", opts)
    if not raw then
        return nil, err
    end
    return M.parse_modules(raw), raw
end

function M.is_loaded(name, opts)
    local modules, err = M.list_modules(opts)
    if not modules then
        return nil, err
    end

    for _, module in ipairs(modules) do
        if module.name == name then
            return true
        end
    end
    return false
end

function M.hooks(opts)
    return M.read("lsm_funcs", opts)
end

function M.stats(opts)
    return M.read("stats", opts)
end

function M.has_cap_mac_admin()
    if deps.getenv("LOONGSHIELD_LUA_LSM_ASSUME_CAP_MAC_ADMIN") == "1" then
        return true
    end

    local ok, capability = pcall(deps.require, "capability")
    if not ok or type(capability) ~= "table" or type(capability.get_proc) ~= "function" then
        return false, "capability module is unavailable"
    end

    local cap = capability.get_proc()
    if not cap or type(cap.flag) ~= "function" then
        return false, "process capabilities are unavailable"
    end

    local flag_ok, enabled = pcall(function()
        return cap:flag("effective", "cap_mac_admin")
    end)
    if not flag_ok then
        return false, tostring(enabled)
    end

    if enabled ~= true then
        return false, "CAP_MAC_ADMIN is not effective"
    end

    return true
end

local function require_cap_mac_admin(opts)
    opts = opts or {}
    if opts.skip_cap_check then
        return true
    end

    local ok, err = M.has_cap_mac_admin()
    if not ok then
        return nil, err
    end
    return true
end

function M.load_source(source, opts)
    opts = opts or {}
    local ok, err = require_cap_mac_admin(opts)
    if not ok then
        return nil, "CAP_MAC_ADMIN required to load Lua-LSM policy: " .. tostring(err)
    end

    return M.write("register", source, opts)
end

function M.load_file(path, opts)
    local source, err = read_file(path)
    if not source then
        return nil, err
    end
    return M.load_source(source, opts)
end

function M.unload(name, opts)
    if type(name) ~= "string" or name == "" then
        return nil, "module name is required"
    end

    opts = opts or {}
    local ok, err = require_cap_mac_admin(opts)
    if not ok then
        return nil, "CAP_MAC_ADMIN required to unload Lua-LSM policy: " .. tostring(err)
    end

    return M.write("unregister", name .. "\n", opts)
end

function M.status(opts)
    opts = opts or {}
    local version, version_err = M.version(opts)
    local modules, modules_raw = M.list_modules(opts)
    local hooks_available = M.exists("lsm_funcs", opts)
    local stats_available = M.exists("stats", opts)

    return {
        root = M.root(opts),
        securityfs_mount = M.securityfs_mount(opts),
        available = version ~= nil,
        version = version,
        error = version_err,
        modules = modules or {},
        modules_raw = modules_raw,
        hooks_available = hooks_available,
        stats_available = stats_available,
        experimental = true,
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
    deps.require = require
end

return M
