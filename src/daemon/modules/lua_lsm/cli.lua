local log = require("runtime.log")
local policy = require("lua_lsm.policy")
local readiness = require("lua_lsm.readiness")
local securityfs = require("lua_lsm.securityfs")

local M = {}

local USAGE = [[
Usage: loongshield lua-lsm <command> [options]

Lua-LSM Policy Manager

Commands:
  status                 Show Lua-LSM runtime status
  doctor                 Run kernel readiness checks
  list                   List loaded Lua-LSM modules
  load <policy.lua>      Validate and load a Lua-LSM policy
  unload <name>          Unload a Lua-LSM policy by module name
  hooks                  Show supported hook stats when enabled
  stats                  Show Lua-LSM VM/cache stats when enabled

Options:
  --root <path>          Override Lua-LSM securityfs root
  --config <path>        Override kernel config path for doctor
  --no-validate          Skip userspace policy metadata validation before load
  --log-level <level>    Set log level (trace, debug, info, warn, error)
  -h, --help             Show this help message

Environment:
  LOONGSHIELD_LUA_LSM_SECURITYFS_ROOT       Default: /sys/kernel/security/lua
  LOONGSHIELD_LUA_LSM_SECURITYFS_MOUNT      Default: parent of securityfs root
  LOONGSHIELD_LUA_LSM_CONFIG_FILE           Kernel config used by doctor
  LOONGSHIELD_LUA_LSM_ASSUME_CAP_MAC_ADMIN  Test-only capability bypass

Exit Codes:
  0 - Command completed successfully
  1 - CLI error, readiness failure, missing ABI file, or kernel write failure
]]

local function print_usage()
    print(USAGE)
end

local function parse_args(argv)
    local opts = {}
    local positionals = {}
    local i = 1

    while i <= #argv do
        local arg = argv[i]
        local key, value = arg:match("^%-%-([%w%-]+)=(.+)$")

        if key == "root" then
            opts.root = value
        elseif key == "config" then
            opts.config_file = value
        elseif key == "log-level" then
            opts.log_level = value
        elseif arg == "--root" or arg == "--config" or arg == "--log-level" then
            if i >= #argv then
                return nil, string.format("Option '%s' requires a value.", arg)
            end
            if arg == "--root" then
                opts.root = argv[i + 1]
            elseif arg == "--config" then
                opts.config_file = argv[i + 1]
            else
                opts.log_level = argv[i + 1]
            end
            i = i + 1
        elseif arg == "--no-validate" then
            opts.no_validate = true
        elseif arg == "--help" or arg == "-h" then
            opts.help = true
        elseif arg:match("^%-") then
            return nil, "Unknown option: " .. arg
        else
            positionals[#positionals + 1] = arg
        end
        i = i + 1
    end

    opts.command = positionals[1]
    opts.args = {}
    for j = 2, #positionals do
        opts.args[#opts.args + 1] = positionals[j]
    end
    return opts
end

local function yn(value)
    return value and "yes" or "no"
end

local function print_status(opts)
    local status = securityfs.status(opts)
    print("Lua-LSM status")
    print("  securityfs root: " .. status.root)
    print("  securityfs mount: " .. status.securityfs_mount)
    print("  available: " .. yn(status.available))
    if status.version then
        print("  version: " .. status.version)
    else
        print("  version: unavailable")
    end
    print("  loaded modules: " .. tostring(#status.modules))
    print("  hooks file: " .. yn(status.hooks_available))
    print("  stats file: " .. yn(status.stats_available))
    print("  experimental: yes")

    return status.available and 0 or 1
end

local function print_doctor(opts)
    local result = readiness.doctor(opts)
    print("Lua-LSM doctor")
    print("  securityfs root: " .. result.root)
    print("  securityfs mount: " .. result.securityfs_mount)

    for _, item in ipairs(result.checks) do
        local prefix
        if item.ok == true then
            prefix = "OK"
        elseif item.required then
            prefix = "FAIL"
        else
            prefix = "WARN"
        end
        print(string.format("  [%s] %s: %s", prefix, item.label, tostring(item.detail or "")))
    end

    return result.ready and 0 or 1
end

local function print_raw_file(label, reader, opts)
    local content, err = reader(opts)
    if not content then
        log.error("%s unavailable: %s", label, tostring(err))
        return 1
    end
    io.write(content)
    if not content:match("\n$") then
        io.write("\n")
    end
    return 0
end

local function list_modules(opts)
    local modules, raw_or_err = securityfs.list_modules(opts)
    if not modules then
        log.error("Lua-LSM modules unavailable: %s", tostring(raw_or_err))
        return 1
    end
    if #modules == 0 then
        print("No Lua-LSM modules loaded.")
        return 0
    end
    print(raw_or_err)
    return 0
end

local function load_policy(path, opts)
    if type(path) ~= "string" or path == "" then
        log.error("load requires a policy file path")
        return 1
    end

    local metadata
    if not opts.no_validate then
        local err
        metadata, err = policy.validate_file(path)
        if not metadata then
            log.error("Policy validation failed: %s", tostring(err))
            return 1
        end

        local loaded, loaded_err = securityfs.is_loaded(metadata.name, opts)
        if loaded == true then
            log.error("Lua-LSM policy '%s' is already loaded", metadata.name)
            return 1
        elseif loaded == nil then
            log.warn("Could not check currently loaded Lua-LSM modules: %s", tostring(loaded_err))
        end

        log.info("Validated Lua-LSM policy '%s' version %s", metadata.name, tostring(metadata.version))
    end

    log.warn("Lua-LSM support is experimental; loading only the explicitly requested local policy.")
    local ok, err = securityfs.load_file(path, opts)
    if not ok then
        log.error("Failed to load Lua-LSM policy: %s", tostring(err))
        return 1
    end

    print("Loaded Lua-LSM policy: " .. path)
    return 0
end

local function unload_policy(name, opts)
    if type(name) ~= "string" or name == "" then
        log.error("unload requires a module name")
        return 1
    end

    local ok, err = securityfs.unload(name, opts)
    if not ok then
        log.error("Failed to unload Lua-LSM policy: %s", tostring(err))
        return 1
    end

    print("Unloaded Lua-LSM policy: " .. name)
    return 0
end

function M.run(argv)
    local opts, err = parse_args(argv or {})
    if not opts then
        log.error(err)
        print("")
        print_usage()
        return 1
    end

    if opts.log_level then
        log.setLevel(opts.log_level)
    end

    if opts.help or not opts.command then
        print_usage()
        return opts.help and 0 or 1
    end

    if opts.command == "status" then
        return print_status(opts)
    elseif opts.command == "doctor" then
        return print_doctor(opts)
    elseif opts.command == "list" then
        return list_modules(opts)
    elseif opts.command == "load" then
        return load_policy(opts.args[1], opts)
    elseif opts.command == "unload" then
        return unload_policy(opts.args[1], opts)
    elseif opts.command == "hooks" then
        return print_raw_file("Lua-LSM hooks", securityfs.hooks, opts)
    elseif opts.command == "stats" then
        return print_raw_file("Lua-LSM stats", securityfs.stats, opts)
    else
        log.error("Unknown lua-lsm command: '%s'", tostring(opts.command))
        print("")
        print_usage()
        return 1
    end
end

return M
