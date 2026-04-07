local log = require('runtime.log')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    io_popen = io.popen,
}

local _dependencies = {}
local _effective_dump_cache = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    _dependencies.io_open = deps.io_open or _default_dependencies.io_open
    _dependencies.io_popen = deps.io_popen or _default_dependencies.io_popen
    _effective_dump_cache = {}
end

M._test_set_dependencies()

local function trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

local SAFE_SHELL_ARG_PATTERN = "^[a-zA-Z0-9%._-]+$"
local SAFE_SHELL_ADDR_PATTERN = "^[a-zA-Z0-9%._:-]+$"
local SSHD_CANDIDATE_PATHS = {
    "/usr/sbin/sshd",
    "/usr/local/sbin/sshd",
    "/sbin/sshd",
    "/usr/bin/sshd",
    "/usr/local/bin/sshd",
    "/bin/sshd",
}

local function sanitize_shell_arg(arg, pattern)
    pattern = pattern or SAFE_SHELL_ARG_PATTERN
    if not arg or not tostring(arg):match(pattern) then
        log.error("Invalid or malicious argument detected for shell command: %s",
            tostring(arg))
        return nil
    end
    return tostring(arg)
end

local function resolve_sshd_path()
    for _, path in ipairs(SSHD_CANDIDATE_PATHS) do
        local file = _dependencies.io_open(path, "r")
        if file then
            file:close()
            return path
        end
    end

    return nil
end

local function read_effective_dump(cmd)
    if _effective_dump_cache[cmd] then
        return _effective_dump_cache[cmd]
    end

    log.debug("Executing sshd config dump command: %s", cmd)
    local handle = _dependencies.io_popen(cmd, "r")
    if not handle then
        local result = {
            available = true,
            error = "Failed to execute sshd config dump command.",
        }
        _effective_dump_cache[cmd] = result
        return result
    end

    local values = {}
    for line in handle:lines() do
        local key, value = line:match("^%s*(%S+)%s+(.*)$")
        if key then
            values[key:lower()] = value
        end
    end

    local ok, status, code = handle:close()
    if not ok or code ~= 0 then
        local message = string.format("sshd command failed with exit code: %s", tostring(code))
        log.debug("The 'sshd -T' command failed with exit code: %s", tostring(code))
        local result = {
            available = true,
            error = message,
        }
        _effective_dump_cache[cmd] = result
        return result
    end

    local result = {
        available = true,
        values = values,
    }
    _effective_dump_cache[cmd] = result
    return result
end

local function read_local_hostname()
    local file = _dependencies.io_open("/proc/sys/kernel/hostname", "r")
    if not file then
        return nil
    end

    local hostname = trim(file:read("*l"))
    file:close()

    if hostname == "" then
        return nil
    end

    return hostname
end

local function resolve_localhost()
    local hostname = read_local_hostname()
    local ip_address
    local localhost_ip

    local f_hosts = _dependencies.io_open("/etc/hosts", "r")
    if f_hosts then
        for line in f_hosts:lines() do
            if not line:match("^#") then
                local line_ip = line:match("^(%S+)")
                for word in line:gmatch("%S+") do
                    if hostname and word == hostname then
                        ip_address = line_ip
                        break
                    end
                    if word == "localhost" then
                        localhost_ip = localhost_ip or line_ip
                    end
                end
            end
            if ip_address and localhost_ip then
                break
            end
        end
        f_hosts:close()
    end

    hostname = hostname or "localhost"
    ip_address = ip_address or localhost_ip or "127.0.0.1"

    return {
        host = hostname,
        addr = ip_address,
    }
end

local function parse_duration_seconds(value)
    local remaining = trim(value):lower():gsub("%s+", "")
    local total = 0
    local multipliers = {
        [""] = 1,
        s = 1,
        m = 60,
        h = 3600,
        d = 86400,
        w = 604800,
    }

    if remaining == "" then
        return nil
    end

    while remaining ~= "" do
        local number, unit, rest = remaining:match("^(%d+)([smhdw]?)(.*)$")
        if not number or multipliers[unit] == nil then
            return nil
        end

        total = total + (tonumber(number) * multipliers[unit])
        remaining = rest
    end

    return total
end

local function normalize_value(value, value_type)
    if value_type == nil then
        return value
    end

    if value_type == "duration_seconds" then
        return parse_duration_seconds(value)
    end

    return nil
end

function M.get_effective_value(params)
    if not (params and params.key and params.conditions) then
        return nil, "Probe 'ssh.get_effective_value' requires 'key' and 'conditions' parameters."
    end

    local sim_conditions = {}
    if params.conditions.from == "localhost" then
        sim_conditions = resolve_localhost()
        sim_conditions.user = params.conditions.user
    else
        return nil, string.format("Unsupported 'from' condition: %s", params.conditions.from)
    end

    local safe_user = sanitize_shell_arg(sim_conditions.user)
    local safe_host = sanitize_shell_arg(sim_conditions.host)
    local safe_addr = sanitize_shell_arg(sim_conditions.addr, SAFE_SHELL_ADDR_PATTERN)

    if not (safe_user and safe_host and safe_addr) then
        return nil, "Invalid characters in command arguments."
    end

    local sshd_path = resolve_sshd_path()
    if not sshd_path then
        log.debug("Could not locate an sshd binary in standard system paths.")
        return {
            available = false,
            value = nil,
            error = "sshd binary not found",
        }
    end

    local cmd = string.format(
        "%s -T -C user=%s -C host=%s -C addr=%s",
        sshd_path, safe_user, safe_host, safe_addr
    )

    local dump_result = read_effective_dump(cmd)
    if dump_result.error ~= nil then
        return {
            available = dump_result.available,
            value = nil,
            error = dump_result.error,
        }
    end

    local search_key = params.key:lower()
    local found_value = dump_result.values and dump_result.values[search_key] or nil

    local normalized_value = normalize_value(found_value, params.value_type)
    if params.value_type ~= nil and normalized_value == nil and found_value ~= nil then
        return nil, string.format("Could not parse SSH value '%s' as %s.", tostring(found_value),
            tostring(params.value_type))
    end

    return {
        available = true,
        value = normalized_value ~= nil and normalized_value or found_value,
    }
end

return M
