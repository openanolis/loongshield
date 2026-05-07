local comparators = require('seharden.comparators')
local fs = require('fs')
local lfs = require('lfs')
local log = require('runtime.log')
local path_list = require('seharden.shared.path_list')
local M = {}

local _default_dependencies = {
    fs_get_gid = fs.get_gid,
    fs_stat = fs.stat,
    io_open = io.open,
    io_popen = io.popen,
    lfs_attributes = lfs.attributes,
    lfs_dir = lfs.dir,
}

local _dependencies = {}
local _effective_dump_cache = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
    path_list._test_set_dependencies({
        lfs_attributes = _dependencies.lfs_attributes,
        lfs_dir = _dependencies.lfs_dir,
    })
    _effective_dump_cache = {}
end

M._test_set_dependencies()

local function trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

local MODE_0600 = tonumber("600", 8)
local MODE_0640 = tonumber("640", 8)
local MODE_0644 = tonumber("644", 8)

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

local function parse_colon_numbers(value)
    local numbers = {}
    for token in trim(value):gmatch("[^:]+") do
        local number = tonumber(token)
        if number == nil then
            return nil
        end
        numbers[#numbers + 1] = number
    end

    if #numbers == 0 then
        return nil
    end

    return numbers
end

local function escape_lua_pattern(value)
    return tostring(value or ""):gsub("([%^%$%(%)%%%.%[%]%+%-%?%*])", "%%%1")
end

local function strip_comment(line)
    local comment_start = tostring(line or ""):find("#", 1, true)
    if comment_start then
        return line:sub(1, comment_start - 1)
    end
    return line
end

local function path_mode(path)
    local attr = _dependencies.lfs_attributes(path)
    return attr and attr.mode or nil
end

local function path_exists_as_file(path)
    return path_mode(path) == "file"
end

local function append_unique(list, seen, path)
    if path and path ~= "" and not seen[path] then
        list[#list + 1] = path
        seen[path] = true
    end
end

local function normalize_include_path(path, base_dir)
    if path:sub(1, 1) == "/" then
        return path
    end
    return (base_dir or "/etc/ssh") .. "/" .. path
end

local function expand_include_spec(spec, base_dir)
    spec = normalize_include_path(spec, base_dir)
    if spec:find("[%*%?%[]") then
        local files = path_list.expand_files({ spec })
        table.sort(files)
        return files
    end
    if path_exists_as_file(spec) then
        return { spec }
    end
    return {}
end

local function discover_include_files(path, base_dir)
    local file = _dependencies.io_open(path, "r")
    if not file then
        return {}
    end

    local includes = {}
    for line in file:lines() do
        local active = trim(strip_comment(line))
        local directive, value = active:match("^(%S+)%s+(.+)$")
        if directive and directive:lower() == "include" then
            for spec in tostring(value or ""):gmatch("%S+") do
                for _, include_path in ipairs(expand_include_spec(spec, base_dir)) do
                    includes[#includes + 1] = include_path
                end
            end
        end
    end
    file:close()
    return includes
end

local function discover_sshd_config_files(params)
    local main_path = params.path or "/etc/ssh/sshd_config"
    local base_dir = params.base_dir or "/etc/ssh"
    local include_dir = params.include_dir or "/etc/ssh/sshd_config.d"
    local queue = {}
    local queued = {}
    local files = {}
    local seen_files = {}

    append_unique(queue, queued, main_path)
    for _, path in ipairs(path_list.expand_files({ include_dir .. "/*.conf" })) do
        append_unique(queue, queued, path)
    end

    local index = 1
    while index <= #queue do
        local path = queue[index]
        index = index + 1

        if path_exists_as_file(path) then
            append_unique(files, seen_files, path)
            for _, include_path in ipairs(discover_include_files(path, base_dir)) do
                append_unique(queue, queued, include_path)
            end
        end
    end

    table.sort(files)
    return files
end

local function get_file_access(path)
    local attr = _dependencies.fs_stat(path)
    if not attr then
        return {
            path = path,
            exists = false,
        }
    end

    return {
        path = path,
        exists = true,
        uid = attr:uid(),
        gid = attr:gid(),
        mode = attr:mode(),
    }
end

local function mode_no_more_permissive(mode, expected)
    return comparators.mode_is_no_more_permissive(mode, expected)
end

local function config_file_access_ok(access)
    return access.exists == true
        and access.uid == 0
        and access.gid == 0
        and mode_no_more_permissive(access.mode, MODE_0600)
end

local function basename(path)
    return tostring(path or ""):match("([^/]+)$") or tostring(path or "")
end

local function list_host_key_files(directory, key_type)
    directory = directory or "/etc/ssh"
    local files = {}
    local ok, iter, dir_obj = pcall(_dependencies.lfs_dir, directory)
    if not ok then
        return nil, tostring(iter)
    end
    if not iter then
        return nil, tostring(dir_obj or "directory unavailable")
    end

    for name in iter, dir_obj do
        local path = directory .. "/" .. name
        if path_mode(path) == "file" then
            if key_type == "private" and name:match("^ssh_host_.+_key$") then
                files[#files + 1] = path
            elseif key_type == "public" and name:match("^ssh_host_.+_key%.pub$") then
                files[#files + 1] = path
            end
        end
    end

    table.sort(files)
    return files
end

local function private_host_key_access_ok(access, ssh_keys_gid)
    if access.exists ~= true or access.uid ~= 0 then
        return false
    end
    if access.gid == 0 then
        return mode_no_more_permissive(access.mode, MODE_0600)
    end
    if ssh_keys_gid ~= nil and access.gid == ssh_keys_gid then
        return mode_no_more_permissive(access.mode, MODE_0640)
    end
    return false
end

local function public_host_key_access_ok(access)
    return access.exists == true
        and access.uid == 0
        and access.gid == 0
        and mode_no_more_permissive(access.mode, MODE_0644)
end

local function inspect_host_key_access(params, key_type, predicate)
    params = params or {}
    local details = {}
    local invalid_count = 0
    local ssh_keys_gid = _dependencies.fs_get_gid("ssh_keys")
    local files, dir_err = list_host_key_files(params.directory, key_type)

    if not files then
        return {
            available = false,
            error = dir_err,
            checked_count = 0,
            invalid_count = 0,
            all_configured = false,
            ssh_keys_gid = ssh_keys_gid,
            details = details,
        }
    end

    for _, path in ipairs(files) do
        local access = get_file_access(path)
        access.type = key_type
        access.basename = basename(path)
        access.configured = predicate(access, ssh_keys_gid)
        details[#details + 1] = access
        if not access.configured then
            invalid_count = invalid_count + 1
        end
    end

    return {
        available = true,
        checked_count = #details,
        invalid_count = invalid_count,
        all_configured = invalid_count == 0,
        ssh_keys_gid = ssh_keys_gid,
        details = details,
    }
end

local function normalize_value(value, value_type)
    if value_type == nil then
        return value
    end

    if value_type == "duration_seconds" then
        return parse_duration_seconds(value)
    end

    if value_type == "colon_numbers" then
        return parse_colon_numbers(value)
    end

    return nil
end

local function normalize_for_compare(value)
    return trim(value):lower()
end

local function allowed_value_set(values)
    local set = {}
    for _, value in ipairs(values or {}) do
        set[normalize_for_compare(value)] = true
    end
    return set
end

local function value_is_present(value)
    if value == nil then
        return false
    end
    if type(value) == "string" then
        return trim(value) ~= ""
    end
    return true
end

local function setting_failure(setting, reason)
    setting.reason = reason
    setting.configured = false
    return setting
end

local function compare_number(value, expected, operator)
    local number = tonumber(value)
    local bound = tonumber(expected)

    if number == nil or bound == nil then
        return false
    end

    if operator == ">=" then
        return number >= bound
    elseif operator == "<=" then
        return number <= bound
    end

    return false
end

local function values_within_maximums(values, maximums)
    if type(values) ~= "table" then
        return false
    end

    for index, maximum in ipairs(maximums or {}) do
        local value = values[index]
        if value ~= nil and tonumber(value) > tonumber(maximum) then
            return false
        end
    end

    return true
end

local function split_algorithm_list(value)
    local algorithms = {}
    for algorithm in tostring(value or ""):gmatch("[^,%s]+") do
        algorithms[#algorithms + 1] = algorithm
    end
    return algorithms
end

local function build_algorithm_set(values)
    local set = {}
    for _, value in ipairs(values or {}) do
        set[normalize_for_compare(value)] = true
    end
    return set
end

local function read_os_release_id(path)
    local file = _dependencies.io_open(path or "/etc/os-release", "r")
    if not file then
        return nil
    end

    for line in file:lines() do
        local key, value = line:match("^%s*([%w_]+)%s*=%s*\"?([^\"\n]*)\"?")
        if key == "ID" then
            file:close()
            return trim(value):lower()
        end
    end

    file:close()
    return nil
end

local function contains_os_disclosure(content, os_id)
    local lowered = tostring(content or ""):lower()
    for _, escape in ipairs({ "\\v", "\\r", "\\m", "\\s" }) do
        if lowered:find(escape, 1, true) then
            return true
        end
    end

    os_id = trim(os_id or "")
    if os_id ~= "" then
        return lowered:match("%f[%w]" .. escape_lua_pattern(os_id) .. "%f[%W]") ~= nil
    end

    return false
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

function M.inspect_banner(params)
    if not (params and params.conditions) then
        return nil, "Probe 'ssh.inspect_banner' requires 'conditions' parameters."
    end

    local setting, err = M.inspect_effective_setting({
        key = "banner",
        conditions = params.conditions,
        require_absolute_path = true,
    })
    if not setting then
        return nil, err
    end

    local result = {
        available = setting.available,
        value = setting.value,
        path = setting.value,
        error = setting.error,
        reason = setting.reason,
        absolute_path = setting.configured == true,
        banner_file_available = false,
        info_leak_found = false,
        configured = false,
    }

    if setting.configured ~= true then
        return result
    end

    local file, open_err = _dependencies.io_open(setting.value, "r")
    if not file then
        result.reason = "banner_file_unavailable"
        result.error = tostring(open_err or "banner file not found")
        return result
    end

    local content = file:read("*a") or ""
    file:close()

    result.banner_file_available = true
    result.info_leak_found = contains_os_disclosure(content,
        read_os_release_id(params.os_release_path or "/etc/os-release"))
    result.configured = result.info_leak_found == false
    if not result.configured then
        result.reason = "info_leak_found"
    end

    return result
end

function M.inspect_effective_setting(params)
    if not (params and params.key and params.conditions) then
        return nil, "Probe 'ssh.inspect_effective_setting' requires 'key' and 'conditions' parameters."
    end

    local result, err = M.get_effective_value({
        key = params.key,
        conditions = params.conditions,
        value_type = params.value_type,
    })
    if not result then
        return nil, err
    end

    local setting = {
        available = result.available,
        key = params.key,
        value = result.value,
        error = result.error,
        configured = false,
    }

    if result.available == false then
        return setting_failure(setting, "unavailable")
    end
    if result.error ~= nil then
        return setting_failure(setting, "error")
    end
    if not value_is_present(result.value) then
        return setting_failure(setting, "missing")
    end

    if params.require_absolute_path then
        local value = trim(result.value)
        if not value:match("^/%S+$") then
            return setting_failure(setting, "not_absolute_path")
        end
    end

    if params.expected_value ~= nil
        and normalize_for_compare(result.value) ~= normalize_for_compare(params.expected_value) then
        return setting_failure(setting, "unexpected_value")
    end

    if params.allowed_values then
        local allowed = allowed_value_set(params.allowed_values)
        if not allowed[normalize_for_compare(result.value)] then
            return setting_failure(setting, "unexpected_value")
        end
    end

    if params.min_value ~= nil and not compare_number(result.value, params.min_value, ">=") then
        return setting_failure(setting, "below_minimum")
    end

    if params.max_value ~= nil and not compare_number(result.value, params.max_value, "<=") then
        return setting_failure(setting, "above_maximum")
    end

    if params.max_values and not values_within_maximums(result.value, params.max_values) then
        return setting_failure(setting, "above_maximum")
    end

    setting.configured = true
    return setting
end

function M.inspect_effective_algorithm_list(params)
    if not (params and params.key and params.conditions and params.disallowed_algorithms) then
        return nil, "Probe 'ssh.inspect_effective_algorithm_list' requires 'key', 'conditions', and 'disallowed_algorithms' parameters."
    end

    local result, err = M.get_effective_value({
        key = params.key,
        conditions = params.conditions,
    })
    if not result then
        return nil, err
    end

    local algorithms = split_algorithm_list(result.value)
    local disallowed_set = build_algorithm_set(params.disallowed_algorithms)
    local disallowed = {}

    for _, algorithm in ipairs(algorithms) do
        if disallowed_set[normalize_for_compare(algorithm)] then
            disallowed[#disallowed + 1] = algorithm
        end
    end

    return {
        available = result.available,
        key = params.key,
        value = result.value,
        error = result.error,
        algorithms = algorithms,
        disallowed = disallowed,
        disallowed_count = #disallowed,
        configured = result.available ~= false
            and result.error == nil
            and #algorithms > 0
            and #disallowed == 0,
    }
end

function M.find_config_directive(params)
    if not (params and params.key) then
        return nil, "Probe 'ssh.find_config_directive' requires a 'key' parameter."
    end

    local files = discover_sshd_config_files(params)
    local details = {}
    local search_key = tostring(params.key):lower()
    local disallowed = allowed_value_set(params.disallowed_values or {})

    for _, path in ipairs(files) do
        local file, open_err = _dependencies.io_open(path, "r")
        if not file then
            return nil, string.format("Could not open sshd configuration '%s': %s",
                path, tostring(open_err))
        end

        local line_number = 0
        for line in file:lines() do
            line_number = line_number + 1
            local active = trim(strip_comment(line))
            local key, value = active:match("^(%S+)%s+(.+)$")
            if key and key:lower() == search_key then
                local matched = false
                if params.disallowed_values then
                    matched = disallowed[normalize_for_compare(value)] == true
                elseif params.numeric_min ~= nil then
                    local numeric = tonumber(value)
                    matched = numeric ~= nil and numeric >= tonumber(params.numeric_min)
                elseif params.numeric_max ~= nil then
                    local numeric = tonumber(value)
                    matched = numeric ~= nil and numeric <= tonumber(params.numeric_max)
                else
                    matched = true
                end

                if matched then
                    details[#details + 1] = {
                        path = path,
                        line = line_number,
                        key = key,
                        value = value,
                    }
                end
            end
        end
        file:close()
    end

    return {
        found = #details > 0,
        count = #details,
        checked_count = #files,
        details = details,
    }
end

function M.inspect_sysconfig_crypto_policy(params)
    params = params or {}
    local path = params.path or "/etc/sysconfig/sshd"
    local file = _dependencies.io_open(path, "r")
    if not file then
        return {
            available = false,
            path = path,
            active_present = false,
            commented_present = false,
            active_details = {},
            commented_details = {},
        }
    end

    local active_details = {}
    local commented_details = {}
    local line_number = 0
    for line in file:lines() do
        line_number = line_number + 1
        if line:match("^%s*#%s*CRYPTO_POLICY%s*=") then
            commented_details[#commented_details + 1] = {
                line = line_number,
                text = line,
            }
        elseif line:match("^%s*CRYPTO_POLICY%s*=") then
            active_details[#active_details + 1] = {
                line = line_number,
                text = line,
            }
        end
    end
    file:close()

    return {
        available = true,
        path = path,
        active_present = #active_details > 0,
        commented_present = #commented_details > 0,
        active_details = active_details,
        commented_details = commented_details,
    }
end

function M.inspect_config_file_access(params)
    params = params or {}
    local details = {}
    local invalid_count = 0

    for _, path in ipairs(discover_sshd_config_files(params)) do
        local access = get_file_access(path)
        access.configured = config_file_access_ok(access)
        details[#details + 1] = access
        if not access.configured then
            invalid_count = invalid_count + 1
        end
    end

    return {
        checked_count = #details,
        invalid_count = invalid_count,
        all_configured = #details > 0 and invalid_count == 0,
        details = details,
    }
end

function M.inspect_private_host_key_access(params)
    return inspect_host_key_access(params, "private", private_host_key_access_ok)
end

function M.inspect_public_host_key_access(params)
    return inspect_host_key_access(params, "public", public_host_key_access_ok)
end

function M.inspect_access_restrictions(params)
    if not params or not params.conditions then
        return nil, "Probe 'ssh.inspect_access_restrictions' requires 'conditions' parameters."
    end

    local configured = false
    local available = true
    local details = {}

    for _, key in ipairs({ "allowusers", "allowgroups", "denyusers", "denygroups" }) do
        local result, err = M.get_effective_value({
            key = key,
            conditions = params.conditions,
        })
        if not result then
            return nil, err
        end

        local value = trim(result.value)
        details[#details + 1] = {
            key = key,
            available = result.available,
            value = result.value,
            error = result.error,
            configured = value ~= "",
        }

        if result.available == false then
            available = false
        end
        if value ~= "" then
            configured = true
        end
    end

    return {
        available = available,
        configured = configured,
        details = details,
    }
end

return M
