local file_probe = require('seharden.probes.file')
local M = {}

local _default_dependencies = {
    io_open = io.open,
    expand_paths = function(paths)
        local result, err = file_probe.list_paths({ paths = paths })
        if not result then
            return nil, err
        end

        local expanded = {}
        for _, item in ipairs(result.details or {}) do
            expanded[#expanded + 1] = item.path
        end
        return expanded
    end,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

local function trim(value)
    return (tostring(value or ""):match("^%s*(.-)%s*$"))
end

local function resolve_pam_paths(params, probe_name)
    local pam_paths = params and params.pam_paths
    if type(pam_paths) ~= "table" or #pam_paths == 0 then
        return nil, string.format("Probe '%s' requires a non-empty 'pam_paths' list.", probe_name)
    end
    return pam_paths
end

local function add_detail(details, path, reason, extra)
    local detail = {
        path = path,
        reason = reason,
    }

    for key, value in pairs(extra or {}) do
        detail[key] = value
    end

    details[#details + 1] = detail
end

local function strip_inline_comment(line)
    local in_quote = false

    for index = 1, #line do
        local char = line:sub(index, index)
        if char == '"' then
            in_quote = not in_quote
        elseif char == "#" and not in_quote then
            local previous = index > 1 and line:sub(index - 1, index - 1) or nil
            if previous == nil or previous:match("%s") then
                return line:sub(1, index - 1)
            end
        end
    end

    return line
end

local function parse_key_value_lines(handle)
    local values = {}

    for line in handle:lines() do
        local trimmed = trim(strip_inline_comment(line))
        if trimmed ~= "" and not trimmed:match("^#") then
            local key, value = trimmed:match("^([^=%s]+)%s*=%s*(.-)%s*$")
            if not key then
                key, value = trimmed:match("^([%S]+)%s+(.-)%s*$")
            end

            if key and value then
                value = value:gsub('^"', ''):gsub('"$', '')
                values[key] = value
            end
        end
    end

    return values
end

local function load_optional_key_value_file(path)
    local file = _dependencies.io_open(path, "r")
    if not file then
        return nil, false
    end

    local values = parse_key_value_lines(file)
    file:close()
    return values, true
end

local function expand_ordered_paths(path_specs)
    local expanded = {}
    local seen = {}

    for _, path_spec in ipairs(path_specs or {}) do
        local matches, err = _dependencies.expand_paths({ path_spec })
        if not matches then
            return nil, err
        end

        table.sort(matches)
        for _, path in ipairs(matches) do
            if not seen[path] then
                expanded[#expanded + 1] = path
                seen[path] = true
            end
        end
    end

    return expanded
end

local function load_optional_key_value_files(path_specs)
    local paths, err = expand_ordered_paths(path_specs)
    if not paths then
        return nil, false, err
    end

    local values = {}
    local found = false

    for _, path in ipairs(paths) do
        local parsed, file_found = load_optional_key_value_file(path)
        if not file_found then
            return nil, false, string.format("Could not open config file '%s' for reading.", path)
        end
        found = true

        for key, value in pairs(parsed) do
            values[key] = value
        end
    end

    return values, found
end

local function parse_pam_line(line)
    local trimmed = trim(line)
    if trimmed == "" or trimmed:match("^#") then
        return nil
    end

    local kind, remainder = trimmed:match("^(%S+)%s+(.+)$")
    if not kind or not remainder then
        return nil
    end

    local control
    local module_name
    local args_text

    if remainder:sub(1, 1) == "[" then
        control, module_name, args_text = remainder:match("^(%b[])%s+(%S+)%s*(.*)$")
    else
        control, module_name, args_text = remainder:match("^(%S+)%s+(%S+)%s*(.*)$")
    end

    if not control or not module_name then
        return nil
    end

    local tokens = {}
    for token in tostring(args_text or ""):gmatch("%S+") do
        tokens[#tokens + 1] = token
    end

    return {
        kind = kind,
        control = control,
        module = module_name,
        args = tokens,
    }
end

local function parse_option(args, option_name)
    for _, arg in ipairs(args) do
        local value = arg:match("^" .. option_name .. "=(.+)$")
        if value then
            return value
        end
    end
    return nil
end

local function has_arg(args, option_name)
    for _, arg in ipairs(args) do
        if arg == option_name then
            return true
        end
    end
    return false
end

local function parse_non_negative_integer(value)
    local number = tonumber(value)
    if not number or number < 0 then
        return nil
    end
    return number
end

local function parse_positive_integer(value)
    local number = tonumber(value)
    if not number or number < 1 then
        return nil
    end
    return number
end

local function parse_integer(value)
    local number = tonumber(value)
    if number == nil then
        return nil
    end
    return number
end

local function load_pam_entries(path)
    local file = _dependencies.io_open(path, "r")
    if not file then
        return nil
    end

    local entries = {}
    for line in file:lines() do
        local entry = parse_pam_line(line)
        if entry then
            entries[#entries + 1] = entry
        end
    end
    file:close()
    return entries
end

local function load_pwquality_config(entry, default_config)
    local config_path = parse_option(entry.args, "conf")
    if not config_path then
        return default_config or {}
    end

    local config, found = load_optional_key_value_file(config_path)
    if not found then
        return nil, "config_missing"
    end

    return config
end

local function read_entry_integer(entry, config, option_name, parser)
    local value = parser(parse_option(entry.args, option_name))
    if value ~= nil then
        return value
    end

    return parser(config and config[option_name])
end

local function get_remember_value(entry, default_config)
    local remember = tonumber(parse_option(entry.args, "remember"))
    if remember then
        return remember
    end

    if entry.module ~= "pam_pwhistory.so" then
        return nil
    end

    local config_path = parse_option(entry.args, "conf")
    if config_path then
        local config, found = load_optional_key_value_file(config_path)
        if not found then
            return nil
        end
        return tonumber(config.remember)
    end

    return tonumber(default_config and default_config.remember)
end

local function is_password_history_module(module_name)
    return module_name == "pam_pwhistory.so" or module_name == "pam_unix.so"
end

function M.check_password_history(params)
    local pam_paths, path_err = resolve_pam_paths(params, "pam.check_password_history")
    if not pam_paths then
        return nil, path_err
    end

    local min_remember = tonumber(params.min_remember) or 24
    if min_remember < 1 then
        return nil, "Probe 'pam.check_password_history' requires a positive 'min_remember' parameter."
    end

    local default_config_paths = params.config_paths
    if type(default_config_paths) ~= "table" or #default_config_paths == 0 then
        default_config_paths = { params.config_path or "/etc/security/pwhistory.conf" }
    end

    local default_config, _, err = load_optional_key_value_files(default_config_paths)
    if err then
        return nil, err
    end

    local details = {}

    for _, path in ipairs(pam_paths) do
        local entries = load_pam_entries(path)
        if not entries then
            return nil, string.format("Could not open PAM file '%s' for reading.", path)
        end

        local path_ok = false
        local saw_history_module = false
        for _, entry in ipairs(entries) do
            if entry.kind == "password" and is_password_history_module(entry.module) then
                saw_history_module = true
                local remember = get_remember_value(entry, default_config)
                if remember and remember >= min_remember then
                    path_ok = true
                    break
                end
            end
        end

        if not path_ok then
            add_detail(details, path,
                saw_history_module and "remember_too_small_or_missing" or "module_missing")
        end
    end

    return {
        count = #details,
        details = details
    }
end

local function count_pwquality_required_classes(entry, config)
    local required_classes = 0
    for _, option_name in ipairs({ "dcredit", "ucredit", "lcredit", "ocredit" }) do
        local configured_value = read_entry_integer(entry, config, option_name, parse_integer)

        if configured_value and configured_value < 0 then
            required_classes = required_classes + 1
        end
    end

    return required_classes
end

local function get_pwquality_policy(entry, default_config, params)
    local config, err = load_pwquality_config(entry, default_config)
    if err then
        return nil, err
    end

    local minlen = read_entry_integer(entry, config, "minlen", parse_positive_integer)
    if minlen == nil then
        minlen = tonumber(params.default_minlen) or 8
    end

    local required_classes = read_entry_integer(entry, config, "minclass", parse_positive_integer)
    if required_classes == nil then
        required_classes = count_pwquality_required_classes(entry, config)
    end

    return {
        minlen = minlen,
        required_classes = required_classes,
    }
end

function M.inspect_pwquality(params)
    local pam_paths, path_err = resolve_pam_paths(params, "pam.inspect_pwquality")
    if not pam_paths then
        return nil, path_err
    end

    local min_minlen = tonumber(params.min_minlen) or 8
    if min_minlen < 1 then
        return nil, "Probe 'pam.inspect_pwquality' requires a positive 'min_minlen' parameter."
    end
    local min_minclass = tonumber(params.min_minclass) or 3
    if min_minclass < 1 then
        return nil, "Probe 'pam.inspect_pwquality' requires a positive 'min_minclass' parameter."
    end

    local default_config, _, err = load_optional_key_value_files(params.config_paths or {})
    if err then
        return nil, err
    end

    local details = {}
    local missing_module_count = 0
    local weak_minlen_count = 0
    local weak_complexity_count = 0

    for _, path in ipairs(pam_paths) do
        local entries = load_pam_entries(path)
        if not entries then
            missing_module_count = missing_module_count + 1
            weak_minlen_count = weak_minlen_count + 1
            add_detail(details, path, "pam_file_unreadable")
        else
            local enabled = false
            local minlen_ok = false
            local complexity_ok = false
            local failure_reason = "module_missing"
            local effective_minlen = nil
            local effective_required_classes = nil

            for _, entry in ipairs(entries) do
                if entry.kind == "password" and entry.module == "pam_pwquality.so" then
                    enabled = true
                    local policy, policy_err = get_pwquality_policy(entry, default_config, params)

                    if policy_err then
                        failure_reason = policy_err
                    else
                        local minlen = policy.minlen
                        local required_classes = policy.required_classes
                        effective_minlen = minlen
                        effective_required_classes = required_classes
                        minlen_ok = minlen and minlen >= min_minlen
                        complexity_ok = required_classes and required_classes >= min_minclass

                        if minlen_ok and complexity_ok then
                            break
                        end

                        if not minlen_ok then
                            failure_reason = "minlen_too_small"
                        elseif not complexity_ok then
                            failure_reason = "complexity_too_weak"
                        end
                    end
                end
            end

            if not enabled then
                missing_module_count = missing_module_count + 1
                weak_minlen_count = weak_minlen_count + 1
                add_detail(details, path, "module_missing")
            else
                if not minlen_ok then
                    weak_minlen_count = weak_minlen_count + 1
                end
                if not complexity_ok then
                    weak_complexity_count = weak_complexity_count + 1
                end

                if not minlen_ok or not complexity_ok then
                    add_detail(details, path, failure_reason, {
                        effective_required_classes = effective_required_classes,
                        effective_minlen = effective_minlen
                    })
                end
            end
        end
    end

    return {
        count = #details,
        missing_module_count = missing_module_count,
        weak_complexity_count = weak_complexity_count,
        weak_minlen_count = weak_minlen_count,
        details = details
    }
end

local function get_faillock_config(entry, default_config)
    local config_path = parse_option(entry.args, "conf")
    if config_path then
        local config, found = load_optional_key_value_file(config_path)
        if not found then
            return nil, "config_missing"
        end
        return config
    end

    return default_config or {}
end

local function get_faillock_deny(entry, params, default_config)
    local configured = parse_positive_integer(parse_option(entry.args, "deny"))
    if configured then
        return configured
    end

    local config, err = get_faillock_config(entry, default_config)
    if err then
        return nil, err
    end

    configured = parse_positive_integer(config.deny)
    if configured then
        return configured
    end

    return tonumber(params.default_deny) or 3
end

local function get_faillock_unlock_time(entry, params, default_config)
    local configured = parse_option(entry.args, "unlock_time")
    if configured ~= nil then
        if configured == "never" then
            return 0
        end
        configured = parse_non_negative_integer(configured)
        if configured then
            return configured
        end
        return nil, "unlock_time_invalid"
    end

    local config, err = get_faillock_config(entry, default_config)
    if err then
        return nil, err
    end

    configured = config.unlock_time
    if configured == "never" then
        return 0
    end
    configured = parse_non_negative_integer(configured)
    if configured then
        return configured
    end
    if config.unlock_time ~= nil then
        return nil, "unlock_time_invalid"
    end

    return tonumber(params.default_unlock_time) or 600
end

local function is_faillock_deny_compliant(deny, params)
    local maximum_deny = tonumber(params.default_deny) or 3
    return deny ~= nil and deny >= 1 and deny <= maximum_deny
end

local function is_faillock_unlock_time_compliant(unlock_time, params)
    local minimum_unlock_time = tonumber(params.default_unlock_time) or 600
    return unlock_time == 0 or (unlock_time ~= nil and unlock_time >= minimum_unlock_time)
end

function M.inspect_faillock(params)
    local pam_paths, path_err = resolve_pam_paths(params, "pam.inspect_faillock")
    if not pam_paths then
        return nil, path_err
    end

    local default_config = {}
    if params.config_path then
        local config, found = load_optional_key_value_file(params.config_path)
        if found then
            default_config = config
        end
    end

    local details = {}

    for _, path in ipairs(pam_paths) do
        local entries = load_pam_entries(path)
        if not entries then
            add_detail(details, path, "pam_file_unreadable")
        else
            local faillock_entries = {}
            local has_preauth = false
            local has_authfail = false
            local has_authsucc = false

            for _, entry in ipairs(entries) do
                if entry.module == "pam_faillock.so" then
                    faillock_entries[#faillock_entries + 1] = entry
                    if entry.kind == "auth" and has_arg(entry.args, "preauth") then
                        has_preauth = true
                    elseif entry.kind == "auth" and has_arg(entry.args, "authfail") then
                        has_authfail = true
                    elseif entry.kind == "auth" and has_arg(entry.args, "authsucc") then
                        has_authsucc = true
                    end
                end
            end

            if #faillock_entries == 0 then
                add_detail(details, path, "module_missing")
            elseif not has_authfail or not (has_authsucc or has_preauth) then
                add_detail(details, path, "stack_incomplete")
            else
                local path_reason = nil
                for _, entry in ipairs(faillock_entries) do
                    local deny, deny_err = get_faillock_deny(entry, params, default_config)
                    local unlock_time, unlock_err = get_faillock_unlock_time(entry, params, default_config)
                    if deny_err then
                        path_reason = deny_err
                        break
                    end
                    if unlock_err then
                        path_reason = unlock_err
                        break
                    end
                    if not is_faillock_deny_compliant(deny, params) then
                        if deny == nil or deny < 1 then
                            path_reason = "deny_invalid"
                        else
                            path_reason = "deny_too_large"
                        end
                        break
                    end
                    if not is_faillock_unlock_time_compliant(unlock_time, params) then
                        if unlock_time == nil or unlock_time < 0 then
                            path_reason = "unlock_time_invalid"
                        else
                            path_reason = "unlock_time_too_short"
                        end
                        break
                    end
                end

                if path_reason then
                    add_detail(details, path, path_reason)
                end
            end
        end
    end

    return {
        count = #details,
        details = details
    }
end

local function is_restrictive_wheel_control(control)
    if control == "required" or control == "requisite" then
        return true
    end

    if type(control) == "string" and control:sub(1, 1) == "[" then
        return control:match("default=die") ~= nil or control:match("default=bad") ~= nil
    end

    return false
end

local function get_wheel_entry_reason(entry)
    if has_arg(entry.args, "deny") then
        return "deny_enabled"
    end

    if has_arg(entry.args, "trust") then
        return "trust_enabled"
    end

    if not has_arg(entry.args, "use_uid") then
        return "use_uid_missing"
    end

    if not is_restrictive_wheel_control(entry.control) then
        return "control_not_restrictive"
    end

    return nil
end

function M.inspect_wheel(params)
    local pam_paths, path_err = resolve_pam_paths(params, "pam.inspect_wheel")
    if not pam_paths then
        return nil, path_err
    end

    local details = {}

    for _, path in ipairs(pam_paths) do
        local entries = load_pam_entries(path)
        if not entries then
            add_detail(details, path, "pam_file_unreadable")
        else
            local found_module = false
            local compliant = false
            local dangerous_reason
            local weak_reason

            for _, entry in ipairs(entries) do
                if entry.kind == "auth" and entry.module == "pam_wheel.so" then
                    found_module = true
                    local reason = get_wheel_entry_reason(entry)
                    if reason == nil then
                        compliant = true
                    elseif reason == "deny_enabled" or reason == "trust_enabled" then
                        dangerous_reason = reason
                        break
                    elseif weak_reason == nil then
                        weak_reason = reason
                    end
                end
            end

            if dangerous_reason or not compliant then
                local reason = "module_missing"
                if dangerous_reason then
                    reason = dangerous_reason
                elseif found_module and weak_reason then
                    reason = weak_reason
                end

                add_detail(details, path, reason)
            end
        end
    end

    return {
        count = #details,
        details = details
    }
end

return M
