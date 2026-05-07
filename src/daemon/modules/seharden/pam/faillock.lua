local common = require('seharden.pam.common')

local M = {}

local function get_faillock_config(entry, default_config)
    local config_path = common.parse_option(entry.args, "conf")
    if config_path then
        local config, found = common.load_optional_key_value_file(config_path)
        if not found then
            return nil, "config_missing"
        end
        return config
    end

    return default_config or {}
end

local function get_faillock_deny(entry, params, default_config)
    local configured = common.parse_positive_integer(common.parse_option(entry.args, "deny"))
    if configured then
        return configured
    end

    local config, err = get_faillock_config(entry, default_config)
    if err then
        return nil, err
    end

    configured = common.parse_positive_integer(config.deny)
    if configured then
        return configured
    end

    return tonumber(params.default_deny) or 3
end

local function get_faillock_unlock_time(entry, params, default_config)
    local configured = common.parse_option(entry.args, "unlock_time")
    if configured ~= nil then
        if configured == "never" then
            return 0
        end
        configured = common.parse_non_negative_integer(configured)
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
    configured = common.parse_non_negative_integer(configured)
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

local function parse_bool_or_number(values, option)
    local value = values and values[option]
    if value == true then
        return true
    end
    return common.parse_non_negative_integer(value)
end

local function setting_from_config(params, values, details)
    local option = params.option

    if option == "deny" then
        local deny = common.parse_positive_integer(values and values.deny)
        local max_deny = tonumber(params.max_deny) or 5
        if deny and deny <= max_deny then
            return true, deny
        end
        common.add_detail(details, params.config_path or "/etc/security/faillock.conf",
            deny and "config_deny_too_large" or "config_deny_missing_or_invalid", {
                option = "deny",
                value = values and values.deny,
            })
        return false, deny
    end

    if option == "unlock_time" then
        local unlock_time = common.parse_non_negative_integer(values and values.unlock_time)
        local min_unlock_time = tonumber(params.min_unlock_time) or 900
        if unlock_time and (unlock_time == 0 or unlock_time >= min_unlock_time) then
            return true, unlock_time
        end
        common.add_detail(details, params.config_path or "/etc/security/faillock.conf",
            unlock_time and "config_unlock_time_too_short" or "config_unlock_time_missing_or_invalid", {
                option = "unlock_time",
                value = values and values.unlock_time,
            })
        return false, unlock_time
    end

    if option == "root_lockout" then
        local even_deny_root = values and values.even_deny_root == true
        local root_unlock_time = parse_bool_or_number(values, "root_unlock_time")
        if even_deny_root then
            return true, values.even_deny_root
        end
        if type(root_unlock_time) == "number" and root_unlock_time >= (tonumber(params.min_root_unlock_time) or 60) then
            return true, root_unlock_time
        end
        common.add_detail(details, params.config_path or "/etc/security/faillock.conf",
            root_unlock_time and "config_root_unlock_time_too_short" or "config_root_lockout_missing", {
                option = "root_lockout",
                value = values and (values.root_unlock_time or values.even_deny_root),
            })
        return false, root_unlock_time
    end

    return nil, nil, "unsupported_option"
end

local function module_argument_is_bad(option, value, params)
    if option == "deny" then
        local deny = common.parse_non_negative_integer(value)
        return deny == nil or deny == 0 or deny > (tonumber(params.max_deny) or 5)
    end
    if option == "unlock_time" then
        local unlock_time = common.parse_non_negative_integer(value)
        local min_unlock_time = tonumber(params.min_unlock_time) or 900
        return unlock_time == nil or (unlock_time > 0 and unlock_time < min_unlock_time)
    end
    if option == "root_unlock_time" then
        local root_unlock_time = common.parse_non_negative_integer(value)
        return root_unlock_time == nil or root_unlock_time < (tonumber(params.min_root_unlock_time) or 60)
    end
    return false
end

local function inspect_module_arguments(params, details)
    local pam_paths = params.pam_paths or {}
    local option = params.option == "root_lockout" and "root_unlock_time" or params.option
    local count = 0

    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            count = count + 1
            common.add_detail(details, path, "pam_file_unreadable")
        else
            for _, entry in ipairs(entries) do
                if entry.kind == "auth" and entry.module == "pam_faillock.so" then
                    local value = common.parse_option(entry.args, option)
                    if value ~= nil and module_argument_is_bad(option, value, params) then
                        count = count + 1
                        common.add_detail(details, path, "module_argument_invalid", {
                            option = option,
                            value = value,
                        })
                    end
                end
            end
        end
    end

    return count
end

function M.inspect(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.inspect_faillock")
    if not pam_paths then
        return nil, path_err
    end

    local default_config = {}
    if params.config_path then
        local config, found = common.load_optional_key_value_file(params.config_path)
        if found then
            default_config = config
        end
    end

    local details = {}

    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            common.add_detail(details, path, "pam_file_unreadable")
        else
            local faillock_entries = {}
            local has_preauth = false
            local has_authfail = false
            local has_authsucc = false

            for _, entry in ipairs(entries) do
                if entry.module == "pam_faillock.so" then
                    faillock_entries[#faillock_entries + 1] = entry
                    if entry.kind == "auth" and common.has_arg(entry.args, "preauth") then
                        has_preauth = true
                    elseif entry.kind == "auth" and common.has_arg(entry.args, "authfail") then
                        has_authfail = true
                    elseif entry.kind == "auth" and common.has_arg(entry.args, "authsucc") then
                        has_authsucc = true
                    end
                end
            end

            if #faillock_entries == 0 then
                common.add_detail(details, path, "module_missing")
            elseif not has_authfail or not (has_authsucc or has_preauth) then
                common.add_detail(details, path, "stack_incomplete")
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
                    common.add_detail(details, path, path_reason)
                end
            end
        end
    end

    return {
        count = #details,
        details = details
    }
end

function M.inspect_setting(params)
    if not params or not params.option then
        return nil, "Probe 'pam.inspect_faillock_setting' requires an 'option' parameter."
    end

    local config_path = params.config_path or "/etc/security/faillock.conf"
    local values, _, _, err = common.load_ordered_settings({ config_path })
    if err then
        return {
            available = false,
            compliant = false,
            count = 1,
            option = params.option,
            config_compliant = false,
            module_argument_violation_count = 0,
            details = {
                {
                    path = config_path,
                    reason = "config_unreadable",
                    error = err,
                }
            },
        }
    end

    local details = {}
    local config_ok, config_value, config_err = setting_from_config(params, values or {}, details)
    if config_err then
        return nil, "Probe 'pam.inspect_faillock_setting' option must be one of: deny, unlock_time, root_lockout."
    end

    local module_argument_violation_count = inspect_module_arguments(params, details)
    local compliant = config_ok and module_argument_violation_count == 0

    return {
        available = true,
        compliant = compliant,
        count = compliant and 0 or #details,
        option = params.option,
        config_value = config_value,
        config_compliant = config_ok,
        module_argument_violation_count = module_argument_violation_count,
        details = details,
    }
end

return M
