local common = require('seharden.pam.common')

local M = {}

local function load_pwquality_config(entry, default_config)
    local config_path = common.parse_option(entry.args, "conf")
    if not config_path then
        return default_config or {}
    end

    local config, found = common.load_optional_key_value_file(config_path)
    if not found then
        return nil, "config_missing"
    end

    return config
end

local function read_entry_integer(entry, config, option_name, parser)
    local value = parser(common.parse_option(entry.args, option_name))
    if value ~= nil then
        return value
    end

    return parser(config and config[option_name])
end

local function count_pwquality_required_classes(entry, config)
    local required_classes = 0
    for _, option_name in ipairs({ "dcredit", "ucredit", "lcredit", "ocredit" }) do
        local configured_value = read_entry_integer(entry, config, option_name, common.parse_integer)

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

    local minlen = read_entry_integer(entry, config, "minlen", common.parse_positive_integer)
    if minlen == nil then
        minlen = tonumber(params.default_minlen) or 8
    end

    local required_classes = read_entry_integer(entry, config, "minclass", common.parse_positive_integer)
    if required_classes == nil then
        required_classes = count_pwquality_required_classes(entry, config)
    end

    return {
        minlen = minlen,
        required_classes = required_classes,
    }
end

local function as_number(value)
    if value == true or value == nil then
        return nil
    end
    return tonumber(value)
end

local function value_is_disallowed(value, disallowed_values)
    if type(disallowed_values) ~= "table" then
        return false
    end

    local text_value = tostring(value)
    local numeric_value = tonumber(value)
    for _, disallowed in ipairs(disallowed_values) do
        if text_value == tostring(disallowed) then
            return true
        end
        local numeric_disallowed = tonumber(disallowed)
        if numeric_value ~= nil and numeric_disallowed ~= nil and numeric_value == numeric_disallowed then
            return true
        end
    end
    return false
end

local function flag_is_enabled(value)
    if value == true then
        return true
    end

    local normalized = tostring(value or ""):lower()
    return normalized == "1" or normalized == "yes" or normalized == "true"
end

local function setting_is_compliant(value, params)
    if params.require_flag and not flag_is_enabled(value) then
        return false, "flag_missing_or_disabled"
    end

    if params.require_present and value == nil then
        return false, "setting_missing"
    end

    if value == nil and params.default_value ~= nil then
        value = params.default_value
    end

    if value_is_disallowed(value, params.disallowed_values) then
        return false, "disallowed_value"
    end

    if params.min_value ~= nil or params.max_value ~= nil then
        local numeric = as_number(value)
        if numeric == nil then
            return false, "value_invalid"
        end
        if params.min_value ~= nil and numeric < tonumber(params.min_value) then
            return false, "value_too_small"
        end
        if params.max_value ~= nil and numeric > tonumber(params.max_value) then
            return false, "value_too_large"
        end
    end

    return true
end

local function inspect_module_arguments(params, details)
    local pam_paths = params.pam_paths or {}
    local option = params.option
    local count = 0

    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            count = count + 1
            common.add_detail(details, path, "pam_file_unreadable")
        else
            for _, entry in ipairs(entries) do
                if entry.kind == "password" and entry.module == "pam_pwquality.so" then
                    local value = common.parse_option(entry.args, option)
                    if value ~= nil then
                        local ok, reason = setting_is_compliant(value, params)
                        if not ok then
                            count = count + 1
                            common.add_detail(details, path, "module_argument_" .. reason, {
                                option = option,
                                value = value,
                            })
                        end
                    end
                end
            end
        end
    end

    return count
end

function M.inspect(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.inspect_pwquality")
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

    local default_config, _, err = common.load_optional_key_value_files(params.config_paths or {})
    if err then
        return nil, err
    end

    local details = {}
    local missing_module_count = 0
    local weak_minlen_count = 0
    local weak_complexity_count = 0

    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            missing_module_count = missing_module_count + 1
            weak_minlen_count = weak_minlen_count + 1
            common.add_detail(details, path, "pam_file_unreadable")
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
                common.add_detail(details, path, "module_missing")
            else
                if not minlen_ok then
                    weak_minlen_count = weak_minlen_count + 1
                end
                if not complexity_ok then
                    weak_complexity_count = weak_complexity_count + 1
                end

                if not minlen_ok or not complexity_ok then
                    common.add_detail(details, path, failure_reason, {
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

function M.inspect_setting(params)
    if not params or not params.option then
        return nil, "Probe 'pam.inspect_pwquality_setting' requires an 'option' parameter."
    end

    local option = params.option
    local config_paths = params.config_paths or {
        "/etc/security/pwquality.conf.d/*.conf",
        "/etc/security/pwquality.conf",
    }
    local values, _, _, err = common.load_ordered_settings(config_paths)
    if err then
        return {
            available = false,
            compliant = false,
            count = 1,
            option = option,
            config_compliant = false,
            module_argument_violation_count = 0,
            details = {
                {
                    path = table.concat(config_paths, ","),
                    reason = "config_unreadable",
                    error = err,
                }
            },
        }
    end

    local config_value = values and values[option]
    if config_value == nil and params.default_value ~= nil then
        config_value = params.default_value
    end

    local config_ok, config_reason = setting_is_compliant(config_value, params)
    local details = {}
    if not config_ok then
        common.add_detail(details, params.config_paths and table.concat(params.config_paths, ",") or option,
            "config_" .. config_reason, {
                option = option,
                value = config_value,
            })
    end

    local module_argument_violation_count = inspect_module_arguments(params, details)
    local compliant = config_ok and module_argument_violation_count == 0

    return {
        available = true,
        compliant = compliant,
        count = compliant and 0 or #details,
        option = option,
        config_value = config_value,
        config_compliant = config_ok,
        module_argument_violation_count = module_argument_violation_count,
        details = details,
    }
end

return M
