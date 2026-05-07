local common = require('seharden.pam.common')

local M = {}

local function get_remember_value(entry, default_config)
    local remember = tonumber(common.parse_option(entry.args, "remember"))
    if remember then
        return remember
    end

    if entry.module ~= "pam_pwhistory.so" then
        return nil
    end

    local config_path = common.parse_option(entry.args, "conf")
    if config_path then
        local config, found = common.load_optional_key_value_file(config_path)
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

local function flag_is_enabled(value)
    if value == true then
        return true
    end

    local normalized = tostring(value or ""):lower()
    return normalized == "1" or normalized == "yes" or normalized == "true"
end

local function inspect_remember_arguments(params, details)
    local count = 0
    local min_remember = tonumber(params.min_remember) or 24

    for _, path in ipairs(params.pam_paths or {}) do
        local entries = common.load_pam_entries(path)
        if not entries then
            count = count + 1
            common.add_detail(details, path, "pam_file_unreadable")
        else
            for _, entry in ipairs(entries) do
                if entry.kind == "password" and entry.module == "pam_pwhistory.so" then
                    local remember_text = common.parse_option(entry.args, "remember")
                    if remember_text ~= nil then
                        local remember = common.parse_positive_integer(remember_text)
                        if not remember or remember < min_remember then
                            count = count + 1
                            common.add_detail(details, path, "module_argument_remember_too_small", {
                                value = remember_text,
                            })
                        end
                    end
                end
            end
        end
    end

    return count
end

local function inspect_use_authtok(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.inspect_pwhistory_setting")
    if not pam_paths then
        return nil, path_err
    end

    local details = {}
    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            common.add_detail(details, path, "pam_file_unreadable")
        else
            local found = false
            for _, entry in ipairs(entries) do
                if entry.kind == "password" and entry.module == "pam_pwhistory.so" then
                    found = true
                    if not common.has_arg(entry.args, "use_authtok") then
                        common.add_detail(details, path, "use_authtok_missing")
                    end
                end
            end
            if not found then
                common.add_detail(details, path, "module_missing")
            end
        end
    end

    return {
        available = true,
        compliant = #details == 0,
        count = #details,
        option = "use_authtok",
        details = details,
    }
end

function M.check(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.check_password_history")
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

    local default_config, _, err = common.load_optional_key_value_files(default_config_paths)
    if err then
        return nil, err
    end

    local details = {}

    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
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
            common.add_detail(details, path,
                saw_history_module and "remember_too_small_or_missing" or "module_missing")
        end
    end

    return {
        count = #details,
        details = details
    }
end

function M.inspect_setting(params)
    if not params or not params.option then
        return nil, "Probe 'pam.inspect_pwhistory_setting' requires an 'option' parameter."
    end

    if params.option == "use_authtok" then
        return inspect_use_authtok(params)
    end

    local config_path = params.config_path or "/etc/security/pwhistory.conf"
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
    local config_ok = false
    local config_value = values and values[params.option]

    if params.option == "remember" then
        local remember = common.parse_positive_integer(config_value)
        config_value = remember
        config_ok = remember ~= nil and remember >= (tonumber(params.min_remember) or 24)
        if not config_ok then
            common.add_detail(details, config_path, "config_remember_missing_or_too_small", {
                value = values and values.remember,
            })
        end
    elseif params.option == "enforce_for_root" then
        config_ok = flag_is_enabled(config_value)
        if not config_ok then
            common.add_detail(details, config_path, "config_enforce_for_root_missing")
        end
    else
        return nil, "Probe 'pam.inspect_pwhistory_setting' option must be one of: remember, enforce_for_root, use_authtok."
    end

    local module_argument_violation_count = 0
    if params.option == "remember" then
        module_argument_violation_count = inspect_remember_arguments(params, details)
    end

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
