local common = require('seharden.pam_common')

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

return M
