local common = require('seharden.pam_common')

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

return M
