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

return M
