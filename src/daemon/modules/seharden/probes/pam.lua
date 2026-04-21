local common = require('seharden.pam_common')
local faillock = require('seharden.pam.faillock')
local password_history = require('seharden.pam.password_history')
local pwquality = require('seharden.pam.pwquality')
local M = {}

function M._test_set_dependencies(deps)
    common._test_set_dependencies(deps)
end

M._test_set_dependencies()

function M.check_password_history(params)
    return password_history.check(params)
end

function M.inspect_pwquality(params)
    return pwquality.inspect(params)
end

function M.inspect_faillock(params)
    return faillock.inspect(params)
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
    if common.has_arg(entry.args, "deny") then
        return "deny_enabled"
    end

    if common.has_arg(entry.args, "trust") then
        return "trust_enabled"
    end

    if not common.has_arg(entry.args, "use_uid") then
        return "use_uid_missing"
    end

    if not is_restrictive_wheel_control(entry.control) then
        return "control_not_restrictive"
    end

    return nil
end

function M.inspect_wheel(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.inspect_wheel")
    if not pam_paths then
        return nil, path_err
    end

    local details = {}

    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            common.add_detail(details, path, "pam_file_unreadable")
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

                common.add_detail(details, path, reason)
            end
        end
    end

    return {
        count = #details,
        details = details
    }
end

return M
