local common = require('seharden.pam.common')

local M = {}

local function is_restrictive_wheel_control(control)
    if control == "required" or control == "requisite" then
        return true
    end

    if type(control) == "string" and control:sub(1, 1) == "[" then
        return control:match("default=die") ~= nil or control:match("default=bad") ~= nil
    end

    return false
end

local function group_membership_reason(group_name, groups)
    if group_name == nil or group_name == "" then
        return "group_missing"
    end
    if groups == nil or groups[group_name] == nil then
        return "group_not_found"
    end
    if #groups[group_name] > 0 then
        return "group_not_empty"
    end
    return nil
end

local function get_wheel_entry_reason(entry, opts)
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

    if opts and opts.require_empty_group then
        return group_membership_reason(common.parse_option(entry.args, "group"), opts.groups)
    end

    return nil
end

function M.inspect(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.inspect_wheel")
    if not pam_paths then
        return nil, path_err
    end

    local details = {}
    local group_members
    if params.require_empty_group then
        group_members = common.load_group_members(params.group_path or "/etc/group")
        if not group_members then
            return {
                count = 1,
                details = {
                    {
                        path = params.group_path or "/etc/group",
                        reason = "group_file_unreadable",
                    },
                },
            }
        end
    end

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
                    local reason = get_wheel_entry_reason(entry, {
                        require_empty_group = params.require_empty_group,
                        groups = group_members,
                    })
                    if reason == nil then
                        compliant = true
                    elseif reason == "deny_enabled"
                        or reason == "trust_enabled"
                        or reason == "group_not_empty" then
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
