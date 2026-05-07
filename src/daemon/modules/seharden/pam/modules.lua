local common = require('seharden.pam.common')

local M = {}

local REQUIREMENTS = {
    faillock = {
        { kind = "auth", module = "pam_faillock.so", arg = "preauth" },
        { kind = "auth", module = "pam_faillock.so", arg = "authfail" },
        { kind = "account", module = "pam_faillock.so" },
    },
    pwquality = {
        { kind = "password", module = "pam_pwquality.so" },
    },
    pwhistory = {
        { kind = "password", module = "pam_pwhistory.so" },
    },
}

local function entry_matches(entry, requirement)
    if entry.kind ~= requirement.kind or entry.module ~= requirement.module then
        return false
    end
    if requirement.arg and not common.has_arg(entry.args, requirement.arg) then
        return false
    end
    return true
end

local function has_requirement(entries, requirement)
    for _, entry in ipairs(entries) do
        if entry_matches(entry, requirement) then
            return true
        end
    end
    return false
end

function M.inspect(params)
    local pam_paths, path_err = common.resolve_pam_paths(params, "pam.inspect_module")
    if not pam_paths then
        return nil, path_err
    end

    local module_name = params.module
    local requirements = REQUIREMENTS[module_name]
    if not requirements then
        return nil, "Probe 'pam.inspect_module' requires module to be one of: faillock, pwquality, pwhistory."
    end

    local details = {}

    for _, path in ipairs(pam_paths) do
        local entries = common.load_pam_entries(path)
        if not entries then
            common.add_detail(details, path, "pam_file_unreadable")
        else
            for _, requirement in ipairs(requirements) do
                if not has_requirement(entries, requirement) then
                    common.add_detail(details, path, "requirement_missing", {
                        kind = requirement.kind,
                        module = requirement.module,
                        arg = requirement.arg,
                    })
                end
            end
        end
    end

    return {
        count = #details,
        details = details,
    }
end

return M
