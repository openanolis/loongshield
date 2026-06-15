local log = require('runtime.log')
local M = {}

local _default_dependencies = {
    os_execute = os.execute,
}

local _dependencies = {}

function M._test_set_dependencies(deps)
    deps = deps or {}
    for key, default in pairs(_default_dependencies) do
        _dependencies[key] = deps[key] or default
    end
end

M._test_set_dependencies()

-- Fix access permissions on log files under /var/log.
-- Iterates the details from logging.inspect_logfile_access probe
-- and applies chmod/chown for each non-compliant file.
-- params: { details (required): list from probe }
function M.fix_logfile_access(params)
    if not params or not params.details or type(params.details) ~= 'table' then
        return nil, "logging.fix_logfile_access: requires 'details' from probe"
    end

    local fixed_count = 0
    local skipped_count = 0
    local errors = {}

    for _, detail in ipairs(params.details) do
        if detail.configured then
            skipped_count = skipped_count + 1
            goto continue
        end

        local path = detail.path
        if not path or not detail.exists then
            skipped_count = skipped_count + 1
            goto continue
        end

        local file_fixed = true

        -- Fix mode if needed
        if not detail.mode_ok and detail.expected_mode then
            local mode_str = string.format('%04o', detail.expected_mode)
            local cmd = string.format("chmod %s '%s' 2>&1", mode_str, path)
            log.debug('logging.fix_logfile_access: %s', cmd)
            local ok, _, code = _dependencies.os_execute(cmd)
            if not ok and code ~= 0 then
                errors[#errors + 1] =
                    string.format("chmod %s failed (exit %s) for '%s'", mode_str, tostring(code), path)
                file_fixed = false
            end
        end

        -- Fix owner/group if needed
        if not detail.owner_ok or not detail.group_ok then
            local target_owner = detail.allowed_owners and detail.allowed_owners[1] or 'root'
            local target_group = detail.allowed_groups and detail.allowed_groups[1] or 'root'
            local cmd = string.format("chown %s:%s '%s' 2>&1", target_owner, target_group, path)
            log.debug('logging.fix_logfile_access: %s', cmd)
            local ok, _, code = _dependencies.os_execute(cmd)
            if not ok and code ~= 0 then
                errors[#errors + 1] = string.format(
                    "chown %s:%s failed (exit %s) for '%s'",
                    target_owner,
                    target_group,
                    tostring(code),
                    path
                )
                file_fixed = false
            end
        end

        if file_fixed then
            fixed_count = fixed_count + 1
        end

        ::continue::
    end

    if #errors > 0 then
        for _, err in ipairs(errors) do
            log.warn('logging.fix_logfile_access: %s', err)
        end
    end

    log.debug(
        'logging.fix_logfile_access: fixed %d file(s), skipped %d, %d error(s)',
        fixed_count,
        skipped_count,
        #errors
    )

    if #errors > 0 then
        return nil, string.format('logging.fix_logfile_access: %d error(s): %s', #errors, errors[1])
    end

    return true
end

return M
