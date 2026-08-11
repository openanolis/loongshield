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

--- Configure MTA for local-only mode (Postfix).
-- Runs 'postconf -e inet_interfaces=loopback-only' and restarts postfix.
-- Idempotent: if no MTA is installed, returns success with a log message.
-- When postfix is absent but another MTA (sendmail/exim) is present, returns
-- an explicit error so the rule is not silently reported as fixed.
function M.configure_mta_local_only(_params)
    -- Check if postconf exists (Postfix installed)
    local check_ok, _, check_code = _dependencies.os_execute('command -v postconf >/dev/null 2>&1')
    local has_postconf = check_ok == true or check_code == 0

    if not has_postconf then
        -- Another MTA may still violate the local-only requirement.
        local mta_ok, _, mta_code = _dependencies.os_execute(
            'command -v sendmail >/dev/null 2>&1 || command -v exim >/dev/null 2>&1'
        )
        local has_other_mta = mta_ok == true or mta_code == 0
        if has_other_mta then
            return nil,
                'network.configure_mta_local_only: postfix is not installed but another MTA (sendmail/exim) '
                    .. 'is present; configure that MTA for local-only mode manually'
        end
        log.debug('network.configure_mta_local_only: no MTA installed, skipping')
        return true
    end

    -- Set inet_interfaces = loopback-only
    local set_cmd = "postconf -e 'inet_interfaces = loopback-only'"
    log.info('network.configure_mta_local_only: %s', set_cmd)
    local ok, _, code = _dependencies.os_execute(set_cmd)
    if not ok and code ~= 0 then
        return nil,
            string.format('network.configure_mta_local_only: postconf failed (exit %s)', tostring(code))
    end

    -- Restart postfix to apply
    local restart_ok, _, restart_code = _dependencies.os_execute('systemctl restart postfix')
    if not restart_ok and restart_code ~= 0 then
        log.warn(
            'network.configure_mta_local_only: postfix restart failed (exit %s), config applied but not active',
            tostring(restart_code)
        )
    end

    return true
end

return M
