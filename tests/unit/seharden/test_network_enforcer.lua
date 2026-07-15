local network_enforcer = require('seharden.enforcers.network')

local function with_commands(commands, fn)
    network_enforcer._test_set_dependencies({
        os_execute = function(cmd)
            local item = commands[cmd]
            if item == nil then
                error('Unexpected command: ' .. tostring(cmd))
            end
            if item == false then
                return nil, 'exit', 1
            end
            return true, 'exit', 0
        end,
    })
    local ok, err = pcall(fn)
    network_enforcer._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_configure_mta_local_only_happy_path()
    with_commands({
        ['command -v postconf >/dev/null 2>&1'] = true,
        ["postconf -e 'inet_interfaces = loopback-only'"] = true,
        ['systemctl restart postfix'] = true,
    }, function()
        local ok, err = network_enforcer.configure_mta_local_only({})
        assert(ok == true, 'Expected configure_mta_local_only to succeed, got: ' .. tostring(err))
    end)
end

function test_configure_mta_local_only_postconf_failure_returns_error()
    with_commands({
        ['command -v postconf >/dev/null 2>&1'] = true,
        ["postconf -e 'inet_interfaces = loopback-only'"] = false,
    }, function()
        local ok, err = network_enforcer.configure_mta_local_only({})
        assert(ok == nil, 'Expected configure_mta_local_only to fail when postconf fails')
        assert(
            type(err) == 'string' and err:find('postconf failed', 1, true),
            'Expected error to mention postconf, got: ' .. tostring(err)
        )
    end)
end

function test_configure_mta_local_only_postfix_absent_other_mta_errors()
    with_commands({
        ['command -v postconf >/dev/null 2>&1'] = false,
        ['command -v sendmail >/dev/null 2>&1 || command -v exim >/dev/null 2>&1'] = true,
    }, function()
        local ok, err = network_enforcer.configure_mta_local_only({})
        assert(ok == nil, 'Expected configure_mta_local_only to fail when another MTA is present')
        assert(
            type(err) == 'string' and err:find('sendmail/exim', 1, true),
            'Expected error to mention the other MTA, got: ' .. tostring(err)
        )
    end)
end

function test_configure_mta_local_only_no_mta_installed_skips()
    with_commands({
        ['command -v postconf >/dev/null 2>&1'] = false,
        ['command -v sendmail >/dev/null 2>&1 || command -v exim >/dev/null 2>&1'] = false,
    }, function()
        local ok, err = network_enforcer.configure_mta_local_only({})
        assert(ok == true, 'Expected configure_mta_local_only to skip when no MTA is installed, got: ' .. tostring(err))
    end)
end

function test_configure_mta_local_only_restart_failure_still_reports_success()
    with_commands({
        ['command -v postconf >/dev/null 2>&1'] = true,
        ["postconf -e 'inet_interfaces = loopback-only'"] = true,
        ['systemctl restart postfix'] = false,
    }, function()
        local ok, err = network_enforcer.configure_mta_local_only({})
        assert(ok == true, 'Expected configure_mta_local_only to succeed even when restart fails')
    end)
end
