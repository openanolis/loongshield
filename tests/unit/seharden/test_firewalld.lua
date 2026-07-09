local firewalld_probe = require('seharden.probes.firewalld')

local function make_reader(output, exit_code)
    output = tostring(output or '')
    local lines = {}
    for line in (output .. '\n'):gmatch('(.-)\n') do
        lines[#lines + 1] = line
    end

    local index = 0
    return {
        lines = function()
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function()
            return exit_code == 0, 'exit', exit_code
        end,
    }
end

local function with_commands(commands, fn)
    firewalld_probe._test_set_dependencies({
        io_popen = function(command, mode)
            assert(mode == 'r', 'Expected firewalld probe to read command output')
            local item = commands[command]
            if item == false then
                return nil
            end
            assert(item ~= nil, 'Unexpected command: ' .. tostring(command))
            return make_reader(item.output, item.exit_code or 0)
        end,
    })

    local ok, err = pcall(fn)
    firewalld_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_inspect_active_zone_targets_accepts_permanent_non_accept_target()
    with_commands({
        ['firewall-cmd --get-active-zones 2>/dev/null'] = {
            output = 'public\n  interfaces: eth0\ntrusted\n  interfaces: lo\n',
        },
        ["firewall-cmd --zone='public' --list-interfaces 2>/dev/null"] = {
            output = 'eth0\n',
        },
        ["firewall-cmd --permanent --zone='public' --get-target 2>/dev/null"] = {
            output = 'default\n',
        },
        ["firewall-cmd --list-all --zone='public' 2>/dev/null"] = {
            output = 'public (active)\n  target: default\n',
        },
        ["firewall-cmd --zone='trusted' --list-interfaces 2>/dev/null"] = {
            output = 'lo\n',
        },
    }, function()
        local result = firewalld_probe.inspect_active_zone_targets()

        assert(result.available == true, 'Expected firewall-cmd command output to be available')
        assert(result.checked_count == 1, 'Expected loopback-only zones to be ignored')
        assert(result.violation_count == 0, 'Expected permanent non-ACCEPT target to pass')
    end)
end

function test_inspect_active_zone_targets_rejects_accept_target()
    with_commands({
        ['firewall-cmd --get-active-zones 2>/dev/null'] = {
            output = 'public\n  interfaces: eth0\n',
        },
        ["firewall-cmd --zone='public' --list-interfaces 2>/dev/null"] = {
            output = 'eth0\n',
        },
        ["firewall-cmd --permanent --zone='public' --get-target 2>/dev/null"] = {
            output = 'ACCEPT\n',
        },
        ["firewall-cmd --list-all --zone='public' 2>/dev/null"] = {
            output = 'public (active)\n  target: ACCEPT\n',
        },
    }, function()
        local result = firewalld_probe.inspect_active_zone_targets()

        assert(result.available == true, 'Expected firewall-cmd command output to be available')
        assert(result.violation_count == 1, 'Expected ACCEPT targets to fail')
        assert(
            result.details[1].reason == 'active_target_accept_or_empty',
            'Expected ACCEPT target violation to be classified'
        )
    end)
end

function test_inspect_active_zone_targets_rejects_non_permanent_target()
    with_commands({
        ['firewall-cmd --get-active-zones 2>/dev/null'] = {
            output = 'public\n  interfaces: eth0\n',
        },
        ["firewall-cmd --zone='public' --list-interfaces 2>/dev/null"] = {
            output = 'eth0\n',
        },
        ["firewall-cmd --permanent --zone='public' --get-target 2>/dev/null"] = {
            output = 'DROP\n',
        },
        ["firewall-cmd --list-all --zone='public' 2>/dev/null"] = {
            output = 'public (active)\n  target: default\n',
        },
    }, function()
        local result = firewalld_probe.inspect_active_zone_targets()

        assert(result.violation_count == 1, 'Expected active/permanent target mismatch to fail')
        assert(
            result.details[1].reason == 'target_not_permanent',
            'Expected target mismatch violation to be classified'
        )
    end)
end

function test_inspect_active_zone_targets_preserves_prior_violations_on_interface_failure()
    with_commands({
        ['firewall-cmd --get-active-zones 2>/dev/null'] = {
            output = 'bad;zone\npublic\n',
        },
        ["firewall-cmd --zone='public' --list-interfaces 2>/dev/null"] = false,
    }, function()
        local result = firewalld_probe.inspect_active_zone_targets()

        assert(result.available == false, 'Expected interface command failure to be unavailable')
        assert(result.checked_count == 0, 'Expected failed interface probe not to count as checked')
        assert(result.violation_count == 1, 'Expected prior invalid-zone violation to be retained')
        assert(result.details[1].reason == 'invalid_zone_name', 'Expected invalid-zone detail')
    end)
end

function test_inspect_active_zone_targets_accepts_valid_zone_name_with_colon()
    with_commands({
        ['firewall-cmd --get-active-zones 2>/dev/null'] = {
            output = 'dmz:blue\n  interfaces: eth0\n',
        },
        ["firewall-cmd --zone='dmz:blue' --list-interfaces 2>/dev/null"] = {
            output = 'eth0\n',
        },
        ["firewall-cmd --permanent --zone='dmz:blue' --get-target 2>/dev/null"] = {
            output = 'default\n',
        },
        ["firewall-cmd --list-all --zone='dmz:blue' 2>/dev/null"] = {
            output = 'dmz:blue (active)\n  target: default\n',
        },
    }, function()
        local result = firewalld_probe.inspect_active_zone_targets()

        assert(result.available == true, 'Expected colon-bearing zone command output to be available')
        assert(result.checked_count == 1, 'Expected valid non-loopback zone to be checked')
        assert(result.violation_count == 0, 'Expected matching non-ACCEPT target to pass')
    end)
end

function test_inspect_active_zone_targets_rejects_no_checked_zones()
    with_commands({
        ['firewall-cmd --get-active-zones 2>/dev/null'] = {
            output = 'trusted\n  interfaces: lo virbr0\n',
        },
        ["firewall-cmd --zone='trusted' --list-interfaces 2>/dev/null"] = {
            output = 'lo virbr0\n',
        },
    }, function()
        local result = firewalld_probe.inspect_active_zone_targets()

        assert(result.checked_count == 0, 'Expected loopback/virtual-only zones not to be checked')
        assert(result.violation_count == 1, 'Expected no active non-loopback zones to fail')
        assert(result.details[1].reason == 'no_active_non_loopback_zone', 'Expected no-output failure to be classified')
    end)
end

function test_inspect_active_zone_targets_reports_unavailable_firewall_cmd()
    with_commands({
        ['firewall-cmd --get-active-zones 2>/dev/null'] = false,
    }, function()
        local result = firewalld_probe.inspect_active_zone_targets()

        assert(result.available == false, 'Expected command execution failure to be reported in-band')
        assert(result.checked_count == 0, 'Expected unavailable command to check no zones')
    end)
end
