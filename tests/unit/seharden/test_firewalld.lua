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

--------------------------------------------------------------------------------
-- firewalld.has_ssh_service / no_ssh_service (on-disk zone configuration)
--------------------------------------------------------------------------------

local ZONES_DIR = '/etc/firewalld/zones'
local LIB_ZONES_DIR = '/usr/lib/firewalld/zones'

local function with_zone_config(zone_dirs, files, fn)
    firewalld_probe._test_set_dependencies({
        lfs_dir = function(dir)
            local names = zone_dirs[dir]
            if not names then
                return nil
            end
            local i = 0
            return function()
                i = i + 1
                return names[i]
            end
        end,
        io_open = function(path, mode)
            local content = files[path]
            if content == nil then
                return nil
            end
            return {
                read = function()
                    return content
                end,
                close = function() end,
            }
        end,
    })

    local ok, err = pcall(fn)
    firewalld_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

local function ssh_service_zone_xml()
    return '<?xml version="1.0" encoding="utf-8"?>\n<zone>\n  <short>Public</short>\n  <service name="ssh"/>\n  <service name="dhcpv6-client"/>\n</zone>\n'
end

local function ssh_port_zone_xml()
    return '<?xml version="1.0" encoding="utf-8"?>\n<zone>\n  <port port="22" protocol="tcp"/>\n</zone>\n'
end

local function no_ssh_zone_xml()
    return '<?xml version="1.0" encoding="utf-8"?>\n<zone>\n  <service name="dhcpv6-client"/>\n</zone>\n'
end

function test_has_ssh_service_with_ssh_service_in_etc_zone()
    with_zone_config(
        { [ZONES_DIR] = { 'public.xml' }, [LIB_ZONES_DIR] = {} },
        { [ZONES_DIR .. '/public.xml'] = ssh_service_zone_xml() },
        function()
            local found, reason = firewalld_probe.has_ssh_service()
            assert(found == true, 'Expected SSH service in /etc zone to be detected')
            assert(type(reason) == 'string' and reason:find('SSH', 1, true), 'Expected reason to mention SSH')
        end
    )
end

function test_has_ssh_service_with_port_22_in_lib_zone()
    with_zone_config(
        { [ZONES_DIR] = {}, [LIB_ZONES_DIR] = { 'public.xml' } },
        { [LIB_ZONES_DIR .. '/public.xml'] = ssh_port_zone_xml() },
        function()
            local found = firewalld_probe.has_ssh_service()
            assert(found == true, 'Expected port 22/tcp in /usr/lib zone to be detected')
        end
    )
end

function test_has_ssh_service_missing_returns_false()
    with_zone_config(
        { [ZONES_DIR] = { 'public.xml' }, [LIB_ZONES_DIR] = { 'public.xml' } },
        {
            [ZONES_DIR .. '/public.xml'] = no_ssh_zone_xml(),
            [LIB_ZONES_DIR .. '/public.xml'] = no_ssh_zone_xml(),
        },
        function()
            local found = firewalld_probe.has_ssh_service()
            assert(found == false, 'Expected false when SSH absent from all zones')
        end
    )
end

function test_has_ssh_service_firewalld_not_installed_returns_false()
    with_zone_config({}, {}, function()
        local found = firewalld_probe.has_ssh_service()
        assert(found == false, 'Expected false when no zone configuration exists (fail-closed for the guard)')
    end)
end

function test_has_ssh_service_does_not_match_sshuttle_service()
    with_zone_config(
        { [ZONES_DIR] = { 'public.xml' }, [LIB_ZONES_DIR] = {} },
        {
            [ZONES_DIR .. '/public.xml'] =
                '<?xml version="1.0" encoding="utf-8"?>\n<zone>\n  <service name="sshuttle"/>\n</zone>\n',
        },
        function()
            local found = firewalld_probe.has_ssh_service()
            assert(found == false, 'Expected sshuttle not to be detected as SSH service')
        end
    )
end

function test_has_ssh_service_port_1022_not_matched()
    with_zone_config(
        { [ZONES_DIR] = { 'public.xml' }, [LIB_ZONES_DIR] = {} },
        {
            [ZONES_DIR .. '/public.xml'] =
                '<?xml version="1.0" encoding="utf-8"?>\n<zone>\n  <port port="1022" protocol="tcp"/>\n</zone>\n',
        },
        function()
            local found = firewalld_probe.has_ssh_service()
            assert(found == false, 'Expected port 1022/tcp not to match SSH')
        end
    )
end

function test_no_ssh_service_inverts_has_ssh_service()
    with_zone_config(
        { [ZONES_DIR] = { 'public.xml' }, [LIB_ZONES_DIR] = {} },
        { [ZONES_DIR .. '/public.xml'] = ssh_service_zone_xml() },
        function()
            local found = firewalld_probe.no_ssh_service()
            assert(found == false, 'Expected no_ssh_service=false when SSH is configured')
        end
    )

    with_zone_config(
        { [ZONES_DIR] = { 'public.xml' }, [LIB_ZONES_DIR] = {} },
        { [ZONES_DIR .. '/public.xml'] = no_ssh_zone_xml() },
        function()
            local found, reason = firewalld_probe.no_ssh_service()
            assert(found == true, 'Expected no_ssh_service=true when SSH is absent')
            assert(type(reason) == 'string' and reason:find('SSH', 1, true), 'Expected reason to mention SSH')
        end
    )
end
