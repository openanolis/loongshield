-- Unit tests for env_detect probe and reinforce_guard mechanism.
-- Tests the container runtime detection probe in isolation and
-- verifies that rule_executor correctly skips reinforce when a guard triggers.

local env_detect = require('seharden.probes.env_detect')

--------------------------------------------------------------------------------
-- env_detect.is_container_host
--------------------------------------------------------------------------------

function test_env_detect_docker_socket()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/run/docker.sock' then
                return { close = function() end }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local detected, reason = env_detect.is_container_host()
    assert(detected == true, 'Expected Docker socket to be detected')
    assert(
        type(reason) == 'string' and reason:find('docker.sock', 1, true),
        'Expected reason to mention docker.sock, got: ' .. tostring(reason)
    )
end

function test_env_detect_containerd_socket()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/run/containerd/containerd.sock' then
                return { close = function() end }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local detected, reason = env_detect.is_container_host()
    assert(detected == true, 'Expected containerd socket to be detected')
    assert(
        type(reason) == 'string' and reason:find('containerd.sock', 1, true),
        'Expected reason to mention containerd.sock, got: ' .. tostring(reason)
    )
end

function test_env_detect_kubelet_process()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        os_execute = function(cmd)
            if cmd:find('pgrep') then
                return true, nil, 0
            end
            return nil, nil, 1
        end,
    })

    local detected, reason = env_detect.is_container_host()
    assert(detected == true, 'Expected kubelet to be detected')
    assert(
        type(reason) == 'string' and reason:find('kubelet', 1, true),
        'Expected reason to mention kubelet, got: ' .. tostring(reason)
    )
end

function test_env_detect_dockerenv_file()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/.dockerenv' then
                return { close = function() end }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local detected, reason = env_detect.is_container_host()
    assert(detected == true, 'Expected /.dockerenv to be detected')
    assert(
        type(reason) == 'string' and reason:find('dockerenv', 1, true),
        'Expected reason to mention dockerenv, got: ' .. tostring(reason)
    )
end

function test_env_detect_no_container_runtime()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local detected = env_detect.is_container_host()
    assert(detected == false, 'Expected no container runtime to be detected')
end

--------------------------------------------------------------------------------
-- env_detect.has_sudo_user
--------------------------------------------------------------------------------

function test_has_sudo_user_with_valid_wheel_member()
    local group_content = 'root:x:0:\nwheel:x:10:alice,bob\nusers:x:100:\n'
    local passwd_content = 'root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\nbob:x:1002:1002::/home/bob:/bin/bash\n'

    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/group' then
                local idx = 0
                local lines = {}
                for line in group_content:gmatch('([^\n]+)') do
                    lines[#lines + 1] = line
                end
                return {
                    lines = function()
                        local i = 0
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            elseif path == '/etc/passwd' then
                local lines = {}
                for line in passwd_content:gmatch('([^\n]+)') do
                    lines[#lines + 1] = line
                end
                return {
                    lines = function()
                        local i = 0
                        return function()
                            i = i + 1
                            return lines[i]
                        end
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found, reason = env_detect.has_sudo_user()
    assert(found == true, 'Expected sudo user to be found, got: ' .. tostring(found))
    assert(
        type(reason) == 'string' and reason:find('alice', 1, true),
        'Expected reason to mention alice, got: ' .. tostring(reason)
    )
end

function test_has_sudo_user_empty_wheel_group()
    local group_content = 'root:x:0:\nwheel:x:10:\nusers:x:100:\n'
    local passwd_content = 'root:x:0:0:root:/root:/bin/bash\n'

    env_detect._test_set_dependencies({
        io_open = function(path)
            local content
            if path == '/etc/group' then
                content = group_content
            elseif path == '/etc/passwd' then
                content = passwd_content
            end
            if not content then return nil end
            local lines = {}
            for line in content:gmatch('([^\n]+)') do
                lines[#lines + 1] = line
            end
            return {
                lines = function()
                    local i = 0
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function() end,
            }
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.has_sudo_user()
    assert(found == false, 'Expected no sudo user when wheel group is empty')
end

function test_has_sudo_user_nologin_shell_excluded()
    local group_content = 'wheel:x:10:svcaccount\n'
    local passwd_content = 'root:x:0:0:root:/root:/bin/bash\nsvcaccount:x:1001:1001::/home/svc:/usr/sbin/nologin\n'

    env_detect._test_set_dependencies({
        io_open = function(path)
            local content
            if path == '/etc/group' then
                content = group_content
            elseif path == '/etc/passwd' then
                content = passwd_content
            end
            if not content then return nil end
            local lines = {}
            for line in content:gmatch('([^\n]+)') do
                lines[#lines + 1] = line
            end
            return {
                lines = function()
                    local i = 0
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function() end,
            }
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.has_sudo_user()
    assert(found == false, 'Expected nologin users to be excluded from sudo check')
end

function test_has_sudo_user_system_uid_excluded()
    local group_content = 'wheel:x:10:sysuser\n'
    local passwd_content = 'root:x:0:0:root:/root:/bin/bash\nsysuser:x:500:500::/home/sys:/bin/bash\n'

    env_detect._test_set_dependencies({
        io_open = function(path)
            local content
            if path == '/etc/group' then
                content = group_content
            elseif path == '/etc/passwd' then
                content = passwd_content
            end
            if not content then return nil end
            local lines = {}
            for line in content:gmatch('([^\n]+)') do
                lines[#lines + 1] = line
            end
            return {
                lines = function()
                    local i = 0
                    return function()
                        i = i + 1
                        return lines[i]
                    end
                end,
                close = function() end,
            }
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.has_sudo_user()
    assert(found == false, 'Expected system UIDs (<1000) to be excluded from sudo check')
end

function test_has_sudo_user_cannot_open_group()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.has_sudo_user()
    assert(found == false, 'Expected false when /etc/group cannot be opened')
end

--------------------------------------------------------------------------------
-- rule_executor.enforce with reinforce_guard
--------------------------------------------------------------------------------

-- These tests exercise the full guard evaluation path inside rule_executor.
-- The env_detect probe is loaded via the normal loader (package.path includes
-- src/daemon/modules/?.lua), so we inject dependencies before calling enforce.

local rule_executor = require('seharden.rule_executor')

function test_guard_skip_returns_manual_on_container_host()
    -- Inject container-host environment into env_detect
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/run/docker.sock' then
                return { close = function() end }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local rule = {
        id = 'test.guard.skip',
        desc = 'Test guard skip',
        probes = {},
        assertion = { compare = 'is_true', actual = 'true', key = 'value' },
        reinforce_guard = {
            name = 'container_host_check',
            func = 'env_detect.is_container_host',
            skip_message = 'Container host detected, skipping.',
        },
        reinforce = {
            { action = 'sysctl.set_value', params = { key = 'net.ipv4.ip_forward', value = '0' } },
        },
    }

    local status, msg = rule_executor.enforce(rule, {}, false)
    assert(status == 'MANUAL', 'Expected MANUAL when guard triggers, got: ' .. tostring(status))
    assert(
        type(msg) == 'string' and msg:find('Container host detected', 1, true),
        'Expected skip_message in reason, got: ' .. tostring(msg)
    )
end

function test_guard_no_skip_on_bare_metal()
    -- Inject bare-metal environment (no container runtime)
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    -- Use a rule with a reinforce action that will fail (enforcer not found)
    -- so we can observe that the guard was NOT triggered and enforce proceeded.
    local rule = {
        id = 'test.guard.no_skip',
        desc = 'Test guard no skip',
        probes = {},
        assertion = { compare = 'is_true', actual = 'true', key = 'value' },
        reinforce_guard = {
            name = 'container_host_check',
            func = 'env_detect.is_container_host',
            skip_message = 'Should not appear.',
        },
        reinforce = {
            { action = 'nonexistent_enforcer.action', params = {} },
        },
    }

    local status, msg = rule_executor.enforce(rule, {}, false)
    -- The guard should NOT trigger, so enforce proceeds and fails with
    -- "Enforcer not found" error (since the enforcer does not exist).
    assert(
        status == 'ERROR',
        'Expected ERROR (enforcer not found) when guard does not trigger, got: ' .. tostring(status)
    )
    assert(msg:find('not found', 1, true), "Expected 'not found' error, got: " .. tostring(msg))
end

function test_guard_nil_guard_proceeds_normally()
    local rule = {
        id = 'test.no_guard',
        desc = 'Test no guard',
        probes = {},
        assertion = { compare = 'is_true', actual = 'true', key = 'value' },
        reinforce = {
            { action = 'nonexistent_enforcer.action', params = {} },
        },
    }

    local status, msg = rule_executor.enforce(rule, {}, false)
    assert(status == 'ERROR', 'Expected ERROR (enforcer not found) without guard, got: ' .. tostring(status))
end

function test_guard_unknown_probe_returns_manual_fail_close()
    local rule = {
        id = 'test.guard.unknown',
        desc = 'Test unknown guard probe',
        probes = {},
        assertion = { compare = 'is_true', actual = 'true', key = 'value' },
        reinforce_guard = {
            name = 'missing_probe',
            func = 'nonexistent_probe.check',
            skip_message = 'Should not appear.',
        },
        reinforce = {
            { action = 'nonexistent_enforcer.action', params = {} },
        },
    }

    local status, msg = rule_executor.enforce(rule, {}, false)
    -- Unknown guard probe should trigger fail-close: return MANUAL
    assert(status == 'MANUAL', 'Expected MANUAL (fail-close) when guard probe is unknown, got: ' .. tostring(status))
    assert(msg:find('not found', 1, true), "Expected 'not found' in skip message, got: " .. tostring(msg))
end

function test_guard_fallback_to_guard_reason()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/run/docker.sock' then
                return { close = function() end }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    -- Guard without skip_message — should fall back to the probe's reason string
    local rule = {
        id = 'test.guard.reason_fallback',
        desc = 'Test guard reason fallback',
        probes = {},
        assertion = { compare = 'is_true', actual = 'true', key = 'value' },
        reinforce_guard = {
            name = 'container_host_check',
            func = 'env_detect.is_container_host',
        },
        reinforce = {
            { action = 'sysctl.set_value', params = { key = 'net.ipv4.ip_forward', value = '0' } },
        },
    }

    local status, msg = rule_executor.enforce(rule, {}, false)
    assert(status == 'MANUAL', 'Expected MANUAL when guard triggers, got: ' .. tostring(status))
    assert(
        type(msg) == 'string' and msg:find('container runtime detected', 1, true),
        'Expected probe reason in msg, got: ' .. tostring(msg)
    )
end

function test_guard_list_task_skip_message_takes_precedence_over_probe_reason()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/run/docker.sock' then
                return { close = function() end }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local rule = {
        id = 'test.guard.list_skip_message',
        desc = 'Test list guard skip message',
        probes = {},
        assertion = { compare = 'is_true', actual = 'true', key = 'value' },
        reinforce_guard = {
            {
                name = 'container_host_check',
                func = 'env_detect.is_container_host',
                skip_message = 'Task-level guard message.',
            },
        },
        reinforce = {
            { action = 'sysctl.set_value', params = { key = 'net.ipv4.ip_forward', value = '0' } },
        },
    }

    local status, msg = rule_executor.enforce(rule, {}, false)

    assert(status == 'MANUAL', 'Expected MANUAL when list guard triggers, got: ' .. tostring(status))
    assert(msg == 'Task-level guard message.', 'Expected task skip_message to take precedence, got: ' .. tostring(msg))
end

function test_successful_enforce_invalidates_probe_state()
    local loader = require('seharden.loader')
    local ssh_probe = require('seharden.probes.ssh')
    local saved_get_enforcer = loader.get_enforcer
    local saved_clear_cache = ssh_probe.clear_cache
    local clear_count = 0

    loader.get_enforcer = function(path)
        if path == 'fake.apply' then
            return function()
                return true
            end, path
        end
        return saved_get_enforcer(path)
    end
    ssh_probe.clear_cache = function()
        clear_count = clear_count + 1
    end

    local ok, status, msg = pcall(rule_executor.enforce, {
        id = 'test.invalidate.probe.state',
        desc = 'Invalidate probe state',
        reinforce = {
            { action = 'fake.apply', params = {} },
        },
    }, {}, false)

    loader.get_enforcer = saved_get_enforcer
    ssh_probe.clear_cache = saved_clear_cache

    assert(ok, tostring(status))
    assert(status == 'DONE', 'Expected successful enforce, got: ' .. tostring(status) .. ' ' .. tostring(msg))
    assert(clear_count == 1, 'Expected successful enforce to clear cached probe state once')
end

--------------------------------------------------------------------------------
-- env_detect.is_legacy_ssh_client
--------------------------------------------------------------------------------

function test_is_legacy_ssh_client_modern_openssh()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        io_popen = function()
            return {
                read = function()
                    return 'OpenSSH_8.9p1, OpenSSL 3.0.7 1 Nov 2022\n'
                end,
                close = function() end,
            }
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local legacy = env_detect.is_legacy_ssh_client()
    assert(legacy == false, 'Expected modern OpenSSH 8.9 to not be legacy')
end

function test_is_legacy_ssh_client_old_openssh()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        io_popen = function()
            return {
                read = function()
                    return 'OpenSSH_5.3p1, OpenSSL 1.0.1e-fips 11 Feb 2013\n'
                end,
                close = function() end,
            }
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local legacy, reason = env_detect.is_legacy_ssh_client()
    assert(legacy == true, 'Expected OpenSSH 5.3 to be detected as legacy')
    assert(type(reason) == 'string' and reason:find('5.3', 1, true), 'Expected reason to mention version')
end

function test_is_legacy_ssh_client_not_installed()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        io_popen = function()
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local legacy = env_detect.is_legacy_ssh_client()
    assert(legacy == false, 'Expected false when ssh is not installed')
end

function test_is_legacy_ssh_client_boundary_6_5()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        io_popen = function()
            return {
                read = function()
                    return 'OpenSSH_6.5p1\n'
                end,
                close = function() end,
            }
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local legacy = env_detect.is_legacy_ssh_client()
    assert(legacy == false, 'Expected OpenSSH 6.5 to be considered modern (boundary)')
end

--------------------------------------------------------------------------------
-- env_detect.no_sudo_user / no_console_access (guard-direction inverses)
--------------------------------------------------------------------------------

local function make_lines_file(content)
    local lines = {}
    for line in content:gmatch('([^\n]+)') do
        lines[#lines + 1] = line
    end
    return {
        lines = function()
            local i = 0
            return function()
                i = i + 1
                return lines[i]
            end
        end,
        close = function() end,
    }
end

function test_no_sudo_user_returns_true_when_no_sudo_user_exists()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/group' then
                return make_lines_file('root:x:0:\nwheel:x:10:\nusers:x:100:\n')
            elseif path == '/etc/passwd' then
                return make_lines_file('root:x:0:0:root:/root:/bin/bash\n')
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found, reason = env_detect.no_sudo_user()
    assert(found == true, 'Expected no_sudo_user=true when wheel group is empty')
    assert(type(reason) == 'string' and reason:find('sudo', 1, true), 'Expected reason to mention sudo')
end

function test_no_sudo_user_returns_false_when_sudo_user_exists()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/group' then
                return make_lines_file('root:x:0:\nwheel:x:10:alice\nusers:x:100:\n')
            elseif path == '/etc/passwd' then
                return make_lines_file('root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n')
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.no_sudo_user()
    assert(found == false, 'Expected no_sudo_user=false when a sudo user exists')
end

function test_no_console_access_returns_true_when_no_console_detected()
    env_detect._test_set_dependencies({
        io_open = function()
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found, reason = env_detect.no_console_access()
    assert(found == true, 'Expected no_console_access=true when no console is detected')
    assert(type(reason) == 'string' and reason:find('console', 1, true), 'Expected reason to mention console')
end

function test_no_console_access_returns_false_when_console_detected()
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/proc/cmdline' then
                return {
                    read = function()
                        return 'BOOT_IMAGE=/vmlinuz console=ttyS0,115200 quiet'
                    end,
                    close = function() end,
                }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.no_console_access()
    assert(found == false, 'Expected no_console_access=false when kernel console= configures a serial console')
end

function test_has_console_access_ignores_mere_ttyS0_device_node()
    -- A ttyS0 device node alone (no console= boot parameter) is not evidence
    -- of console access; only /proc/cmdline, cloud markers, or IPMI count.
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/sys/class/tty/ttyS0' then
                return { close = function() end }
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.has_console_access()
    assert(found == false, 'Expected ttyS0 device node alone not to count as console access')
end

function test_has_sudo_user_collects_members_from_both_groups()
    -- wheel exists but is empty; the sudo group carries the real member.
    env_detect._test_set_dependencies({
        io_open = function(path)
            if path == '/etc/group' then
                return make_lines_file('root:x:0:\nwheel:x:10:\nsudo:x:27:alice\n')
            elseif path == '/etc/passwd' then
                return make_lines_file('root:x:0:0:root:/root:/bin/bash\nalice:x:1001:1001::/home/alice:/bin/bash\n')
            end
            return nil
        end,
        os_execute = function()
            return nil, nil, 1
        end,
    })

    local found = env_detect.has_sudo_user()
    assert(found == true, 'Expected sudo group members to be detected even when wheel is empty')
end
