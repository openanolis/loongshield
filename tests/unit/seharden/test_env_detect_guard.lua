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
