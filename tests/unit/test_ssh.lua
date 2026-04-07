local ssh_probe = require('seharden.probes.ssh')

local Mocks = {}

local function setup()
    Mocks = {
        popen_called_with = nil,
        popen_call_count = 0,
        popen_returns = {
            lines = function() return (""):gmatch("([^\n]+)") end,
            close = function() return true, "exit", 0 end,
        },
        fake_files = {},
    }

    local function fake_io_open(path, mode)
        if Mocks.fake_files[path] then
            local content = Mocks.fake_files[path]
            return {
                read = function() return content end,
                lines = function() return content:gmatch("([^\n]+)") end,
                close = function() end,
            }
        end
        return nil -- Simulate file not found
    end

    local function fake_io_popen(cmd, mode)
        Mocks.popen_called_with = cmd
        Mocks.popen_call_count = Mocks.popen_call_count + 1
        return Mocks.popen_returns
    end

    ssh_probe._test_set_dependencies({
        io_open = fake_io_open,
        io_popen = fake_io_popen,
    })
end

-- ====================
-- Test Cases
-- ====================

function test_get_effective_value_successfully()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("LogLevel INFO\nPasswordAuthentication yes\nPermitRootLogin no"):gmatch("([^\n]+)")
    end

    local expected_command = "/usr/sbin/sshd -T -C user=testuser -C host=testhost -C addr=192.168.1.100"
    local params = { key = "PasswordAuthentication", conditions = { from = "localhost", user = "testuser" } }

    local result = ssh_probe.get_effective_value(params)

    assert(Mocks.popen_called_with == expected_command, "Probe was called with an unexpected command.")
    assert(result.value == "yes", "Did not correctly parse the value from sshd output.")
end

function test_get_effective_value_parses_duration_units_when_requested()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("LoginGraceTime 1m30s"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.get_effective_value({
        key = "LoginGraceTime",
        value_type = "duration_seconds",
        conditions = { from = "localhost", user = "root" }
    })

    assert(result.value == 90, "Expected SSH duration values to be normalized to seconds.")
end

function test_get_effective_value_reports_duration_parse_errors()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("LoginGraceTime forever"):gmatch("([^\n]+)")
    end

    local result, err = ssh_probe.get_effective_value({
        key = "LoginGraceTime",
        value_type = "duration_seconds",
        conditions = { from = "localhost", user = "root" }
    })

    assert(result == nil, "Expected unparsable SSH duration values to fail the probe.")
    assert(err == "Could not parse SSH value 'forever' as duration_seconds.",
        "Expected SSH duration parse failures to return a descriptive error.")
end

function test_handles_key_not_in_output()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("LogLevel INFO"):gmatch("([^\n]+)")
    end

    local params = { key = "NonExistentKey", conditions = { from = "localhost", user = "root" } }

    local result = ssh_probe.get_effective_value(params)

    assert(result.value == nil, "Value should be nil when key is not found.")
    assert(result.error == nil, "Should not return an error when key is not found.")
end

function test_handles_failed_sshd_command()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.close = function() return true, "exit", 1 end

    local params = { key = "PasswordAuthentication", conditions = { from = "localhost", user = "root" } }

    local result, err = ssh_probe.get_effective_value(params)

    assert(err == nil, "Expected operational sshd failures to stay within probe results.")
    assert(result.available == true, "Expected sshd path discovery to succeed before command execution.")
    assert(result.value == nil, "Expected command failures to return no effective value.")
    assert(result.error == "sshd command failed with exit code: 1",
        "Did not return the correct command failure message.")
end

function test_handles_ip_not_found_in_hosts()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "unknownhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  someotherhost"
    Mocks.popen_returns.lines = function()
        return ("PasswordAuthentication yes"):gmatch("([^\n]+)")
    end

    local params = { key = "PasswordAuthentication", conditions = { from = "localhost", user = "root" } }

    local result = ssh_probe.get_effective_value(params)

    assert(result.value == "yes", "Expected localhost resolution to fall back instead of failing")
    assert(Mocks.popen_called_with
        == "/usr/sbin/sshd -T -C user=root -C host=unknownhost -C addr=127.0.0.1",
        "Expected SSH probe to fall back to loopback address when hostname mapping is absent")
end

function test_handles_missing_hostname_with_localhost_fallback()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/etc/hosts"] = "127.0.0.1 localhost"
    Mocks.popen_returns.lines = function()
        return ("PasswordAuthentication no"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.get_effective_value({
        key = "PasswordAuthentication",
        conditions = { from = "localhost", user = "root" }
    })

    assert(result.value == "no", "Expected SSH probe to use localhost fallback when hostname is unavailable")
    assert(Mocks.popen_called_with
        == "/usr/sbin/sshd -T -C user=root -C host=localhost -C addr=127.0.0.1",
        "Expected SSH probe to fall back to localhost host and loopback address")
end

function test_accepts_ipv6_localhost_resolution()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/etc/hosts"] = "::1 localhost"
    Mocks.popen_returns.lines = function()
        return ("PasswordAuthentication yes"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.get_effective_value({
        key = "PasswordAuthentication",
        conditions = { from = "localhost", user = "root" }
    })

    assert(result.value == "yes", "Expected SSH probe to accept IPv6 localhost addresses")
    assert(Mocks.popen_called_with
        == "/usr/sbin/sshd -T -C user=root -C host=localhost -C addr=::1",
        "Expected SSH probe to preserve the IPv6 localhost address in sshd conditions")
end

function test_handles_invalid_shell_arguments()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"

    local result, err = ssh_probe.get_effective_value({
        key = "PasswordAuthentication",
        conditions = { from = "localhost", user = "bad user" }
    })

    assert(result == nil, "Expected invalid shell arguments to fail the probe.")
    assert(err == "Invalid characters in command arguments.",
        "Expected invalid shell arguments to return a descriptive error.")
    assert(Mocks.popen_called_with == nil, "sshd command should not be called for invalid arguments.")
end

function test_handles_failed_popen()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns = nil

    local result, err = ssh_probe.get_effective_value({
        key = "PasswordAuthentication",
        conditions = { from = "localhost", user = "root" }
    })

    assert(err == nil, "Expected operational popen failures to stay within probe results.")
    assert(result.available == true, "Expected sshd path discovery to succeed before io.popen.")
    assert(result.value == nil, "Expected io.popen failure to return no effective value.")
    assert(result.error == "Failed to execute sshd config dump command.",
        "Expected io.popen failure to return a descriptive error.")
end

function test_get_effective_value_with_missing_parameters()
    setup()

    local res1, err1 = ssh_probe.get_effective_value({ key = "somekey" })
    local res2, err2 = ssh_probe.get_effective_value({ conditions = {} })

    assert(res1 == nil and err1, "Should return an error if 'conditions' is missing.")
    assert(res2 == nil and err2, "Should return an error if 'key' is missing.")
end

function test_falls_back_to_alternate_sshd_path()
    setup()

    Mocks.fake_files["/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("PasswordAuthentication yes"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.get_effective_value({
        key = "PasswordAuthentication",
        conditions = { from = "localhost", user = "root" }
    })

    assert(result.value == "yes", "Expected SSH probe to use alternate sshd locations when needed.")
    assert(Mocks.popen_called_with
        == "/sbin/sshd -T -C user=root -C host=testhost -C addr=192.168.1.100",
        "Expected SSH probe to fall back to another standard sshd path.")
end

function test_reports_missing_sshd_binary_without_engine_error()
    setup()

    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"

    local result, err = ssh_probe.get_effective_value({
        key = "PasswordAuthentication",
        conditions = { from = "localhost", user = "root" }
    })

    assert(err == nil, "Expected missing sshd binaries to be reported as probe data.")
    assert(result.available == false, "Expected SSH probe to mark sshd as unavailable when absent.")
    assert(result.value == nil, "Expected no effective value when sshd is missing.")
    assert(result.error == "sshd binary not found",
        "Expected missing sshd binaries to return a clear error string.")
    assert(Mocks.popen_called_with == nil, "Expected SSH probe not to execute sshd when it cannot be found.")
end

function test_caches_sshd_dump_for_repeated_queries()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("PasswordAuthentication yes\nPermitRootLogin no"):gmatch("([^\n]+)")
    end

    local password_result = ssh_probe.get_effective_value({
        key = "PasswordAuthentication",
        conditions = { from = "localhost", user = "root" }
    })
    local root_login_result = ssh_probe.get_effective_value({
        key = "PermitRootLogin",
        conditions = { from = "localhost", user = "root" }
    })

    assert(password_result.value == "yes", "Expected the first SSH lookup to succeed.")
    assert(root_login_result.value == "no", "Expected repeated SSH lookups to reuse the cached dump.")
    assert(Mocks.popen_call_count == 1, "Expected repeated SSH lookups for the same command to execute sshd once.")
end
