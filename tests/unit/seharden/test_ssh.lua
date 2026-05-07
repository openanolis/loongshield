local ssh_probe = require('seharden.probes.ssh')

local Mocks = {}

local function make_attr(uid, gid, mode)
    return {
        uid = function() return uid end,
        gid = function() return gid end,
        mode = function() return mode end,
    }
end

local function setup()
    Mocks = {
        popen_called_with = nil,
        popen_call_count = 0,
        popen_returns = {
            lines = function() return (""):gmatch("([^\n]+)") end,
            close = function() return true, "exit", 0 end,
        },
        fake_files = {},
        fake_stats = {},
        fake_attrs = {},
        dir_entries = {},
        group_ids = {},
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

    local function fake_lfs_attributes(path)
        if Mocks.fake_attrs[path] then
            return Mocks.fake_attrs[path]
        end
        if Mocks.fake_files[path] ~= nil then
            return { mode = "file" }
        end
        if Mocks.dir_entries[path] then
            return { mode = "directory" }
        end
        return nil
    end

    local function fake_lfs_dir(path)
        local entries = Mocks.dir_entries[path]
        if not entries then
            return nil
        end
        local dir_obj = { entries = entries, index = 0 }
        return function(state)
            state.index = state.index + 1
            return state.entries[state.index]
        end, dir_obj
    end

    ssh_probe._test_set_dependencies({
        fs_get_gid = function(name)
            return Mocks.group_ids[name]
        end,
        fs_stat = function(path)
            return Mocks.fake_stats[path]
        end,
        io_open = fake_io_open,
        io_popen = fake_io_popen,
        lfs_attributes = fake_lfs_attributes,
        lfs_dir = fake_lfs_dir,
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

function test_inspect_sysconfig_crypto_policy_requires_only_commented_assignment()
    setup()

    Mocks.fake_files["/etc/sysconfig/sshd"] = table.concat({
        "# CRYPTO_POLICY=",
        "OPTIONS='-u chrony'",
    }, "\n")

    local clean = ssh_probe.inspect_sysconfig_crypto_policy({
        path = "/etc/sysconfig/sshd"
    })

    Mocks.fake_files["/etc/sysconfig/sshd"] = table.concat({
        "# CRYPTO_POLICY=",
        "CRYPTO_POLICY=",
    }, "\n")

    local dirty = ssh_probe.inspect_sysconfig_crypto_policy({
        path = "/etc/sysconfig/sshd"
    })

    assert(clean.active_present == false, "Expected commented CRYPTO_POLICY to be ignored as active config")
    assert(clean.commented_present == true, "Expected commented CRYPTO_POLICY evidence to be reported")
    assert(dirty.active_present == true, "Expected active CRYPTO_POLICY assignment to be flagged")
end

function test_inspect_sysconfig_crypto_policy_allows_absent_assignment_as_evidence()
    setup()

    Mocks.fake_files["/etc/sysconfig/sshd"] = "OPTIONS='-u chrony'\n"

    local result = ssh_probe.inspect_sysconfig_crypto_policy({
        path = "/etc/sysconfig/sshd"
    })

    assert(result.active_present == false, "Expected absent CRYPTO_POLICY assignment not to be active")
    assert(result.commented_present == false,
        "Expected commented CRYPTO_POLICY evidence to remain separate from compliance")
end

function test_inspect_config_file_access_discovers_dropins_and_includes()
    setup()

    Mocks.fake_files["/etc/ssh/sshd_config"] = table.concat({
        "Include /opt/ssh/*.conf",
    }, "\n")
    Mocks.fake_files["/etc/ssh/sshd_config.d/10-hardening.conf"] = "PermitRootLogin no"
    Mocks.fake_files["/opt/ssh/custom.conf"] = "PasswordAuthentication no"
    Mocks.dir_entries["/etc/ssh/sshd_config.d"] = { ".", "..", "10-hardening.conf" }
    Mocks.dir_entries["/opt/ssh"] = { ".", "..", "custom.conf" }
    Mocks.fake_stats["/etc/ssh/sshd_config"] = make_attr(0, 0, tonumber("600", 8))
    Mocks.fake_stats["/etc/ssh/sshd_config.d/10-hardening.conf"] = make_attr(0, 0, tonumber("600", 8))
    Mocks.fake_stats["/opt/ssh/custom.conf"] = make_attr(0, 10, tonumber("644", 8))

    local result = ssh_probe.inspect_config_file_access({
        path = "/etc/ssh/sshd_config",
        include_dir = "/etc/ssh/sshd_config.d",
    })

    assert(result.checked_count == 3, "Expected main config, default drop-in, and Include target to be checked")
    assert(result.invalid_count == 1, "Expected invalid Include target access to be flagged")
    assert(result.all_configured == false, "Expected any invalid config file to fail the aggregate access flag")
end

function test_inspect_config_file_access_fails_when_no_config_files_exist()
    setup()

    local result = ssh_probe.inspect_config_file_access({
        path = "/etc/ssh/sshd_config",
        include_dir = "/etc/ssh/sshd_config.d",
    })

    assert(result.checked_count == 0, "Expected missing sshd config evidence to be visible")
    assert(result.all_configured == false, "Expected zero checked config files not to pass")
end

function test_inspect_private_host_key_access_allows_root_or_ssh_keys_policy()
    setup()

    Mocks.dir_entries["/etc/ssh"] = {
        ".",
        "..",
        "ssh_host_rsa_key",
        "ssh_host_ed25519_key",
        "ssh_host_rsa_key.pub",
    }
    Mocks.group_ids.ssh_keys = 74
    Mocks.fake_files["/etc/ssh/ssh_host_rsa_key"] = "private"
    Mocks.fake_files["/etc/ssh/ssh_host_ed25519_key"] = "private"
    Mocks.fake_files["/etc/ssh/ssh_host_rsa_key.pub"] = "public"
    Mocks.fake_stats["/etc/ssh/ssh_host_rsa_key"] = make_attr(0, 0, tonumber("600", 8))
    Mocks.fake_stats["/etc/ssh/ssh_host_ed25519_key"] = make_attr(0, 74, tonumber("640", 8))

    local result = ssh_probe.inspect_private_host_key_access({
        directory = "/etc/ssh",
    })

    assert(result.checked_count == 2, "Expected only private host key files to be checked")
    assert(result.invalid_count == 0, "Expected root:0600 and ssh_keys:0640 private keys to pass")
    assert(result.all_configured == true, "Expected compliant private host keys to pass")
end

function test_inspect_private_host_key_access_rejects_permissive_keys()
    setup()

    Mocks.dir_entries["/etc/ssh"] = { ".", "..", "ssh_host_rsa_key" }
    Mocks.fake_files["/etc/ssh/ssh_host_rsa_key"] = "private"
    Mocks.fake_stats["/etc/ssh/ssh_host_rsa_key"] = make_attr(0, 0, tonumber("640", 8))

    local result = ssh_probe.inspect_private_host_key_access({
        directory = "/etc/ssh",
    })

    assert(result.invalid_count == 1, "Expected root-owned private keys with group read to fail")
    assert(result.all_configured == false, "Expected permissive private host key access to fail")
end

function test_inspect_private_host_key_access_fails_when_directory_unavailable()
    setup()

    local result = ssh_probe.inspect_private_host_key_access({
        directory = "/etc/ssh",
    })

    assert(result.available == false, "Expected unavailable SSH key directory evidence to fail closed")
    assert(result.all_configured == false, "Expected unavailable SSH key directory not to pass")
end

function test_inspect_public_host_key_access_allows_no_public_keys()
    setup()

    Mocks.dir_entries["/etc/ssh"] = { ".", "..", "sshd_config" }

    local result = ssh_probe.inspect_public_host_key_access({
        directory = "/etc/ssh",
    })

    assert(result.checked_count == 0, "Expected no public host keys to be reported explicitly")
    assert(result.all_configured == true, "Expected absence of public host keys to pass CIS audit semantics")
end

function test_inspect_public_host_key_access_rejects_non_root_group()
    setup()

    Mocks.dir_entries["/etc/ssh"] = { ".", "..", "ssh_host_rsa_key.pub" }
    Mocks.fake_files["/etc/ssh/ssh_host_rsa_key.pub"] = "public"
    Mocks.fake_stats["/etc/ssh/ssh_host_rsa_key.pub"] = make_attr(0, 10, tonumber("644", 8))

    local result = ssh_probe.inspect_public_host_key_access({
        directory = "/etc/ssh",
    })

    assert(result.invalid_count == 1, "Expected public host keys with non-root group to fail")
    assert(result.all_configured == false, "Expected invalid public host key access to fail")
end

function test_inspect_access_restrictions_reports_any_effective_allow_or_deny_list()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("allowgroups ssh-users\npermitrootlogin no"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.inspect_access_restrictions({
        conditions = { from = "localhost", user = "root" }
    })

    assert(result.available == true, "Expected sshd effective configuration to be available")
    assert(result.configured == true, "Expected AllowGroups to satisfy SSH access restriction evidence")
    assert(Mocks.popen_call_count == 1, "Expected access restriction checks to share the cached sshd dump")
end

function test_inspect_effective_setting_validates_common_cis_constraints()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return table.concat({
            "disableforwarding yes",
            "loglevel VERBOSE",
            "clientaliveinterval 15",
            "maxsessions 10",
            "logingracetime 1m",
            "maxstartups 10:30:60",
        }, "\n"):gmatch("([^\n]+)")
    end

    local conditions = { from = "localhost", user = "root" }
    local disabled = ssh_probe.inspect_effective_setting({
        key = "disableforwarding",
        conditions = conditions,
        expected_value = "yes",
    })
    local loglevel = ssh_probe.inspect_effective_setting({
        key = "loglevel",
        conditions = conditions,
        allowed_values = { "INFO", "VERBOSE" },
    })
    local alive = ssh_probe.inspect_effective_setting({
        key = "clientaliveinterval",
        conditions = conditions,
        min_value = 1,
    })
    local sessions = ssh_probe.inspect_effective_setting({
        key = "maxsessions",
        conditions = conditions,
        max_value = 10,
    })
    local grace = ssh_probe.inspect_effective_setting({
        key = "logingracetime",
        value_type = "duration_seconds",
        conditions = conditions,
        min_value = 1,
        max_value = 60,
    })
    local startups = ssh_probe.inspect_effective_setting({
        key = "maxstartups",
        value_type = "colon_numbers",
        conditions = conditions,
        max_values = { 10, 30, 60 },
    })

    assert(disabled.configured == true, "Expected yes/no SSH settings to pass expected-value checks")
    assert(loglevel.configured == true, "Expected allowed SSH values to be compared case-insensitively")
    assert(alive.configured == true, "Expected numeric minimum checks to pass")
    assert(sessions.configured == true, "Expected numeric maximum checks to pass")
    assert(grace.configured == true and grace.value == 60, "Expected durations to be normalized before comparison")
    assert(startups.configured == true, "Expected MaxStartups tuples at CIS limits to pass")
end

function test_inspect_effective_setting_rejects_overly_permissive_maxstartups()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("maxstartups 10:30:100"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.inspect_effective_setting({
        key = "maxstartups",
        value_type = "colon_numbers",
        conditions = { from = "localhost", user = "root" },
        max_values = { 10, 30, 60 },
    })

    assert(result.configured == false, "Expected MaxStartups above 10:30:60 to fail")
    assert(result.reason == "above_maximum", "Expected overly permissive tuples to report the reason")
end

function test_inspect_effective_algorithm_list_rejects_weak_algorithms()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.popen_returns.lines = function()
        return ("ciphers aes256-ctr,aes128-cbc"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.inspect_effective_algorithm_list({
        key = "ciphers",
        conditions = { from = "localhost", user = "root" },
        disallowed_algorithms = { "aes128-cbc" },
    })

    assert(result.configured == false, "Expected weak SSH algorithms to fail")
    assert(result.disallowed_count == 1, "Expected weak algorithm evidence to be retained")
    assert(result.disallowed[1] == "aes128-cbc", "Expected the offending algorithm name to be reported")
end

function test_inspect_banner_requires_absolute_existing_non_leaking_file()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.fake_files["/etc/issue.net"] = "Authorized access only\n"
    Mocks.fake_files["/etc/os-release"] = 'ID="alinux"\n'
    Mocks.popen_returns.lines = function()
        return ("banner /etc/issue.net"):gmatch("([^\n]+)")
    end

    local result = ssh_probe.inspect_banner({
        conditions = { from = "localhost", user = "root" },
    })

    assert(result.configured == true, "Expected an absolute existing clean banner file to pass")
    assert(result.banner_file_available == true, "Expected banner file availability evidence")
    assert(result.info_leak_found == false, "Expected ordinary banner text not to leak OS information")
end

function test_inspect_banner_rejects_missing_relative_or_leaking_banners()
    setup()

    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.fake_files["/etc/os-release"] = 'ID="alinux"\n'
    Mocks.popen_returns.lines = function()
        return ("banner issue.net"):gmatch("([^\n]+)")
    end

    local relative = ssh_probe.inspect_banner({
        conditions = { from = "localhost", user = "root" },
    })

    setup()
    Mocks.fake_files["/usr/sbin/sshd"] = "binary"
    Mocks.fake_files["/proc/sys/kernel/hostname"] = "testhost"
    Mocks.fake_files["/etc/hosts"] = "192.168.1.100  testhost"
    Mocks.fake_files["/etc/os-release"] = 'ID="alinux"\n'
    Mocks.fake_files["/etc/issue.net"] = "Welcome to alinux \\r\n"
    Mocks.popen_returns.lines = function()
        return ("banner /etc/issue.net"):gmatch("([^\n]+)")
    end

    local leaking = ssh_probe.inspect_banner({
        conditions = { from = "localhost", user = "root" },
    })

    assert(relative.configured == false, "Expected relative Banner paths to fail")
    assert(relative.reason == "not_absolute_path", "Expected relative paths to report a clear reason")
    assert(leaking.configured == false, "Expected OS-disclosing banner content to fail")
    assert(leaking.info_leak_found == true, "Expected banner OS disclosure evidence to be retained")
end

function test_find_config_directive_searches_discovered_sshd_config_files()
    setup()

    Mocks.fake_files["/etc/ssh/sshd_config"] = "Include /etc/ssh/sshd_config.d/*.conf\n"
    Mocks.fake_files["/etc/ssh/sshd_config.d/10-hardening.conf"] = "MaxAuthTries 4\n"
    Mocks.fake_files["/etc/ssh/sshd_config.d/99-weak.conf"] = "MaxAuthTries 6\n"
    Mocks.dir_entries["/etc/ssh/sshd_config.d"] = { ".", "..", "10-hardening.conf", "99-weak.conf" }

    local result = ssh_probe.find_config_directive({
        key = "MaxAuthTries",
        path = "/etc/ssh/sshd_config",
        include_dir = "/etc/ssh/sshd_config.d",
        numeric_min = 5,
    })

    assert(result.checked_count == 3, "Expected main config and discovered drop-ins to be searched")
    assert(result.found == true, "Expected noncompliant included directives to be detected")
    assert(result.details[1].path == "/etc/ssh/sshd_config.d/99-weak.conf",
        "Expected offending include path evidence to be retained")
end
