package.preload["nm"] = function()
    return {
        client_new = function()
            return nil, "no nm"
        end
    }
end

local network_probe = require('seharden.probes.network')

local function handle_for(lines, exit_code)
    lines = lines or {}
    local index = 0
    return {
        lines = function()
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function()
            if exit_code and exit_code ~= 0 then
                return nil, "exit", exit_code
            end
            return true, "exit", 0
        end
    }
end

local function dir_iter(entries)
    local state = { entries = entries, index = 0 }
    return function(s)
        s.index = s.index + 1
        return s.entries[s.index]
    end, state
end

local function make_client()
    return {
        get_devices = function()
            local devices = {
                { get_iface = function() return "eth0" end, get_ip4_address = function() return "10.0.0.1" end },
                { get_iface = function() return "lo" end, get_ip4_address = function() return nil end },
            }
            local i = 0
            return function()
                i = i + 1
                return devices[i]
            end
        end,
        wireless_enabled = function() return true end,
        wwan_enabled = function() return false end,
        close = function() end
    }
end

function test_get_all_interface_ips()
    network_probe._test_set_dependencies({
        client_new = function() return make_client() end
    })
    local result = network_probe.get_all_interface_ips()
    assert(result.eth0 == "10.0.0.1", "Expected eth0 IP to be returned")
    assert(result.lo == nil, "Expected interfaces without IP to be omitted")
end

function test_get_wireless_radio_states()
    network_probe._test_set_dependencies({
        client_new = function() return make_client() end
    })
    local result = network_probe.get_wireless_radio_states()
    assert(result.wifi_enabled == true, "Expected wifi_enabled true")
    assert(result.wwan_enabled == false, "Expected wwan_enabled false")
end

function test_get_wireless_radio_states_no_client()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end
    })
    local result = network_probe.get_wireless_radio_states()
    assert(result.wifi_enabled == false, "Expected wifi_enabled false on failure")
    assert(result.wwan_enabled == false, "Expected wwan_enabled false on failure")
end

function test_find_listening_ports_reports_requested_ports()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        io_popen = function(cmd, mode)
            assert(cmd == "ss -lntuH 2>/dev/null",
                "Expected listening port probe to suppress noisy ss stderr output")
            assert(mode == "r", "Expected listening port probe to open a read pipe")
            local lines = {
                "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*",
                "tcp LISTEN 0 128 0.0.0.0:631 0.0.0.0:*",
                "udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*",
            }
            local index = 0
            return {
                lines = function()
                    return function()
                        index = index + 1
                        return lines[index]
                    end
                end,
                close = function()
                    return true
                end
            }
        end
    })

    local result = network_probe.find_listening_ports({ ports = { 23, 631 } })
    assert(result.count == 1, "Expected only requested listening ports to be reported")
    assert(result.details[1].port == 631, "Expected port 631 to be flagged")
    assert(result.details[1].proto == "tcp", "Expected protocol to be preserved")
end

function test_find_listening_ports_reports_unavailable_ss_as_probe_evidence()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        io_popen = function()
            local index = 0
            return {
                lines = function()
                    return function()
                        index = index + 1
                        return nil
                    end
                end,
                close = function()
                    return nil, "exit", 127
                end
            }
        end
    })

    local result, err = network_probe.find_listening_ports({ ports = { 631 } })

    assert(err == nil, "Expected unavailable ss to be returned as probe evidence, not a probe error")
    assert(result.available == false, "Expected unavailable ss to be marked unavailable")
    assert(result.count == nil, "Expected unavailable ss to avoid reporting a false zero count")
    assert(result.error:find("127", 1, true), "Expected probe evidence to preserve ss exit code")
end

function test_find_listening_ports_requires_valid_port_numbers()
    local result, err = network_probe.find_listening_ports({ ports = { 0 } })
    assert(result == nil, "Expected invalid port definitions to fail")
    assert(err:match("valid port numbers"), "Expected error to mention valid port numbers")
end

function test_inspect_mta_local_only_flags_non_loopback_smtp_ports()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        io_popen = function(cmd)
            if cmd == "ss -lntuH 2>/dev/null" then
                return handle_for({
                    "tcp LISTEN 0 128 0.0.0.0:25 0.0.0.0:*",
                    "tcp LISTEN 0 128 127.0.0.1:587 0.0.0.0:*",
                })
            end
            if cmd:match("^postconf") then
                return handle_for({ "inet_interfaces = localhost" })
            end
            return handle_for({}, 127)
        end,
    })

    local result = network_probe.inspect_mta_local_only({ ports = { 25, 465, 587 } })

    assert(result.available == true, "Expected ss evidence to be available")
    assert(result.local_only == false, "Expected non-loopback SMTP listener to fail local-only audit")
    assert(result.non_loopback_count == 1, "Expected one non-loopback listener")
    assert(result.config_local_only == true, "Expected localhost MTA config to pass its side of the audit")
end

function test_inspect_mta_local_only_passes_loopback_listeners_and_absent_mta_config()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        io_popen = function(cmd)
            if cmd == "ss -lntuH 2>/dev/null" then
                return handle_for({
                    "tcp LISTEN 0 128 127.0.0.1:25 0.0.0.0:*",
                    "tcp LISTEN 0 128 [::1]:587 [::]:*",
                })
            end
            return handle_for({}, 127)
        end,
    })

    local result = network_probe.inspect_mta_local_only({ ports = { 25, 465, 587 } })

    assert(result.local_only == true,
        "Expected loopback-only listeners and no detected MTA config to pass")
    assert(result.config_detected == false, "Expected absent MTA commands to be reported in-band")
end

function test_inspect_mta_local_only_rejects_config_bound_to_all_interfaces()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        io_popen = function(cmd)
            if cmd == "ss -lntuH 2>/dev/null" then
                return handle_for({})
            end
            if cmd:match("^postconf") then
                return handle_for({ "inet_interfaces = all" })
            end
            return handle_for({}, 127)
        end,
    })

    local result = network_probe.inspect_mta_local_only({ ports = { 25, 465, 587 } })

    assert(result.non_loopback_count == 0, "Expected no socket listener findings")
    assert(result.config_local_only == false, "Expected inet_interfaces=all to fail")
    assert(result.local_only == false, "Expected non-local MTA config to fail even when not listening")
end

function test_inspect_mta_local_only_rejects_wildcard_and_mixed_config_values()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        io_popen = function(cmd)
            if cmd == "ss -lntuH 2>/dev/null" then
                return handle_for({})
            end
            if cmd:match("^postconf") then
                return handle_for({ "inet_interfaces = localhost, 192.168.1.10" })
            end
            if cmd:match("^exim") then
                return handle_for({ "local_interfaces = <; 127.0.0.1 ; ::1" })
            end
            if cmd:match("^grep %-i") then
                return handle_for({ "Addr=0.0.0.0" })
            end
            return handle_for({}, 127)
        end,
    })

    local result = network_probe.inspect_mta_local_only({ ports = { 25, 465, 587 } })

    assert(result.config_detected == true, "Expected all detected MTA configs to be reported")
    assert(#result.config_details == 3, "Expected Postfix, Exim, and Sendmail evidence to be retained")
    assert(result.config_local_only == false,
        "Expected mixed loopback/non-loopback or wildcard MTA config values to fail")
    assert(result.local_only == false, "Expected any non-local MTA config to fail the aggregate rule")
end

function test_inspect_mta_local_only_requires_every_detected_config_to_be_local_only()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        io_popen = function(cmd)
            if cmd == "ss -lntuH 2>/dev/null" then
                return handle_for({})
            end
            if cmd:match("^postconf") then
                return handle_for({ "inet_interfaces = localhost" })
            end
            if cmd:match("^exim") then
                return handle_for({ "local_interfaces = 10.0.0.5" })
            end
            return handle_for({}, 127)
        end,
    })

    local result = network_probe.inspect_mta_local_only({ ports = { 25, 465, 587 } })

    assert(result.config_details[1].local_only == true, "Expected loopback Postfix config to pass")
    assert(result.config_details[2].local_only == false, "Expected non-loopback Exim config to fail")
    assert(result.local_only == false, "Expected one non-local config to fail the aggregate rule")
end

function test_inspect_wireless_modules_passes_when_no_wireless_interfaces_exist()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        lfs_dir = function(path)
            assert(path == "/sys/class/net", "Expected sysfs network root to be listed")
            return dir_iter({ ".", "..", "eth0" })
        end,
        lfs_attributes = function(path)
            if path == "/sys/class/net/eth0/wireless" then
                return nil
            end
            return { mode = "directory" }
        end,
    })

    local result = network_probe.inspect_wireless_modules({ sys_class_net = "/sys/class/net" })

    assert(result.available == true, "Expected sysfs interface listing to be marked available")
    assert(result.wireless_present == false, "Expected no wireless interfaces")
    assert(result.disabled == true, "Expected no wireless interfaces to satisfy CIS disabled semantics")
end

function test_inspect_wireless_modules_fails_when_sysfs_cannot_be_listed()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        lfs_dir = function()
            return nil, "permission denied"
        end,
    })

    local result = network_probe.inspect_wireless_modules({ sys_class_net = "/sys/class/net" })

    assert(result.available == false, "Expected unavailable sysfs evidence to fail closed")
    assert(result.disabled == false, "Expected unavailable wireless evidence not to pass")
    assert(result.error:find("permission denied", 1, true), "Expected directory error evidence to be retained")
end

function test_inspect_wireless_modules_fails_when_wireless_module_is_not_disabled()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        lfs_dir = function(path)
            assert(path == "/sys/class/net", "Expected sysfs network root to be listed")
            return dir_iter({ ".", "..", "wlan0" })
        end,
        lfs_attributes = function(path)
            if path == "/sys/class/net/wlan0/wireless" then
                return { mode = "directory" }
            end
            return { mode = "directory" }
        end,
        io_popen = function(cmd)
            assert(cmd:find("readlink %-f", 1, false), "Expected wireless module discovery to resolve module symlink")
            return handle_for({ "/sys/module/iwlwifi" })
        end,
        kmod_get_disable_state = function(params)
            assert(params.name == "iwlwifi", "Expected wireless driver module to be checked")
            return { name = params.name, disabled = false, loaded = true }
        end,
    })

    local result = network_probe.inspect_wireless_modules({ sys_class_net = "/sys/class/net" })

    assert(result.wireless_present == true, "Expected wireless interface evidence")
    assert(result.invalid_count == 1, "Expected enabled wireless module to be counted")
    assert(result.disabled == false, "Expected enabled wireless module to fail CIS disabled semantics")
end

function test_inspect_wireless_modules_fails_when_module_cannot_be_resolved()
    network_probe._test_set_dependencies({
        client_new = function() return nil, "no nm" end,
        lfs_dir = function()
            return dir_iter({ ".", "..", "wlan0" })
        end,
        lfs_attributes = function(path)
            if path == "/sys/class/net/wlan0/wireless" then
                return { mode = "directory" }
            end
            return { mode = "directory" }
        end,
        io_popen = function()
            return handle_for({}, 1)
        end,
        kmod_get_disable_state = function()
            error("kmod should not be queried without a resolved module")
        end,
    })

    local result = network_probe.inspect_wireless_modules({ sys_class_net = "/sys/class/net" })

    assert(result.unresolved_count == 1, "Expected unresolved wireless driver evidence to be visible")
    assert(result.disabled == false, "Expected unresolved wireless module evidence to fail closed")
end

function test_network_probe_can_load_without_nm_module_for_port_checks()
    local saved_preload = package.preload["nm"]
    local saved_nm = package.loaded["nm"]
    local saved_probe = package.loaded["seharden.probes.network"]

    package.preload["nm"] = nil
    package.loaded["nm"] = nil
    package.loaded["seharden.probes.network"] = nil

    local ok, reloaded = pcall(require, "seharden.probes.network")

    package.preload["nm"] = saved_preload
    package.loaded["nm"] = saved_nm
    package.loaded["seharden.probes.network"] = saved_probe

    assert(ok == true, "Expected network probe module to load even when nm is unavailable")
    assert(type(reloaded.find_listening_ports) == "function",
        "Expected port-listening probe to remain available without nm")
end
