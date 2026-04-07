package.preload["nm"] = function()
    return {
        client_new = function()
            return nil, "no nm"
        end
    }
end

local network_probe = require('seharden.probes.network')

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

function test_find_listening_ports_requires_valid_port_numbers()
    local result, err = network_probe.find_listening_ports({ ports = { 0 } })
    assert(result == nil, "Expected invalid port definitions to fail")
    assert(err:match("valid port numbers"), "Expected error to mention valid port numbers")
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
