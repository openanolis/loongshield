local sysctl_probe = require('seharden.probes.sysctl')
local T = {}

T.FAKE_PROC_ROOT = "/tmp/loongshield_sysctl_test_proc"

function T.setup()
    os.execute("rm -rf " .. T.FAKE_PROC_ROOT)

    local mock_path = T.FAKE_PROC_ROOT .. "/net/ipv4"
    os.execute("mkdir -p " .. mock_path)

    local f = assert(io.open(mock_path .. "/ip_forward", "w"))
    f:write("0\n")
    f:close()

    sysctl_probe.set_procfs_root(T.FAKE_PROC_ROOT)
end

function T.teardown()
    sysctl_probe.set_procfs_root("/proc/sys")
    sysctl_probe._test_set_dependencies()
    os.execute("rm -rf " .. T.FAKE_PROC_ROOT)
end

-- ==================== Test Cases ====================

function test_get_live_value_successfully()
    T.setup()

    local params = { key = "net.ipv4.ip_forward" }
    local result = sysctl_probe.get_live_value(params)
    assert(result.value == "0", "Failed to get correct sysctl value. Got: " .. tostring(result.value))

    T.teardown()
end

function test_get_live_value_for_non_existent_key()
    T.setup()

    local params = { key = "net.ipv4.non_existent_key" }
    local result, err = sysctl_probe.get_live_value(params)
    assert(err == nil, "Expected missing sysctl key evidence to be reported in-band")
    assert(result ~= nil, "Expected non-existent sysctl key to return structured evidence")
    assert(result.available == false, "Expected missing sysctl key to be unavailable")
    assert(result.value == nil, "Expected missing sysctl key not to have a value")
    assert(result.error:find("non_existent_key", 1, true), "Expected missing sysctl error to mention the key path")

    T.teardown()
end

function test_get_live_value_with_missing_parameter()
    local result, err = sysctl_probe.get_live_value({})
    assert(result == nil, "Expected result to be nil when key parameter is missing")
    assert(err:match("requires a 'key' parameter"), "Incorrect error message for missing parameter")
end

function test_get_live_value_rejects_invalid_key()
    local params = { key = "net.ipv4..ip_forward" }
    local result, err = sysctl_probe.get_live_value(params)
    assert(result == nil, "Expected invalid sysctl key to fail")
    assert(err == "Invalid key", "Expected invalid key error")
end

function test_get_persistent_value_uses_effective_sysctl_order()
    local files = {
        ["/usr/lib/sysctl.d/50-default.conf"] = "net.ipv4.ip_forward = 1\n",
        ["/etc/sysctl.d/50-default.conf"] = "net.ipv4.ip_forward = 0\n",
        ["/run/sysctl.d/99-runtime.conf"] = "net.ipv4.ip_forward = 1\n",
        ["/etc/sysctl.conf"] = "net/ipv4/ip_forward = 0\n",
    }
    local dirs = {
        ["/etc/sysctl.d"] = { ".", "..", "50-default.conf" },
        ["/run/sysctl.d"] = { ".", "..", "99-runtime.conf" },
        ["/usr/lib/sysctl.d"] = { ".", "..", "50-default.conf" },
    }

    sysctl_probe._test_set_dependencies({
        lfs_attributes = function(path, attr)
            local mode
            if files[path] then
                mode = "file"
            elseif dirs[path] then
                mode = "directory"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function(path)
            local entries = assert(dirs[path], "Unexpected directory: " .. tostring(path))
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only sysctl config access")
            local content = assert(files[path], "Unexpected file: " .. tostring(path))
            return {
                lines = function()
                    local lines = {}
                    for line in (content .. "\n"):gmatch("(.-)\n") do
                        lines[#lines + 1] = line
                    end
                    local index = 0
                    return function()
                        index = index + 1
                        return lines[index]
                    end
                end,
                close = function() end,
            }
        end,
    })

    local result = sysctl_probe.get_persistent_value({
        key = "net.ipv4.ip_forward",
        sysctl_d_dirs = { "/etc/sysctl.d", "/run/sysctl.d", "/usr/lib/sysctl.d" },
        sysctl_conf = "/etc/sysctl.conf",
    })

    sysctl_probe._test_set_dependencies()

    assert(result.found == true, "Expected persistent sysctl key to be found")
    assert(result.value == "0", "Expected /etc/sysctl.conf to be the final effective value")
    assert(result.source == "/etc/sysctl.conf", "Expected final source to identify the winning file")
end

function test_get_effective_value_requires_live_and_persistent_values_to_match()
    T.setup()

    sysctl_probe._test_set_dependencies({
        io_open = function(path, mode)
            if path == T.FAKE_PROC_ROOT .. "/net/ipv4/ip_forward" then
                return io.open(path, mode)
            end
            assert(path == "/etc/sysctl.conf", "Expected configured persistent source")
            return {
                lines = function()
                    local done = false
                    return function()
                        if done then return nil end
                        done = true
                        return "net.ipv4.ip_forward = 1"
                    end
                end,
                close = function() end,
            }
        end,
        lfs_attributes = function(path, attr)
            local mode
            if path == "/etc/sysctl.conf" then
                mode = "file"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function()
            return function() return nil end
        end,
    })

    local result = sysctl_probe.get_effective_value({
        key = "net.ipv4.ip_forward",
        sysctl_d_dirs = {},
        sysctl_conf = "/etc/sysctl.conf",
    })

    assert(result.live_value == "0", "Expected live value from fake procfs")
    assert(result.persistent_value == "1", "Expected persistent value from fake sysctl.conf")
    assert(result.value == nil, "Expected mismatched live/persistent values not to pass as effective")

    T.teardown()
end

function test_get_effective_value_reports_missing_live_value_without_engine_error()
    T.setup()

    sysctl_probe._test_set_dependencies({
        io_open = function(path, mode)
            if path == T.FAKE_PROC_ROOT .. "/net/ipv4/non_existent_key" then
                return nil, "No such file or directory"
            end
            assert(path == "/etc/sysctl.conf", "Expected configured persistent source")
            return {
                lines = function()
                    local done = false
                    return function()
                        if done then return nil end
                        done = true
                        return "net.ipv4.non_existent_key = 0"
                    end
                end,
                close = function() end,
            }
        end,
        lfs_attributes = function(path, attr)
            local mode
            if path == "/etc/sysctl.conf" then
                mode = "file"
            end
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        lfs_dir = function()
            return function() return nil end
        end,
    })

    local result, err = sysctl_probe.get_effective_value({
        key = "net.ipv4.non_existent_key",
        sysctl_d_dirs = {},
        sysctl_conf = "/etc/sysctl.conf",
    })

    assert(err == nil, "Expected missing live sysctl evidence not to become a probe error")
    assert(result.live_available == false, "Expected missing live sysctl evidence to be explicit")
    assert(result.live_value == nil, "Expected missing live sysctl evidence not to have a value")
    assert(result.persistent_found == true, "Expected persistent evidence to remain available")
    assert(result.value == nil, "Expected missing live evidence to fail effective value checks in-band")

    T.teardown()
end
