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
    assert(result == nil, "Expected non-existent sysctl key to fail the probe")
    assert(err:find("non_existent_key", 1, true), "Expected missing sysctl error to mention the key path")

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
