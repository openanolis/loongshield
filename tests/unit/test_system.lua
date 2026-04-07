local system_probe = require('seharden.probes.system')

local function make_reader(lines, close_ok, close_code)
    local index = 0
    return {
        lines = function()
            return function()
                index = index + 1
                return lines[index]
            end
        end,
        close = function()
            return close_ok ~= false, nil, close_code
        end
    }
end

local function with_dependencies(deps, fn)
    system_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    system_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_get_supported_audit_arches_prefers_ausyscall_detection()
    with_dependencies({
        io_popen = function(cmd, mode)
            assert(mode == "r", "Expected system probe to open commands read-only")
            if cmd == "uname -m" then
                return make_reader({ "x86_64" })
            end
            if cmd == "ausyscall b64 0 2>/dev/null" then
                return make_reader({ "read" })
            end
            if cmd == "ausyscall b32 0 2>/dev/null" then
                return make_reader({ "restart_syscall" })
            end
            error("Unexpected command: " .. cmd)
        end
    }, function()
        local result = system_probe.get_supported_audit_arches()

        assert(result.count == 2, "Expected both b64 and b32 audit arches to be detected")
        assert(result.arches[1] == "b64", "Expected native b64 arch to be listed first")
        assert(result.arches[2] == "b32", "Expected compat b32 arch to be listed second")
        assert(result.machine_arch == "x86_64", "Expected machine architecture to be preserved")
    end)
end

function test_get_supported_audit_arches_falls_back_to_machine_arch()
    with_dependencies({
        io_popen = function(cmd, mode)
            assert(mode == "r", "Expected system probe to open commands read-only")
            if cmd == "uname -m" then
                return make_reader({ "loongarch64" })
            end
            if cmd == "ausyscall b64 0 2>/dev/null" or cmd == "ausyscall b32 0 2>/dev/null" then
                return make_reader({}, false, 1)
            end
            error("Unexpected command: " .. cmd)
        end
    }, function()
        local result = system_probe.get_supported_audit_arches()

        assert(result.count == 1, "Expected machine-arch fallback to yield one audit arch")
        assert(result.arches[1] == "b64", "Expected 64-bit machine fallback to require b64 audit rules")
        assert(result.machine_arch == "loongarch64", "Expected fallback to preserve machine architecture")
    end)
end
