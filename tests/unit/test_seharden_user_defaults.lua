local user_defaults = require('seharden.user_defaults')

local function make_reader(lines)
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

function test_read_uid_min_supports_assignment_syntax()
    local result = user_defaults.read_uid_min(function(path, mode)
        assert(path == "/tmp/login.defs", "Expected configured login.defs path to be used")
        assert(mode == "r", "Expected login.defs to be opened read-only")
        return make_reader({
            "# comment",
            "UID_MIN = 500",
        })
    end, "/tmp/login.defs")

    assert(result == 500, "Expected UID_MIN assignment syntax to be parsed")
end

function test_read_uid_min_defaults_to_1000_when_file_is_missing()
    local result = user_defaults.read_uid_min(function(path, mode)
        assert(path == "/tmp/login.defs", "Expected configured login.defs path to be used")
        assert(mode == "r", "Expected login.defs to be opened read-only")
        return nil
    end, "/tmp/login.defs")

    assert(result == 1000, "Expected missing login.defs to fall back to the default UID_MIN")
end

function test_get_useradd_defaults_prefers_useradd_output_on_success()
    local result, err = user_defaults.get_useradd_defaults(
        function(cmd, mode)
            assert(cmd == "useradd -D 2>/dev/null", "Expected stderr-silenced useradd invocation")
            assert(mode == "r", "Expected useradd output to be opened read-only")
            return make_reader({
                "GROUP=100",
                "INACTIVE=30",
                "SHELL=/bin/bash",
            })
        end,
        function()
            error("Expected successful useradd output to avoid defaults-file fallback")
        end,
        "/tmp/test-useradd-defaults")

    assert(err == nil, "Expected successful useradd probe to avoid surfacing an error")
    assert(result ~= nil, "Expected parsed defaults from useradd output")
    assert(result.GROUP == "100", "Expected string defaults to be preserved")
    assert(result.INACTIVE == 30, "Expected INACTIVE to be parsed numerically")
    assert(result.SHELL == "/bin/bash", "Expected SHELL to be preserved")
end

function test_get_useradd_defaults_falls_back_when_useradd_is_unavailable()
    local result, err = user_defaults.get_useradd_defaults(
        function()
            return nil
        end,
        function(path, mode)
            assert(path == "/tmp/test-useradd-defaults", "Expected configured useradd defaults path to be used")
            assert(mode == "r", "Expected defaults file to be opened read-only")
            return make_reader({
                "GROUP=100",
                "INACTIVE=45",
            })
        end,
        "/tmp/test-useradd-defaults")

    assert(err == nil, "Expected defaults file fallback to avoid surfacing an error")
    assert(result ~= nil, "Expected fallback defaults to be returned")
    assert(result.INACTIVE == 45, "Expected fallback INACTIVE value to be parsed numerically")
end
