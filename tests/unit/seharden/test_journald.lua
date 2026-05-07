local journald_probe = require('seharden.probes.journald')

local function with_dependencies(deps, fn)
    journald_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    journald_probe._test_set_dependencies({})
    if not ok then
        error(err, 0)
    end
end

local function handle_for(content)
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
end

local function dir_iter(entries)
    local state = { entries = entries, index = 0 }
    return function(s)
        s.index = s.index + 1
        return s.entries[s.index]
    end, state
end

function test_inspect_forward_to_syslog_disabled_accepts_default_missing_value()
    with_dependencies({
        lfs_attributes = function()
            return nil
        end,
    }, function()
        local result = journald_probe.inspect_forward_to_syslog_disabled({
            path = "/etc/systemd/journald.conf",
            config_dirs = { "/etc/systemd" },
        })

        assert(result.available == true, "Expected missing config to use systemd default")
        assert(result.found == false, "Expected missing ForwardToSyslog evidence")
        assert(result.configured == true, "Expected default ForwardToSyslog=no to pass")
    end)
end

function test_inspect_forward_to_syslog_disabled_uses_effective_dropin_precedence()
    local files = {
        ["/usr/lib/systemd/journald.conf"] = "[Journal]\nForwardToSyslog=yes\n",
        ["/etc/systemd/journald.conf.d/99-local.conf"] = "[Journal]\nForwardToSyslog=no\n",
    }
    local dirs = {
        ["/etc/systemd/journald.conf.d"] = { ".", "..", "99-local.conf" },
    }

    with_dependencies({
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
            return dir_iter(assert(dirs[path], "Unexpected directory: " .. tostring(path)))
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only journald config access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local result = journald_probe.inspect_forward_to_syslog_disabled({
            path = "/etc/systemd/journald.conf",
            config_dirs = { "/etc/systemd", "/usr/lib/systemd" },
        })

        assert(result.available == true, "Expected effective config to be readable")
        assert(result.value == "no", "Expected higher-precedence drop-in value")
        assert(result.configured == true, "Expected explicit no to pass")
    end)
end

function test_inspect_forward_to_syslog_disabled_rejects_yes_and_unknown_values()
    local files = {
        ["/etc/systemd/journald.conf"] = "[Journal]\nForwardToSyslog=yes\n",
        ["/etc/systemd/bad.conf"] = "[Journal]\nForwardToSyslog=maybe\n",
    }

    with_dependencies({
        lfs_attributes = function(path, attr)
            local mode = files[path] and "file" or nil
            if attr == "mode" then
                return mode
            end
            return mode and { mode = mode } or nil
        end,
        io_open = function(path)
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local yes = journald_probe.inspect_forward_to_syslog_disabled({
            path = "/etc/systemd/journald.conf",
            config_dirs = { "/etc/systemd" },
        })
        local unknown = journald_probe.inspect_forward_to_syslog_disabled({
            path = "/etc/systemd/bad.conf",
            config_dirs = { "/etc/systemd" },
        })

        assert(yes.configured == false, "Expected ForwardToSyslog=yes to fail")
        assert(unknown.configured == false, "Expected unknown boolean value to fail")
    end)
end
