local syslog_probe = require('seharden.probes.syslog')

local function with_dependencies(deps, fn)
    syslog_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    syslog_probe._test_set_dependencies()
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

function test_inspect_rsyslog_effective_config_accepts_restrictive_file_create_mode()
    local files = {
        ["/etc/rsyslog.conf"] = "$FileCreateMode 0600\n",
        ["/etc/rsyslog.d/10-extra.conf"] = "# $FileCreateMode 0666\n",
    }

    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/rsyslog.d" then
                return { mode = "directory" }
            end
            if files[path] then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/rsyslog.d", "Expected rsyslog drop-in enumeration")
            return dir_iter({ ".", "..", "10-extra.conf" })
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only rsyslog config access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local result = syslog_probe.inspect_rsyslog_effective_config({
            paths = { "/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf" },
            require_file_create_mode_max = "0640",
        })

        assert(result.available == true, "Expected rsyslog config evidence to be available")
        assert(result.checked_count == 2, "Expected main config and drop-in to be inspected")
        assert(result.file_create_mode_found == true, "Expected active FileCreateMode evidence")
        assert(result.file_create_mode_ok == true, "Expected 0600 to satisfy 0640 maximum")
        assert(result.all_configured == true, "Expected file-create-mode-only check to pass")
    end)
end

function test_inspect_rsyslog_effective_config_rejects_later_permissive_file_mode()
    local files = {
        ["/etc/rsyslog.conf"] = "$FileCreateMode 0640\n",
        ["/etc/rsyslog.d/99-bad.conf"] = "$FileCreateMode 0666\n",
    }

    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/rsyslog.d" then
                return { mode = "directory" }
            end
            if files[path] then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            return dir_iter({ ".", "..", "99-bad.conf" })
        end,
        io_open = function(path)
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local result = syslog_probe.inspect_rsyslog_effective_config({
            paths = { "/etc/rsyslog.conf", "/etc/rsyslog.d/*.conf" },
            require_file_create_mode_max = "0640",
        })

        assert(result.file_create_mode_found == true, "Expected FileCreateMode evidence")
        assert(result.file_create_mode_ok == false, "Expected permissive override to fail")
        assert(result.file_create_mode_violation_count == 1, "Expected one bad FileCreateMode")
        assert(result.all_configured == false, "Expected aggregate failure")
    end)
end

function test_inspect_rsyslog_effective_config_detects_active_tcp_remote_input()
    local files = {
        ["/etc/rsyslog.conf"] = table.concat({
            '# module(load="imtcp")',
            'module(load="imtcp")',
            'input(type="imtcp" port="514")',
        }, "\n"),
    }

    with_dependencies({
        lfs_attributes = function(path)
            if files[path] then
                return { mode = "file" }
            end
            return nil
        end,
        io_open = function(path)
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
    }, function()
        local result = syslog_probe.inspect_rsyslog_effective_config({
            paths = { "/etc/rsyslog.conf" },
            disallow_remote_input = true,
        })

        assert(result.available == true, "Expected rsyslog config evidence to be available")
        assert(result.remote_input_enabled == true, "Expected active imtcp input to be detected")
        assert(result.remote_input_count == 2, "Expected module and input evidence")
        assert(result.all_configured == false, "Expected remote-input prohibition to fail")
    end)
end

function test_inspect_rsyslog_effective_config_fails_closed_without_files()
    with_dependencies({
        lfs_attributes = function()
            return nil
        end,
    }, function()
        local result = syslog_probe.inspect_rsyslog_effective_config({
            paths = { "/etc/rsyslog.conf" },
            disallow_remote_input = true,
        })

        assert(result.available == false, "Expected missing rsyslog config evidence to be unavailable")
        assert(result.all_configured == false, "Expected missing config not to pass")
    end)
end
