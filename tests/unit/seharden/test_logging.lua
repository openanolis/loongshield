local logging_probe = require('seharden.probes.logging')

local function with_dependencies(deps, fn)
    logging_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    logging_probe._test_set_dependencies()
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

local function make_attr(uid, gid, mode)
    return {
        uid = function() return uid end,
        gid = function() return gid end,
        mode = function() return mode end,
    }
end

function test_inspect_logfile_access_accepts_default_and_journal_policies()
    local dirs = {
        ["/var/log"] = { ".", "..", "messages", "journal" },
        ["/var/log/journal"] = { ".", "..", "system.journal" },
    }
    local modes = {
        ["/var/log"] = "directory",
        ["/var/log/journal"] = "directory",
        ["/var/log/messages"] = "file",
        ["/var/log/journal/system.journal"] = "file",
    }
    local stats = {
        ["/var/log/messages"] = make_attr(0, 4, tonumber("640", 8)),
        ["/var/log/journal/system.journal"] = make_attr(0, 190, tonumber("640", 8)),
    }

    with_dependencies({
        lfs_attributes = function(path)
            return modes[path] and { mode = modes[path] } or nil
        end,
        lfs_dir = function(path)
            return dir_iter(assert(dirs[path], "Unexpected directory: " .. tostring(path)))
        end,
        fs_stat = function(path)
            return stats[path]
        end,
        io_open = function(path)
            if path == "/etc/passwd" then
                return handle_for("root:x:0:0:root:/root:/bin/bash\nsyslog:x:101:101::/nonexistent:/sbin/nologin\n")
            end
            if path == "/etc/group" then
                return handle_for("root:x:0:\nadm:x:4:\nsystemd-journal:x:190:\n")
            end
            return nil, "unexpected file"
        end,
    }, function()
        local result = logging_probe.inspect_logfile_access({ root_path = "/var/log" })

        assert(result.available == true, "Expected /var/log evidence to be available")
        assert(result.checked_count == 2, "Expected both regular log files to be inspected")
        assert(result.violation_count == 0, "Expected compliant logfile access")
        assert(result.all_configured == true, "Expected aggregate pass")
    end)
end

function test_inspect_logfile_access_reports_permission_and_owner_violations()
    local modes = {
        ["/var/log"] = "directory",
        ["/var/log/open.log"] = "file",
        ["/var/log/unknown-owner.log"] = "file",
    }
    local stats = {
        ["/var/log/open.log"] = make_attr(0, 4, tonumber("666", 8)),
        ["/var/log/unknown-owner.log"] = make_attr(9000, 4, tonumber("640", 8)),
    }

    with_dependencies({
        lfs_attributes = function(path)
            return modes[path] and { mode = modes[path] } or nil
        end,
        lfs_dir = function()
            return dir_iter({ ".", "..", "open.log", "unknown-owner.log" })
        end,
        fs_stat = function(path)
            return stats[path]
        end,
        io_open = function(path)
            if path == "/etc/passwd" then
                return handle_for("root:x:0:0:root:/root:/bin/bash\n")
            end
            if path == "/etc/group" then
                return handle_for("root:x:0:\nadm:x:4:\n")
            end
            return nil, "unexpected file"
        end,
    }, function()
        local result = logging_probe.inspect_logfile_access({ root_path = "/var/log" })

        assert(result.available == true, "Expected readable evidence")
        assert(result.violation_count == 2, "Expected mode and unmapped owner violations")
        assert(result.all_configured == false, "Expected aggregate failure")
        assert(result.details[1].configured == false, "Expected noncompliant detail evidence")
    end)
end

function test_inspect_logfile_access_fails_in_band_when_log_dir_unreadable()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/var/log" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function()
            return nil, "permission denied"
        end,
        io_open = function(path)
            if path == "/etc/passwd" then
                return handle_for("root:x:0:0:root:/root:/bin/bash\n")
            end
            if path == "/etc/group" then
                return handle_for("root:x:0:\n")
            end
            return nil, "unexpected file"
        end,
    }, function()
        local result = logging_probe.inspect_logfile_access({ root_path = "/var/log" })

        assert(result.available == false, "Expected unreadable directory evidence to be unavailable")
        assert(result.all_configured == false, "Expected unreadable evidence not to pass")
        assert(result.error:find("permission denied", 1, true), "Expected traversal error evidence")
    end)
end
