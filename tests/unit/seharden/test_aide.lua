local aide_probe = require('seharden.probes.aide')

local function with_dependencies(deps, fn)
    aide_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    aide_probe._test_set_dependencies()
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

function test_inspect_required_file_rules_expands_aliases_and_includes()
    local files = {
        ["/etc/aide.conf"] = table.concat({
            "AUDIT = p+i+n+u+g+s+b+acl+xattrs+sha512",
            "@@include /etc/aide.conf.d/audit.conf",
        }, "\n"),
        ["/etc/aide.conf.d/audit.conf"] = "/usr/sbin/auditctl AUDIT\n",
    }

    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/aide.conf.d" then
                return { mode = "directory" }
            end
            if path == "/usr/sbin/auditctl" or files[path] then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/aide.conf.d", "Expected AIDE include directory enumeration")
            return dir_iter({ ".", "..", "audit.conf" })
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected read-only AIDE config access")
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
        io_popen = function(cmd, mode)
            assert(mode == "r", "Expected readlink output to be read")
            return {
                read = function()
                    assert(cmd:find("/sbin/auditctl", 1, true), "Expected /sbin tool candidate to be resolved")
                    return "/usr/sbin/auditctl"
                end,
                close = function() end,
            }
        end,
    }, function()
        local result = aide_probe.inspect_required_file_rules({
            config_paths = { "/etc/aide.conf" },
            required_tools = { "auditctl" },
            required_attrs = { "p", "i", "n", "u", "g", "s", "b", "acl", "xattrs", "sha512" },
        })

        assert(result.available == true, "Expected AIDE config evidence to be available")
        assert(result.checked_count == 2, "Expected main config and include file to be parsed")
        assert(result.required_count == 1, "Expected existing audit tool to be checked")
        assert(result.all_configured == true, "Expected complete AIDE rule to pass")
    end)
end

function test_inspect_required_file_rules_reports_missing_attrs_in_band()
    local files = {
        ["/etc/aide.conf"] = "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs\n",
    }

    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/aide.conf" or path == "/usr/sbin/auditd" then
                return { mode = "file" }
            end
            return nil
        end,
        io_open = function(path)
            return handle_for(assert(files[path], "Unexpected file: " .. tostring(path)))
        end,
        io_popen = function()
            return {
                read = function() return "/usr/sbin/auditd" end,
                close = function() end,
            }
        end,
    }, function()
        local result = aide_probe.inspect_required_file_rules({
            config_paths = { "/etc/aide.conf" },
            required_tools = { "auditd" },
            required_attrs = { "p", "i", "n", "u", "g", "s", "b", "acl", "xattrs", "sha512" },
        })

        assert(result.available == true, "Expected readable config to be available")
        assert(result.all_configured == false, "Expected missing sha512 to fail the aggregate")
        assert(result.violation_count == 1, "Expected one audit tool violation")
        assert(result.details[1].missing_attrs[1] == "sha512", "Expected missing attr evidence")
    end)
end

function test_inspect_required_file_rules_treats_missing_tools_as_not_required()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/aide.conf" then
                return { mode = "file" }
            end
            return nil
        end,
        io_open = function()
            return handle_for("")
        end,
    }, function()
        local result = aide_probe.inspect_required_file_rules({
            config_paths = { "/etc/aide.conf" },
            required_tools = { "autrace" },
            required_attrs = { "sha512" },
        })

        assert(result.available == true, "Expected AIDE config to be available")
        assert(result.required_count == 0, "Expected absent audit tools not to be required")
        assert(result.all_configured == true, "Expected no existing audit tools to pass")
    end)
end

function test_inspect_required_file_rules_fails_closed_when_config_missing()
    with_dependencies({
        lfs_attributes = function()
            return nil
        end,
    }, function()
        local result = aide_probe.inspect_required_file_rules({
            config_paths = { "/etc/aide.conf" },
            required_tools = { "auditctl" },
            required_attrs = { "sha512" },
        })

        assert(result.available == false, "Expected missing AIDE config evidence not to pass as available")
        assert(result.all_configured == false, "Expected missing config evidence to fail closed")
    end)
end
