local sudo_probe = require('seharden.probes.sudo')

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

local function with_dependencies(deps, fn)
    sudo_probe._test_set_dependencies(deps)
    local ok, err = pcall(fn)
    sudo_probe._test_set_dependencies()
    if not ok then
        error(err, 0)
    end
end

function test_find_use_pty_resolves_includedir_and_reports_negations()
    with_dependencies({
        get_short_hostname = function()
            return "host"
        end,
        lfs_attributes = function(path)
            if path == "/etc/sudoers" then
                return { mode = "file" }
            end
            if path == "/etc/sudoers.d" then
                return { mode = "directory" }
            end
            if path == "/etc/sudoers.d/10-hardening" or path == "/etc/sudoers.d/90-legacy" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/sudoers.d", "Expected sudo probe to enumerate the includedir")
            local entries = {
                ".",
                "..",
                "README.md",
                "10-hardening",
                "90-legacy",
                "50-temp~",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected sudo probe to open files read-only")
            if path == "/etc/sudoers" then
                return make_reader({
                    "#includedir /etc/sudoers.d"
                })
            end
            if path == "/etc/sudoers.d/10-hardening" then
                return make_reader({
                    "Defaults use_pty"
                })
            end
            if path == "/etc/sudoers.d/90-legacy" then
                return make_reader({
                    "Defaults !use_pty"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = sudo_probe.find_use_pty({
            paths = { "/etc/sudoers" }
        })

        assert(result.found == true, "Expected included sudoers files to enable use_pty")
        assert(result.count == 1, "Expected one active use_pty directive")
        assert(result.conflicting_count == 1, "Expected explicit !use_pty directives to be reported")
    end)
end

function test_find_use_pty_requires_global_enable_and_honors_last_flag_on_line()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/sudoers" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            error("Did not expect includedir enumeration")
        end,
        io_open = function(path, mode)
            assert(path == "/etc/sudoers", "Expected sudo probe to read the configured sudoers file")
            assert(mode == "r", "Expected sudo probe to open files read-only")
            return make_reader({
                "Defaults:deploy use_pty",
                "Defaults !use_pty, use_pty",
                "Defaults!SHELLS !use_pty",
            })
        end
    }, function()
        local result = sudo_probe.find_use_pty({
            paths = { "/etc/sudoers" }
        })

        assert(result.found == true, "Expected a final global use_pty setting to satisfy the positive check")
        assert(result.count == 1, "Expected only global use_pty settings to satisfy the policy")
        assert(result.conflicting_count == 1, "Expected scoped !use_pty directives to remain violations")
    end)
end

function test_find_nopasswd_entries_handles_include_and_ignores_indented_comments()
    with_dependencies({
        get_short_hostname = function()
            return "host"
        end,
        lfs_attributes = function(path)
            if path == "/etc/sudoers" or path == "/etc/sudoers.host" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            error("Did not expect includedir enumeration")
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected sudo probe to open files read-only")
            if path == "/etc/sudoers" then
                return make_reader({
                    "@include /etc/sudoers.%h",
                    "   # alice ALL=(ALL) NOPASSWD: ALL",
                })
            end
            if path == "/etc/sudoers.host" then
                return make_reader({
                    "alice ALL=(ALL) NOPASSWD: /bin/systemctl"
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = sudo_probe.find_nopasswd_entries({
            paths = { "/etc/sudoers" }
        })

        assert(result.count == 1, "Expected included sudoers entries to be scanned for NOPASSWD")
        assert(result.details[1].path == "/etc/sudoers.host", "Expected host-expanded include path to be preserved")
    end)
end

function test_find_nopasswd_entries_reports_authenticate_disabled_defaults()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/sudoers" then
                return { mode = "file" }
            end
            return nil
        end,
        lfs_dir = function()
            error("Did not expect includedir enumeration")
        end,
        io_open = function(path, mode)
            assert(path == "/etc/sudoers", "Expected sudo probe to read the configured sudoers file")
            assert(mode == "r", "Expected sudo probe to open files read-only")
            return make_reader({
                "Defaults lecture=once",
                "Defaults:deploy !authenticate",
            })
        end
    }, function()
        local result = sudo_probe.find_nopasswd_entries({
            paths = { "/etc/sudoers" }
        })

        assert(result.count == 1, "Expected !authenticate Defaults entries to be treated as no-password sudo violations")
        assert(result.details[1].reason == "authenticate_disabled",
            "Expected !authenticate violations to preserve their reason")
    end)
end

function test_collect_audit_paths_tracks_root_file_includedir_and_explicit_includes()
    with_dependencies({
        get_short_hostname = function()
            return "host"
        end,
        lfs_attributes = function(path)
            if path == "/etc/sudoers"
                or path == "/etc/sudoers.host"
                or path == "/etc/sudoers.d/10-hardening" then
                return { mode = "file" }
            end
            if path == "/etc/sudoers.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/sudoers.d", "Expected sudo probe to enumerate the includedir")
            local entries = {
                ".",
                "..",
                "10-hardening",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected sudo probe to open files read-only")
            if path == "/etc/sudoers" then
                return make_reader({
                    "@include /etc/sudoers.%h",
                    "#includedir /etc/sudoers.d",
                })
            end
            if path == "/etc/sudoers.host" then
                return make_reader({
                    "Defaults use_pty",
                })
            end
            if path == "/etc/sudoers.d/10-hardening" then
                return make_reader({
                    "Defaults secure_path=/usr/sbin:/usr/bin",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = sudo_probe.collect_audit_paths({
            paths = { "/etc/sudoers" }
        })

        assert(result.count == 3, "Expected sudo audit path collection to include active root, include, and includedir paths")
        assert(result.details[1].path == "/etc/sudoers", "Expected root sudoers file to be included")
        assert(result.details[2].path == "/etc/sudoers.host", "Expected explicit include file to be included")
        assert(result.details[3].path == "/etc/sudoers.d", "Expected includedir path to be included")
    end)
end

function test_collect_permission_paths_tracks_included_files_and_directories()
    with_dependencies({
        get_short_hostname = function()
            return "host"
        end,
        lfs_attributes = function(path)
            if path == "/etc/sudoers"
                or path == "/etc/sudoers.host"
                or path == "/etc/sudoers.d/10-hardening" then
                return { mode = "file" }
            end
            if path == "/etc/sudoers.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/sudoers.d", "Expected sudo probe to enumerate the includedir")
            local entries = {
                ".",
                "..",
                "10-hardening",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected sudo probe to open files read-only")
            if path == "/etc/sudoers" then
                return make_reader({
                    "@include /etc/sudoers.%h",
                    "#includedir /etc/sudoers.d",
                })
            end
            if path == "/etc/sudoers.host" then
                return make_reader({
                    "Defaults use_pty",
                })
            end
            if path == "/etc/sudoers.d/10-hardening" then
                return make_reader({
                    "Defaults secure_path=/usr/sbin:/usr/bin",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = sudo_probe.collect_permission_paths({
            paths = { "/etc/sudoers" }
        })

        assert(result.count == 4, "Expected sudo permission path collection to include files and includedir")
        assert(result.details[1].path_type == "file", "Expected /etc/sudoers to be recorded as a file")
        assert(result.details[3].path_type == "directory", "Expected includedir path to be recorded as a directory")
        assert(result.details[4].path == "/etc/sudoers.d/10-hardening", "Expected includedir member file to be included")
    end)
end

function test_collect_permission_paths_skips_includedir_members_with_dots()
    with_dependencies({
        lfs_attributes = function(path)
            if path == "/etc/sudoers" or path == "/etc/sudoers.d/10-hardening" or path == "/etc/sudoers.d/README.md" then
                return { mode = "file" }
            end
            if path == "/etc/sudoers.d" then
                return { mode = "directory" }
            end
            return nil
        end,
        lfs_dir = function(path)
            assert(path == "/etc/sudoers.d", "Expected sudo probe to enumerate the includedir")
            local entries = {
                ".",
                "..",
                "10-hardening",
                "README.md",
            }
            local index = 0
            return function()
                index = index + 1
                return entries[index]
            end
        end,
        io_open = function(path, mode)
            assert(mode == "r", "Expected sudo probe to open files read-only")
            if path == "/etc/sudoers" then
                return make_reader({
                    "#includedir /etc/sudoers.d",
                })
            end
            if path == "/etc/sudoers.d/10-hardening" then
                return make_reader({
                    "Defaults use_pty",
                })
            end
            error("Unexpected path: " .. path)
        end
    }, function()
        local result = sudo_probe.collect_permission_paths({
            paths = { "/etc/sudoers" }
        })

        assert(result.count == 3, "Expected includedir members with dots to be skipped")
        for _, detail in ipairs(result.details) do
            assert(detail.path ~= "/etc/sudoers.d/README.md",
                "Expected dotted includedir members to be excluded from sudoers traversal")
        end
    end)
end
